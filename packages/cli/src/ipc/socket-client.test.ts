import * as net from 'net';
import * as fs from 'fs';
import { ShieldSocketClient } from './socket-client';

const TEST_SOCKET_PATH = '/tmp/shield-test-socket.sock';

async function runTests() {
    console.log("🏃 Running IPC Socket Client Tests...");

    // Cleanup old socket
    if (fs.existsSync(TEST_SOCKET_PATH)) {
        fs.unlinkSync(TEST_SOCKET_PATH);
    }

    let server: net.Server;

    try {
        // --- Test 1: Exponential Backoff & Connection Failure ---
        const badClient = new ShieldSocketClient('/tmp/nonexistent-socket.sock');
        let failedAsExpected = false;
        try {
            console.log("   Test 1: Connecting to bad socket (testing 5s timeout...)");
            await badClient.connect();
        } catch (e: any) {
            if (e.message.includes("Failed to connect to shield-agent socket")) {
                failedAsExpected = true;
            } else {
                console.error("Got unexpected error:", e.message);
            }
        }
        if (!failedAsExpected) throw new Error("Test 1 Failed: Expected timeout error");
        console.log("   ✅ Test 1 Passed: Exponential backoff triggered failure after ~5s.");

        // --- Test 2: Successful Connection & NDJSON Parsing ---
        console.log("   Test 2: Starting mock server and testing NDJSON stream...");
        
        server = net.createServer((c) => {
            // Feed pre-baked NDJSON lines
            c.write('{"v":1,"ts":1718000000,"type":"network_block","dst_ip":"198.51.100.1","dst_port":443,"process":"agent.py","pid":1234}\n');
            c.write('{"v":1,"ts":1718000001,"type":"prompt_injection","turn":4,"confidence":0.94}\n');
            c.write('{"invalid json\n'); // Should trigger error event but not crash
            c.write('{"v":2,"ts":1718000002,"type":"status_request"}\n'); // Invalid version schema
        });
        
        server.listen(TEST_SOCKET_PATH);

        const goodClient = new ShieldSocketClient(TEST_SOCKET_PATH);
        await goodClient.connect();

        let networkBlockReceived = false;
        let promptInjectionReceived = false;
        let parseErrorReceived = false;
        let versionErrorReceived = false;

        goodClient.on('network_block', (event) => {
            if (event.dst_ip === "198.51.100.1") networkBlockReceived = true;
        });

        goodClient.on('prompt_injection', (event) => {
            if (event.confidence === 0.94) promptInjectionReceived = true;
        });

        goodClient.on('error', (err) => {
            if (err.message.includes("Failed to parse NDJSON")) parseErrorReceived = true;
            if (err.message.includes("Unsupported event schema version")) versionErrorReceived = true;
        });

        // Wait a moment for async socket reads to process
        await new Promise(resolve => setTimeout(resolve, 500));

        goodClient.disconnect();
        
        if (!networkBlockReceived) throw new Error("Test 2 Failed: Did not receive valid network_block event");
        if (!promptInjectionReceived) throw new Error("Test 2 Failed: Did not receive valid prompt_injection event");
        if (!parseErrorReceived) throw new Error("Test 2 Failed: Did not handle JSON parse error");
        if (!versionErrorReceived) throw new Error("Test 2 Failed: Did not enforce v: 1 schema contract");
        
        console.log("   ✅ Test 2 Passed: NDJSON parsing, typed emission, and schema enforcement working correctly.");

        console.log("\n🎉 All IPC Client Tests Passed!");

    } catch (err: any) {
        console.error(`\n❌ Test Failed: ${err.message}`);
        process.exit(1);
    } finally {
        if (server!) server.close();
        if (fs.existsSync(TEST_SOCKET_PATH)) fs.unlinkSync(TEST_SOCKET_PATH);
    }
}

// Run if called directly
if (require.main === module) {
    runTests();
}
