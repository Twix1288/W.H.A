import { exec } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs';
import * as path from 'path';
import { ShieldSocketClient } from './socket-client';

const execAsync = promisify(exec);

async function waitForSocket(socketPath: string, timeoutMs: number = 10000): Promise<void> {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
        try {
            await fs.promises.access(socketPath);
            return; // socket file exists, proceed
        } catch {
            await new Promise(r => setTimeout(r, 200));
        }
    }
    throw new Error(`Socket file never appeared at ${socketPath} after ${timeoutMs}ms`);
}

async function runIntegrationTest() {
    console.log("🏃 Running E2E Integration Test...");

    const useDocker = !process.env.NO_DOCKER;
    const socketMountDir = '/tmp/shield-test-sockets';
    if (!fs.existsSync(socketMountDir)) {
        fs.mkdirSync(socketMountDir, { recursive: true });
    }
    const socketPath = path.join(socketMountDir, 'shield-agent.sock');
    if (fs.existsSync(socketPath)) {
        fs.unlinkSync(socketPath);
    }

    let containerName = '';

    if (useDocker) {
        console.log("   Building shield-agent image...");
        try {
            await execAsync('cd ../shield-agent && docker build -t shield-agent-integration -f Dockerfile.smoketest .');
        } catch (e: any) {
            console.error("Failed to build image:", e.message);
            process.exit(1);
        }

        console.log("   Starting container with --privileged for eBPF...");
        containerName = `shield-test-${Date.now()}`;
        await execAsync(`docker run -d --name ${containerName} --privileged -v ${socketMountDir}:/tmp -v /sys/kernel/debug:/sys/kernel/debug:rw -v /sys/kernel/tracing:/sys/kernel/tracing:rw shield-agent-integration sleep infinity`);
    }

    try {
        if (useDocker) {
            console.log("   Starting agent in background...");
            // Start it in background and redirect logs to a file we can inspect if it fails
            await execAsync(`docker exec -d ${containerName} sh -c "/app/shield-agent > /tmp/agent.log 2>&1"`);
        } else {
            console.log("   Waiting for agent (assumed to be started externally via NO_DOCKER)...");
        }

        console.log("   Connecting TS Client to socket...");
        await waitForSocket(socketPath);
        const client = new ShieldSocketClient(socketPath);
        
        let networkBlocked = false;
        client.on('network_block', (event) => {
            console.log(`   ✅ Received network_block event from eBPF! PID: ${event.pid}, IP: ${event.dst_ip}`);
            if (event.dst_ip === "1.1.1.1") {
                networkBlocked = true;
            }
        });

        client.on('error', (err) => {
            console.error("Socket Error:", err.message);
        });

        // Use the tested exponential backoff
        await client.connect();

        console.log("   Triggering mocked agent outbound call...");
        if (useDocker) {
            await execAsync(`docker exec ${containerName} apt-get update && apt-get install -y curl`);
            await execAsync(`docker exec ${containerName} curl -s -m 2 https://1.1.1.1 || true`);
        } else {
            await execAsync(`curl -s -m 2 https://1.1.1.1 || true`);
        }

        // Wait a second for event to stream
        await new Promise(r => setTimeout(r, 1000));

        client.disconnect();

        if (!networkBlocked) {
            throw new Error("Did not receive correct network_block event");
        }

        console.log("\n🎉 E2E Integration Test Passed!");

    } catch (err: any) {
        console.error(`\n❌ Integration Test Failed: ${err.message}`);
        process.exit(1);
    } finally {
        if (useDocker && containerName) {
            await execAsync(`docker rm -f ${containerName} || true`);
        }
        if (fs.existsSync('../shield-agent/shield-agent-bin')) {
            fs.unlinkSync('../shield-agent/shield-agent-bin');
        }
    }
}

if (require.main === module) {
    runIntegrationTest();
}
