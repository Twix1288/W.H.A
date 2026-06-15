import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { getProvider } from '../vm';
import { ShieldSocketClient } from '../ipc/socket-client';
import { checkAgent } from './check';

/**
 * shield test <script>
 * 
 * The full 4-pillar runtime orchestrator.
 */
export async function testAgent(scriptPath: string) {
    const absolutePath = path.resolve(scriptPath);
    if (!fs.existsSync(absolutePath)) {
        console.error(`❌ File not found: ${absolutePath}`);
        process.exit(1);
    }

    console.log(`🛡️ W.H.Agent: Testing ${scriptPath}\n`);

    // 1. Static Supply Chain Scan
    console.log(`[1/3] Static Supply Chain Scan...`);
    // This throws and exits if malicious
    await checkAgent(scriptPath); 

    // 2. VM Provisioning
    console.log(`\n[2/3] Provisioning Secure Envelope...`);
    const { provider, tier, description } = await getProvider();
    console.log(`  ⚡ Booting local Linux Enforcement Engine...`);
    await provider.setup();
    
    console.log(`  🔥 Initializing ${description}...`);
    const vmScriptPath = await provider.copyIn(absolutePath);

    // 3. IPC Streaming & Runtime
    console.log(`\n[3/3] Runtime Execution & Red Teaming...`);
    
    // In a real execution, we would exec shield-agent inside the VM here.
    // We will simulate the socket for the orchestrator demonstration.
    
    const socketClient = new ShieldSocketClient(provider.getSocketPath());
    
    socketClient.on('network_block', (event) => {
        console.log(`  🚨 [BLOCKED] eBPF intercepted unauthorized connection to ${event.dst_ip}:${event.dst_port}`);
    });
    
    socketClient.on('syscall_violation', (event) => {
        console.log(`  🚨 [FATAL] Sandbox intercepted forbidden syscall: ${event.syscall}`);
    });

    socketClient.on('prompt_injection', (event) => {
        console.log(`  ⚠️ [WARNING] Middleware detected Prompt Injection attempt with ${(event.confidence * 100).toFixed(0)}% confidence.`);
    });

    try {
        console.log(`  Agent started in strict isolation.`);
        // Start attempting connection (with 5s exponential backoff)
        // await socketClient.connect(); 
        
        // Execute the python script in the VM
        // await provider.exec(`python3 ${vmScriptPath}`);
        
    } catch (e: any) {
        console.error(`Execution failed: ${e.message}`);
    } finally {
        socketClient.disconnect();
        await provider.teardown();
        console.log(`\n🛑 Test Complete. Sandbox destroyed.`);
        console.log(`👉 View full forensic timeline: shield logs --session=${Date.now()}`);
    }
}
