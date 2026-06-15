import { getProvider } from '../vm';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { execSync } from 'child_process';


export async function setup() {
    console.log("⚙️ W.H.Agent Initial Setup");
    console.log("Determining optimal virtualization path for your architecture...\n");

    try {
        const { provider, tier, description } = await getProvider();
        
        console.log(`📍 Selected Architecture: ${description} (${tier})`);
        console.log(`Applying idempotent configuration...`);
        
        await provider.setup();

        console.log(`\n📥 Fetching pre-compiled shield-agent binary...`);
        const agentDir = path.join(os.homedir(), '.wh-agent', 'bin');
        if (!fs.existsSync(agentDir)) {
            fs.mkdirSync(agentDir, { recursive: true });
        }
        
        const platform = os.platform();
        const arch = os.arch();
        const agentPath = path.join(agentDir, 'shield-agent');


        console.log(`[INFO] (Simulated Download) Fetched shield-agent for ${platform}-${arch} to ${agentPath}`);
        

        fs.writeFileSync(agentPath, '#!/bin/sh\necho "Mock agent running"\n');
        fs.chmodSync(agentPath, 0o755);
        
        console.log(`\n✅ Setup complete! You are ready to use 'shield check' and 'shield run'.`);

    } catch (e: any) {
        console.error(`\n❌ Setup Failed: ${e.message}`);
        console.error("Please ensure Docker Desktop or WSL2 is installed.");
        process.exit(1);
    }
}
