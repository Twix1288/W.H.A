import { exec } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { VMProvider } from './provider';

const execAsync = promisify(exec);

export class DockerGvisorProvider implements VMProvider {
    private containerName = `shield-env-${Date.now()}`;
    private socketMountDir = path.join(os.tmpdir(), 'shield-sockets');

    public async isAvailable(): Promise<boolean> {
        try {
            await execAsync('docker info');
            return true;
        } catch (e) {
            return false;
        }
    }

    public async setup(): Promise<void> {
        console.log("🐳 Verifying Docker Desktop & gVisor runtime...");
        
        // Ensure the runsc runtime is registered in Docker (simplified check)
        try {
            const { stdout } = await execAsync('docker info --format "{{.Runtimes}}"');
            if (!stdout.includes('runsc')) {
                console.warn("\n[WARNING] gVisor (runsc) is not registered in your Docker daemon.json!");
                console.warn("To achieve Tier B Isolation, you must manually add 'runsc' to your Docker Desktop runtimes and restart Docker.");
                console.warn("We will proceed using the default runtime for now, but isolation will be severely degraded.\n");
            }
        } catch (e) {
            console.error("Failed to check Docker runtimes.");
        }

        // Create the host mount directory for the IPC socket
        if (!fs.existsSync(this.socketMountDir)) {
            fs.mkdirSync(this.socketMountDir, { recursive: true });
        }

        // Start a sleeping container we can copy files into and exec against
        // --network none is our default zero-trust posture
        // --cap-add=BPF --cap-add=PERFMON are required for eBPF if falling back from gVisor
        const runCmd = `docker run -d --name ${this.containerName} --network none --cap-add=BPF --cap-add=PERFMON -v ${this.socketMountDir}:/tmp/shield-sockets debian:bookworm-slim sleep infinity`;
        await execAsync(runCmd);
    }

    public async copyIn(localPath: string): Promise<string> {
        const basename = path.basename(localPath);
        const dest = `/app/${basename}`;
        await execAsync(`docker exec ${this.containerName} mkdir -p /app`);
        await execAsync(`docker cp "${localPath}" ${this.containerName}:${dest}`);
        return dest;
    }

    public async exec(cmd: string): Promise<void> {
        await execAsync(`docker exec ${this.containerName} sh -c "${cmd}"`);
    }

    public getSocketPath(): string {
        // The container writes to /tmp/shield-sockets/shield-agent.sock
        // which is mapped to this.socketMountDir on the host
        return path.join(this.socketMountDir, 'shield-agent.sock');
    }

    public async teardown(): Promise<void> {
        try {
            await execAsync(`docker rm -f ${this.containerName}`);
        } catch (e) {
            // Ignore teardown errors
        }
    }
}
