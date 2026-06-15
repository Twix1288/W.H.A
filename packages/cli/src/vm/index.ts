import * as os from 'os';
import { VMProvider } from './provider';
import { WslProvider } from './wsl';
import { DockerGvisorProvider } from './docker-gvisor';
import { LimaProvider } from './lima';

export async function getProvider(): Promise<{ provider: VMProvider, tier: string, description: string }> {
    const platform = os.platform();
    const arch = os.arch();

    if (platform === 'win32') {
        const wsl = new WslProvider();
        if (await wsl.isAvailable()) {
            return { provider: wsl, tier: 'Tier A', description: 'Hardware MicroVM (WSL2 Firecracker)' };
        }
        console.log("👉 Falling back to Docker Desktop gVisor for Windows...");
        return { provider: new DockerGvisorProvider(), tier: 'Tier B', description: 'Userspace Kernel (Docker Desktop Windows)' };
    }

    if (platform === 'darwin') {
        if (arch === 'arm64') {
            return { provider: new DockerGvisorProvider(), tier: 'Tier B', description: 'Userspace Kernel (Docker Desktop Apple Silicon)' };
        } else {
            const lima = new LimaProvider();
            return { provider: lima, tier: 'Tier A', description: 'Hardware MicroVM (Lima Intel Mac)' };
        }
    }

    // Default Linux (CI/CD)
    throw new Error("Native Linux execution uses direct binary execution, not a VM provider. (To be implemented)");
}
