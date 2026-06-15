import { exec } from "node:child_process";
import * as path from "node:path";
import { promisify } from "node:util";
import type { VMProvider } from "./provider";

const execAsync = promisify(exec);

export class LimaProvider implements VMProvider {
	private instanceName = "shield-ubuntu";
	private expectedKernel = "6.5.0-1014-lima"; // Pinned kernel for eBPF stability

	public async isAvailable(): Promise<boolean> {
		try {
			await execAsync("limactl --version");
			const { stdout } = await execAsync('limactl ls --format "{{.Name}}"');
			return stdout.includes(this.instanceName);
		} catch (_e) {
			return false;
		}
	}

	public async setup(): Promise<void> {
		console.log("🍏 Verifying Lima VM & Intel KVM requirements...");

		const { stdout: kernel } = await execAsync(
			`limactl shell ${this.instanceName} uname -r`,
		);
		if (kernel.trim() !== this.expectedKernel) {
			console.error(`\n[CRITICAL ERROR] Lima VM kernel mismatch.`);
			console.error(`Expected: ${this.expectedKernel}`);
			console.error(`Found:    ${kernel.trim()}`);
			console.error(
				`eBPF probes will silently fail on unpinned kernels. Please run 'shield setup' to rebuild the VM.\n`,
			);
			process.exit(1);
		}
	}

	public async copyIn(localPath: string): Promise<string> {
		const basename = path.basename(localPath);
		const dest = `/tmp/${basename}`;
		await execAsync(`limactl cp "${localPath}" ${this.instanceName}:${dest}`);
		return dest;
	}

	public async exec(cmd: string): Promise<void> {
		await execAsync(`limactl shell ${this.instanceName} bash -c "${cmd}"`);
	}

	public getSocketPath(): string {
		// Lima forwards sockets if configured, or we can use SSH forwarding.
		// For simplicity in this local implementation, assume it's mounted.
		// In production, this would likely be an SSH reverse tunnel configured by limactl.
		return `/tmp/shield-lima-socket.sock`;
	}

	public async teardown(): Promise<void> {
		await this.exec("rm -f /tmp/shield-agent.sock");
	}
}
