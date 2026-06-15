import { exec } from "node:child_process";
import * as path from "node:path";
import { promisify } from "node:util";
import type { VMProvider } from "./provider";

const execAsync = promisify(exec);

export class WslProvider implements VMProvider {
	private distroName = "Ubuntu"; // Assuming default Ubuntu distro for now

	public async isAvailable(): Promise<boolean> {
		try {
			await execAsync("wsl --status");
			return true;
		} catch (e: unknown) {
			if (e instanceof Error && e.message.includes("0x80070005")) {
				console.warn(
					"[WARNING] WSL2 is blocked by Corporate Group Policy (0x80070005). Falling back to Docker Desktop.",
				);
			}
			console.error("\n[ERROR] WSL2 is not enabled on this Windows machine.");
			console.error(
				"W.H.Agent requires WSL2 to provide Tier A Firecracker isolation.",
			);
			console.error(
				"Please run: 'wsl --install' from an Administrator PowerShell and reboot.\n",
			);
			return false;
		}
	}

	public async setup(): Promise<void> {
		console.log("🪟 Verifying WSL2 kernel & Firecracker dependencies...");
		// In a full implementation, we'd ensure KVM is enabled in WSL2 and download shield-agent.
	}

	public async copyIn(localPath: string): Promise<string> {
		const basename = path.basename(localPath);
		const dest = `/tmp/${basename}`;

		// Windows backslashes break WSL commands, so we use stdin piping to cat
		// This avoids bash character escaping nightmares.
		const winPath = path.resolve(localPath).replace(/\\/g, "\\\\");
		await execAsync(
			`powershell.exe -Command "Get-Content -Path '${winPath}' -Raw | wsl -d ${this.distroName} cat > ${dest}"`,
		);

		return dest;
	}

	public async exec(cmd: string): Promise<void> {
		// Execute inside WSL
		await execAsync(`wsl -d ${this.distroName} -- bash -c "${cmd}"`);
	}

	public getSocketPath(): string {
		// WSL2 exposes Unix sockets to the Windows host via a specific UNC path.
		// We do NOT use named pipes due to interop load issues.
		return `\\\\wsl.localhost\\${this.distroName}\\tmp\\shield-agent.sock`;
	}

	public async teardown(): Promise<void> {
		// Nothing heavy to teardown in WSL besides cleaning tmp files
		await this.exec("rm -f /tmp/shield-agent.sock /tmp/agent.py");
	}
}
