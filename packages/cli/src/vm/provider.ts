export interface VMProvider {
	/**
	 * Checks if the specific VM provider is available and properly configured
	 * on the host system.
	 */
	isAvailable(): Promise<boolean>;

	/**
	 * Provisions the VM/Container environment. Must be idempotent.
	 */
	setup(): Promise<void>;

	/**
	 * Copies a file from the host machine into the isolated VM workspace.
	 * @param localPath The absolute path on the host.
	 * @returns The path to the copied file inside the VM.
	 */
	copyIn(localPath: string): Promise<string>;

	/**
	 * Executes a command synchronously inside the VM.
	 * @param cmd The command string.
	 */
	exec(cmd: string): Promise<void>;

	/**
	 * Returns the host-accessible path to the shield-agent IPC Unix socket.
	 */
	getSocketPath(): string;

	/**
	 * Destroys the VM/Container and cleans up resources.
	 */
	teardown(): Promise<void>;
}
