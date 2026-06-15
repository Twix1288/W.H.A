import { EventEmitter } from "node:events";
import * as net from "node:net";
import * as readline from "node:readline";
import type { ShieldEvent } from "./events";

export class ShieldSocketClient extends EventEmitter {
	private socketPath: string;
	private client: net.Socket | null = null;
	private connected: boolean = false;

	constructor(socketPath: string) {
		super();
		this.socketPath = socketPath;
	}

	/**
	 * Connects to the Unix socket with exponential backoff.
	 * Retries up to 5 seconds total elapsed time.
	 */
	public async connect(): Promise<void> {
		return new Promise((resolve, reject) => {
			const maxWaitMs = 5000;
			const startTime = Date.now();
			let _attempt = 1;
			let currentDelay = 100;

			const tryConnect = () => {
				this.client = net.createConnection(this.socketPath);

				this.client.on("connect", () => {
					this.connected = true;
					this.setupStream();
					resolve();
				});

				this.client.on("error", (err: any) => {
					const elapsed = Date.now() - startTime;
					if (elapsed + currentDelay > maxWaitMs) {
						this.client?.destroy();
						reject(
							new Error(
								`Failed to connect to shield-agent socket at ${this.socketPath} after ${elapsed}ms: ${err.message}`,
							),
						);
						return;
					}

					// Exponential backoff
					this.client?.destroy();
					setTimeout(tryConnect, currentDelay);
					currentDelay = Math.min(currentDelay * 2, 1000);
					_attempt++;
				});

				this.client.on("close", () => {
					this.connected = false;
					this.emit("close");
				});
			};

			tryConnect();
		});
	}

	private setupStream() {
		if (!this.client) return;

		const rl = readline.createInterface({
			input: this.client,
			crlfDelay: Infinity,
		});

		rl.on("line", (line) => {
			if (!line.trim()) return;
			try {
				const event = JSON.parse(line) as ShieldEvent;

				// Validate schema contract
				if (event.v !== 1) {
					this.emit(
						"error",
						new Error(`Unsupported event schema version: ${event.v}`),
					);
					return;
				}

				// Emit typed event
				this.emit("event", event);

				// Also emit specifically by type for granular listeners
				this.emit(event.type, event);
			} catch (_err) {
				this.emit("error", new Error(`Failed to parse NDJSON line: ${line}`));
			}
		});
	}

	public disconnect() {
		if (this.client && this.connected) {
			this.client.destroy();
			this.connected = false;
		}
	}
}
