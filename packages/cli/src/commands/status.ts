import { getProvider } from "../vm";

/**
 * shield status
 *
 * Explicitly surfaces the isolation tier and VM health, prioritizing honesty.
 */
export async function status() {
	console.log("🛡️ W.H.Agent System Status\n");

	try {
		const { tier, description } = await getProvider();

		console.log(`Supply chain:   native (Node.js)`);
		console.log(`Middleware:     native (Python, ONNX runtime)`);

		if (tier === "Tier B") {
			console.log(`Sandboxing:     gVisor/runsc via Docker Desktop (experimental, unverified)`);
			console.log(`eBPF:           seccomp + gVisor syscall interception (experimental)`);
			console.log(`                NOTE: the 'run' Linux backends fail closed; do not`);
			console.log(`                rely on this path to contain untrusted code.`);
		} else {
			console.log(`Sandboxing:     Firecracker microVM`);
			console.log(`eBPF:           Native kernel tracepoints`);
		}

		console.log(`Isolation tier: ${tier} — ${description}`);
	} catch (e: unknown) {
		if (e instanceof Error) {
			console.error(`❌ Failed to retrieve system status: ${e.message}`);
		}
	}
}
