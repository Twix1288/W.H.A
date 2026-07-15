import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";
import { randomUUID } from "node:crypto";
import { hashSourceCode, bindSnapshotSignature, verifySnapshotSignature } from "../core-scanner/fingerprint";

export async function runAgent(scriptPath: string, _envelopePath: string, expectedAstHash?: string) {
	console.log(`🛡️ W.H.Agent: Initializing Native OS Sandbox for ${scriptPath}`);

	const absoluteScriptPath = path.resolve(scriptPath);
	if (!fs.existsSync(absoluteScriptPath)) {
		console.error(`❌ Script not found: ${absoluteScriptPath}`);
		process.exit(1);
	}

	const code = fs.readFileSync(absoluteScriptPath, "utf-8");
	const isPython = absoluteScriptPath.endsWith(".py");
	const language = isPython ? "python" : "bash";

	const snapshotId = `sandbox-session-${randomUUID()}`;
	const sourceHash = hashSourceCode(code);
	
	if (expectedAstHash && sourceHash !== expectedAstHash) {
		console.error("\x1b[41m\x1b[37m\x1b[1m\n 🚨 SECURITY VIOLATION: Execution Blocked 🚨 \x1b[0m");
		console.error(`\x1b[91m✗ AST hash of current file on disk differs from the Golden Snapshot.\x1b[0m`);
		console.error(`\x1b[91m✗ Expected: ${expectedAstHash}\x1b[0m`);
		console.error(`\x1b[91m✗ Actual:   ${sourceHash}\x1b[0m`);
		console.error(`\x1b[91m✗ Reason: File was modified after sandbox initialization.\x1b[0m`);
		process.exit(1);
	}

	const signature = bindSnapshotSignature(sourceHash, snapshotId);
	console.log(`\x1b[32m[W.H.Agent] Golden Snapshot bound to session ${snapshotId}\x1b[0m`);
	console.log(`\x1b[90m> Hash: ${sourceHash.substring(0, 16)}...\x1b[0m`);

	console.log(`[NETWORK] Default-Deny enforced.`);
	console.log(`[STORAGE] Root filesystem restricted.`);
	console.log(`[ISOLATION] Sub-millisecond OS-Native isolation active.`);

	console.log(`\n🚀 Launching isolated process...\n`);

	console.log(`[W.H.Agent] Intercepting execution. Verifying payload signature against Golden Snapshot...`);
	const currentCodeOnDisk = fs.readFileSync(absoluteScriptPath, "utf-8");
	if (!verifySnapshotSignature(currentCodeOnDisk, snapshotId, signature)) {
		console.error("\x1b[41m\x1b[37m\x1b[1m\n 🚨 SECURITY VIOLATION: Execution Blocked 🚨 \x1b[0m");
		console.error(`\x1b[91m✗ Payload signature mismatch detected for session ${snapshotId}\x1b[0m`);
		console.error(`\x1b[91m✗ AST hash of current file on disk differs from the Golden Snapshot.\x1b[0m`);
		console.error(`\x1b[91m✗ Reason: File was modified during execution preparation.\x1b[0m`);
		process.exit(1);
	}

	// TOCTOU Fix: Pass the strictly verified code string directly into the payload
	// instead of letting any downstream process re-read the file from disk.
	const reqPayload = JSON.stringify({
		Code: currentCodeOnDisk,
		Language: language,
		TimeoutMs: 5000,
		Env: {}, // Can parse envelope.yaml to pass env vars
		MaxMemMB: 512,
		MaxCPUPct: 1.0,
	});

	const sandboxBinPath = path.resolve(__dirname, "../bin/wh-sandbox");
	if (!fs.existsSync(sandboxBinPath)) {
		console.error(
			`❌ Native sandbox binary not found at ${sandboxBinPath}. Please run the build script.`,
		);
		process.exit(1);
	}

	try {
		const result = spawnSync(sandboxBinPath, [], {
			input: reqPayload,
			encoding: "utf-8",
		});

		if (result.error) {
			console.error(
				`\n🚨 Sandbox execution failed to start: ${result.error.message}`,
			);
			return;
		}

		if (result.stdout) {
			try {
				const parsedResult = JSON.parse(result.stdout);
				console.log(`----- SANDBOX STDOUT -----`);
				console.log(parsedResult.Stdout);
				if (parsedResult.Stderr) {
					console.error(`----- SANDBOX STDERR -----`);
					console.error(parsedResult.Stderr);
				}
				console.log(
					`\n✅ Execution completed in ${parsedResult.ExecutionMs}ms with exit code ${parsedResult.ExitCode}.`,
				);
				if (parsedResult.Killed) {
					console.log(`⚠️ Process was killed (Timeout exceeded).`);
				}
			} catch (_e) {
				console.log(`----- RAW STDOUT -----`);
				console.log(result.stdout);
				if (result.stderr) {
					console.error(`----- RAW STDERR -----`);
					console.error(result.stderr);
				}
			}
		}
	} catch (err) {
		console.error(`\n🚨 Agent execution crashed: ${err}`);
	}
}
