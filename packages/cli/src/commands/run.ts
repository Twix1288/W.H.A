import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";
import { astFingerprint } from "../core-scanner/parser";

export async function runAgent(
	scriptPath: string,
	_envelopePath: string,
	expectedAstHash?: string,
) {
	console.log(`🛡️ W.H.Agent: Initializing Native OS Sandbox for ${scriptPath}`);

	const absoluteScriptPath = path.resolve(scriptPath);
	if (!fs.existsSync(absoluteScriptPath)) {
		console.error(`❌ Script not found: ${absoluteScriptPath}`);
		process.exit(1);
	}

	// Read the file EXACTLY ONCE. The same in-memory bytes are what we fingerprint
	// AND what we hand to the sandbox, so there is no time-of-check/time-of-use gap
	// between verification and execution (an earlier version re-read the file after
	// hashing, reopening that window).
	const code = fs.readFileSync(absoluteScriptPath, "utf-8");
	const isPython = absoluteScriptPath.endsWith(".py");
	const language = isPython ? "python" : "bash";

	// Golden Snapshot: a real AST fingerprint (structure + identifiers/literals,
	// insensitive to comments/formatting) of the exact bytes we are about to run.
	const astHash = astFingerprint(code, path.extname(absoluteScriptPath));

	// TOCTOU protection: if the caller pinned the AST hash from a prior
	// `wh-agent check`, refuse to run anything whose AST no longer matches — i.e.
	// the tool's code changed after it was scanned.
	if (expectedAstHash && astHash !== expectedAstHash) {
		console.error(
			"\x1b[41m\x1b[37m\x1b[1m\n 🚨 SECURITY VIOLATION: Execution Blocked 🚨 \x1b[0m",
		);
		console.error(
			`\x1b[91m✗ AST fingerprint differs from the pinned Golden Snapshot.\x1b[0m`,
		);
		console.error(`\x1b[91m✗ Expected: ${expectedAstHash}\x1b[0m`);
		console.error(`\x1b[91m✗ Actual:   ${astHash}\x1b[0m`);
		console.error(
			`\x1b[91m✗ Reason: the tool's code changed after it was scanned.\x1b[0m`,
		);
		process.exit(1);
	}

	console.log(
		`\x1b[32m[W.H.Agent] Golden Snapshot AST fingerprint: ${astHash}\x1b[0m`,
	);
	if (!expectedAstHash) {
		console.log(
			`\x1b[90m> Pin it with --ast-hash ${astHash} to block execution if the file changes.\x1b[0m`,
		);
	}

	console.log(`[NETWORK] Default-Deny enforced.`);
	console.log(`[STORAGE] Root filesystem restricted.`);
	console.log(`[ISOLATION] Sub-millisecond OS-Native isolation active.`);

	console.log(`\n🚀 Launching isolated process...\n`);

	// Pass the exact bytes we fingerprinted straight into the payload (no re-read).
	// MaxMemMB / MaxCPUPct are intentionally omitted — no backend enforces hard
	// memory/CPU limits yet; the real bounds are the wall-clock timeout and the
	// sandbox's output cap.
	const reqPayload = JSON.stringify({
		Code: code,
		Language: language,
		TimeoutMs: 5000,
		Env: {}, // Can parse envelope.yaml to pass env vars
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
				if (parsedResult.DetachedReaped > 0) {
					// The payload forked a process that detached from our group
					// (setsid/new session) to try to outlive the sandbox. We swept it
					// up by its scratch cwd, but this is NOT a clean, self-contained
					// run — surface it rather than let the ✅ above imply otherwise.
					console.log(
						`\x1b[33m⚠️  Reaped ${parsedResult.DetachedReaped} detached process(es): the script tried to spawn work that would outlive the sandbox.\x1b[0m`,
					);
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
