import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";
import { astFingerprint } from "../core-scanner/parser";
import { loadSandboxScope } from "./envelope";

// ─── Exit codes ───────────────────────────────────────────────────────────────
// These are the command's contract with CI and with callers. Previously `run`
// exited 0 unconditionally.
/** The sandbox tooling itself failed (missing binary, spawn error, bad output). */
const EXIT_TOOLING_FAILURE = 1;
/** The backend refused to execute — fail-closed, nothing ran. */
const EXIT_SANDBOX_REFUSED = 2;
/** The script was killed for exceeding its timeout (conventional 124). */
const EXIT_TIMEOUT = 124;
/** Cap on sandbox output we will buffer (Node's default is only 1MiB). */
const RUN_MAX_OUTPUT_BYTES = 64 * 1024 * 1024;
/** Outer wall clock for the sandbox process itself. */
const RUN_WALL_CLOCK_MS = 120_000;

export async function runAgent(
	scriptPath: string,
	envelopePath: string,
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

	// Resolve the enforceable sandbox scope from the envelope (optional). A missing
	// envelope keeps the sandbox fully hermetic — the prior default. Declared
	// mounts become read-only/read-write grants on specific host subtrees; an
	// egress proxy narrows the default network deny to a single local endpoint.
	const scope = loadSandboxScope(envelopePath);
	for (const w of scope.warnings) {
		console.log(`\x1b[33m⚠️  ${w}\x1b[0m`);
	}

	if (scope.egressProxy) {
		console.log(`[NETWORK] Egress allowed ONLY to proxy ${scope.egressProxy}.`);
	} else {
		console.log(`[NETWORK] Default-Deny enforced.`);
	}
	if (scope.allowPaths.length > 0) {
		console.log(`[STORAGE] Scoped to ${scope.allowPaths.length} opened path(s):`);
		for (const p of scope.allowPaths) {
			console.log(`          ${p.Write ? "rw" : "ro"}  ${p.Path}`);
		}
	} else {
		console.log(`[STORAGE] Root filesystem restricted (scratch-only).`);
	}
	console.log(`[ISOLATION] Sub-millisecond OS-Native isolation active.`);

	console.log(`\n🚀 Launching isolated process...\n`);

	// Pass the exact bytes we fingerprinted straight into the payload (no re-read).
	// MaxMemMB / MaxCPUPct are intentionally omitted — no backend enforces hard
	// memory/CPU limits yet; the real bounds are the wall-clock timeout, the
	// inherited RLIMIT_CPU/RLIMIT_FSIZE, and the sandbox's output cap.
	const reqPayload = JSON.stringify({
		Code: code,
		Language: language,
		TimeoutMs: 5000,
		Env: {}, // Can parse envelope.yaml to pass env vars
		AllowPaths: scope.allowPaths,
		EgressProxy: scope.egressProxy ?? "",
	});

	const sandboxBinPath = path.resolve(__dirname, "../bin/wh-sandbox");
	if (!fs.existsSync(sandboxBinPath)) {
		console.error(
			`❌ Native sandbox binary not found at ${sandboxBinPath}. Please run the build script.`,
		);
		process.exit(1);
	}

	// Exit status to finish with once output has been reported.
	let sandboxExit = 0;

	try {
		const result = spawnSync(sandboxBinPath, [], {
			input: reqPayload,
			encoding: "utf-8",
			// Node's default maxBuffer is 1MiB. Exceeding it sets result.error, and the
			// old code then printed "failed to start" and exited 0 — for a payload that
			// had ALREADY RUN TO COMPLETION, with all of its output discarded. A
			// security tool must never report "nothing happened" about code that ran.
			maxBuffer: RUN_MAX_OUTPUT_BYTES,
			// Belt-and-braces wall clock: the Go side enforces its own TimeoutMs, but if
			// the sandbox process itself wedges (e.g. a pathological mount walk) the CLI
			// must not hang forever with no way out.
			timeout: RUN_WALL_CLOCK_MS,
		});

		if (result.error) {
			const isBufferOverflow =
				(result.error as NodeJS.ErrnoException).code === "ENOBUFS" ||
				/maxBuffer/i.test(result.error.message);
			console.error(
				isBufferOverflow
					? `\n🚨 Sandbox produced more than ${RUN_MAX_OUTPUT_BYTES} bytes of output; the script DID run but its output was truncated and cannot be reported faithfully.`
					: `\n🚨 Sandbox execution failed to start: ${result.error.message}`,
			);
			process.exit(EXIT_TOOLING_FAILURE);
		}

		// A backend that refuses to execute (Linux Landlock/gVisor and Windows both
		// fail closed by design) exits non-zero with EMPTY stdout. The old code only
		// looked at stdout, so it printed NOTHING AT ALL and exited 0 — turning a
		// correct fail-closed refusal into a silent success. That is the single most
		// dangerous outcome in this file: the user is told isolation is active and
		// never told that their untrusted code did not run.
		if (!result.stdout || !result.stdout.trim()) {
			const detail = (result.stderr ?? "").trim();
			console.error(
				`\n🛑 The sandbox did not execute the script (backend exited ${result.status ?? "unknown"}).`,
			);
			if (detail) console.error(detail);
			console.error(
				`\n   Nothing was run. On Linux (landlock/gvisor) and Windows the backend fails closed\n` +
					`   by design rather than provide fake isolation — see 'wh-agent run --help'.`,
			);
			process.exit(EXIT_SANDBOX_REFUSED);
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
				// Remember what to exit with. `run` previously ALWAYS exited 0, so a
				// failed script, a timeout kill, and a clean success were
				// indistinguishable to any caller — including CI.
				if (parsedResult.Killed) {
					sandboxExit = EXIT_TIMEOUT;
				} else if (typeof parsedResult.ExitCode === "number" && parsedResult.ExitCode !== 0) {
					// Preserve the script's own status, clamped into a valid exit range.
					sandboxExit = Math.min(Math.max(parsedResult.ExitCode, 1), 125);
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
				// Unparseable sandbox output means we cannot vouch for what happened.
				process.exit(EXIT_TOOLING_FAILURE);
			}
		}
	} catch (err) {
		console.error(`\n🚨 Agent execution crashed: ${err}`);
		process.exit(EXIT_TOOLING_FAILURE);
	}

	if (sandboxExit !== 0) process.exit(sandboxExit);
}
