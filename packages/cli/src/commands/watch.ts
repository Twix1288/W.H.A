import { existsSync } from "node:fs";
import { resolve } from "node:path";
import type { Severity } from "../core-scanner/types.js";
import { startWatcher } from "../core-scanner/watch/index.js";
import type { AlertMode } from "../core-scanner/watch/types.js";

interface WatchOptions {
	readonly debounce?: string;
	readonly alert?: string;
	readonly webhook?: string;
	readonly minSeverity?: string;
	readonly block?: boolean;
}

const VALID_ALERT_MODES: ReadonlyArray<AlertMode> = [
	"terminal",
	"webhook",
	"both",
];
const VALID_SEVERITIES: ReadonlyArray<Severity> = [
	"critical",
	"high",
	"medium",
	"low",
	"info",
];

/**
 * Resolve the directory to watch. Re-implemented locally on purpose: the original
 * lives in the legacy `core-scanner/index.ts`, which calls `program.parse()` at
 * module load — importing from it would trigger CLI argument parsing as a side
 * effect. This helper is a copy, not an import.
 */
function resolveTargetPath(pathArg?: string): string {
	if (pathArg) return resolve(pathArg);
	const localClaude = resolve(process.cwd(), ".claude");
	if (existsSync(localClaude)) return localClaude;
	const home = process.env.HOME ?? process.env.USERPROFILE ?? ".";
	const homeClaude = resolve(home, ".claude");
	if (existsSync(homeClaude)) return homeClaude;
	return process.cwd();
}

/**
 * `wh-agent watch` — continuously watch an agent config directory and alert when
 * its security posture drifts (a new MCP server, widened permissions, a new hook,
 * a new secret, etc.). Cross-platform and fully local; no backend required.
 */
export async function watchConfig(
	targetPath: string | undefined,
	options: WatchOptions,
): Promise<void> {
	const resolved = resolveTargetPath(targetPath);
	if (!existsSync(resolved)) {
		console.error(`Error: Path does not exist: ${resolved}`);
		process.exit(1);
	}

	const debounceMs = Number.parseInt(options.debounce ?? "500", 10);
	if (Number.isNaN(debounceMs) || debounceMs < 100) {
		console.error("Error: --debounce must be an integer of at least 100 (ms).");
		process.exit(1);
	}

	const alertMode = (options.alert ?? "terminal") as AlertMode;
	if (!VALID_ALERT_MODES.includes(alertMode)) {
		console.error(
			`Error: --alert must be one of: ${VALID_ALERT_MODES.join(", ")}.`,
		);
		process.exit(1);
	}

	if ((alertMode === "webhook" || alertMode === "both") && !options.webhook) {
		console.error(
			"Error: --webhook <url> is required when --alert is 'webhook' or 'both'.",
		);
		process.exit(1);
	}

	const minSeverity = (options.minSeverity ?? "info") as Severity;
	if (!VALID_SEVERITIES.includes(minSeverity)) {
		console.error(
			`Error: --min-severity must be one of: ${VALID_SEVERITIES.join(", ")}.`,
		);
		process.exit(1);
	}

	console.log("\n  W.H.Agent — watch (config drift)\n");
	console.log(`  Watching:      ${resolved}`);
	console.log(`  Debounce:      ${debounceMs}ms`);
	console.log(`  Alert mode:    ${alertMode}`);
	console.log(`  Min severity:  ${minSeverity}`);
	if (options.webhook) console.log(`  Webhook:       ${options.webhook}`);
	console.log("\n  Establishing baseline (initial scan)...");

	const { stop, getState } = startWatcher({
		paths: [resolved],
		debounceMs,
		alertMode,
		webhookUrl: options.webhook,
		minSeverity,
		blockOnCritical: options.block ?? false,
	});

	const state = getState();

	// Any path we could not watch is reported, not skipped. Pointing `watch` at a
	// file used to establish zero watchers and then claim to be watching.
	for (const err of state.setupErrors) {
		console.error(`  Cannot watch: ${err}`);
	}
	if (!state.isRunning) {
		console.error(
			"\n  Nothing is being watched — no drift can be detected. This is a failure, not an idle state.",
		);
		stop();
		process.exit(1);
	}

	// Changes made while the watcher was DOWN. Reported before the baseline line so
	// it is not mistaken for the current state being clean.
	if (state.startupDrift) {
		const d = state.startupDrift;
		console.error(
			`  DRIFT SINCE LAST RUN: ${d.newFindings.length} new, ${d.resolvedFindings.length} resolved ` +
				`(score ${d.previousScore} -> ${d.currentScore}).`,
		);
	}

	if (state.baselineError) {
		// A scan that FAILED is not an all-clear, and must never be reported as one.
		console.error(`  Baseline:      SCAN FAILED — ${state.baselineError}`);
		console.error(
			"                 This is NOT an all-clear: the target was not audited.",
		);
	} else if (state.baseline) {
		console.log(
			`  Baseline:      score ${state.baseline.score.numericScore}/100 (${state.baseline.score.grade}), ${state.baseline.findings.length} finding(s)`,
		);
	} else {
		console.log("  Baseline:      no config files found to scan yet");
	}

	// --block: for CI use — exit non-zero if the initial scan already has
	// critical findings. (Ongoing drift is reported via alerts, not exit codes,
	// because a watch process is long-running.)
	if (options.block) {
		// A failed baseline fails the gate. Previously this branch required a
		// non-null baseline, so an unreadable config file made `--block` a no-op:
		// the gate passed and the process kept running, which is the exact opposite
		// of what a CI gate is for.
		if (state.baselineError) {
			console.error(
				"\n  BLOCKED: the initial scan did not complete, so this configuration is unverified.",
			);
			stop();
			process.exit(2);
		}
		if (state.rootChangedSinceBaseline) {
			console.error(
				"\n  BLOCKED: the watched path now resolves somewhere different than when the " +
					"baseline was recorded — this is not the configuration that was approved.",
			);
			stop();
			process.exit(2);
		}
		if (state.startupDrift && state.startupDrift.newFindings.length > 0) {
			console.error(
				"\n  BLOCKED: the configuration changed since the stored baseline.",
			);
			stop();
			process.exit(2);
		}
		const hasCritical =
			state.baseline?.findings.some((f) => f.severity === "critical") ?? false;
		if (hasCritical) {
			console.error(
				"\n  BLOCKED: critical findings present in the initial scan.",
			);
			stop();
			process.exit(2);
		}
		// `--block` is documented as a CI gate. A gate that never returns cannot be
		// used in CI, so in block mode we report the verdict and exit rather than
		// entering the watch loop.
		console.log("\n  PASSED: no critical findings in the initial scan.\n");
		stop();
		process.exit(0);
	}

	console.log("\n  Watching for changes... (Ctrl+C to stop)\n");

	const handleSignal = (): void => {
		console.log("\n  Stopping watch.\n");
		stop();
		process.exit(0);
	};
	process.on("SIGINT", handleSignal);
	process.on("SIGTERM", handleSignal);

	// The active fs.watch handles keep the event loop alive, so this async
	// function resolving here does not end the process.
}
