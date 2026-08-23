import { existsSync, readdirSync, statSync, watch } from "node:fs";
import { resolve } from "node:path";
import { calculateScore } from "../reporter/score.js";
import { scan } from "../scanner/index.js";
import type { Severity } from "../types.js";
import { dispatchAlert } from "./alerts.js";
import { createBaseline, diffBaseline } from "./diff.js";
import type {
	DriftResult,
	ScanBaseline,
	WatchConfig,
	WatcherState,
} from "./types.js";

type WatchHandle = ReturnType<typeof watch>;
type WatchListener = (
	eventType: string,
	filename: string | Buffer | null,
) => void;

const SEVERITY_ORDER: Record<Severity, number> = {
	critical: 0,
	high: 1,
	medium: 2,
	low: 3,
	info: 4,
};

/**
 * Start watching the given paths for config changes.
 * Returns a cleanup function that stops watching.
 */
export function startWatcher(config: WatchConfig): {
	readonly stop: () => void;
	readonly getState: () => WatcherState;
} {
	let baseline: ScanBaseline | null = null;
	let lastDrift: DriftResult | null = null;
	let scanCount = 0;
	let debounceTimer: ReturnType<typeof setTimeout> | null = null;
	let isScanning = false;
	let rescanQueued = false;
	const watchers: WatchHandle[] = [];
	/** Paths that could not be watched. Surfaced rather than silently skipped. */
	const setupErrors: string[] = [];
	/** Why the baseline scan failed, if it did. Distinct from "nothing to scan". */
	let baselineError: string | null = null;

	// Perform initial scan to establish baseline
	const initial = performInitialScan(config);
	if (initial.status === "ok") {
		baseline = initial.baseline;
		scanCount = 1;
	} else if (initial.status === "error") {
		baselineError = initial.message;
	}

	// Serialize rescans: a change arriving mid-scan (or during a slow webhook
	// dispatch) must not start a second overlapping handleChange that diffs
	// against a stale baseline. Coalesce concurrent triggers into one queued
	// follow-up rescan so drift is never double-counted or lost.
	function runRescan(): void {
		if (isScanning) {
			rescanQueued = true;
			return;
		}
		isScanning = true;
		void handleChange(config, baseline, (result) => {
			if (result.newBaseline) {
				baseline = result.newBaseline;
			}
			if (result.drift) {
				lastDrift = result.drift;
			}
			scanCount += 1;
		}).finally(() => {
			isScanning = false;
			if (rescanQueued) {
				rescanQueued = false;
				runRescan();
			}
		});
	}

	// Set up watchers for each path.
	//
	// These used to be silent `continue`s. Pointing `watch` at a FILE — the
	// obvious thing to do, e.g. `watch .claude/settings.json` — therefore
	// established zero watchers, printed a 100/100 baseline and "Watching for
	// changes...", and returned immediately having monitored nothing. The same
	// happened for a path that did not exist. Both are now reported, and a run
	// that established no watchers at all is a hard failure rather than a
	// convincing no-op.
	for (const watchPath of config.paths) {
		const resolvedPath = resolve(watchPath);
		if (!existsSync(resolvedPath)) {
			setupErrors.push(`${resolvedPath}: path does not exist`);
			continue;
		}

		if (!statSync(resolvedPath).isDirectory()) {
			setupErrors.push(
				`${resolvedPath}: not a directory — pass the config DIRECTORY to watch ` +
					`(e.g. its parent), not an individual file`,
			);
			continue;
		}

		try {
			const pathWatchers = createPathWatchers(resolvedPath, () => {
				// Debounce: wait for config.debounceMs of silence before rescanning
				if (debounceTimer) {
					clearTimeout(debounceTimer);
				}
				debounceTimer = setTimeout(runRescan, config.debounceMs);
			});
			watchers.push(...pathWatchers);
		} catch (error) {
			const message = error instanceof Error ? error.message : String(error);
			console.error(`  Failed to watch ${resolvedPath}: ${message}`);
		}
	}

	function stop(): void {
		if (debounceTimer) {
			clearTimeout(debounceTimer);
			debounceTimer = null;
		}
		for (const w of watchers) {
			w.close();
		}
		watchers.length = 0;
	}

	function getState(): WatcherState {
		return {
			isRunning: watchers.length > 0,
			setupErrors: [...setupErrors],
			baselineError,
			baseline,
			lastDrift,
			scanCount,
		};
	}

	return { stop, getState };
}

function createPathWatchers(
	resolvedPath: string,
	listener: WatchListener,
): ReadonlyArray<WatchHandle> {
	// Keep a long-running watch alive across recoverable OS-level watcher errors
	// (e.g. inotify ENOSPC on Linux, or a watched directory being deleted/renamed).
	// Without an 'error' listener these surface as uncaught exceptions and crash
	// the whole `watch` process.
	const withErrorHandler = (handle: WatchHandle): WatchHandle => {
		handle.on("error", (error: unknown) => {
			const message = error instanceof Error ? error.message : String(error);
			console.error(`  Watch error on ${resolvedPath}: ${message}`);
		});
		return handle;
	};

	// fs.watch({ recursive: true }) is natively supported on macOS and Windows.
	// On Linux before Node 20 it is SILENTLY ignored (no throw) — only the top
	// directory is watched, so subdirectory changes would be missed. Detect that
	// case up front and use the per-directory fallback instead of relying on a
	// thrown error that never comes.
	const nodeMajor = Number.parseInt(process.versions.node.split(".")[0], 10);
	const recursiveUnsafe =
		process.platform === "linux" &&
		Number.isFinite(nodeMajor) &&
		nodeMajor < 20;

	if (!recursiveUnsafe) {
		try {
			return [
				withErrorHandler(watch(resolvedPath, { recursive: true }, listener)),
			];
		} catch (error) {
			if (!isRecursiveWatchUnsupported(error)) {
				throw error;
			}
		}
	}

	const fallbackWatchers: WatchHandle[] = [];

	try {
		for (const directory of collectWatchDirectories(resolvedPath)) {
			fallbackWatchers.push(withErrorHandler(watch(directory, listener)));
		}
		return fallbackWatchers;
	} catch (error) {
		for (const watcher of fallbackWatchers) {
			watcher.close();
		}
		throw error;
	}
}

function collectWatchDirectories(rootPath: string): ReadonlyArray<string> {
	const directories = [rootPath];
	const queue = [rootPath];

	while (queue.length > 0) {
		const currentPath = queue.shift();
		if (!currentPath) {
			continue;
		}

		for (const entry of readdirSync(currentPath, { withFileTypes: true })) {
			if (!entry.isDirectory()) {
				continue;
			}

			const childPath = resolve(currentPath, entry.name);
			directories.push(childPath);
			queue.push(childPath);
		}
	}

	return directories;
}

function isRecursiveWatchUnsupported(error: unknown): boolean {
	if (!(error instanceof Error)) {
		return false;
	}

	const nodeError = error as NodeJS.ErrnoException;
	return (
		nodeError.code === "ERR_FEATURE_UNAVAILABLE_ON_PLATFORM" ||
		(nodeError.code === "ERR_INVALID_ARG_VALUE" &&
			error.message.toLowerCase().includes("recursive"))
	);
}

/**
 * Perform the initial scan to establish a baseline.
 */
/**
 * Result of the baseline scan.
 *
 * A plain `ScanBaseline | null` conflated two very different states: "there is
 * nothing here to scan" and "the scan FAILED". One unreadable file in the watched
 * directory threw, the error was logged, null was returned, and the command then
 * printed "no config files found to scan yet" — an all-clear for a directory it
 * could not read. Worse, `--block` was gated on a non-null baseline, so a failed
 * scan skipped the CI gate entirely and the process kept running.
 */
type InitialScanResult =
	| { readonly status: "ok"; readonly baseline: ScanBaseline }
	| { readonly status: "empty" }
	| { readonly status: "error"; readonly message: string };

function performInitialScan(config: WatchConfig): InitialScanResult {
	const targetPath = config.paths[0];
	if (!targetPath) return { status: "error", message: "no watch path configured" };
	if (!existsSync(targetPath)) {
		return { status: "error", message: `${targetPath} does not exist` };
	}

	try {
		const result = scan(targetPath);
		const minIndex = SEVERITY_ORDER[config.minSeverity];
		const filteredFindings = result.findings.filter(
			(f) => SEVERITY_ORDER[f.severity] <= minIndex,
		);
		const report = calculateScore({ ...result, findings: filteredFindings });
		return {
			status: "ok",
			baseline: createBaseline(filteredFindings, report.score),
		};
	} catch (error) {
		const message = error instanceof Error ? error.message : String(error);
		return { status: "error", message };
	}
}

interface ChangeResult {
	readonly newBaseline: ScanBaseline | null;
	readonly drift: DriftResult | null;
}

/**
 * Handle a detected file change by rescanning and diffing.
 */
async function handleChange(
	config: WatchConfig,
	currentBaseline: ScanBaseline | null,
	onResult: (result: ChangeResult) => void,
): Promise<void> {
	try {
		const targetPath = config.paths[0];
		if (!targetPath || !existsSync(targetPath)) {
			// The watched configuration disappearing is itself drift — and the most
			// suspicious kind. Returning silently meant deleting (or symlink-swapping)
			// the config directory blinded the watcher with no alert and no error,
			// while it kept reporting itself as running.
			console.error(
				`  WATCH TARGET GONE: ${targetPath ?? "(none)"} no longer exists — drift detection is blind.`,
			);
			return;
		}

		const result = scan(targetPath);
		const minIndex = SEVERITY_ORDER[config.minSeverity];
		const filteredFindings = result.findings.filter(
			(f) => SEVERITY_ORDER[f.severity] <= minIndex,
		);
		const report = calculateScore({ ...result, findings: filteredFindings });
		const newBaseline = createBaseline(filteredFindings, report.score);

		if (currentBaseline) {
			const drift = diffBaseline(
				currentBaseline,
				filteredFindings,
				report.score,
			);

			if (drift.newFindings.length > 0 || drift.resolvedFindings.length > 0) {
				const delivery = await dispatchAlert(
					drift,
					config.alertMode,
					config.webhookUrl,
				);
				if (delivery.delivered) {
					onResult({ newBaseline, drift });
				} else {
					// Hold the baseline back so this drift is re-detected and re-alerted
					// next cycle. Advancing it here would discard the event permanently —
					// at-least-once delivery matters far more than avoiding a duplicate
					// alert for a security monitor.
					onResult({ newBaseline: null, drift });
				}
			} else {
				onResult({ newBaseline, drift: null });
			}
		} else {
			onResult({ newBaseline, drift: null });
		}
	} catch (error) {
		const message = error instanceof Error ? error.message : String(error);
		// A failed rescan is not "no drift". Say so explicitly, and do NOT advance
		// the baseline — otherwise a config that becomes unreadable silently freezes
		// drift detection while the watcher still looks healthy.
		console.error(
			`  RE-SCAN FAILED: ${message} — drift was NOT evaluated for this change.`,
		);
	}
}
