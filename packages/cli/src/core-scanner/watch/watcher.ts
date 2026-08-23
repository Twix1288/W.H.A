import { existsSync, readdirSync, statSync, watch } from "node:fs";
import { resolve } from "node:path";
import { calculateScore } from "../reporter/score.js";
import { scan } from "../scanner/index.js";
import type { Severity } from "../types.js";
import { dispatchAlert } from "./alerts.js";
import { createBaseline, diffBaseline } from "./diff.js";
import {
	type ContentDrift,
	diffFileDigests,
	digestContent,
	hasContentDrift,
	identityOf,
	loadBaseline,
	type PathIdentity,
	sameIdentity,
	saveBaseline,
	toScanBaseline,
} from "./state.js";
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
	/** sha256 per tracked config file — catches changes that produce no new finding. */
	let fileDigests: Record<string, string> = {};
	/** Identity of the watch root, so a symlink swap is detectable. */
	let rootIdentity: PathIdentity | null = null;
	/** Drift detected on startup against the stored baseline (i.e. while we were down). */
	let startupDrift: DriftResult | null = null;
	/** The watched path resolves somewhere different than when the baseline was stored. */
	let rootChangedSinceBaseline = false;
	/** Timestamp of the first event in the current debounce burst. */
	let burstStartedAt: number | null = null;

	const targetPath = config.paths[0];

	/**
	 * Upper bound on how long a continuous write burst can postpone a rescan.
	 * Generous relative to the debounce so ordinary editor activity still
	 * coalesces, but finite so starvation is impossible.
	 */
	const maxWaitMs = Math.max(config.debounceMs * 5, 5000);

	function persistBaseline(): void {
		if (!targetPath || !baseline) return;
		const result = saveBaseline(targetPath, baseline, fileDigests, rootIdentity);
		if (!result.ok) {
			// A baseline we cannot persist means the next restart re-baselines against
			// the current state. Say so rather than failing silently.
			console.error(
				`  Could not persist the watch baseline (${result.error}) — drift will not survive a restart.`,
			);
		}
	}

	function reportContentDrift(drift: ContentDrift): void {
		// Reported separately from findings, and deliberately more quietly: a
		// content change with no new finding is a weaker signal, and presenting it
		// as a finding would train people to ignore real ones.
		for (const f of drift.changed) {
			console.error(`    changed:  ${f} (contents differ, findings unchanged)`);
		}
		for (const f of drift.added) console.error(`    added:    ${f}`);
		for (const f of drift.removed) console.error(`    removed:  ${f}`);
	}

	// Perform initial scan to establish baseline.
	//
	// The baseline used to be in-memory only, so restarting silently adopted
	// whatever the configuration looked like at that moment as "normal" — an
	// attacker only had to wait for (or cause) a restart. A stored baseline for
	// this target is loaded first and the fresh scan is diffed against it, so
	// changes made while the watcher was DOWN are reported on startup.
	const initial = performInitialScan(config);
	const persisted = targetPath ? loadBaseline(targetPath) : null;

	if (initial.status === "ok") {
		fileDigests = initial.fileDigests;
		rootIdentity = identityOf(targetPath ?? "");

		if (persisted) {
			const restored = toScanBaseline(persisted);
			const offlineDrift = diffBaseline(
				restored,
				initial.baseline.findings,
				initial.baseline.score,
			);
			const offlineContent = diffFileDigests(persisted.fileDigests ?? {}, fileDigests);
			const rootSwapped =
				persisted.rootIdentity != null &&
				!sameIdentity(persisted.rootIdentity, rootIdentity);

			if (rootSwapped) {
				rootChangedSinceBaseline = true;
				console.error(
					"  WATCH ROOT CHANGED since the last run: the watched path now resolves to a " +
						"different directory or inode. Treat the current configuration as unverified.",
				);
			}
			if (
				offlineDrift.newFindings.length > 0 ||
				offlineDrift.resolvedFindings.length > 0 ||
				hasContentDrift(offlineContent)
			) {
				console.error(
					"  DRIFT WHILE NOT WATCHING: the configuration changed since the stored baseline.",
				);
				reportContentDrift(offlineContent);
				startupDrift = offlineDrift;
				lastDrift = offlineDrift;
			}
		}

		baseline = initial.baseline;
		scanCount = 1;
		persistBaseline();
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
		void handleChange(config, baseline, fileDigests, rootIdentity, (result) => {
			if (result.newBaseline) {
				baseline = result.newBaseline;
			}
			if (result.drift) {
				lastDrift = result.drift;
			}
			if (result.fileDigests) fileDigests = { ...result.fileDigests };
			if (result.rootIdentity !== undefined) rootIdentity = result.rootIdentity;
			scanCount += 1;
			// Persist only when the baseline actually advanced. A held-back baseline
			// (undelivered alert) must stay un-persisted so the drift is re-reported.
			if (result.newBaseline) persistBaseline();
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
				// Debounce with a MAXIMUM WAIT.
				//
				// A plain trailing debounce restarts its timer on every event, so any
				// process writing to the watched directory faster than --debounce
				// postpones the rescan forever — trivially weaponisable to suppress
				// drift detection, and reachable by accident with a noisy build
				// watcher. Track when the current burst began and force a rescan once
				// maxWait elapses, regardless of continuing activity.
				const now = Date.now();
				if (burstStartedAt === null) burstStartedAt = now;

				if (debounceTimer) clearTimeout(debounceTimer);

				const elapsed = now - burstStartedAt;
				const remaining = Math.max(0, maxWaitMs - elapsed);
				const delay = Math.min(config.debounceMs, remaining);

				debounceTimer = setTimeout(() => {
					burstStartedAt = null;
					runRescan();
				}, delay);
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
			startupDrift,
			rootChangedSinceBaseline,
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
	| {
			readonly status: "ok";
			readonly baseline: ScanBaseline;
			/** sha256 of every tracked config file, for content-level drift. */
			readonly fileDigests: Record<string, string>;
	  }
	| { readonly status: "empty" }
	| { readonly status: "error"; readonly message: string };

/**
 * sha256 of each config file the scan actually read.
 *
 * Diffing findings alone misses a whole class of change: swapping an MCP
 * server's package for a malicious one with the same permissions shape produces
 * an identical finding set, and therefore no drift at all.
 */
function digestsOf(result: ReturnType<typeof scan>): Record<string, string> {
	const digests: Record<string, string> = {};
	for (const file of result.target.files) {
		digests[file.path] = digestContent(file.content);
	}
	return digests;
}

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
			fileDigests: digestsOf(result),
		};
	} catch (error) {
		const message = error instanceof Error ? error.message : String(error);
		return { status: "error", message };
	}
}

interface ChangeResult {
	readonly newBaseline: ScanBaseline | null;
	readonly drift: DriftResult | null;
	readonly fileDigests?: Readonly<Record<string, string>>;
	readonly rootIdentity?: PathIdentity | null;
}

/**
 * Handle a detected file change by rescanning and diffing.
 */
async function handleChange(
	config: WatchConfig,
	currentBaseline: ScanBaseline | null,
	previousDigests: Readonly<Record<string, string>>,
	previousIdentity: PathIdentity | null,
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

		// A path is not an identity. fs.watch holds a descriptor to whatever the
		// path resolved to at start, so replacing the directory with a symlink
		// elsewhere leaves the watcher bound to a detached inode: no events, no
		// error, and it still reports itself as running.
		const currentIdentity = identityOf(targetPath);
		const rootSwapped =
			previousIdentity != null && !sameIdentity(previousIdentity, currentIdentity);
		if (rootSwapped) {
			console.error(
				`  WATCH ROOT SWAPPED: ${targetPath} now resolves to a different directory or inode ` +
					`(was ${previousIdentity?.realpath}, now ${currentIdentity?.realpath ?? "unresolvable"}). ` +
					"Existing watchers are bound to the OLD target and are blind.",
			);
		}

		const result = scan(targetPath);
		const minIndex = SEVERITY_ORDER[config.minSeverity];
		const filteredFindings = result.findings.filter(
			(f) => SEVERITY_ORDER[f.severity] <= minIndex,
		);
		const report = calculateScore({ ...result, findings: filteredFindings });
		const newBaseline = createBaseline(filteredFindings, report.score);
		const currentDigests = digestsOf(result);
		const contentDrift = diffFileDigests(previousDigests, currentDigests);

		if (currentBaseline) {
			const drift = diffBaseline(
				currentBaseline,
				filteredFindings,
				report.score,
			);

			// Content-only drift: the files changed but the finding set did not. Worth
			// surfacing (an MCP server's package can be swapped for a malicious one
			// with an identical permissions shape) but reported more quietly than a
			// finding, and it does not gate the baseline on alert delivery.
			if (
				hasContentDrift(contentDrift) &&
				drift.newFindings.length === 0 &&
				drift.resolvedFindings.length === 0
			) {
				console.error("  Configuration changed (no change in findings):");
				for (const f of contentDrift.changed) console.error(`    changed:  ${f}`);
				for (const f of contentDrift.added) console.error(`    added:    ${f}`);
				for (const f of contentDrift.removed) console.error(`    removed:  ${f}`);
			}

			if (drift.newFindings.length > 0 || drift.resolvedFindings.length > 0) {
				const delivery = await dispatchAlert(
					drift,
					config.alertMode,
					config.webhookUrl,
				);
				if (delivery.delivered) {
					onResult({ newBaseline, drift, fileDigests: currentDigests, rootIdentity: currentIdentity });
				} else {
					// Hold the baseline back so this drift is re-detected and re-alerted
					// next cycle. Advancing it here would discard the event permanently —
					// at-least-once delivery matters far more than avoiding a duplicate
					// alert for a security monitor.
					onResult({ newBaseline: null, drift, fileDigests: currentDigests, rootIdentity: currentIdentity });
				}
			} else {
				onResult({ newBaseline, drift: null, fileDigests: currentDigests, rootIdentity: currentIdentity });
			}
		} else {
			onResult({ newBaseline, drift: null, fileDigests: currentDigests, rootIdentity: currentIdentity });
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
