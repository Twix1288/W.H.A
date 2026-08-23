import type { Finding, SecurityScore, Severity } from "../types.js";

// ─── Watch Configuration ────────────────────────────────────

export interface WatchConfig {
	readonly paths: ReadonlyArray<string>;
	readonly debounceMs: number;
	readonly alertMode: AlertMode;
	readonly webhookUrl?: string;
	readonly minSeverity: Severity;
	readonly blockOnCritical: boolean;
}

export type AlertMode = "terminal" | "webhook" | "both";

// ─── Baseline & Drift ───────────────────────────────────────

export interface ScanBaseline {
	readonly timestamp: string;
	readonly score: SecurityScore;
	readonly findings: ReadonlyArray<Finding>;
	readonly findingIds: ReadonlySet<string>;
}

export interface DriftResult {
	readonly timestamp: string;
	readonly newFindings: ReadonlyArray<Finding>;
	readonly resolvedFindings: ReadonlyArray<Finding>;
	readonly scoreDelta: number;
	readonly previousScore: number;
	readonly currentScore: number;
	readonly isRegression: boolean;
	readonly hasCritical: boolean;
}

// ─── Watch Events ───────────────────────────────────────────

export interface WatchEvent {
	readonly type: "change" | "rename";
	readonly filename: string;
	readonly timestamp: string;
}

export interface WatcherState {
	readonly isRunning: boolean;
	/**
	 * Paths the watcher could NOT watch (missing, or not a directory). Previously
	 * these were skipped silently, so `watch <file>` reported a clean baseline and
	 * "Watching for changes..." while monitoring nothing at all.
	 */
	readonly setupErrors: ReadonlyArray<string>;
	/**
	 * Why the baseline scan failed, if it did. `null` with a `null` baseline means
	 * "nothing to scan"; a message means "could not scan" — which is NOT an
	 * all-clear and must fail a `--block` gate.
	 */
	readonly baselineError: string | null;
	readonly baseline: ScanBaseline | null;
	readonly lastDrift: DriftResult | null;
	/**
	 * Drift found on startup by diffing the fresh scan against the STORED
	 * baseline — i.e. changes made while the watcher was not running. Previously
	 * impossible to detect: the baseline was in-memory only, so a restart adopted
	 * whatever it found as "normal".
	 */
	readonly startupDrift: DriftResult | null;
	/**
	 * The watched path resolves to a different directory/inode than when the
	 * baseline was stored — i.e. it was swapped while we were not running. The
	 * configuration being gated is not the one previously approved.
	 */
	readonly rootChangedSinceBaseline: boolean;
	readonly scanCount: number;
}
