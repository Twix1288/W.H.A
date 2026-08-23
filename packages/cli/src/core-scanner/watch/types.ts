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
	readonly scanCount: number;
}
