import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startWatcher } from "./watcher.js";

// Deterministic tests for the config-drift engine. We exercise the real scanner
// via the synchronous initial scan only — no reliance on fs.watch event timing,
// which would be flaky in CI.
describe("startWatcher (config-drift engine)", () => {
	let root: string;
	let configDir: string;

	beforeAll(() => {
		root = mkdtempSync(join(tmpdir(), "wh-watch-"));
		configDir = join(root, ".claude");
		mkdirSync(configDir, { recursive: true });
		// A config with obvious problems so the scan yields findings.
		writeFileSync(
			join(configDir, "settings.json"),
			JSON.stringify({
				permissions: { allow: ["Bash(*)", "Read(~/.ssh/**)"] },
				env: { OPENAI_API_KEY: `sk-proj-${"A".repeat(40)}` },
			}),
		);
	});

	afterAll(() => {
		rmSync(root, { recursive: true, force: true });
	});

	test("establishes a baseline with findings on start, then stops cleanly", () => {
		const { stop, getState } = startWatcher({
			paths: [configDir],
			debounceMs: 100,
			alertMode: "terminal",
			minSeverity: "info",
			blockOnCritical: false,
		});

		try {
			const state = getState();
			expect(state.isRunning).toBe(true);
			expect(state.baseline).not.toBeNull();
			expect(state.scanCount).toBeGreaterThanOrEqual(1);
			expect(state.baseline?.findings.length ?? 0).toBeGreaterThan(0);
			// The baseline score is a valid SecurityScore.
			expect(state.baseline?.score.numericScore).toBeGreaterThanOrEqual(0);
			expect(state.baseline?.score.numericScore).toBeLessThanOrEqual(100);
		} finally {
			stop();
		}

		// stop() must close all watchers and report not-running.
		expect(getState().isRunning).toBe(false);
	});

	test("returns a null baseline for an empty directory (no crash)", () => {
		const empty = mkdtempSync(join(tmpdir(), "wh-watch-empty-"));
		const { stop, getState } = startWatcher({
			paths: [empty],
			debounceMs: 100,
			alertMode: "terminal",
			minSeverity: "info",
			blockOnCritical: false,
		});
		try {
			// An empty dir yields no config findings; the engine must not throw.
			expect(getState().baseline?.findings.length ?? 0).toBe(0);
		} finally {
			stop();
			rmSync(empty, { recursive: true, force: true });
		}
	});
});
