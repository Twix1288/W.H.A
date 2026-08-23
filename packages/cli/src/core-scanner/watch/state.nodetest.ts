// Regression tests for durable watch state. See docs/plans/DURABLE-WATCH-STATE.md.
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { after, before, describe, test } from "node:test";
import type { Finding, SecurityScore } from "../types.ts";
import {
	diffFileDigests,
	digestContent,
	hasContentDrift,
	identityOf,
	loadBaseline,
	sameIdentity,
	saveBaseline,
	stateFileFor,
	toScanBaseline,
} from "./state.ts";
import type { ScanBaseline } from "./types.ts";

let tmp: string;
let prevHome: string | undefined;

before(() => {
	tmp = fs.mkdtempSync(path.join(os.tmpdir(), "wh-state-"));
	prevHome = process.env.AGENTSHIELD_HOME;
	process.env.AGENTSHIELD_HOME = path.join(tmp, "home");
});

after(() => {
	if (prevHome === undefined) delete process.env.AGENTSHIELD_HOME;
	else process.env.AGENTSHIELD_HOME = prevHome;
	fs.rmSync(tmp, { recursive: true, force: true });
});

const score: SecurityScore = {
	numericScore: 80,
	grade: "B",
	breakdown: {},
} as unknown as SecurityScore;

const finding = (id: string): Finding =>
	({
		id,
		severity: "high",
		category: "mcp",
		title: `finding ${id}`,
		description: "d",
		file: "settings.json",
		line: 1,
	}) as unknown as Finding;

const baselineOf = (ids: string[]): ScanBaseline => ({
	timestamp: new Date(0).toISOString(),
	score,
	findings: ids.map(finding),
	findingIds: new Set(ids),
});

describe("state keying", () => {
	test("state is keyed per target, not globally", () => {
		// The pre-existing watchdog state was a single un-keyed global file, so
		// watching a second target corrupted the first target's drift detection.
		assert.notEqual(stateFileFor("/tmp/a"), stateFileFor("/tmp/b"));
	});

	test("the key is the LOGICAL path, so a symlink swap keeps the same key", () => {
		// Keying by realpath would give a swapped target a different key — it would
		// quietly get a fresh baseline and the swap would be invisible, which is the
		// opposite of what we need.
		const linkDir = path.join(tmp, "keying");
		fs.mkdirSync(path.join(linkDir, "a"), { recursive: true });
		fs.mkdirSync(path.join(linkDir, "b"), { recursive: true });
		const link = path.join(linkDir, "link");

		fs.symlinkSync(path.join(linkDir, "a"), link);
		const before = stateFileFor(link);
		fs.unlinkSync(link);
		fs.symlinkSync(path.join(linkDir, "b"), link);
		const after = stateFileFor(link);

		assert.equal(before, after, "a symlink swap must not change the state key");
	});

	test("relative and absolute forms of one path share a key", () => {
		assert.equal(stateFileFor(process.cwd()), stateFileFor("."));
	});
});

describe("baseline persistence", () => {
	test("round-trips through disk", () => {
		const target = path.join(tmp, "t1");
		const b = baselineOf(["a", "b"]);
		const written = saveBaseline(target, b, { "settings.json": "d1" }, null);
		assert.equal(written.ok, true);

		const loaded = loadBaseline(target);
		assert.ok(loaded, "baseline should load back");
		assert.deepEqual([...toScanBaseline(loaded).findingIds].sort(), ["a", "b"]);
		assert.deepEqual(loaded?.fileDigests, { "settings.json": "d1" });
	});

	test("a corrupt state file reads as NO BASELINE, never as no-drift", () => {
		// Otherwise truncating the state file would be a way to silence the watcher.
		const target = path.join(tmp, "t2");
		saveBaseline(target, baselineOf(["a"]), {}, null);
		const file = stateFileFor(target);
		fs.writeFileSync(file, '{"version":1,"findings":[' /* truncated */);
		assert.equal(loadBaseline(target), null);
	});

	test("a state file from a different version is ignored, not guessed at", () => {
		const target = path.join(tmp, "t3");
		saveBaseline(target, baselineOf(["a"]), {}, null);
		const file = stateFileFor(target);
		const parsed = JSON.parse(fs.readFileSync(file, "utf-8"));
		parsed.version = 999;
		fs.writeFileSync(file, JSON.stringify(parsed));
		assert.equal(loadBaseline(target), null);
	});

	test("a missing baseline is null, not an error", () => {
		assert.equal(loadBaseline(path.join(tmp, "never-written")), null);
	});

	test("the state file is not world-readable", () => {
		const target = path.join(tmp, "t4");
		saveBaseline(target, baselineOf(["a"]), {}, null);
		const mode = fs.statSync(stateFileFor(target)).mode & 0o077;
		assert.equal(mode, 0, "state file must not be group/other readable");
	});

	test("a failed write is reported rather than silently dropped", () => {
		// A baseline we cannot persist means the next restart re-baselines against
		// whatever it finds; the caller has to be able to say so.
		const target = path.join(tmp, "t5");
		const dir = path.dirname(stateFileFor(target));
		fs.mkdirSync(dir, { recursive: true });
		fs.chmodSync(dir, 0o500); // read+execute only
		try {
			const result = saveBaseline(target, baselineOf(["a"]), {}, null);
			assert.equal(result.ok, false);
		} finally {
			fs.chmodSync(dir, 0o700);
		}
	});
});

describe("filesystem identity", () => {
	test("a path resolving elsewhere is a different identity", () => {
		const root = path.join(tmp, "ident");
		fs.mkdirSync(path.join(root, "a"), { recursive: true });
		fs.mkdirSync(path.join(root, "b"), { recursive: true });
		const link = path.join(root, "link");

		fs.symlinkSync(path.join(root, "a"), link);
		const first = identityOf(link);
		fs.unlinkSync(link);
		fs.symlinkSync(path.join(root, "b"), link);
		const second = identityOf(link);

		assert.ok(first && second);
		assert.equal(sameIdentity(first, second), false, "swap must be detected");
	});

	test("an unchanged path keeps its identity", () => {
		const d = path.join(tmp, "stable");
		fs.mkdirSync(d, { recursive: true });
		assert.ok(sameIdentity(identityOf(d), identityOf(d)));
	});

	test("a missing path has no identity, and never compares equal", () => {
		assert.equal(identityOf(path.join(tmp, "nope")), null);
		assert.equal(sameIdentity(null, null), false);
	});
});

describe("content-level drift", () => {
	test("detects a change that produces no new finding", () => {
		// Swapping an MCP server's package for a malicious one with the same
		// permissions shape yields an identical finding set, so finding-only
		// diffing reported no drift at all.
		const before = { "settings.json": digestContent("legit-docs-server") };
		const after = { "settings.json": digestContent("evil-docs-server") };
		const drift = diffFileDigests(before, after);
		assert.deepEqual(drift.changed, ["settings.json"]);
		assert.ok(hasContentDrift(drift));
	});

	test("detects added and removed files", () => {
		const drift = diffFileDigests({ a: "1" }, { b: "2" });
		assert.deepEqual(drift.added, ["b"]);
		assert.deepEqual(drift.removed, ["a"]);
	});

	test("identical content is not drift", () => {
		const same = { a: digestContent("x"), b: digestContent("y") };
		assert.equal(hasContentDrift(diffFileDigests(same, { ...same })), false);
	});
});
