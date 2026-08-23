import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import type { Finding, SecurityScore } from "../types.js";
import type { ScanBaseline } from "./types.js";

/**
 * Durable, per-target watch state.
 *
 * See docs/plans/DURABLE-WATCH-STATE.md for the design and the reasoning behind
 * the storage choice. In short: the baseline used to live only in memory, so
 * restarting the watcher silently adopted whatever the configuration looked like
 * at that moment as "normal" — including a configuration an attacker had just
 * changed. Persisting it is what makes the other watch fixes meaningful.
 *
 * Deliberately plain JSON with an atomic write, not an embedded database: state
 * is written once per (already debounced) drift event, and every native module
 * this CLI depends on has been a packaging problem.
 */

/** Bump when the on-disk shape changes; an older/newer file is ignored, not guessed at. */
const STATE_VERSION = 1;

function stateDir(): string {
	const home = process.env.AGENTSHIELD_HOME ?? path.join(os.homedir(), ".wh-agent");
	return path.join(home, "baselines");
}

/**
 * State is keyed by the LOGICAL path the user asked to watch (absolute, but NOT
 * symlink-resolved), and the resolved identity is stored inside the file.
 *
 * Keying by realpath instead looks tempting and is wrong: a symlink swap would
 * then produce a DIFFERENT key, so the swapped target would quietly get a fresh
 * baseline and the swap — the thing we most want to catch — would be invisible.
 * The logical path is the stable identity; what it resolves to is precisely the
 * thing that can change and must be compared.
 *
 * Keying per target also fixes the existing un-keyed global state file, where
 * watching a second target corrupted the first target's drift detection.
 */
export function stateFileFor(targetPath: string): string {
	const logical = path.resolve(targetPath);
	const key = crypto.createHash("sha256").update(logical).digest("hex").slice(0, 16);
	return path.join(stateDir(), `${key}.json`);
}

/** Filesystem identity of a path. A path is not an identity; an inode is. */
export interface PathIdentity {
	readonly realpath: string;
	readonly dev: number;
	readonly ino: number;
}

export function identityOf(target: string): PathIdentity | null {
	try {
		const st = fs.statSync(target);
		return { realpath: fs.realpathSync(target), dev: st.dev, ino: st.ino };
	} catch {
		return null;
	}
}

export function sameIdentity(
	a: PathIdentity | null,
	b: PathIdentity | null,
): boolean {
	if (!a || !b) return false;
	return a.realpath === b.realpath && a.dev === b.dev && a.ino === b.ino;
}

export interface PersistedBaseline {
	readonly version: number;
	readonly target: string;
	readonly timestamp: string;
	readonly score: SecurityScore;
	readonly findings: ReadonlyArray<Finding>;
	/** Fingerprints of the findings above, for fast diffing. */
	readonly findingIds: ReadonlyArray<string>;
	/**
	 * sha256 of each tracked config file's contents, keyed by path.
	 *
	 * Findings alone are not enough: swapping an MCP server's package for a
	 * malicious one with the same permissions shape produces an identical finding
	 * set and therefore no drift at all. Content digests catch that.
	 */
	readonly fileDigests: Readonly<Record<string, string>>;
	/** Identity of the watch root, so a symlink swap is detectable. */
	readonly rootIdentity: PathIdentity | null;
}

export function digestContent(content: string): string {
	return crypto.createHash("sha256").update(content).digest("hex");
}

/**
 * Read the stored baseline for a target.
 *
 * A missing, corrupt, or version-mismatched file returns null — meaning "no
 * baseline", which causes one to be established. It must never be interpreted as
 * "no drift": that would make corrupting the state file a way to silence the
 * watcher.
 */
export function loadBaseline(targetPath: string): PersistedBaseline | null {
	const file = stateFileFor(targetPath);
	try {
		if (!fs.existsSync(file)) return null;
		const parsed = JSON.parse(fs.readFileSync(file, "utf-8")) as PersistedBaseline;
		if (!parsed || parsed.version !== STATE_VERSION) return null;
		if (!Array.isArray(parsed.findings) || !Array.isArray(parsed.findingIds)) {
			return null;
		}
		return parsed;
	} catch {
		return null;
	}
}

/**
 * Persist a baseline atomically: write a temp file, then rename over the target.
 * Rename is atomic within a filesystem, so a crash mid-write cannot leave a torn
 * file that later reads as a valid-but-wrong baseline.
 */
export function saveBaseline(
	targetPath: string,
	baseline: ScanBaseline,
	fileDigests: Readonly<Record<string, string>>,
	rootIdentity: PathIdentity | null,
): { ok: true } | { ok: false; error: string } {
	const file = stateFileFor(targetPath);
	const payload: PersistedBaseline = {
		version: STATE_VERSION,
		target: targetPath,
		timestamp: baseline.timestamp,
		score: baseline.score,
		findings: baseline.findings,
		findingIds: [...baseline.findingIds],
		fileDigests,
		rootIdentity,
	};

	const tmp = `${file}.${process.pid}.tmp`;
	try {
		fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
		fs.writeFileSync(tmp, JSON.stringify(payload, null, 2), { mode: 0o600 });
		fs.renameSync(tmp, file);
		return { ok: true };
	} catch (err) {
		try {
			fs.rmSync(tmp, { force: true });
		} catch {
			// best effort
		}
		return { ok: false, error: err instanceof Error ? err.message : String(err) };
	}
}

/** Rehydrate the in-memory baseline shape from a persisted one. */
export function toScanBaseline(p: PersistedBaseline): ScanBaseline {
	return {
		timestamp: p.timestamp,
		score: p.score,
		findings: p.findings,
		findingIds: new Set(p.findingIds),
	};
}

export interface ContentDrift {
	readonly changed: ReadonlyArray<string>;
	readonly added: ReadonlyArray<string>;
	readonly removed: ReadonlyArray<string>;
}

/** Compare two digest maps. Empty arrays mean the tracked content is identical. */
export function diffFileDigests(
	previous: Readonly<Record<string, string>>,
	current: Readonly<Record<string, string>>,
): ContentDrift {
	const changed: string[] = [];
	const added: string[] = [];
	const removed: string[] = [];

	for (const [file, digest] of Object.entries(current)) {
		if (!Object.hasOwn(previous, file)) added.push(file);
		else if (previous[file] !== digest) changed.push(file);
	}
	for (const file of Object.keys(previous)) {
		if (!Object.hasOwn(current, file)) removed.push(file);
	}

	return { changed: changed.sort(), added: added.sort(), removed: removed.sort() };
}

export function hasContentDrift(d: ContentDrift): boolean {
	return d.changed.length > 0 || d.added.length > 0 || d.removed.length > 0;
}
