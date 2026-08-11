import { existsSync, readdirSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import * as path from "node:path";
import { parse as parseYaml } from "yaml";
import type { Severity } from "../types.js";
import {
	type CompiledRule,
	OverrideSchema,
	PackSchema,
	type PatternCategory,
	type PatternRuleDef,
	type Profile,
} from "./types.js";

// A minimal fail-SAFE set used ONLY if the shipped YAML packs cannot be located
// (a broken install). Without this a packaging bug would silently disable the
// guard's most important detections; instead we keep the critical few and warn.
const BUILTIN_FALLBACK: ReadonlyArray<{
	id: string;
	pattern: string;
	flags?: string;
	title: string;
	severity: Severity;
	category: PatternCategory;
}> = [
	{
		id: "CMD-REVSHELL-DEVTCP",
		pattern:
			"/dev/tcp/(?:\\d{1,3}\\.\\d{1,3}|[A-Za-z0-9-]+(?:\\.[A-Za-z0-9-]+)+)/\\d+\\b",
		title: "Reverse shell via /dev/tcp",
		severity: "critical",
		category: "command",
	},
	{
		id: "CMD-DOWNLOAD-EXEC-PIPE",
		pattern:
			"\\b(?:curl|wget|fetch)\\b[^\\n|]*\\|\\s*(?:sudo\\s+)?(?:[/\\w.]+/)?(?:bash|zsh|sh|python[23]?|node|perl|ruby)\\b",
		flags: "i",
		title: "Download piped to an interpreter",
		severity: "critical",
		category: "command",
	},
];

// Resolve the directory holding the shipped default packs. At runtime the bundle
// is dist/index.js and the packs sit at <package>/packs; in dev this file lives
// deeper under src/. Try the known-good relative offsets, first hit wins.
function findDefaultPacksDir(): string | null {
	const candidates = [
		path.resolve(__dirname, "../packs"), // published: dist/../packs
		path.resolve(__dirname, "../../packs"),
		path.resolve(__dirname, "../../../packs"), // dev: src/core-scanner/patterns → cli/packs
		path.resolve(__dirname, "../../../../packs"),
	];
	for (const dir of candidates) {
		if (existsSync(dir) && hasYaml(dir)) return dir;
	}
	return null;
}

function hasYaml(dir: string): boolean {
	try {
		return readdirSync(dir).some((f) => f.endsWith(".yaml") || f.endsWith(".yml"));
	} catch {
		return false;
	}
}

function readYamlFiles(dir: string): { file: string; doc: unknown }[] {
	const out: { file: string; doc: unknown }[] = [];
	let entries: string[] = [];
	try {
		entries = readdirSync(dir);
	} catch {
		return out;
	}
	for (const f of entries) {
		if (!f.endsWith(".yaml") && !f.endsWith(".yml")) continue;
		try {
			out.push({ file: path.join(dir, f), doc: parseYaml(readFileSync(path.join(dir, f), "utf-8")) });
		} catch (err) {
			warn(`skipping unreadable pack ${f}: ${err instanceof Error ? err.message : err}`);
		}
	}
	return out;
}

let warned = false;
function warn(msg: string): void {
	// One-time-ish stderr warning; never throws, never touches stdout (which
	// carries the guard's machine-readable decision).
	process.stderr.write(`[wh-agent rule packs] ${msg}\n`);
	warned = true;
}

function compile(
	def: PatternRuleDef,
	category: PatternCategory,
): CompiledRule | null {
	try {
		return {
			id: def.id,
			re: new RegExp(def.pattern, def.flags ?? ""),
			title: def.title,
			severity: def.severity,
			category,
			confidence: def.confidence ?? 0.75,
			tags: def.tags ?? [],
			profiles: (def.profiles ?? ["permissive", "default", "strict"]) as Profile[],
		};
	} catch (err) {
		warn(`invalid regex in rule ${def.id}: ${err instanceof Error ? err.message : err}`);
		return null;
	}
}

interface LoadedRules {
	readonly rules: ReadonlyArray<CompiledRule>;
}

let cache: LoadedRules | null = null;

function userOverrideDirs(): string[] {
	return [
		path.join(process.cwd(), ".wh-agent", "rules"),
		path.join(process.env.AGENTSHIELD_HOME ?? path.join(homedir(), ".wh-agent"), "rules"),
	];
}

/**
 * Load and compile all rule packs (shipped defaults + user overrides), once.
 * User override files may ADD rules (each carrying its own `category`) and list
 * built-in ids under `suppress:` to disable them. Never throws: a broken pack is
 * skipped with a warning; if nothing loads at all, a critical built-in fallback
 * is used so detection is never silently empty.
 */
export function loadRules(): ReadonlyArray<CompiledRule> {
	if (cache) return cache.rules;

	const compiled: CompiledRule[] = [];
	const suppress = new Set<string>();

	const defaultsDir = findDefaultPacksDir();
	if (defaultsDir) {
		for (const { file, doc } of readYamlFiles(defaultsDir)) {
			const parsed = PackSchema.safeParse(doc);
			if (!parsed.success) {
				warn(`invalid pack ${path.basename(file)}: ${parsed.error.issues[0]?.message}`);
				continue;
			}
			for (const rule of parsed.data.rules) {
				const c = compile(rule, parsed.data.category);
				if (c) compiled.push(c);
			}
		}
	}

	if (compiled.length === 0) {
		warn(
			`no rule packs found (looked near ${__dirname}); using ${BUILTIN_FALLBACK.length} built-in critical patterns only. Reinstall to restore full coverage.`,
		);
		for (const f of BUILTIN_FALLBACK) {
			const c = compile(
				{ id: f.id, pattern: f.pattern, flags: f.flags, title: f.title, severity: f.severity },
				f.category,
			);
			if (c) compiled.push(c);
		}
	}

	// User overrides (additive + suppressions).
	for (const dir of userOverrideDirs()) {
		if (!existsSync(dir)) continue;
		for (const { file, doc } of readYamlFiles(dir)) {
			const parsed = OverrideSchema.safeParse(doc);
			if (!parsed.success) {
				warn(`invalid override ${path.basename(file)}: ${parsed.error.issues[0]?.message}`);
				continue;
			}
			for (const id of parsed.data.suppress ?? []) suppress.add(id);
			for (const rule of parsed.data.rules ?? []) {
				const c = compile(rule, rule.category as PatternCategory);
				if (c) compiled.push(c);
			}
		}
	}

	const final = compiled.filter((r) => !suppress.has(r.id));
	// De-dupe by id (a user override with an existing id replaces the built-in:
	// keep the LAST occurrence).
	const byId = new Map<string, CompiledRule>();
	for (const r of final) byId.set(r.id, r);
	cache = { rules: [...byId.values()] };
	return cache.rules;
}

/** Reset the cache — for tests that vary the environment. */
export function _resetRuleCache(): void {
	cache = null;
	warned = false;
}

export function _warnedForTest(): boolean {
	return warned;
}
