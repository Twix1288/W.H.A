import type { Finding } from "../rules.js";
import { loadRules } from "./loader.js";
import type { PatternCategory, Profile } from "./types.js";

export interface ScanTextOptions {
	readonly profile?: Profile;
	/** Restrict to these categories (default: all). */
	readonly categories?: ReadonlyArray<PatternCategory>;
}

function lineOf(content: string, index: number): number {
	if (index <= 0) return 1;
	let line = 1;
	for (let i = 0; i < index && i < content.length; i++) {
		if (content[i] === "\n") line++;
	}
	return line;
}

/**
 * Run the shared pattern rule packs over a piece of text and return Findings.
 * Used by `check` and `scan` (on file source) and `guard` (on the code a tool
 * call will run). One Finding per matching rule (first match's line); a rule is
 * active when the requested profile is in its `profiles` set. Purely additive to
 * whatever engine the caller already runs.
 */
export function scanText(content: string, opts: ScanTextOptions = {}): Finding[] {
	const profile: Profile = opts.profile ?? "default";
	const catFilter = opts.categories ? new Set(opts.categories) : null;
	const findings: Finding[] = [];

	for (const rule of loadRules()) {
		if (!rule.profiles.includes(profile)) continue;
		if (catFilter && !catFilter.has(rule.category)) continue;
		// Use a non-global regex test first (cheap), then locate the first match
		// for a line number. RegExp objects from the loader are not global, so
		// there is no lastIndex state to reset between calls.
		const m = rule.re.exec(content);
		if (!m) continue;
		findings.push({
			ruleId: rule.id,
			name: rule.title,
			severity: rule.severity,
			category: rule.category,
			message: rule.title,
			line: lineOf(content, m.index ?? 0),
			fixable: false,
		});
	}
	return findings;
}

/** Categories most relevant when screening a command/tool-call at runtime. */
export const RUNTIME_CATEGORIES: ReadonlyArray<PatternCategory> = [
	"command",
	"injection",
	"secret",
	"sensitive-path",
];
