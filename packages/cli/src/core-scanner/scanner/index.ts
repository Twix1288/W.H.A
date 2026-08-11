import { detectHarnessAdapters } from "../harness-adapters/index.js";
import { scanText } from "../patterns/index.js";
import { getBuiltinRules } from "../rules/index.js";
import { analyzeSkillHealth } from "../skills/health.js";
import { isExampleLikePath, isPluginCachePath } from "../source-context.js";
import type {
	ConfigFile,
	Finding,
	HarnessAdapterSummary,
	Rule,
	RuntimeConfidence,
	ScanTarget,
	Severity,
	SkillHealthSummary,
} from "../types.js";
import { discoverConfigFiles } from "./discovery.js";

export interface ScanResult {
	readonly target: ScanTarget;
	readonly findings: ReadonlyArray<Finding>;
	readonly skillHealth?: SkillHealthSummary;
	readonly harnessAdapters?: HarnessAdapterSummary;
}

/**
 * Main scanner: discovers config files and runs all rules against them.
 */
export function scan(targetPath: string): ScanResult {
	const target = discoverConfigFiles(targetPath);
	const rules = getBuiltinRules();
	const findings = [
		...runRules(target.files, rules, target.path),
		...runPackRules(target.files),
		...runParseabilityChecks(target.files),
	];
	const skillHealth = analyzeSkillHealth(target.files);
	const harnessAdapters = detectHarnessAdapters(targetPath);

	return { target, findings, skillHealth, harnessAdapters };
}

// Map a shared-pack category to the scanner's FindingCategory. `secret` is
// deliberately absent: scan's existing secrets rule (rules/secrets.ts) is the
// authority for hardcoded secrets, so packs don't re-report them here.
const PACK_CATEGORY_TO_FINDING: Record<string, Finding["category"] | undefined> = {
	command: "exfiltration",
	injection: "injection",
	"sensitive-path": "exposure",
};

/**
 * FAIL CLOSED on unparseable security configs. Every content rule wraps
 * `JSON.parse` in `try{...}catch{return []}`, so a settings.json / mcp.json /
 * .claude.json / .mcp.json with a syntax error previously produced ZERO findings
 * and a perfect grade — the scanner could not tell "clean" from "couldn't read
 * it". This emits a high-severity finding so an unauditable config is never a
 * silent all-clear.
 */
function runParseabilityChecks(files: ReadonlyArray<ConfigFile>): Finding[] {
	const JSON_CONFIG_TYPES = new Set<ConfigFile["type"]>([
		"settings-json",
		"mcp-json",
	]);
	const out: Finding[] = [];
	for (const file of files) {
		if (!JSON_CONFIG_TYPES.has(file.type)) continue;
		if (!file.path.toLowerCase().endsWith(".json")) continue;
		if (file.content.trim() === "") continue; // empty file is handled elsewhere
		try {
			JSON.parse(file.content);
		} catch (err) {
			out.push({
				// Critical, not merely high: `scan` exits non-zero only on a critical,
				// so this is what makes a CI gate FAIL CLOSED on a config it couldn't
				// audit, rather than passing green with a finding nobody's exit-code
				// check will catch.
				id: "config-unparseable",
				severity: "critical",
				category: "misconfiguration",
				title: "Configuration file could not be parsed — NOT audited",
				description: `${file.path} is not valid JSON (${err instanceof Error ? err.message : "parse error"}), so its security rules could not run. An unreadable config is NOT an all-clear — fix the syntax and re-scan.`,
				file: file.path,
				line: 1,
			});
		}
	}
	return out;
}

/**
 * Run the shared regex rule packs over BUNDLED SCRIPT files (hook scripts, hook
 * code, and unclassified code) — the surface `scan` previously never
 * security-analyzed (a credential-stealing or reverse-shell script inside a
 * skill was invisible). This is the same pack engine `check` and `guard` use, so
 * detection is unified. Prose/config files keep their existing dedicated rules;
 * secrets stay owned by rules/secrets.ts (see PACK_CATEGORY_TO_FINDING).
 */
function runPackRules(files: ReadonlyArray<ConfigFile>): Finding[] {
	const CODE_TYPES = new Set(["hook-code", "hook-script", "unknown"]);
	const out: Finding[] = [];
	for (const file of files) {
		if (!CODE_TYPES.has(file.type)) continue;
		for (const f of scanText(file.content, {
			profile: "default",
			categories: ["command", "injection", "sensitive-path"],
		})) {
			const category = PACK_CATEGORY_TO_FINDING[f.category];
			if (!category) continue;
			out.push({
				id: f.ruleId,
				// Pack rule severities are drawn from the Severity union (validated by
				// the pack schema); the engine's Finding types it loosely as string.
				severity: f.severity as Severity,
				category,
				title: f.name,
				description: `${f.message} (detected in a bundled script by rule ${f.ruleId}).`,
				file: file.path,
				line: f.line,
			});
		}
	}
	return out;
}

/**
 * Run all rules against all config files, collecting findings.
 */
function runRules(
	files: ReadonlyArray<ConfigFile>,
	rules: ReadonlyArray<Rule>,
	scanRoot: string,
): ReadonlyArray<Finding> {
	const findings: Finding[] = [];

	for (const file of files) {
		for (const rule of rules) {
			const ruleFindings = rule.check(file, files);
			findings.push(...ruleFindings);
		}
	}

	const filesByPath = new Map(files.map((file) => [file.path, file]));
	const annotatedFindings = findings.map((finding) => {
		const annotatedFinding = annotateFindingRuntimeConfidence(
			finding,
			filesByPath,
			scanRoot,
		);
		return adjustFindingForSourceContext(annotatedFinding);
	});

	// Sort by severity (critical first)
	return [...annotatedFindings].sort((a, b) => {
		const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
		return order[a.severity] - order[b.severity];
	});
}

function classifyRuntimeConfidence(
	file: ConfigFile,
	scanRoot: string,
): RuntimeConfidence | undefined {
	const normalizedPath = file.path.replace(/\\/g, "/").toLowerCase();
	if (
		normalizedPath === "settings.local.json" ||
		normalizedPath.endsWith("/settings.local.json")
	) {
		return "project-local-optional";
	}

	if (isPluginCachePath(file.path, scanRoot)) {
		return "plugin-cache";
	}

	if (file.type === "hook-code") {
		return "hook-code";
	}

	if (
		file.type === "settings-json" &&
		/(?:^|\/)(?:\.claude\/)?hooks\/hooks\.json$/i.test(normalizedPath)
	) {
		return "plugin-manifest";
	}

	if (isExampleLikePath(normalizedPath)) {
		return "docs-example";
	}

	return undefined;
}

function annotateFindingRuntimeConfidence(
	finding: Finding,
	filesByPath: ReadonlyMap<string, ConfigFile>,
	scanRoot: string,
): Finding {
	if (finding.runtimeConfidence) {
		return finding;
	}

	const file = filesByPath.get(finding.file);
	const runtimeConfidence = file
		? classifyRuntimeConfidence(file, scanRoot)
		: undefined;
	return runtimeConfidence ? { ...finding, runtimeConfidence } : finding;
}

function adjustFindingForSourceContext(finding: Finding): Finding {
	switch (finding.runtimeConfidence) {
		case "docs-example":
			return adjustDocsExampleFinding(finding);
		case "plugin-cache":
			return adjustPluginCacheFinding(finding);
		case "plugin-manifest":
			return adjustPluginManifestFinding(finding);
		default:
			return finding;
	}
}

function adjustDocsExampleFinding(finding: Finding): Finding {
	if (finding.category === "secrets") {
		return withPrefixedDescription(
			{
				...finding,
				title: prefixTitle(finding.title, "Example config"),
			},
			"This finding comes from docs or sample configuration in the repository. It indicates risky guidance or example defaults, not confirmed active runtime exposure.",
		);
	}

	return withPrefixedDescription(
		{
			...finding,
			severity: downgradeStructuralSeverity(finding.severity),
			title: prefixTitle(finding.title, "Example config"),
		},
		"This finding comes from docs or sample configuration in the repository. It indicates risky guidance or example defaults, not confirmed active runtime exposure.",
	);
}

function adjustPluginCacheFinding(finding: Finding): Finding {
	if (finding.category === "secrets") {
		return withPrefixedDescription(
			{
				...finding,
				title: prefixTitle(finding.title, "Plugin cache"),
			},
			"This finding comes from an installed Claude plugin cache. It indicates packaged plugin content present on disk, not confirmed top-level runtime configuration.",
		);
	}

	return withPrefixedDescription(
		{
			...finding,
			severity: downgradeStructuralSeverity(finding.severity),
			title: prefixTitle(finding.title, "Plugin cache"),
		},
		"This finding comes from an installed Claude plugin cache. It indicates packaged plugin content present on disk, not confirmed top-level runtime configuration.",
	);
}

function adjustPluginManifestFinding(finding: Finding): Finding {
	return withPrefixedDescription(
		{
			...finding,
			title: prefixTitle(finding.title, "Plugin hook manifest"),
		},
		"This finding comes from a declarative hook manifest. Review the referenced hook implementation to confirm the exact runtime behavior.",
	);
}

function downgradeStructuralSeverity(severity: Severity): Severity {
	switch (severity) {
		case "critical":
			return "high";
		case "high":
			return "medium";
		case "medium":
			return "low";
		default:
			return severity;
	}
}

function prefixTitle(title: string, prefix: string): string {
	return title.startsWith(`${prefix}: `) ? title : `${prefix}: ${title}`;
}

function withPrefixedDescription(finding: Finding, prefix: string): Finding {
	return finding.description.startsWith(prefix)
		? finding
		: { ...finding, description: `${prefix} ${finding.description}` };
}

export { discoverConfigFiles } from "./discovery.js";
