import type { ConfigFile, Finding, Rule } from "../types.js";
import type { VulnerableConfig } from "./vulnerable-configs.js";
import { vulnerableConfigs } from "./vulnerable-configs.js";

export type { VulnerableConfig } from "./vulnerable-configs.js";
export { vulnerableConfigs } from "./vulnerable-configs.js";

// ─── Corpus Validation Types ──────────────────────────────

export interface CorpusValidationResult {
	readonly configId: string;
	readonly configName: string;
	readonly category: string;
	readonly expectedFindings: number;
	readonly actualFindings: number;
	readonly missingRules: ReadonlyArray<string>;
	readonly extraRules: ReadonlyArray<string>;
	readonly passed: boolean;
}

export interface CorpusCategoryBreakdown {
	readonly category: string;
	readonly totalConfigs: number;
	readonly detected: number;
	readonly missed: number;
	readonly detectionRate: number;
}

export type CorpusAccuracyPriority = "critical" | "high" | "medium";

export interface CorpusAccuracyRecommendation {
	readonly category: string;
	readonly priority: CorpusAccuracyPriority;
	readonly missedConfigs: number;
	readonly totalConfigs: number;
	readonly detectionRate: number;
	readonly configIds: ReadonlyArray<string>;
	readonly missingRules: ReadonlyArray<string>;
	readonly action: string;
}

export interface CorpusValidation {
	readonly totalConfigs: number;
	readonly passed: number;
	readonly failed: number;
	readonly detectionRate: number;
	readonly readyForRegressionGate: boolean;
	readonly categoryBreakdown: ReadonlyArray<CorpusCategoryBreakdown>;
	readonly accuracyRecommendations: ReadonlyArray<CorpusAccuracyRecommendation>;
	readonly results: ReadonlyArray<CorpusValidationResult>;
}

export interface CorpusGateOptions {
	readonly minDetectionRate?: number;
}

export interface CorpusGateResult {
	readonly passed: boolean;
	readonly minDetectionRate: number;
	readonly detectionRate: number;
	readonly failedConfigs: ReadonlyArray<CorpusValidationResult>;
	readonly failedCategories: ReadonlyArray<CorpusCategoryBreakdown>;
	readonly accuracyRecommendations: ReadonlyArray<CorpusAccuracyRecommendation>;
	readonly reasons: ReadonlyArray<string>;
}

// ─── Scan Function Types ──────────────────────────────────

/**
 * A simple scan function that takes files and returns findings.
 */
export type ScanFn = (
	files: ReadonlyArray<{
		readonly path: string;
		readonly content: string;
		readonly type: string;
	}>,
) => ReadonlyArray<Finding>;

/**
 * A rule-aware scan function that takes files and rules,
 * and returns findings grouped by rule ID.
 */
export type RuleScanFn = (
	files: ReadonlyArray<ConfigFile>,
	rules: ReadonlyArray<Rule>,
) => Map<string, ReadonlyArray<Finding>>;

// ─── Validation ───────────────────────────────────────────

/**
 * Validate that the scanner catches all expected findings in each corpus config.
 *
 * Uses rule-aware scanning: each rule is run separately so we can track
 * exactly which rule produced which findings.
 */
export function validateCorpus(
	ruleScanFn: RuleScanFn,
	rules: ReadonlyArray<Rule>,
): CorpusValidation {
	const results: CorpusValidationResult[] = [];

	for (const config of vulnerableConfigs) {
		const result = validateSingleConfig(config, ruleScanFn, rules);
		results.push(result);
	}

	const passed = results.filter((r) => r.passed).length;
	const failed = results.filter((r) => !r.passed).length;
	const detectionRate =
		vulnerableConfigs.length > 0 ? passed / vulnerableConfigs.length : 1;

	return {
		totalConfigs: vulnerableConfigs.length,
		passed,
		failed,
		detectionRate,
		readyForRegressionGate: failed === 0,
		categoryBreakdown: buildCategoryBreakdown(results),
		accuracyRecommendations: buildAccuracyRecommendations(results),
		results,
	};
}

/**
 * Evaluate whether the built-in corpus is strong enough to gate a release/CI run.
 *
 * The default is intentionally strict: every corpus config must pass. A lower
 * threshold can be supplied for temporary migration windows while still keeping
 * the failed configs/categories visible to automation.
 */
export function evaluateCorpusGate(
	validation: CorpusValidation,
	options: CorpusGateOptions = {},
): CorpusGateResult {
	const minDetectionRate = options.minDetectionRate ?? 1;
	const failedConfigs = validation.results.filter((result) => !result.passed);
	const failedCategories = validation.categoryBreakdown.filter(
		(category) => category.missed > 0,
	);
	const reasons: string[] = [];

	if (validation.detectionRate < minDetectionRate) {
		reasons.push(
			`Detection rate ${formatRate(validation.detectionRate)} is below required ${formatRate(minDetectionRate)}.`,
		);
	}

	if (!validation.readyForRegressionGate) {
		reasons.push(`Missed ${failedConfigs.length} corpus configs.`);
	}

	for (const category of failedCategories) {
		reasons.push(
			`Category "${category.category}" missed ${category.missed}/${category.totalConfigs} configs.`,
		);
	}

	return {
		passed: reasons.length === 0,
		minDetectionRate,
		detectionRate: validation.detectionRate,
		failedConfigs,
		failedCategories,
		accuracyRecommendations: validation.accuracyRecommendations,
		reasons,
	};
}

/**
 * Validate a single vulnerable config against the scanner.
 */
function validateSingleConfig(
	config: VulnerableConfig,
	ruleScanFn: RuleScanFn,
	rules: ReadonlyArray<Rule>,
): CorpusValidationResult {
	const configFiles: ConfigFile[] = config.files.map((f) => ({
		path: f.path,
		content: f.content,
		type: f.type,
	}));

	// Run each rule separately and collect findings by rule ID
	const findingsByRule = ruleScanFn(configFiles, rules);

	// Compare against expected findings
	const missingRules: string[] = [];
	let expectedTotal = 0;
	let actualTotal = 0;

	for (const [_ruleId, findings] of findingsByRule) {
		actualTotal += findings.length;
	}

	for (const expected of config.expectedFindings) {
		expectedTotal += expected.count;
		const ruleFindings = findingsByRule.get(expected.ruleId) ?? [];

		if (ruleFindings.length < expected.count) {
			missingRules.push(
				`${expected.ruleId} (expected ${expected.count}, got ${ruleFindings.length})`,
			);
		}
	}

	// Find rules that fired but were not expected
	const expectedRuleIds = new Set(config.expectedFindings.map((e) => e.ruleId));
	const extraRules: string[] = [];
	for (const [ruleId, findings] of findingsByRule) {
		if (!expectedRuleIds.has(ruleId) && findings.length > 0) {
			extraRules.push(`${ruleId} (${findings.length})`);
		}
	}

	return {
		configId: config.id,
		configName: config.name,
		category: config.category,
		expectedFindings: expectedTotal,
		actualFindings: actualTotal,
		missingRules,
		extraRules,
		passed: missingRules.length === 0,
	};
}

function buildCategoryBreakdown(
	results: ReadonlyArray<CorpusValidationResult>,
): ReadonlyArray<CorpusCategoryBreakdown> {
	const byCategory = new Map<string, { total: number; detected: number }>();

	for (const result of results) {
		const current = byCategory.get(result.category) ?? {
			total: 0,
			detected: 0,
		};
		byCategory.set(result.category, {
			total: current.total + 1,
			detected: current.detected + (result.passed ? 1 : 0),
		});
	}

	return [...byCategory.entries()]
		.sort(([left], [right]) => left.localeCompare(right))
		.map(([category, counts]) => {
			const missed = counts.total - counts.detected;
			return {
				category,
				totalConfigs: counts.total,
				detected: counts.detected,
				missed,
				detectionRate: counts.total > 0 ? counts.detected / counts.total : 1,
			};
		});
}

function buildAccuracyRecommendations(
	results: ReadonlyArray<CorpusValidationResult>,
): ReadonlyArray<CorpusAccuracyRecommendation> {
	const failedByCategory = new Map<string, CorpusValidationResult[]>();

	for (const result of results) {
		if (result.passed) {
			continue;
		}

		const current = failedByCategory.get(result.category) ?? [];
		current.push(result);
		failedByCategory.set(result.category, current);
	}

	return [...failedByCategory.entries()]
		.map(([category, failedResults]) => {
			const categoryResults = results.filter(
				(result) => result.category === category,
			);
			const totalConfigs = categoryResults.length;
			const missedConfigs = failedResults.length;
			const detected = totalConfigs - missedConfigs;
			const detectionRate = totalConfigs > 0 ? detected / totalConfigs : 1;
			const missingRules = uniqueValues(
				failedResults.flatMap((result) =>
					result.missingRules.map(parseMissingRuleId),
				),
			);
			const configIds = failedResults.map((result) => result.configId);

			return {
				category,
				priority: priorityForCorpusGap(detectionRate, missedConfigs),
				missedConfigs,
				totalConfigs,
				detectionRate,
				configIds,
				missingRules,
				action: buildAccuracyRecommendationAction(
					category,
					missingRules,
					configIds,
				),
			} satisfies CorpusAccuracyRecommendation;
		})
		.sort(
			(left, right) =>
				priorityRank(left.priority) - priorityRank(right.priority) ||
				right.missedConfigs - left.missedConfigs ||
				left.detectionRate - right.detectionRate ||
				left.category.localeCompare(right.category),
		);
}

function parseMissingRuleId(missingRule: string): string {
	return missingRule.split(" ")[0] ?? missingRule;
}

function uniqueValues(values: ReadonlyArray<string>): string[] {
	return [...new Set(values.filter(Boolean))].sort();
}

function priorityForCorpusGap(
	detectionRate: number,
	missedConfigs: number,
): CorpusAccuracyPriority {
	if (detectionRate === 0 || missedConfigs >= 3) {
		return "critical";
	}

	if (detectionRate < 0.8 || missedConfigs >= 2) {
		return "high";
	}

	return "medium";
}

function priorityRank(priority: CorpusAccuracyPriority): number {
	switch (priority) {
		case "critical":
			return 0;
		case "high":
			return 1;
		case "medium":
			return 2;
	}
}

function buildAccuracyRecommendationAction(
	category: string,
	missingRules: ReadonlyArray<string>,
	configIds: ReadonlyArray<string>,
): string {
	const ruleScope =
		missingRules.length > 0
			? `missing rule coverage for ${missingRules.join(", ")}`
			: `missed configs ${configIds.join(", ")}`;

	return `Improve ${category} corpus coverage by adding or fixing scanner fixtures and rules for ${ruleScope}.`;
}

function formatRate(rate: number): string {
	return `${(rate * 100).toFixed(1)}%`;
}

// ─── Helpers ──────────────────────────────────────────────

/**
 * Returns all configs in the corpus.
 */
export function getCorpusConfigs(): ReadonlyArray<VulnerableConfig> {
	return vulnerableConfigs;
}

/**
 * Returns a single config by ID.
 */
export function getCorpusConfig(id: string): VulnerableConfig | undefined {
	return vulnerableConfigs.find((c) => c.id === id);
}

/**
 * Default rule-aware scan function: runs each rule against each file
 * and returns findings grouped by rule ID.
 */
export function defaultRuleScanFn(
	files: ReadonlyArray<ConfigFile>,
	rules: ReadonlyArray<Rule>,
): Map<string, ReadonlyArray<Finding>> {
	const result = new Map<string, Finding[]>();

	for (const rule of rules) {
		const findings: Finding[] = [];
		for (const file of files) {
			findings.push(...rule.check(file));
		}
		if (findings.length > 0) {
			result.set(rule.id, findings);
		}
	}

	return result;
}
