import type {
	PolicyPackPromotionResult,
	PolicyPackPromotionReviewItem,
} from "./policy/index.js";

export type ActionPolicyPromotionStatus =
	| "not-run"
	| "verified"
	| "needs-review"
	| "error";

export interface ActionPolicyPromotionRuntimeSmoke {
	readonly policyPath: string;
	readonly targetPath: string;
	readonly policyStatus: string;
}

export interface ActionPolicyPromotionSummary {
	readonly status: ActionPolicyPromotionStatus;
	readonly pack: string;
	readonly policyName: string;
	readonly digest: string;
	readonly promoted: boolean;
	readonly dryRun: boolean;
	readonly outputPath: string;
	readonly sourceFile: string;
	readonly totalReviewItems: number;
	readonly actionRequiredCount: number;
	readonly reviewItems: ReadonlyArray<PolicyPackPromotionReviewItem>;
}

export function summarizePolicyPromotion(
	result: PolicyPackPromotionResult,
	options: {
		readonly runtimeSmoke?: ActionPolicyPromotionRuntimeSmoke;
	} = {},
): ActionPolicyPromotionSummary {
	const reviewItems = options.runtimeSmoke
		? markRuntimeSmokeVerified(result.reviewItems, options.runtimeSmoke)
		: result.reviewItems;
	const actionRequiredCount = reviewItems.filter(
		(item) => item.status === "action_required",
	).length;

	return {
		status: actionRequiredCount > 0 ? "needs-review" : "verified",
		pack: result.pack,
		policyName: result.policyName,
		digest: result.sha256,
		promoted: result.promoted,
		dryRun: result.dryRun,
		outputPath: result.outputPath,
		sourceFile: result.sourceFile,
		totalReviewItems: reviewItems.length,
		actionRequiredCount,
		reviewItems,
	};
}

export function renderPolicyPromotionJobSummary(
	summary: ActionPolicyPromotionSummary,
): string {
	const lines = [
		"",
		"",
		"## W.H.Agent Policy Promotion",
		"",
		`- Status: ${summary.status}`,
		`- Pack: ${summary.pack}`,
		`- Policy: ${summary.policyName}`,
		`- Digest: ${summary.digest}`,
		`- Promoted: ${summary.promoted ? "yes" : "no"}`,
		`- Dry run: ${summary.dryRun ? "yes" : "no"}`,
		`- Source: ${summary.sourceFile}`,
		`- Output: ${summary.outputPath}`,
		`- Review items: ${summary.totalReviewItems}`,
		`- Action required: ${summary.actionRequiredCount}`,
	];

	if (summary.reviewItems.length > 0) {
		lines.push("", "### Promotion Review Items", "");
		for (const item of summary.reviewItems) {
			const evidence =
				item.evidencePaths.length > 0
					? ` evidence=${item.evidencePaths.join(", ")}`
					: "";
			lines.push(
				`- ${item.id} (${item.status}, ${item.severity}): ${item.title}${evidence}`,
			);
			lines.push(`  - ${item.detail}`);
			lines.push(`  - recommendation: ${item.recommendation}`);
		}
	}

	lines.push("");
	return lines.join("\n");
}

function markRuntimeSmokeVerified(
	reviewItems: ReadonlyArray<PolicyPackPromotionReviewItem>,
	runtimeSmoke: ActionPolicyPromotionRuntimeSmoke,
): ReadonlyArray<PolicyPackPromotionReviewItem> {
	return reviewItems.map((item) => {
		if (item.id !== "runtime-smoke-test") return item;

		return {
			...item,
			status: "verified",
			severity: "info",
			detail:
				`Runtime smoke scan completed against ${runtimeSmoke.targetPath} ` +
				`with ${runtimeSmoke.policyPath}; policy status ${runtimeSmoke.policyStatus}.`,
			evidencePaths: [runtimeSmoke.policyPath],
			recommendation:
				"Attach this Action job summary to the policy promotion evidence.",
		};
	});
}
