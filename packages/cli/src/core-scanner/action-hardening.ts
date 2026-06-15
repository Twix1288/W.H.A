import type { Finding, Severity } from "./types.js";

export type PackageManagerHardeningStatus = "hardened" | "needs-review";

export interface PackageManagerHardeningSummary {
	readonly status: PackageManagerHardeningStatus;
	readonly findings: ReadonlyArray<Finding>;
	readonly totalFindings: number;
	readonly criticalCount: number;
	readonly highCount: number;
	readonly registryCredentialCount: number;
	readonly lifecycleScriptCount: number;
	readonly releaseAgeGateCount: number;
}

function isPackageManagerHardeningFinding(finding: Finding): boolean {
	return finding.id.startsWith("package-manager-");
}

function countSeverity(
	findings: ReadonlyArray<Finding>,
	severity: Severity,
): number {
	return findings.filter((finding) => finding.severity === severity).length;
}

function countByIdFragment(
	findings: ReadonlyArray<Finding>,
	fragments: ReadonlyArray<string>,
): number {
	return findings.filter((finding) =>
		fragments.some((fragment) => finding.id.includes(fragment)),
	).length;
}

export function summarizePackageManagerHardening(
	findings: ReadonlyArray<Finding>,
): PackageManagerHardeningSummary {
	const hardeningFindings = findings.filter(isPackageManagerHardeningFinding);

	return {
		status: hardeningFindings.length > 0 ? "needs-review" : "hardened",
		findings: hardeningFindings,
		totalFindings: hardeningFindings.length,
		criticalCount: countSeverity(hardeningFindings, "critical"),
		highCount: countSeverity(hardeningFindings, "high"),
		registryCredentialCount: countByIdFragment(hardeningFindings, [
			"registry-credential",
		]),
		lifecycleScriptCount: countByIdFragment(hardeningFindings, [
			"lifecycle-scripts",
			"dangerously-allow-all-builds",
			"strict-dep-builds",
		]),
		releaseAgeGateCount: countByIdFragment(hardeningFindings, [
			"release-age-gate",
		]),
	};
}

export function renderPackageManagerHardeningJobSummary(
	summary: PackageManagerHardeningSummary,
): string {
	const lines = [
		"",
		"",
		"## W.H.Agent Package Manager Hardening",
		"",
		`- Status: ${summary.status}`,
		`- Findings: ${summary.totalFindings}`,
		`- Critical findings: ${summary.criticalCount}`,
		`- High findings: ${summary.highCount}`,
		`- Registry credential findings: ${summary.registryCredentialCount}`,
		`- Lifecycle script findings: ${summary.lifecycleScriptCount}`,
		`- Release-age gate findings: ${summary.releaseAgeGateCount}`,
	];

	if (summary.findings.length > 0) {
		lines.push("", "### Findings", "");
		for (const finding of summary.findings.slice(0, 20)) {
			const location = finding.line
				? `${finding.file}:${finding.line}`
				: finding.file;
			lines.push(
				`- ${finding.id} (${finding.severity}) ${location}: ${finding.title}`,
			);
		}

		if (summary.findings.length > 20) {
			lines.push(
				`- ${summary.findings.length - 20} additional finding(s) omitted`,
			);
		}
	}

	lines.push("");
	return lines.join("\n");
}
