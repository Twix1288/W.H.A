import type { BaselineComparison, GateResult } from "./baseline/index.js";

export type ActionBaselineStatus =
  | "not-run"
  | "missing"
  | "passed"
  | "failed";

export function statusForBaselineGate(result: GateResult): ActionBaselineStatus {
  return result.passed ? "passed" : "failed";
}

export function renderBaselineJobSummary(
  comparison: BaselineComparison,
  gateResult: GateResult
): string {
  const status = statusForBaselineGate(gateResult);
  const lines = [
    "",
    "",
    "## W.H.Agent Baseline Drift",
    "",
    `- Status: ${status}`,
    `- Baseline timestamp: ${comparison.baselineTimestamp}`,
    `- Score: ${comparison.baselineScore} -> ${comparison.currentScore} (${formatScoreDelta(comparison.scoreDelta)})`,
    `- New findings: ${comparison.newFindings.length}`,
    `- Resolved findings: ${comparison.resolvedFindings.length}`,
    `- Unchanged findings: ${comparison.unchangedCount}`,
    `- New critical findings: ${comparison.newCriticalCount}`,
    `- New high findings: ${comparison.newHighCount}`,
  ];

  if (gateResult.reasons.length > 0) {
    lines.push("", "### Gate Reasons", "");
    for (const reason of gateResult.reasons) {
      lines.push(`- ${reason}`);
    }
  }

  if (comparison.newFindings.length > 0) {
    lines.push("", "### New Findings", "");
    for (const finding of comparison.newFindings.slice(0, 20)) {
      lines.push(
        `- ${finding.severity}: ${finding.title} (${finding.file})`
      );
    }
    if (comparison.newFindings.length > 20) {
      lines.push(`- ...${comparison.newFindings.length - 20} more`);
    }
  }

  if (comparison.resolvedFindings.length > 0) {
    lines.push("", "### Resolved Findings", "");
    for (const finding of comparison.resolvedFindings.slice(0, 20)) {
      lines.push(`- ${finding.severity}: ${finding.title} (${finding.file})`);
    }
    if (comparison.resolvedFindings.length > 20) {
      lines.push(`- ...${comparison.resolvedFindings.length - 20} more`);
    }
  }

  lines.push("");
  return lines.join("\n");
}

export function renderMissingBaselineJobSummary(baselinePath: string): string {
  return [
    "",
    "",
    "## W.H.Agent Baseline Drift",
    "",
    "- Status: missing",
    `- Baseline path: ${baselinePath}`,
    "- Comparison skipped because the baseline file could not be loaded.",
    "",
  ].join("\n");
}

function formatScoreDelta(delta: number): string {
  return delta > 0 ? `+${delta}` : String(delta);
}
