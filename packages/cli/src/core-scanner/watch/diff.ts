import { fingerprintFinding } from "../fingerprint.js";
import type { Finding, SecurityScore } from "../types.js";
import type { ScanBaseline, DriftResult } from "./types.js";

export { fingerprintFinding } from "../fingerprint.js";

/**
 * Create a baseline snapshot from a scan result.
 */
export function createBaseline(
  findings: ReadonlyArray<Finding>,
  score: SecurityScore
): ScanBaseline {
  const findingIds = new Set(findings.map(fingerprintFinding));
  return {
    timestamp: new Date().toISOString(),
    score,
    findings,
    findingIds,
  };
}

/**
 * Diff current scan results against a baseline to detect drift.
 * Returns new findings, resolved findings, and score delta.
 */
export function diffBaseline(
  baseline: ScanBaseline,
  currentFindings: ReadonlyArray<Finding>,
  currentScore: SecurityScore
): DriftResult {
  const currentIds = new Set(currentFindings.map(fingerprintFinding));

  const newFindings = currentFindings.filter(
    (f) => !baseline.findingIds.has(fingerprintFinding(f))
  );

  const resolvedFindings = baseline.findings.filter(
    (f) => !currentIds.has(fingerprintFinding(f))
  );

  const scoreDelta =
    currentScore.numericScore - baseline.score.numericScore;

  const hasCritical = newFindings.some((f) => f.severity === "critical");
  const isRegression = newFindings.length > 0 || scoreDelta < 0;

  return {
    timestamp: new Date().toISOString(),
    newFindings,
    resolvedFindings,
    scoreDelta,
    previousScore: baseline.score.numericScore,
    currentScore: currentScore.numericScore,
    isRegression,
    hasCritical,
  };
}
