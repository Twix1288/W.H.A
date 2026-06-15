import { createHash } from "node:crypto";
import type { Finding } from "./types.js";

type FingerprintFinding = Pick<Finding, "id" | "file" | "evidence">;

export function fingerprintFinding(finding: FingerprintFinding): string {
  return `${finding.id}::${finding.file}::${evidenceFingerprint(finding.evidence)}`;
}

export function legacyEvidenceFingerprint(finding: FingerprintFinding): string {
  return `${finding.id}::${finding.file}::${finding.evidence ?? ""}`;
}

function evidenceFingerprint(evidence: string | undefined): string {
  if (!evidence) {
    return "sha256:no-evidence";
  }

  return `sha256:${createHash("sha256").update(evidence).digest("hex").slice(0, 16)}`;
}
