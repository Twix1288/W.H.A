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

// --- Golden Snapshot Hash Binding ---

/**
 * Computes a deterministic hash of the tool's source code exactly as it was scanned.
 */
export function hashSourceCode(sourceCode: string): string {
	return `sha256:${createHash("sha256").update(sourceCode).digest("hex")}`;
}

/**
 * Binds the verified AST source hash to the generated snapshot ID.
 * This ensures that a given snapshot can only be used if the underlying source code hasn't changed.
 */
export function bindSnapshotSignature(sourceHash: string, snapshotId: string): string {
	// In production, this might use HMAC with a local machine key to prevent signature spoofing.
	// For now, we bind the two identities together cryptographically.
	const payload = `${sourceHash}::${snapshotId}`;
	const signature = createHash("sha256").update(payload).digest("hex");
	return `v1::${signature}`;
}

/**
 * Verifies that the live on-disk tool still matches the source hash that was used to create the snapshot.
 * Returns true if the signature is valid, preventing tampered scripts from bypassing the AST scan.
 */
export function verifySnapshotSignature(currentSourceCode: string, snapshotId: string, boundSignature: string): boolean {
	const currentSourceHash = hashSourceCode(currentSourceCode);
	const expectedSignature = bindSnapshotSignature(currentSourceHash, snapshotId);
	return expectedSignature === boundSignature;
}
