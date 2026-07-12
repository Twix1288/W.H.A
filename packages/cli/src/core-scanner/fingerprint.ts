import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
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

// 1. Secret Scope: Process-lifetime memory only. Never logged, never written to disk.
let sessionSecret: Buffer | null = null;

function initSessionSecret(): void {
	if (!sessionSecret) {
		sessionSecret = randomBytes(32);
	}
}

/**
 * Binds the verified AST source hash to the generated snapshot ID.
 * This ensures that a given snapshot can only be used if the underlying source code hasn't changed.
 */
export function bindSnapshotSignature(sourceHash: string, snapshotId: string): string {
	if (!sessionSecret) initSessionSecret();
	
	// 2. Binding: Single MAC input combining both variables securely
	const payload = `${sourceHash}::${snapshotId}`;
	const signature = createHmac("sha256", sessionSecret!).update(payload).digest("hex");
	return `v1::hmac::${signature}`;
}

/**
 * Verifies that the live on-disk tool still matches the source hash that was used to create the snapshot.
 * Returns true if the signature is valid, preventing tampered scripts from bypassing the AST scan.
 */
export function verifySnapshotSignature(currentSourceCode: string, snapshotId: string, boundSignature: string): boolean {
	if (!sessionSecret) return false;
	
	const currentSourceHash = hashSourceCode(currentSourceCode);
	const expectedSignature = bindSnapshotSignature(currentSourceHash, snapshotId);
	
	// 3. Comparison: Constant-time equality check
	const expectedBuf = Buffer.from(expectedSignature);
	const boundBuf = Buffer.from(boundSignature);
	
	if (expectedBuf.length !== boundBuf.length) return false;
	return timingSafeEqual(expectedBuf, boundBuf);
}
