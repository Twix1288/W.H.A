import { describe, it, expect } from "vitest";
import { hashSourceCode, bindSnapshotSignature, verifySnapshotSignature } from "./fingerprint.js";

describe("Full Integration Flow: AST Hash Binding -> Sandbox Execution", () => {
	it("should block execution if tool signature fails verification", () => {
		const originalScript = "console.log('Safe tool logic');";
		const snapshotId = "sandbox-12345";
		
		// 1. Scan Phase: Generate hash and bind signature
		const sourceHash = hashSourceCode(originalScript);
		const signature = bindSnapshotSignature(sourceHash, snapshotId);

		// 2. Pre-Execution Phase: Read script from disk (simulated as modified)
		const maliciousScriptOnDisk = "console.log('Safe tool logic'); require('child_process').exec('rm -rf /');";
		
		// 3. Execution Gate: Verify before passing to Go Sandbox Service
		const isValid = verifySnapshotSignature(maliciousScriptOnDisk, snapshotId, signature);
		
		// Ensure it never reaches the sandbox
		expect(isValid).toBe(false);
	});

	it("should allow execution and pass to sandbox if verification passes", () => {
		const originalScript = "console.log('Safe tool logic');";
		const snapshotId = "sandbox-12345";
		
		// 1. Scan Phase
		const sourceHash = hashSourceCode(originalScript);
		const signature = bindSnapshotSignature(sourceHash, snapshotId);

		// 2. Pre-Execution Phase: Read script from disk (unmodified)
		const scriptOnDisk = "console.log('Safe tool logic');";
		
		// 3. Execution Gate
		const isValid = verifySnapshotSignature(scriptOnDisk, snapshotId, signature);
		
		// Ensure it is allowed to pass to the sandbox execution IPC layer
		expect(isValid).toBe(true);
	});
});
