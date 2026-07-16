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

	test("JSON-v2 and SARIF report taint status; Python is now fully supported", () => {
		const pythonFile = path.join(scratchDir, "pysupported.py");
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
		const pyStatus = jsonContent.files_status.find((s: any) => s.file.includes("pysupported.py"));
		const jsStatus = jsonContent.files_status.find((s: any) => s.file.includes("supported.js"));

		// Python now has real taint tracking (parity with JS/TS), and every file
		// carries a golden-snapshot AST hash.
		expect(pyStatus.status).toBe("scanned_full");
		expect(jsStatus.status).toBe("scanned_full");
		expect(pyStatus.ast_hash).toMatch(/^sha256-ast:/);

		const sarifOutFile = path.join(scratchDir, "out.sarif");

		// Run check using SARIF format
		spawnSync(
			"node",
			[cliPath, "check", pythonFile, jsFile, "--format", "sarif", "--output", sarifOutFile],
			{ encoding: "utf-8" }
		);

		const sarifContent = JSON.parse(fs.readFileSync(sarifOutFile, "utf-8"));

		const artifacts = sarifContent.runs[0].artifacts;
		const pyArtifact = artifacts.find((a: any) => a.location.uri.includes("pysupported.py"));
		const jsArtifact = artifacts.find((a: any) => a.location.uri.includes("supported.js"));

		expect(pyArtifact.properties.status).toBe("scanned_full");
		expect(jsArtifact.properties.status).toBe("scanned_full");
		expect(pyArtifact.properties.astHash).toMatch(/^sha256-ast:/);
	});

	test("Golden Snapshot: run blocks when the pinned --ast-hash no longer matches", () => {
		// Runs the real CLI in a node subprocess (where tree-sitter loads). The
		// block happens at the AST-hash gate, before the sandbox is ever launched,
		// so this holds even without the sandbox binary present.
		const target = path.join(scratchDir, "pinned.py");
		fs.writeFileSync(target, "print('the originally-scanned tool')");

		const result = spawnSync(
			"node",
			[cliPath, "run", target, "--experimental", "--ast-hash", "sha256-ast:deadbeefdeadbeef"],
			{ encoding: "utf-8" }
		);

		const out = (result.stdout || "") + (result.stderr || "");
		expect(out).toContain("SECURITY VIOLATION");
		expect(out).toContain("changed after it was scanned");
		// It must NOT have reached execution.
		expect(out).not.toContain("SANDBOX STDOUT");
		expect(result.status).not.toBe(0);
	});

	test("Golden Snapshot: run proceeds when the pinned --ast-hash matches", () => {
		const target = path.join(scratchDir, "matching.py");
		fs.writeFileSync(target, "print('trusted tool')");

		// Obtain the real AST hash via `check`.
		const jsonOut = path.join(scratchDir, "match.json");
		spawnSync("node", [cliPath, "check", target, "--format", "json-v2", "--output", jsonOut], {
			encoding: "utf-8",
		});
		const hash = JSON.parse(fs.readFileSync(jsonOut, "utf-8")).files_status[0].ast_hash;
		expect(hash).toMatch(/^sha256-ast:/);

		const result = spawnSync(
			"node",
			[cliPath, "run", target, "--experimental", "--ast-hash", hash],
			{ encoding: "utf-8" }
		);
		const out = (result.stdout || "") + (result.stderr || "");
		// The AST-hash gate must pass (no violation); it then proceeds to the sandbox.
		expect(out).not.toContain("SECURITY VIOLATION");
		expect(out).toContain(hash);
	});
});
