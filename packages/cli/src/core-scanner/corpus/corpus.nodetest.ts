// Runs under `tsx --test`.
//
// WHY THIS FILE EXISTS
// --------------------
// The repo shipped a 565-line corpus of deliberately vulnerable agent configs
// (`vulnerable-configs.ts`) together with a full validation harness
// (`validateCorpus`, `evaluateCorpusGate`) — and NOTHING invoked either one. The
// corpus's only importer was `core-scanner/index.ts`, which is dead code, so no
// test and no CI job ever asserted that the scanner still detects the things it
// was built to detect.
//
// For a security scanner that is the load-bearing test: a detection regression is
// silent by nature. Every rule can quietly stop matching and the whole suite stays
// green, because the other tests assert plumbing rather than detection.
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { getBuiltinRules } from "../rules/index.ts";
import {
	defaultRuleScanFn,
	evaluateCorpusGate,
	validateCorpus,
	vulnerableConfigs,
} from "./index.ts";

describe("vulnerable-config corpus (detection regression gate)", () => {
	test("the corpus is non-empty and well-formed", () => {
		assert.ok(vulnerableConfigs.length > 0, "corpus must not be empty");
		for (const c of vulnerableConfigs) {
			assert.ok(c.id, "every config needs an id");
			assert.ok(c.files.length > 0, `${c.id}: needs at least one file`);
			assert.ok(
				c.expectedFindings.length > 0,
				`${c.id}: needs at least one expected finding, or it asserts nothing`,
			);
		}
	});

	test("config ids are unique", () => {
		const ids = vulnerableConfigs.map((c) => c.id);
		assert.equal(new Set(ids).size, ids.length, "duplicate corpus config ids");
	});

	test("every corpus config is detected by the shipped rules", () => {
		const validation = validateCorpus(defaultRuleScanFn, getBuiltinRules());
		const gate = evaluateCorpusGate(validation);

		if (!gate.passed) {
			const detail = validation.results
				.filter((r) => !r.passed)
				.map(
					(r) =>
						`  - ${r.configId} (${r.category}): missing rules [${r.missingRules.join(", ")}]` +
						` expected ${r.expectedFindings} finding(s), got ${r.actualFindings}`,
				)
				.join("\n");
			assert.fail(
				`Detection regression — ${validation.failed}/${validation.totalConfigs} corpus configs ` +
					`no longer trip their rules (detection rate ${(validation.detectionRate * 100).toFixed(1)}%):\n${detail}`,
			);
		}
		assert.equal(validation.failed, 0);
		assert.ok(validation.readyForRegressionGate);
	});

	test("detection rate is reported per category", () => {
		const validation = validateCorpus(defaultRuleScanFn, getBuiltinRules());
		assert.ok(validation.categoryBreakdown.length > 0);
		for (const cat of validation.categoryBreakdown) {
			assert.ok(
				cat.detectionRate >= 0 && cat.detectionRate <= 1,
				`${cat.category}: detection rate out of range`,
			);
		}
	});
});
