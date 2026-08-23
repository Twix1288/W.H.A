// Regression tests for the `install` supply-chain gate.
//
// Each case below corresponds to a defect found in the production-readiness
// audit. These are the pure helpers; the network-dependent flow is covered by the
// e2e suite.
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import popularPackages from "./popular-packages.json" with { type: "json" };
import {
	checkTyposquat,
	isVendorBundle,
	normalizeRegistry,
	SCANNABLE_SOURCE_RE,
} from "./install.ts";

describe("install: typosquat gate", () => {
	test("a package on the popular list is never flagged as a typosquat", () => {
		// The gate hard-blocked 66 of the 304 packages on its OWN reference list —
		// express, vue, redis, zod, next, jest, cors, mysql. A supply-chain gate that
		// refuses the most popular packages on npm gets switched off, and a gate
		// nobody runs protects nobody.
		const flagged = (popularPackages as string[]).filter(
			(p) => checkTyposquat(p).risky,
		);
		assert.deepEqual(
			flagged,
			[],
			`${flagged.length} popular packages are self-flagged as typosquats: ${flagged.slice(0, 12).join(", ")}`,
		);
	});

	test("real typosquats are still caught", () => {
		for (const name of ["expresss", "lodahs", "reqeust", "raect", "axios2"]) {
			const r = checkTyposquat(name);
			assert.ok(r.risky, `${name} should be flagged as a typosquat`);
			assert.ok(r.similarTo.length > 0, `${name} should name what it resembles`);
		}
	});

	test("short names use a tighter edit distance (1, not 2)", () => {
		// A single edit on a short popular name IS a typosquat signal and stays
		// flagged (`qq` for `qs`/`q`, `vuex` for `vue`). What the shorter budget
		// prevents is flagging a 2-edit difference, where a 4-character name has
		// diverged too far to be a plausible typo.
		assert.ok(checkTyposquat("qq").risky, "one edit from a short name is a squat");
		assert.equal(
			checkTyposquat("zzz").risky,
			false,
			"two edits from any short popular name is too far to be a typo",
		);
	});

	test("legitimate near-miss packages are allowlisted", () => {
		// These are real, widely-used packages that sit within an edit of a popular
		// name. Without the allowlist the gate makes them permanently uninstallable.
		for (const name of ["preact", "ms", "chai", "vite"]) {
			assert.equal(
				checkTyposquat(name).risky,
				false,
				`${name} is legitimate and must not be blocked`,
			);
		}
	});

	test("an unrelated name is not flagged", () => {
		for (const name of [
			"my-internal-company-utils",
			"@acme/design-system",
			"totally-unique-name-xyz",
		]) {
			assert.equal(
				checkTyposquat(name).risky,
				false,
				`${name} should not be flagged`,
			);
		}
	});
});

describe("install: registry URL handling", () => {
	test("defaults to public npm", () => {
		assert.equal(normalizeRegistry(undefined), "https://registry.npmjs.org");
	});

	test("accepts a custom https registry and strips a trailing slash", () => {
		assert.equal(
			normalizeRegistry("https://npm.internal.example.com/"),
			"https://npm.internal.example.com",
		);
	});

	test("rejects a non-http(s) protocol", () => {
		for (const bad of ["ftp://x", "file:///etc/passwd", "javascript:alert(1)"]) {
			assert.throws(
				() => normalizeRegistry(bad),
				/Unsupported --registry-url protocol|Invalid --registry-url/,
				`${bad} should be rejected`,
			);
		}
	});

	test("rejects a malformed URL", () => {
		assert.throws(() => normalizeRegistry("not a url"), /Invalid --registry-url/);
	});
});

describe("install: source scan coverage", () => {
	test("ESM, CJS, JSX and TSX files are scanned", () => {
		// The filter was /\.(js|ts|json)$/ with NO `i` flag, so a malicious ESM
		// package was reported "clean".
		for (const f of [
			"a.js",
			"a.mjs",
			"a.cjs",
			"a.jsx",
			"a.ts",
			"a.tsx",
			"a.cts",
			"a.mts",
			"a.json",
			"a.JS",
			"a.MJS",
		]) {
			assert.ok(SCANNABLE_SOURCE_RE.test(f), `${f} must be scanned`);
		}
	});

	test("non-source files are not scanned", () => {
		for (const f of ["a.png", "a.md", "a.txt", "README", "a.wasm"]) {
			assert.equal(SCANNABLE_SOURCE_RE.test(f), false, `${f} should be skipped`);
		}
	});
});

describe("install: vendored/minified classification", () => {
	test("bundled output paths are recognised", () => {
		for (const p of [
			"dist/compiled/webpack/bundle5.js",
			"build/main.js",
			"vendor/thing.js",
			"lib/app.min.js",
			"esm/index.js",
		]) {
			assert.ok(isVendorBundle(p, "short content"), `${p} should be vendored`);
		}
	});

	test("a single enormous line is treated as minified", () => {
		assert.ok(isVendorBundle("src/app.js", `const x=${"a".repeat(6000)};`));
	});

	test("ordinary authored source is NOT treated as vendored", () => {
		const src = ["export function add(a, b) {", "  return a + b;", "}", ""].join("\n");
		assert.equal(isVendorBundle("src/math.js", src), false);
		assert.equal(isVendorBundle("index.js", src), false);
	});
});
