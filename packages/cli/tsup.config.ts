import { defineConfig } from "tsup";

export default defineConfig({
	entry: ["src/index.ts"],
	format: ["cjs"],
	minify: true,
	platform: "node",
	target: "node20",
	// chalk v5 is ESM-only ("type": "module"). Left as an external it emitted a
	// bare `require("chalk")` into the CJS bundle, which throws ERR_REQUIRE_ESM on
	// Node 20.0–20.18 — a range this package's `engines: ">=20"` explicitly claims
	// to support and which is still common in CI images. Every command died at
	// startup with a stack trace, and `guard` (a PreToolUse hook that signals its
	// verdict purely through stdout JSON) produced no verdict at all.
	//
	// Bundling chalk into the CJS output removes the require(ESM) boundary
	// entirely, so the declared engines range is honest again. The native
	// tree-sitter addons and the TypeScript compiler stay external — they cannot
	// be bundled and are loaded lazily at runtime.
	noExternal: ["chalk"],
});
