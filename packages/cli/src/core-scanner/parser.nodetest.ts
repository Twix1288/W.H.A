// Runs under NODE (via `tsx --test`), not bun: tree-sitter ships native (.node)
// bindings that bun's node-gyp-build resolution can't load, but node loads them
// fine — and node is the CLI's actual runtime. These are real, executed tests.
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { astFingerprint } from "./parser.ts";

describe("astFingerprint (Golden Snapshot AST hash)", () => {
	test("is a real AST hash: insensitive to formatting/whitespace", () => {
		const a = astFingerprint(`def f(x):\n    return x+1\n`, ".py");
		const b = astFingerprint(`def   f( x ):\n        return    x + 1\n`, ".py");
		assert.equal(a, b);
		assert.ok(a.startsWith("sha256-ast:"));
	});

	test("is insensitive to added/changed comments", () => {
		const a = astFingerprint(`x = get_secret()\nsend(x)\n`, ".py");
		const b = astFingerprint(
			`# a comment\nx = get_secret()  # inline\nsend(x)\n`,
			".py",
		);
		assert.equal(a, b);
	});

	test("is sensitive to a changed identifier (semantic change)", () => {
		assert.notEqual(
			astFingerprint(`send(secret)\n`, ".py"),
			astFingerprint(`send(other)\n`, ".py"),
		);
	});

	test("is sensitive to a changed literal", () => {
		const a = astFingerprint(`url = "https://good.example"\n`, ".py");
		const b = astFingerprint(`url = "https://evil.example"\n`, ".py");
		assert.notEqual(a, b);
	});

	test("is sensitive to an added call (behavior change)", () => {
		assert.notEqual(
			astFingerprint(`print("hi")\n`, ".py"),
			astFingerprint(`print("hi")\nexfiltrate()\n`, ".py"),
		);
	});

	test("works for every claimed language and yields an AST hash", () => {
		for (const [src, ext] of [
			[`console.log("hi")`, ".js"],
			[`const x: number = 1`, ".ts"],
			[`echo hi`, ".sh"],
			[`fn main() { println!("hi"); }`, ".rs"],
		] as const) {
			assert.ok(
				astFingerprint(src, ext).startsWith("sha256-ast:"),
				`${ext} should hash as AST`,
			);
		}
	});

	test("falls back to a text hash (distinct prefix) for unknown extensions", () => {
		assert.ok(
			astFingerprint(`whatever content`, ".unknown").startsWith("sha256-text:"),
		);
	});

	test("an AST hash can never equal a text hash for the same bytes", () => {
		assert.notEqual(
			astFingerprint(`x = 1\n`, ".py"),
			astFingerprint(`x = 1\n`, ".unknown"),
		);
	});

	// ─── Operator sensitivity ────────────────────────────────────────────
	// Regression tests for a critical Golden Snapshot bypass: tree-sitter models
	// operators as ANONYMOUS tokens, so a canonicalizer that walks only named
	// children drops every operator. `and` -> `or` and `==` -> `!=` are the two
	// canonical ways to invert an auth check, and both produced an IDENTICAL
	// fingerprint, defeating `run --ast-hash` entirely.

	test("is sensitive to a flipped boolean operator (and -> or)", () => {
		const a = astFingerprint(
			`def check(u, p):\n    return u == "admin" and p == "secret"\n`,
			".py",
		);
		const b = astFingerprint(
			`def check(u, p):\n    return u == "admin" or p == "secret"\n`,
			".py",
		);
		assert.notEqual(a, b, "and/or must not share a fingerprint");
	});

	test("is sensitive to a flipped comparison operator (== -> !=)", () => {
		assert.notEqual(
			astFingerprint(`if user == "admin":\n    grant()\n`, ".py"),
			astFingerprint(`if user != "admin":\n    grant()\n`, ".py"),
		);
	});

	test("is sensitive to a negated condition (not)", () => {
		assert.notEqual(
			astFingerprint(`if authorized(u):\n    grant()\n`, ".py"),
			astFingerprint(`if not authorized(u):\n    grant()\n`, ".py"),
		);
	});

	test("is sensitive to arithmetic and comparison operator swaps", () => {
		assert.notEqual(
			astFingerprint(`limit = base + delta\n`, ".py"),
			astFingerprint(`limit = base - delta\n`, ".py"),
		);
		assert.notEqual(
			astFingerprint(`if n < max_retries:\n    retry()\n`, ".py"),
			astFingerprint(`if n > max_retries:\n    retry()\n`, ".py"),
		);
	});

	test("operator sensitivity holds in every supported language", () => {
		const cases: ReadonlyArray<readonly [string, string, string]> = [
			[".js", `if (a === b) { grant(); }`, `if (a !== b) { grant(); }`],
			[".ts", `const ok: boolean = a && b;`, `const ok: boolean = a || b;`],
			[".sh", `if [ "$a" = "$b" ]; then grant; fi`, `if [ "$a" != "$b" ]; then grant; fi`],
			[".rs", `fn f(a: i32, b: i32) -> bool { a == b }`, `fn f(a: i32, b: i32) -> bool { a != b }`],
		];
		for (const [ext, x, y] of cases) {
			assert.notEqual(
				astFingerprint(x, ext),
				astFingerprint(y, ext),
				`${ext}: operator swap must change the fingerprint`,
			);
		}
	});

	test("the same bytes under different grammars never share a fingerprint", () => {
		// `run` dispatches by extension; a fingerprint taken with one grammar must
		// never validate a file executed under another interpreter.
		assert.notEqual(
			astFingerprint(`x = 1\n`, ".py"),
			astFingerprint(`x = 1\n`, ".sh"),
		);
	});

	test("still ignores comments now that anonymous tokens are hashed", () => {
		assert.equal(
			astFingerprint(`a = b and c\n`, ".py"),
			astFingerprint(`# lead\na = b and c  # trail\n`, ".py"),
		);
		assert.equal(
			astFingerprint(`const x = a && b;`, ".js"),
			astFingerprint(`/* lead */\nconst x = a && b; // trail`, ".js"),
		);
	});
});
