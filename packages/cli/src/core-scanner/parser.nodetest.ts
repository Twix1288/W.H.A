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
});
