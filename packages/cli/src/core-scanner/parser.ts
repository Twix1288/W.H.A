import { createHash } from "node:crypto";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import Parser from "tree-sitter";

export type ParseResult =
	| { type: "ast"; tree: Parser.Tree; source: string; parser: Parser }
	| { type: "text"; lines: string[]; source: string };

// Single source of truth for which extensions have a real grammar, so parsing
// and AST fingerprinting never drift.
//
// LAZY: each grammar is a native module. Loading all five eagerly cost ~21ms on
// every process start, which `guard` pays on EVERY tool call while needing at most
// one of them. Grammars are now required on first use and cached.
declare const require: (id: string) => any;

const GRAMMAR_LOADERS: Record<string, () => unknown> = {
	".py": () => require("tree-sitter-python"),
	".js": () => require("tree-sitter-javascript"),
	".jsx": () => require("tree-sitter-javascript"),
	".mjs": () => require("tree-sitter-javascript"),
	".cjs": () => require("tree-sitter-javascript"),
	".ts": () => {
		const m = require("tree-sitter-typescript");
		return m.typescript || m;
	},
	".tsx": () => {
		const m = require("tree-sitter-typescript");
		return m.tsx || m.typescript || m;
	},
	".sh": () => require("tree-sitter-bash"),
	".bash": () => require("tree-sitter-bash"),
	".rs": () => require("tree-sitter-rust"),
};

const grammarCache = new Map<string, unknown>();

export function grammarForExt(ext: string): unknown | null {
	const key = ext.toLowerCase();
	const loader = GRAMMAR_LOADERS[key];
	if (!loader) return null;
	const cached = grammarCache.get(key);
	if (cached !== undefined) return cached;
	const grammar = loader();
	grammarCache.set(key, grammar);
	return grammar;
}

/** Extensions with a real grammar, without loading any of them. */
export function supportedGrammarExts(): ReadonlyArray<string> {
	return Object.keys(GRAMMAR_LOADERS);
}

// Stable, human-readable grammar identity used to domain-separate fingerprints.
// Extensions that share a grammar (.js/.jsx/.mjs/.cjs) intentionally share an id;
// what must never collide is two DIFFERENT grammars over the same bytes.
const GRAMMAR_IDS: Record<string, string> = {
	".py": "python",
	".js": "javascript",
	".jsx": "javascript",
	".mjs": "javascript",
	".cjs": "javascript",
	".ts": "typescript",
	".tsx": "tsx",
	".sh": "bash",
	".bash": "bash",
	".rs": "rust",
};

export function grammarIdForExt(ext: string): string {
	return GRAMMAR_IDS[ext.toLowerCase()] ?? "unknown";
}

/** Parse a source string into a tree-sitter tree, or null if no grammar exists. */
export function parseSourceToTree(
	source: string,
	ext: string,
): Parser.Tree | null {
	const language = grammarForExt(ext);
	if (!language) return null;
	const parser = new Parser();
	parser.setLanguage(language as any);
	return parser.parse(source);
}

/**
 * Parse already-in-memory source into a ParseResult, without touching disk. Used
 * by the runtime `guard` hook, which analyzes the code a tool call is ABOUT to
 * run (from the hook payload, not a file). `parseFile` is this plus a read, so
 * both paths behave identically. Unknown extensions fall back to line-based text.
 */
export function parseSource(source: string, ext: string): ParseResult {
	const language = grammarForExt(ext);
	if (!language) {
		return { type: "text", lines: source.split("\n"), source };
	}
	const parser = new Parser();
	parser.setLanguage(language as any);
	const tree = parser.parse(source);
	return { type: "ast", tree, source, parser };
}

export async function parseFile(filePath: string): Promise<ParseResult> {
	const source = await fs.readFile(filePath, "utf-8");
	return parseSource(source, path.extname(filePath));
}

// ─── AST Fingerprint (Golden Snapshot) ────────────────────────────────
//
// A real structural hash of the code, NOT a hash of the raw text. It serializes
// the parse tree (node types + every token's text) while ignoring comments and
// all whitespace/formatting. Two files that differ only in comments or formatting
// produce the SAME hash; any semantic change (a renamed identifier, a changed
// literal, an added call, a FLIPPED OPERATOR) produces a DIFFERENT hash. This is
// what lets a golden snapshot detect that a tool's behavior changed after it was
// scanned.
//
// IMPORTANT (was a critical bypass): tree-sitter models operators as ANONYMOUS
// tokens — `and`, `or`, `==`, `!=`, `&&`, `+` are not "named" nodes. Walking only
// namedChild() therefore dropped every operator from the canonical form, so
// `u == "admin" and p == "secret"` and the same line with `or` hashed IDENTICALLY.
// Flipping a boolean or comparison operator is the canonical way to invert an auth
// check, so the fingerprint was blind to the single most security-relevant edit an
// attacker can make. We now walk ALL children and include anonymous token text.
// Whitespace is not tokenized by tree-sitter, so format-insensitivity is preserved;
// comments are dropped explicitly below.

function isCommentType(type: string): boolean {
	return (
		type === "comment" || type === "line_comment" || type === "block_comment"
	);
}

function canonicalize(node: Parser.SyntaxNode): string {
	// Walk ALL children, not just named ones: operators and other structural
	// punctuation are anonymous tokens and MUST contribute to the fingerprint.
	const children: Parser.SyntaxNode[] = [];
	for (let i = 0; i < node.childCount; i++) {
		const child = node.child(i);
		if (child && !isCommentType(child.type)) children.push(child);
	}
	if (children.length === 0) {
		// Leaf: include the token text so identifiers, literals AND operators affect
		// the hash. For an anonymous operator token, `type` already is the operator
		// text (e.g. type "and", text "and"); emitting both is redundant but keeps a
		// single unambiguous encoding for every leaf.
		return `${node.type}=${node.text}`;
	}
	return `${node.type}(${children.map(canonicalize).join(",")})`;
}

/**
 * Computes the golden-snapshot fingerprint of a source file.
 *
 * Returns `sha256-ast:<hex>` for languages with a grammar (structural hash), or
 * `sha256-text:<hex>` for unsupported extensions (normalized-text fallback so the
 * snapshot still detects byte changes — just not formatting-insensitive). The
 * prefix makes the algorithm explicit and prevents an AST hash from ever being
 * compared against a text hash.
 */
export function astFingerprint(source: string, ext: string): string {
	const tree = parseSourceToTree(source, ext);
	if (!tree) {
		const normalized = source.replace(/\r\n/g, "\n");
		return `sha256-text:${createHash("sha256").update(normalized).digest("hex")}`;
	}
	// Bind the digest to the grammar the tree was produced with. `run` picks an
	// interpreter by extension, so a fingerprint taken under one grammar must never
	// validate bytes that will be executed under another.
	const canonical = `${grammarIdForExt(ext)}\u0000${canonicalize(tree.rootNode)}`;
	return `sha256-ast:${createHash("sha256").update(canonical).digest("hex")}`;
}
