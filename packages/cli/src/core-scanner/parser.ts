import { createHash } from "node:crypto";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import Parser from "tree-sitter";
import Bash from "tree-sitter-bash";
import JavaScript from "tree-sitter-javascript";
import Python from "tree-sitter-python";
import Rust from "tree-sitter-rust";
import TypeScript from "tree-sitter-typescript";

export type ParseResult =
	| { type: "ast"; tree: Parser.Tree; source: string; parser: Parser }
	| { type: "text"; lines: string[]; source: string };

// Single source of truth for which extensions have a real grammar, so parsing
// and AST fingerprinting never drift.
const GRAMMARS: Record<string, unknown> = {
	".py": Python,
	".js": JavaScript,
	".jsx": JavaScript,
	".mjs": JavaScript,
	".cjs": JavaScript,
	".ts": (TypeScript as any).typescript || TypeScript,
	".tsx":
		(TypeScript as any).tsx || (TypeScript as any).typescript || TypeScript,
	".sh": Bash,
	".bash": Bash,
	".rs": Rust,
};

export function grammarForExt(ext: string): unknown | null {
	return GRAMMARS[ext.toLowerCase()] ?? null;
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
// the parse tree's named nodes (types + leaf token text) while ignoring comments
// and all whitespace/formatting. Two files that differ only in comments or
// formatting produce the SAME hash; any semantic change (a renamed identifier, a
// changed literal, an added call) produces a DIFFERENT hash. This is what lets a
// golden snapshot detect that a tool's behavior changed after it was scanned.

function isCommentType(type: string): boolean {
	return (
		type === "comment" || type === "line_comment" || type === "block_comment"
	);
}

function canonicalize(node: Parser.SyntaxNode): string {
	const named: Parser.SyntaxNode[] = [];
	for (let i = 0; i < node.namedChildCount; i++) {
		const child = node.namedChild(i);
		if (child && !isCommentType(child.type)) named.push(child);
	}
	if (named.length === 0) {
		// Leaf: include the token text so identifiers and literals affect the hash
		// (a renamed variable or changed string is a real, security-relevant change).
		return `${node.type}=${node.text}`;
	}
	return `${node.type}(${named.map(canonicalize).join(",")})`;
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
	const canonical = canonicalize(tree.rootNode);
	return `sha256-ast:${createHash("sha256").update(canonical).digest("hex")}`;
}
