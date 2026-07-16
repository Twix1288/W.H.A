import * as path from "node:path";
import type { TaintFlow, TaintNode, TaintResult } from "../types.js";
import { analyzeTaint as analyzeJsTsTaint } from "./analyzer.js";
import { analyzePolyglotTaint } from "./polyglot.js";

const TS_COMPILER_LANGS = [".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"];
const POLYGLOT_LANGS = [".py", ".sh", ".bash", ".rs"];

// Taint dataflow is supported for JS/TS (TypeScript-compiler analyzer) and for
// Python/Bash/Rust (tree-sitter polyglot analyzer).
export function isTaintSupported(filePath: string): boolean {
	const lower = filePath.toLowerCase();
	return [...TS_COMPILER_LANGS, ...POLYGLOT_LANGS].some((ext) =>
		lower.endsWith(ext),
	);
}

export function isTsCompilerLang(filePath: string): boolean {
	const lower = filePath.toLowerCase();
	return TS_COMPILER_LANGS.some((ext) => lower.endsWith(ext));
}

/**
 * Analyze files for source→sink taint flows across all supported languages.
 * JS/TS use the TypeScript-compiler analyzer; Python/Bash/Rust use the
 * tree-sitter polyglot analyzer. Results are merged into one TaintResult.
 */
export function analyzeTaint(
	files: ReadonlyArray<{ readonly path: string; readonly content: string }>,
): TaintResult {
	const jsTsFiles = files.filter((f) => isTsCompilerLang(f.path));
	const jsTsResult = analyzeJsTsTaint(jsTsFiles);

	const flows: TaintFlow[] = [...jsTsResult.flows];
	const sources: TaintNode[] = [...jsTsResult.sources];
	const sinks: TaintNode[] = [...jsTsResult.sinks];

	for (const file of files) {
		if (isTsCompilerLang(file.path)) continue;
		const poly = analyzePolyglotTaint(
			file.path,
			file.content,
			path.extname(file.path),
		);
		if (poly) {
			flows.push(...poly.flows);
			sources.push(...poly.sources);
			sinks.push(...poly.sinks);
		}
	}

	return { flows, sources, sinks };
}
