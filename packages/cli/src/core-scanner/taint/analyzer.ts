import * as ts from "typescript";
import type { Severity, TaintFlow, TaintNode, TaintResult } from "../types.js";

// Kept intentionally free of any tree-sitter import: this module is the JS/TS
// analyzer (TypeScript compiler). Python/Bash/Rust dispatch lives in index.ts so
// that importing this file never pulls in tree-sitter's native bindings.
function isJsTs(filePath: string): boolean {
	const lower = filePath.toLowerCase();
	return [".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"].some((e) => lower.endsWith(e));
}

// ─── Source & Sink Definitions ────────────────────────────────

const CREDENTIAL_SOURCES = new Set(["process.env", "process.env.get"]);

const FILE_READ_SOURCES = new Set([
	"fs.readFileSync",
	"fs.readFile",
	"fs.promises.readFile",
	"path.join", // Heuristic: path joining with tainted variables is often a source
]);

const NETWORK_INPUT_SOURCES = new Set([
	"fetch",
	"http.get",
	"https.get",
	"axios.get",
	"axios.post",
]);

const USER_INPUT_SOURCES = new Set(["process.stdin", "process.argv"]);

const ALL_SOURCES = new Set([
	...CREDENTIAL_SOURCES,
	...FILE_READ_SOURCES,
	...NETWORK_INPUT_SOURCES,
	...USER_INPUT_SOURCES,
]);

const NETWORK_OUTPUT_SINKS = new Set([
	"fetch",
	"http.request",
	"https.request",
	"axios.post",
	"axios.put",
	"axios.patch",
]);

const EXEC_SINKS = new Set([
	"eval",
	"exec",
	"execSync",
	"spawn",
	"spawnSync",
	"child_process.exec",
	"child_process.execSync",
	"child_process.spawn",
	"child_process.spawnSync",
	"vm.runInContext",
	"vm.runInNewContext",
	"vm.runInThisContext",
]);

const FILE_WRITE_SINKS = new Set([
	"fs.writeFileSync",
	"fs.writeFile",
	"fs.promises.writeFile",
	"fs.appendFileSync",
	"fs.appendFile",
	"fs.promises.appendFile",
]);

const ALL_SINKS = new Set([
	...NETWORK_OUTPUT_SINKS,
	...EXEC_SINKS,
	...FILE_WRITE_SINKS,
]);

const AI_AGENT_TOOL_WHITELIST = new Set([
	"run_command",
	"execute_command",
	"execute_bash",
	"python_run",
]);

// ─── Taint Rules ──────────────────────────────────────────────

function pickRule(
	sourceName: string,
	sinkName: string,
	isDirect: boolean,
): string {
	if (CREDENTIAL_SOURCES.has(sourceName) && NETWORK_OUTPUT_SINKS.has(sinkName))
		return "TT3";
	if (FILE_READ_SOURCES.has(sourceName) && NETWORK_OUTPUT_SINKS.has(sinkName))
		return "TT4";
	if (
		(NETWORK_INPUT_SOURCES.has(sourceName) ||
			USER_INPUT_SOURCES.has(sourceName)) &&
		EXEC_SINKS.has(sinkName)
	)
		return "TT5";
	return isDirect ? "TT1" : "TT2";
}

function getRuleSeverity(ruleId: string): Severity {
	switch (ruleId) {
		case "TT1":
			return "high";
		case "TT2":
			return "medium";
		case "TT3":
			return "critical";
		case "TT4":
			return "high";
		case "TT5":
			return "critical";
		default:
			return "medium";
	}
}

function classify(
	name: string,
	categories: { names: Set<string>; label: string }[],
	def: string,
): string {
	for (const cat of categories) {
		if (cat.names.has(name)) return cat.label;
	}
	return def;
}

const SOURCE_CATEGORIES = [
	{ names: CREDENTIAL_SOURCES, label: "credential/environment" },
	{ names: FILE_READ_SOURCES, label: "file read" },
	{ names: NETWORK_INPUT_SOURCES, label: "network input" },
	{ names: USER_INPUT_SOURCES, label: "user input" },
];

const SINK_CATEGORIES = [
	{ names: NETWORK_OUTPUT_SINKS, label: "network output" },
	{ names: EXEC_SINKS, label: "code execution" },
	{ names: FILE_WRITE_SINKS, label: "file write" },
];

interface TaintedVar {
	name: string;
	sourceCall: string;
	lineno: number;
}

// ─── AST Helpers ──────────────────────────────────────────────

function getCallName(node: ts.Node): string | null {
	if (ts.isCallExpression(node)) {
		return getIdentifierName(node.expression);
	}
	return null;
}

function getIdentifierName(node: ts.Node): string | null {
	if (ts.isIdentifier(node)) {
		return node.text;
	}
	// `this` so that `this.x` yields a stable key ("this.x"); without this a class
	// attribute assignment (this.x = secret) produced a null name and was dropped.
	if (node.kind === ts.SyntaxKind.ThisKeyword) {
		return "this";
	}
	if (ts.isPropertyAccessExpression(node)) {
		const obj = getIdentifierName(node.expression);
		const prop = getIdentifierName(node.name);
		if (obj && prop) return `${obj}.${prop}`;
	}
	return null;
}

// ─── Main Analyzer ────────────────────────────────────────────

export function analyzeTaint(
	files: ReadonlyArray<{ readonly path: string; readonly content: string }>,
): TaintResult {
	const allSources: TaintNode[] = [];
	const allSinks: TaintNode[] = [];
	const allFlows: TaintFlow[] = [];

	for (const file of files) {
		// Only JS/TS here; Python/Bash/Rust are handled by the polyglot dispatch
		// in index.ts (kept separate so this file never imports tree-sitter).
		if (!isJsTs(file.path)) {
			continue;
		}

		const sourceFile = ts.createSourceFile(
			file.path,
			file.content,
			ts.ScriptTarget.Latest,
			true,
		);

		const tainted: Map<string, TaintedVar> = new Map();

		// Simple identifier aliases: `const r = axios` → r resolves to axios, so a
		// sink/source reached through the alias (`r.post(...)`, `e.API_KEY` where
		// `const e = process.env`) is still recognized. Only plain identifier =
		// identifier assignments are recorded.
		const aliases = new Map<string, string>();
		function resolveAlias(name: string): string {
			const dot = name.indexOf(".");
			const head = dot === -1 ? name : name.slice(0, dot);
			const target = aliases.get(head);
			return target ? target + (dot === -1 ? "" : name.slice(dot)) : name;
		}

		function emit(
			ruleId: string,
			lineno: number,
			msg: string,
			srcName: string,
			sinkName: string,
		) {
			const sourceNode: TaintNode = {
				file: file.path,
				line: lineno,
				label: srcName,
				type: "source",
			};
			const sinkNode: TaintNode = {
				file: file.path,
				line: lineno,
				label: sinkName,
				type: "sink",
			};
			allSources.push(sourceNode);
			allSinks.push(sinkNode);

			allFlows.push({
				source: sourceNode,
				sink: sinkNode,
				path: [msg],
				severity: getRuleSeverity(ruleId),
				description: msg,
			});
		}

		function visit(node: ts.Node) {
			// 1. Check for assignments to track tainted variables
			if (ts.isVariableDeclaration(node) && node.initializer) {
				handleAssignment(node.name, node.initializer);
			} else if (
				ts.isBinaryExpression(node) &&
				node.operatorToken.kind === ts.SyntaxKind.EqualsToken
			) {
				handleAssignment(node.left, node.right);
			}

			// 2. Check for sink calls
			if (ts.isCallExpression(node)) {
				const rawSink = getCallName(node);
				const sinkName = rawSink ? resolveAlias(rawSink) : null;

				// Skip if the function called is a known AI agent tool
				if (sinkName && AI_AGENT_TOOL_WHITELIST.has(sinkName)) {
					ts.forEachChild(node, visit);
					return;
				}

				if (sinkName && ALL_SINKS.has(sinkName)) {
					const lineno =
						sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;

					// Check flows inside the sink's arguments
					node.arguments.forEach((arg) => {
						checkDirectSources(arg, sinkName, lineno);
						checkTaintedVars(arg, sinkName, lineno);
					});
				}
			}

			ts.forEachChild(node, visit);
		}

		function handleAssignment(target: ts.Node, value: ts.Node) {
			const targetName = getIdentifierName(target);
			if (!targetName) return;

			// Record a plain `x = y` identifier alias (y a bare identifier) so a sink
			// reached via x is resolved back to y.
			if (ts.isIdentifier(target) && ts.isIdentifier(value)) {
				aliases.set(target.text, value.text);
			}

			const lineno =
				sourceFile.getLineAndCharacterOfPosition(target.getStart()).line + 1;
			let sourceFound = false;

			function findSource(n: ts.Node) {
				const rawName =
					getCallName(n) ||
					(ts.isPropertyAccessExpression(n) ? getIdentifierName(n) : null);
				const name = rawName ? resolveAlias(rawName) : null;
				if (name && ALL_SOURCES.has(name as string)) {
					tainted.set(targetName as string, {
						name: targetName as string,
						sourceCall: name as string,
						lineno,
					});
					sourceFound = true;
				} else if (name?.startsWith("process.env")) {
					tainted.set(targetName as string, {
						name: targetName as string,
						sourceCall: "process.env",
						lineno,
					});
					sourceFound = true;
				} else if (ts.isIdentifier(n)) {
					// Taint propagation: target = taintedVar
					const t = tainted.get(n.text);
					if (t) {
						tainted.set(targetName as string, {
							name: targetName as string,
							sourceCall: t.sourceCall,
							lineno: t.lineno,
						});
						sourceFound = true;
					}
				}
				if (!sourceFound) ts.forEachChild(n, findSource);
			}
			findSource(value);
		}

		function checkDirectSources(
			argNode: ts.Node,
			sinkName: string,
			lineno: number,
		) {
			function find(n: ts.Node) {
				const rawName =
					getCallName(n) ||
					(ts.isPropertyAccessExpression(n) ? getIdentifierName(n) : null);
				const name = rawName ? resolveAlias(rawName) : null;
				if (name && (ALL_SOURCES.has(name as string) || name.startsWith("process.env"))) {
					const srcName = name.startsWith("process.env") ? "process.env" : name;
					const rule = pickRule(srcName, sinkName, true);
					const srcCat = classify(srcName, SOURCE_CATEGORIES, "data source");
					const sinkCat = classify(sinkName, SINK_CATEGORIES, "data sink");
					emit(
						rule,
						lineno,
						`Direct flow: ${srcName} (${srcCat}) -> ${sinkName} (${sinkCat})`,
						srcName,
						sinkName,
					);
				}
				ts.forEachChild(n, find);
			}
			find(argNode);
		}

		function checkTaintedVars(
			argNode: ts.Node,
			sinkName: string,
			lineno: number,
		) {
			function emitTainted(t: TaintedVar) {
				const rule = pickRule(t.sourceCall, sinkName, false);
				const srcCat = classify(t.sourceCall, SOURCE_CATEGORIES, "data source");
				const sinkCat = classify(sinkName, SINK_CATEGORIES, "data sink");
				emit(
					rule,
					lineno,
					`Tainted flow: '${t.name}' from ${t.sourceCall} (line ${t.lineno}, ${srcCat}) -> ${sinkName} (${sinkCat})`,
					t.sourceCall,
					sinkName,
				);
			}

			function find(n: ts.Node) {
				// Member access (o.x, this.x): look the WHOLE access path up in the
				// tainted map. Previously only bare identifiers were checked, so a
				// tainted object field written as `o.x = secret` was a dead store —
				// never matched at the sink. Recurse into the object expression but not
				// the property-name identifier (which is not a variable reference).
				if (ts.isPropertyAccessExpression(n)) {
					const full = getIdentifierName(n);
					if (full) {
						const t = tainted.get(full);
						if (t) emitTainted(t);
					}
					find(n.expression);
					return;
				}
				if (ts.isIdentifier(n)) {
					const t = tainted.get(n.text);
					if (t) emitTainted(t);
					return;
				}
				ts.forEachChild(n, find);
			}
			find(argNode);
		}

		visit(sourceFile);
	}

	// Deduplicate flows
	const uniqueFlows = Array.from(
		new Map(allFlows.map((f) => [f.description, f])).values(),
	);
	const severityOrder: Record<Severity, number> = {
		critical: 0,
		high: 1,
		medium: 2,
		low: 3,
		info: 4,
	};
	const sortedFlows = uniqueFlows.sort(
		(a, b) => severityOrder[a.severity] - severityOrder[b.severity],
	);

	// Deduplicate sources and sinks
	const uniqueSources = Array.from(
		new Map(
			allSources.map((s) => [`${s.file}:${s.line}:${s.label}`, s]),
		).values(),
	);
	const uniqueSinks = Array.from(
		new Map(
			allSinks.map((s) => [`${s.file}:${s.line}:${s.label}`, s]),
		).values(),
	);

	return {
		flows: sortedFlows,
		sources: uniqueSources,
		sinks: uniqueSinks,
	};
}
