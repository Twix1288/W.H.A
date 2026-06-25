import * as ts from "typescript";
import type { Severity, TaintFlow, TaintNode, TaintResult } from "../types.js";

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
		// Only process files we can parse as AST (JS/TS)
		if (!file.path.endsWith(".js") && !file.path.endsWith(".ts")) {
			continue;
		}

		const sourceFile = ts.createSourceFile(
			file.path,
			file.content,
			ts.ScriptTarget.Latest,
			true,
		);

		const tainted: Map<string, TaintedVar> = new Map();

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
				const sinkName = getCallName(node);
				
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

			const lineno =
				sourceFile.getLineAndCharacterOfPosition(target.getStart()).line + 1;
			let sourceFound = false;

			function findSource(n: ts.Node) {
				const name =
					getCallName(n) ||
					(ts.isPropertyAccessExpression(n) ? getIdentifierName(n) : null);
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
				const name =
					getCallName(n) ||
					(ts.isPropertyAccessExpression(n) ? getIdentifierName(n) : null);
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
			function find(n: ts.Node) {
				if (ts.isIdentifier(n)) {
					const t = tainted.get(n.text);
					if (t) {
						const rule = pickRule(t.sourceCall, sinkName, false);
						const srcCat = classify(
							t.sourceCall,
							SOURCE_CATEGORIES,
							"data source",
						);
						const sinkCat = classify(sinkName, SINK_CATEGORIES, "data sink");
						emit(
							rule,
							lineno,
							`Tainted flow: '${t.name}' from ${t.sourceCall} (line ${t.lineno}, ${srcCat}) -> ${sinkName} (${sinkCat})`,
							t.sourceCall,
							sinkName,
						);
					}
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
