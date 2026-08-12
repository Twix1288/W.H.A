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

// ─── Interprocedural summaries ────────────────────────────────
//
// A per-function summary lets a call site reason about a callee WITHOUT inlining:
//   - returnsSource: calling F yields data derived from an in-body source
//     (so `x = F()` taints x; `sink(F())` flows).
//   - paramReturns:  params that flow to F's return (pass-through: `id(secret)`).
//   - paramSinks:    params that reach a sink INSIDE F (so `F(secret)` flows).
// Summaries are computed ONLY for functions defined in this file (never assume an
// imported/unknown function taints or sinks — the key false-positive guardrail),
// via a monotonic bounded fixpoint so chains and bounded recursion converge.

interface FnDef {
	readonly params: string[];
	readonly body: ts.Node;
}
interface FnSummary {
	returnsSource: string | null;
	paramReturns: Set<number>;
	paramSinks: Map<number, string>;
}

function sourceRankOf(name: string): number {
	if (name.startsWith("process.env") || CREDENTIAL_SOURCES.has(name)) return 4;
	if (FILE_READ_SOURCES.has(name)) return 3;
	if (NETWORK_INPUT_SOURCES.has(name)) return 2;
	if (USER_INPUT_SOURCES.has(name)) return 1;
	return 0;
}
function stronger(a: string | null, b: string | null): string | null {
	if (!a) return b;
	if (!b) return a;
	return sourceRankOf(b) > sourceRankOf(a) ? b : a;
}
// The source name a node directly denotes, if any (a source call or a
// process.env-style attribute). Returns null for non-sources.
function sourceNameOf(n: ts.Node): string | null {
	const name =
		getCallName(n) ||
		(ts.isPropertyAccessExpression(n) ? getIdentifierName(n) : null);
	if (!name) return null;
	if (ALL_SOURCES.has(name)) return name;
	if (name.startsWith("process.env")) return "process.env";
	return null;
}
function isFnLike(n: ts.Node): boolean {
	return (
		ts.isFunctionDeclaration(n) ||
		ts.isFunctionExpression(n) ||
		ts.isArrowFunction(n) ||
		ts.isMethodDeclaration(n)
	);
}
// Walk a subtree but do NOT descend into nested function bodies, so a summary
// reflects only its own function.
function walkOwn(node: ts.Node, fn: (n: ts.Node) => void): void {
	fn(node);
	node.forEachChild((c) => {
		if (isFnLike(c)) return;
		walkOwn(c, fn);
	});
}

function collectFunctions(root: ts.Node): Map<string, FnDef> {
	const fns = new Map<string, FnDef>();
	function rec(node: ts.Node) {
		if (ts.isFunctionDeclaration(node) && node.name && node.body) {
			fns.set(node.name.text, {
				params: node.parameters.map((p) => p.name.getText()),
				body: node.body,
			});
		} else if (
			ts.isMethodDeclaration(node) &&
			node.body &&
			ts.isIdentifier(node.name)
		) {
			fns.set(node.name.text, {
				params: node.parameters.map((p) => p.name.getText()),
				body: node.body,
			});
		} else if (
			ts.isVariableDeclaration(node) &&
			ts.isIdentifier(node.name) &&
			node.initializer &&
			(ts.isArrowFunction(node.initializer) ||
				ts.isFunctionExpression(node.initializer)) &&
			node.initializer.body
		) {
			fns.set(node.name.text, {
				params: node.initializer.parameters.map((p) => p.name.getText()),
				body: node.initializer.body,
			});
		}
		ts.forEachChild(node, rec);
	}
	rec(root);
	return fns;
}

function computeSummary(
	fn: FnDef,
	summaries: Map<string, FnSummary>,
): FnSummary {
	const paramIndex = new Map<string, number>();
	fn.params.forEach((p, i) => {
		paramIndex.set(p, i);
	});

	// Light taint propagation within the body: var -> params reaching it / strongest source.
	const fromParams = new Map<string, Set<number>>();
	const fromSource = new Map<string, string>();

	const assigns: { target: string | null; value: ts.Node }[] = [];
	walkOwn(fn.body, (n) => {
		if (ts.isVariableDeclaration(n) && n.initializer && ts.isIdentifier(n.name)) {
			assigns.push({ target: n.name.text, value: n.initializer });
		} else if (
			ts.isBinaryExpression(n) &&
			n.operatorToken.kind === ts.SyntaxKind.EqualsToken
		) {
			assigns.push({ target: getIdentifierName(n.left), value: n.right });
		}
	});

	function exprTaint(node: ts.Node): { params: Set<number>; source: string | null } {
		const params = new Set<number>();
		let source: string | null = null;
		function rec(n: ts.Node) {
			const s = sourceNameOf(n);
			if (s) source = stronger(source, s);
			if (ts.isCallExpression(n)) {
				const callee = getCallName(n);
				const summ = callee ? summaries.get(callee) : undefined;
				if (summ) {
					if (summ.returnsSource) source = stronger(source, summ.returnsSource);
					if (summ.paramReturns.size) {
						n.arguments.forEach((a, i) => {
							if (summ.paramReturns.has(i)) {
								const t = exprTaint(a);
								for (const p of t.params) params.add(p);
								source = stronger(source, t.source);
							}
						});
					}
				}
			}
			if (ts.isIdentifier(n)) {
				const pi = paramIndex.get(n.text);
				if (pi !== undefined) params.add(pi);
				const fp = fromParams.get(n.text);
				if (fp) for (const p of fp) params.add(p);
				const fs = fromSource.get(n.text);
				if (fs) source = stronger(source, fs);
			}
			n.forEachChild(rec);
		}
		rec(node);
		return { params, source };
	}

	for (let pass = 0; pass < 6; pass++) {
		let changed = false;
		for (const a of assigns) {
			if (!a.target) continue;
			const t = exprTaint(a.value);
			if (t.params.size) {
				const cur = fromParams.get(a.target) ?? new Set<number>();
				const before = cur.size;
				for (const p of t.params) cur.add(p);
				if (cur.size !== before) {
					fromParams.set(a.target, cur);
					changed = true;
				}
			}
			if (t.source) {
				const prev = fromSource.get(a.target) ?? null;
				const next = stronger(prev, t.source);
				if (next && next !== prev) {
					fromSource.set(a.target, next);
					changed = true;
				}
			}
		}
		if (!changed) break;
	}

	const paramSinks = new Map<number, string>();
	walkOwn(fn.body, (n) => {
		if (!ts.isCallExpression(n)) return;
		const callName = getCallName(n);
		if (!callName) return;
		// A param reaching a DIRECT known sink's arguments.
		if (ALL_SINKS.has(callName)) {
			n.arguments.forEach((arg) => {
				for (const p of exprTaint(arg).params) {
					if (!paramSinks.has(p)) paramSinks.set(p, callName);
				}
			});
		}
		// A param reaching another summarized function's param-sink (n-hop chains,
		// resolved across fixpoint rounds).
		const summ = summaries.get(callName);
		if (summ && summ.paramSinks.size) {
			summ.paramSinks.forEach((internalSink, j) => {
				const arg = n.arguments[j];
				if (!arg) return;
				for (const p of exprTaint(arg).params) {
					if (!paramSinks.has(p)) paramSinks.set(p, internalSink);
				}
			});
		}
	});

	const paramReturns = new Set<number>();
	let returnsSource: string | null = null;
	walkOwn(fn.body, (n) => {
		if (ts.isReturnStatement(n) && n.expression) {
			const t = exprTaint(n.expression);
			for (const p of t.params) paramReturns.add(p);
			returnsSource = stronger(returnsSource, t.source);
		}
	});
	// Arrow function with an expression body (no `return`): the body IS the return.
	if (!ts.isBlock(fn.body)) {
		const t = exprTaint(fn.body);
		for (const p of t.params) paramReturns.add(p);
		returnsSource = stronger(returnsSource, t.source);
	}

	return { returnsSource, paramReturns, paramSinks };
}

function sameSummary(a: FnSummary, b: FnSummary): boolean {
	if (a.returnsSource !== b.returnsSource) return false;
	if (a.paramReturns.size !== b.paramReturns.size) return false;
	for (const p of a.paramReturns) if (!b.paramReturns.has(p)) return false;
	if (a.paramSinks.size !== b.paramSinks.size) return false;
	for (const [k, v] of a.paramSinks) if (b.paramSinks.get(k) !== v) return false;
	return true;
}

function buildSummaries(root: ts.Node): Map<string, FnSummary> {
	const fns = collectFunctions(root);
	const summaries = new Map<string, FnSummary>();
	for (const name of fns.keys()) {
		summaries.set(name, {
			returnsSource: null,
			paramReturns: new Set(),
			paramSinks: new Map(),
		});
	}
	const K = Math.min(fns.size + 2, 12);
	for (let round = 0; round < K; round++) {
		let changed = false;
		for (const [name, fn] of fns) {
			const s = computeSummary(fn, summaries);
			if (!sameSummary(summaries.get(name) as FnSummary, s)) {
				summaries.set(name, s);
				changed = true;
			}
		}
		if (!changed) break;
	}
	return summaries;
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

		// Per-file function summaries for interprocedural flow (see the summary
		// engine above). Same-file functions only.
		const summaries = buildSummaries(sourceFile);

		// The tainted origin (source-call name) an argument expression carries, if
		// any — a direct source or a reference to an already-tainted variable/member.
		function argOrigin(argNode: ts.Node): string | null {
			let origin: string | null = null;
			function rec(n: ts.Node) {
				if (!origin) {
					const rawName =
						getCallName(n) ||
						(ts.isPropertyAccessExpression(n) ? getIdentifierName(n) : null);
					const name = rawName ? resolveAlias(rawName) : null;
					if (name && (ALL_SOURCES.has(name) || name.startsWith("process.env"))) {
						origin = name.startsWith("process.env") ? "process.env" : name;
					}
				}
				if (!origin && ts.isIdentifier(n)) {
					const t = tainted.get(n.text);
					if (t) origin = t.sourceCall;
				} else if (!origin && ts.isPropertyAccessExpression(n)) {
					const full = getIdentifierName(n);
					if (full) {
						const t = tainted.get(full);
						if (t) origin = t.sourceCall;
					}
				}
				if (!origin) n.forEachChild(rec);
			}
			rec(argNode);
			return origin;
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

				// Interprocedural param-to-sink: a call to a same-file function whose
				// parameter reaches an internal sink, passed a tainted argument.
				const summ = sinkName ? summaries.get(sinkName) : undefined;
				if (summ && summ.paramSinks.size) {
					const lineno =
						sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;
					summ.paramSinks.forEach((internalSink, i) => {
						const arg = node.arguments[i];
						if (!arg) return;
						const o = argOrigin(arg);
						if (o) {
							emit(
								pickRule(o, internalSink, false),
								lineno,
								`Interprocedural flow: ${o} -> ${internalSink} via ${sinkName}() (argument ${i + 1})`,
								o,
								internalSink,
							);
						}
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
				} else if (ts.isCallExpression(n) && name && summaries.has(name)) {
					// Interprocedural: `x = F(...)` where F returns tainted data (from an
					// in-body source, or by passing an argument through to its return).
					const summ = summaries.get(name) as FnSummary;
					if (summ.returnsSource) {
						tainted.set(targetName as string, {
							name: targetName as string,
							sourceCall: summ.returnsSource,
							lineno,
						});
						sourceFound = true;
					} else if (summ.paramReturns.size) {
						for (const i of summ.paramReturns) {
							const arg = n.arguments[i];
							const o = arg ? argOrigin(arg) : null;
							if (o) {
								tainted.set(targetName as string, {
									name: targetName as string,
									sourceCall: o,
									lineno,
								});
								sourceFound = true;
								break;
							}
						}
					}
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
				} else if (ts.isCallExpression(n) && name && summaries.has(name)) {
					// Interprocedural: a source-returning (or pass-through) function called
					// directly inside a sink argument, e.g. `fetch(url, getSecret())`.
					const summ = summaries.get(name) as FnSummary;
					const origin =
						summ.returnsSource ??
						(summ.paramReturns.size
							? [...summ.paramReturns]
									.map((i) => (n.arguments[i] ? argOrigin(n.arguments[i]) : null))
									.find((o): o is string => !!o) ?? null
							: null);
					if (origin) {
						emit(
							pickRule(origin, sinkName, false),
							lineno,
							`Interprocedural flow: ${origin} -> ${sinkName} via ${name}()`,
							origin,
							sinkName,
						);
					}
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
