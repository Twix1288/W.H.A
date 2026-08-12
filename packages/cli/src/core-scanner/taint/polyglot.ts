import type Parser from "tree-sitter";
import { parseSourceToTree } from "../parser.js";
import type { Severity, TaintFlow, TaintNode } from "../types.js";

// Polyglot taint analysis for the non-JS/TS languages the README claims: Python,
// Bash, and Rust. It runs on the tree-sitter AST (JS/TS keep their dedicated
// TypeScript-compiler analyzer). This is the same class of analysis the JS/TS
// path does — name-based source→sink dataflow with fixpoint propagation across
// assignments — extended to the other grammars so all five claimed languages get
// real taint tracking rather than parse-only support.

type SourceKind = "sensitive" | "input";

interface LangSpec {
	// Callee-name suffixes that introduce taint, grouped by what kind of data.
	sensitiveSources: string[]; // secrets, env, files, credentials
	inputSources: string[]; // user/network controlled input
	networkSinks: string[]; // data leaving the machine
	execSinks: string[]; // command / code execution
	// Grammar node types.
	callTypes: string[];
	assignTypes: string[];
	identifierTypes: string[];
	// Interprocedural: the function-definition node type (null = no summaries for
	// this language, e.g. Bash), plus the field names for its parameters/body and
	// the return-value node types.
	functionType: string | null;
	paramField: string;
	bodyField: string;
	returnTypes: string[];
}

const PYTHON: LangSpec = {
	sensitiveSources: [
		"os.getenv",
		"getenv",
		"os.environ.get",
		"environ",
		"os.environ",
		"open",
		"read_text",
		"getpass",
		"getpass.getpass",
		"read",
	],
	inputSources: [
		"input",
		"sys.argv",
		"argv",
		"stdin",
		"recv",
		"request.args",
		"request.json",
	],
	networkSinks: [
		"requests.post",
		"requests.put",
		"requests.get",
		"requests.patch",
		"urlopen",
		"urllib.request.urlopen",
		"httpx.post",
		"httpx.get",
		"session.post",
		// METHOD-only HTTP verbs (leading "."): match ANY receiver — catches
		// `s = requests.Session(); s.post(...)` and `import requests as r; r.post(...)`
		// — while a plain user function named `send`/`post` is NOT a sink. `get` is
		// deliberately excluded (would false-positive on `dict.get`).
		".post",
		".put",
		".patch",
		".send",
		".sendall",
	],
	execSinks: [
		"os.system",
		"system",
		"subprocess.run",
		"subprocess.call",
		"subprocess.Popen",
		"subprocess.check_output",
		"subprocess.check_call",
		"Popen",
		"os.popen",
		"popen",
		"eval",
		"exec",
		"check_output",
	],
	callTypes: ["call"],
	assignTypes: ["assignment", "augmented_assignment"],
	identifierTypes: ["identifier", "attribute"],
	functionType: "function_definition",
	paramField: "parameters",
	bodyField: "body",
	returnTypes: ["return_statement"],
};

const BASH: LangSpec = {
	sensitiveSources: ["cat", "printenv", "env", "head", "less", "read"],
	inputSources: ["read", "curl", "wget"],
	networkSinks: ["curl", "wget", "nc", "netcat", "ssh", "scp"],
	execSinks: ["eval", "sh", "bash", "source", "exec"],
	callTypes: ["command", "command_substitution"],
	assignTypes: ["variable_assignment"],
	identifierTypes: ["variable_name", "word", "simple_expansion", "expansion"],
	functionType: null,
	paramField: "",
	bodyField: "",
	returnTypes: [],
};

const RUST: LangSpec = {
	sensitiveSources: [
		"env::var",
		"std::env::var",
		"var",
		"read_to_string",
		"fs::read",
		"fs::read_to_string",
		"read",
	],
	inputSources: ["args", "std::env::args", "read_line", "stdin"],
	networkSinks: [
		"reqwest::get",
		"reqwest::post",
		"get",
		"post",
		"send",
		"write_all",
		// reqwest builder methods that carry the request PAYLOAD. The canonical
		// exfil shape `client.post(url).body(secret).send()` puts the tainted value
		// on `.body()`/`.json()`/`.form()`, not in the args of `.post`/`.send`, so
		// without these the chained-builder form was missed.
		"body",
		"json",
		"form",
	],
	execSinks: ["Command::new", "process::Command", "spawn", "output", "status"],
	callTypes: ["call_expression", "macro_invocation", "method_call"],
	assignTypes: ["let_declaration", "assignment_expression"],
	identifierTypes: ["identifier", "scoped_identifier", "field_expression"],
	functionType: "function_item",
	paramField: "parameters",
	bodyField: "body",
	returnTypes: ["return_expression"],
};

function specForExt(ext: string): LangSpec | null {
	switch (ext.toLowerCase()) {
		case ".py":
			return PYTHON;
		case ".sh":
		case ".bash":
			return BASH;
		case ".rs":
			return RUST;
		default:
			return null;
	}
}

// A callee matches a pattern if it equals it, or ends with a dotted/scoped
// segment equal to it (so `os.getenv` matches "getenv", `std::env::var` matches
// "env::var", `requests.post` matches "requests.post").
//
// A pattern PREFIXED with "." is METHOD-ONLY: it matches only with a receiver
// (`x.post`, `requests::post`), never a bare call. This is how a plain user
// function literally named `send`/`post` is NOT mistaken for an HTTP sink, while
// `client.post(...)` still matches.
function calleeMatches(callee: string, patterns: string[]): boolean {
	return patterns.some((p) => {
		if (p.startsWith(".")) {
			const seg = p.slice(1);
			return callee.endsWith("." + seg) || callee.endsWith("::" + seg);
		}
		return (
			callee === p || callee.endsWith("." + p) || callee.endsWith("::" + p)
		);
	});
}

function walk(
	node: Parser.SyntaxNode,
	fn: (n: Parser.SyntaxNode) => void,
): void {
	fn(node);
	for (let i = 0; i < node.namedChildCount; i++) {
		const c = node.namedChild(i);
		if (c) walk(c, fn);
	}
}

// The dotted/scoped name of whatever a call node invokes.
function calleeName(callNode: Parser.SyntaxNode): string {
	const fn =
		callNode.childForFieldName("function") ||
		callNode.childForFieldName("name") ||
		callNode.childForFieldName("macro") ||
		callNode.namedChild(0);
	return (fn?.text ?? "").trim();
}

function collectCallees(
	root: Parser.SyntaxNode,
	spec: LangSpec,
): { name: string; node: Parser.SyntaxNode }[] {
	const out: { name: string; node: Parser.SyntaxNode }[] = [];
	walk(root, (n) => {
		if (spec.callTypes.includes(n.type)) {
			const name = calleeName(n);
			if (name) out.push({ name, node: n });
		}
	});
	return out;
}

function collectIdentifiers(root: Parser.SyntaxNode, spec: LangSpec): string[] {
	const out: string[] = [];
	walk(root, (n) => {
		if (spec.identifierTypes.includes(n.type)) {
			// For expansions like $VAR, strip the leading $ so it matches the assigned name.
			out.push(n.text.replace(/^\$\{?/, "").replace(/\}$/, ""));
		}
	});
	return out;
}

function sourceKind(callee: string, spec: LangSpec): SourceKind | null {
	if (calleeMatches(callee, spec.sensitiveSources)) return "sensitive";
	if (calleeMatches(callee, spec.inputSources)) return "input";
	return null;
}

// Attribute/member sources used WITHOUT a call, e.g. `data=os.environ` or
// `sys.argv` — a very common exfiltration shape that pure call-matching misses.
// Restricted to DOTTED patterns (os.environ, sys.argv, request.args) so bare
// method names like "read"/"open" can't false-positive on ordinary attributes.
function attrSourceKind(text: string, spec: LangSpec): SourceKind | null {
	const dotted = (p: string) => p.includes(".") || p.includes("::");
	const match = (patterns: string[]) =>
		patterns
			.filter(dotted)
			.some((p) => text === p || text.endsWith(`.${p}`) || text.endsWith(`::${p}`));
	if (match(spec.sensitiveSources)) return "sensitive";
	if (match(spec.inputSources)) return "input";
	return null;
}

// Strongest source kind anywhere in a subtree, considering both source CALLS
// (os.getenv(...)) and source ATTRIBUTE accesses (os.environ). "sensitive" wins.
function subtreeSourceKind(
	node: Parser.SyntaxNode,
	spec: LangSpec,
): SourceKind | null {
	let kind: SourceKind | null = null;
	const consider = (k: SourceKind | null) => {
		if (k === "sensitive") kind = "sensitive";
		else if (k && kind !== "sensitive") kind = "input";
	};
	walk(node, (n) => {
		if (spec.callTypes.includes(n.type)) {
			consider(sourceKind(calleeName(n), spec));
		} else if (
			(n.type === "attribute" ||
				n.type === "field_expression" ||
				n.type === "scoped_identifier") &&
			n.text.includes(".")
		) {
			consider(attrSourceKind(n.text, spec));
		} else if (n.type === "simple_expansion" || n.type === "expansion") {
			// Bash: a variable expansion whose NAME looks like a secret
			// (AWS_SECRET_ACCESS_KEY, API_TOKEN, DB_PASSWORD, …) is a sensitive
			// source even without a `cat`/`printenv` call — catches direct exfil like
			// `curl -d "$AWS_SECRET_ACCESS_KEY"`.
			const varName = n.text.replace(/^\$\{?/, "").replace(/\}$/, "");
			if (/(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIALS?|APIKEY)/i.test(varName)) {
				consider("sensitive");
			}
		}
	});
	return kind;
}

function assignParts(
	node: Parser.SyntaxNode,
): { targets: string[]; value: Parser.SyntaxNode } | null {
	const left =
		node.childForFieldName("left") ||
		node.childForFieldName("name") ||
		node.childForFieldName("pattern");
	const value =
		node.childForFieldName("right") || node.childForFieldName("value");
	if (!value) return null;
	const targets: string[] = [];
	if (left) {
		if (left.type === "identifier" || left.type === "variable_name") {
			targets.push(left.text);
		} else {
			// tuple/pattern targets: collect the identifiers in the LHS
			walk(left, (n) => {
				if (n.type === "identifier" || n.type === "variable_name")
					targets.push(n.text);
			});
		}
	}
	return targets.length ? { targets, value } : null;
}

function riskySeverity(): Severity {
	return "high" as Severity;
}

// ─── Interprocedural summaries (Python/Rust; Bash has functionType null) ───────
// Mirrors the JS/TS analyzer: per-function summaries + a bounded fixpoint, for
// same-file functions only (never assume an imported/unknown function taints or
// sinks). See taint/analyzer.ts for the design rationale.

interface PolySummary {
	returnsKind: SourceKind | null;
	paramReturns: Set<number>;
	paramSinks: Map<number, "network" | "exec">;
}

function strongerKind(
	a: SourceKind | null,
	b: SourceKind | null,
): SourceKind | null {
	if (a === "sensitive" || b === "sensitive") return "sensitive";
	return a ?? b;
}

function bodyWalkOwn(
	node: Parser.SyntaxNode,
	spec: LangSpec,
	fn: (n: Parser.SyntaxNode) => void,
): void {
	fn(node);
	for (let i = 0; i < node.namedChildCount; i++) {
		const c = node.namedChild(i);
		if (!c) continue;
		if (spec.functionType && c.type === spec.functionType) continue;
		bodyWalkOwn(c, spec, fn);
	}
}

function firstIdentText(n: Parser.SyntaxNode): string | null {
	let found: string | null = null;
	walk(n, (x) => {
		if (!found && x.type === "identifier") found = x.text;
	});
	return found;
}

function paramNames(fnNode: Parser.SyntaxNode, spec: LangSpec): string[] {
	const params = fnNode.childForFieldName(spec.paramField);
	if (!params) return [];
	const names: string[] = [];
	for (let i = 0; i < params.namedChildCount; i++) {
		const c = params.namedChild(i);
		if (!c) continue;
		if (c.type === "identifier") names.push(c.text);
		else {
			const id = firstIdentText(c);
			if (id) names.push(id);
		}
	}
	return names;
}

function callArgs(callNode: Parser.SyntaxNode): Parser.SyntaxNode[] {
	const argsNode = callNode.childForFieldName("arguments");
	if (!argsNode) return [];
	const out: Parser.SyntaxNode[] = [];
	for (let i = 0; i < argsNode.namedChildCount; i++) {
		const c = argsNode.namedChild(i);
		if (!c || c.type === "comment") continue;
		if (c.type === "keyword_argument") {
			const v = c.childForFieldName("value");
			if (v) out.push(v);
		} else out.push(c);
	}
	return out;
}

function collectFunctionsPoly(
	root: Parser.SyntaxNode,
	spec: LangSpec,
): Map<string, { params: string[]; body: Parser.SyntaxNode }> {
	const fns = new Map<string, { params: string[]; body: Parser.SyntaxNode }>();
	if (!spec.functionType) return fns;
	walk(root, (n) => {
		if (n.type !== spec.functionType) return;
		const nameNode = n.childForFieldName("name");
		const body = n.childForFieldName(spec.bodyField);
		if (nameNode && body)
			fns.set(nameNode.text, { params: paramNames(n, spec), body });
	});
	return fns;
}

function computeSummaryPoly(
	fn: { params: string[]; body: Parser.SyntaxNode },
	spec: LangSpec,
	summaries: Map<string, PolySummary>,
): PolySummary {
	const paramIndex = new Map<string, number>();
	fn.params.forEach((p, i) => {
		paramIndex.set(p, i);
	});
	const fromParams = new Map<string, Set<number>>();
	const fromSource = new Map<string, SourceKind>();

	const assigns: { targets: string[]; value: Parser.SyntaxNode }[] = [];
	bodyWalkOwn(fn.body, spec, (n) => {
		if (spec.assignTypes.includes(n.type)) {
			const p = assignParts(n);
			if (p) assigns.push(p);
		}
	});

	function exprTaint(node: Parser.SyntaxNode): {
		params: Set<number>;
		kind: SourceKind | null;
	} {
		const params = new Set<number>();
		let kind: SourceKind | null = null;
		walk(node, (n) => {
			if (spec.callTypes.includes(n.type)) {
				const cn = calleeName(n);
				const sk = sourceKind(cn, spec);
				if (sk) kind = strongerKind(kind, sk);
				const summ = summaries.get(cn);
				if (summ) {
					if (summ.returnsKind) kind = strongerKind(kind, summ.returnsKind);
					if (summ.paramReturns.size) {
						const args = callArgs(n);
						for (const i of summ.paramReturns) {
							const a = args[i];
							if (a) {
								const t = exprTaint(a);
								for (const p of t.params) params.add(p);
								kind = strongerKind(kind, t.kind);
							}
						}
					}
				}
			} else if (
				(n.type === "attribute" ||
					n.type === "field_expression" ||
					n.type === "scoped_identifier") &&
				n.text.includes(".")
			) {
				const sk = attrSourceKind(n.text, spec);
				if (sk) kind = strongerKind(kind, sk);
			}
			if (spec.identifierTypes.includes(n.type)) {
				const name = n.text.replace(/^\$\{?/, "").replace(/\}$/, "");
				const pi = paramIndex.get(name);
				if (pi !== undefined) params.add(pi);
				const fp = fromParams.get(name);
				if (fp) for (const p of fp) params.add(p);
				const fs = fromSource.get(name);
				if (fs) kind = strongerKind(kind, fs);
			}
		});
		return { params, kind };
	}

	for (let pass = 0; pass < 6; pass++) {
		let changed = false;
		for (const a of assigns) {
			const t = exprTaint(a.value);
			for (const tg of a.targets) {
				if (t.params.size) {
					const cur = fromParams.get(tg) ?? new Set<number>();
					const before = cur.size;
					for (const p of t.params) cur.add(p);
					if (cur.size !== before) {
						fromParams.set(tg, cur);
						changed = true;
					}
				}
				if (t.kind) {
					const prev = fromSource.get(tg) ?? null;
					const next = strongerKind(prev, t.kind);
					if (next && next !== prev) {
						fromSource.set(tg, next);
						changed = true;
					}
				}
			}
		}
		if (!changed) break;
	}

	const paramSinks = new Map<number, "network" | "exec">();
	bodyWalkOwn(fn.body, spec, (n) => {
		if (!spec.callTypes.includes(n.type)) return;
		const cn = calleeName(n);
		const isNet = calleeMatches(cn, spec.networkSinks);
		const isExec = calleeMatches(cn, spec.execSinks);
		if (isNet || isExec) {
			const argsNode = n.childForFieldName("arguments") ?? n;
			for (const p of exprTaint(argsNode).params)
				if (!paramSinks.has(p)) paramSinks.set(p, isNet ? "network" : "exec");
		}
		const summ = summaries.get(cn);
		if (summ && summ.paramSinks.size) {
			const args = callArgs(n);
			summ.paramSinks.forEach((sk, j) => {
				const a = args[j];
				if (!a) return;
				for (const p of exprTaint(a).params)
					if (!paramSinks.has(p)) paramSinks.set(p, sk);
			});
		}
	});

	const paramReturns = new Set<number>();
	let returnsKind: SourceKind | null = null;
	bodyWalkOwn(fn.body, spec, (n) => {
		if (spec.returnTypes.includes(n.type)) {
			const t = exprTaint(n);
			for (const p of t.params) paramReturns.add(p);
			returnsKind = strongerKind(returnsKind, t.kind);
		}
	});
	// Rust implicit return: the block's final expression.
	if (spec.functionType === "function_item" && fn.body.namedChildCount > 0) {
		const last = fn.body.namedChild(fn.body.namedChildCount - 1);
		if (
			last &&
			!last.type.endsWith("_statement") &&
			!last.type.endsWith("_declaration") &&
			last.type !== "return_expression"
		) {
			const t = exprTaint(last);
			for (const p of t.params) paramReturns.add(p);
			returnsKind = strongerKind(returnsKind, t.kind);
		}
	}

	return { returnsKind, paramReturns, paramSinks };
}

function samePolySummary(a: PolySummary, b: PolySummary): boolean {
	if (a.returnsKind !== b.returnsKind) return false;
	if (a.paramReturns.size !== b.paramReturns.size) return false;
	for (const p of a.paramReturns) if (!b.paramReturns.has(p)) return false;
	if (a.paramSinks.size !== b.paramSinks.size) return false;
	for (const [k, v] of a.paramSinks) if (b.paramSinks.get(k) !== v) return false;
	return true;
}

function buildSummariesPoly(
	root: Parser.SyntaxNode,
	spec: LangSpec,
): Map<string, PolySummary> {
	const fns = collectFunctionsPoly(root, spec);
	const summaries = new Map<string, PolySummary>();
	for (const name of fns.keys())
		summaries.set(name, {
			returnsKind: null,
			paramReturns: new Set(),
			paramSinks: new Map(),
		});
	const K = Math.min(fns.size + 2, 12);
	for (let round = 0; round < K; round++) {
		let changed = false;
		for (const [name, fn] of fns) {
			const s = computeSummaryPoly(fn, spec, summaries);
			if (!samePolySummary(summaries.get(name) as PolySummary, s)) {
				summaries.set(name, s);
				changed = true;
			}
		}
		if (!changed) break;
	}
	return summaries;
}

// The taint kind an argument carries at a call site (direct source or a
// reference to an already-tainted file-global variable).
function argKind(
	argNode: Parser.SyntaxNode,
	spec: LangSpec,
	tainted: Map<string, SourceKind>,
): SourceKind | null {
	let kind = subtreeSourceKind(argNode, spec);
	for (const id of collectIdentifiers(argNode, spec)) {
		const k = tainted.get(id);
		if (k) kind = strongerKind(kind, k);
	}
	return kind;
}

// The source kind produced by calling any summarized function within `node`
// (return-taint, or pass-through of a tainted argument).
function interReturnKind(
	node: Parser.SyntaxNode,
	spec: LangSpec,
	summaries: Map<string, PolySummary>,
	tainted: Map<string, SourceKind>,
): SourceKind | null {
	let kind: SourceKind | null = null;
	walk(node, (n) => {
		if (!spec.callTypes.includes(n.type)) return;
		const summ = summaries.get(calleeName(n));
		if (!summ) return;
		if (summ.returnsKind) kind = strongerKind(kind, summ.returnsKind);
		if (summ.paramReturns.size) {
			const args = callArgs(n);
			for (const i of summ.paramReturns) {
				const a = args[i];
				if (a) kind = strongerKind(kind, argKind(a, spec, tainted));
			}
		}
	});
	return kind;
}

/**
 * Analyze one non-JS/TS file for source→sink taint flows. Returns the flows plus
 * the discovered source/sink nodes, in the same shape the JS/TS analyzer emits.
 */
export function analyzePolyglotTaint(
	filePath: string,
	content: string,
	ext: string,
): { flows: TaintFlow[]; sources: TaintNode[]; sinks: TaintNode[] } | null {
	const spec = specForExt(ext);
	if (!spec) return null;
	const tree = parseSourceToTree(content, ext);
	if (!tree) return null;

	const root = tree.rootNode;
	const flows: TaintFlow[] = [];
	const sources: TaintNode[] = [];
	const sinks: TaintNode[] = [];

	// Interprocedural summaries for same-file functions (empty for Bash).
	const summaries = buildSummariesPoly(root, spec);

	// 1. Fixpoint propagation of taint through assignments.
	const tainted = new Map<string, SourceKind>();
	const assignments: { targets: string[]; value: Parser.SyntaxNode }[] = [];
	walk(root, (n) => {
		if (spec.assignTypes.includes(n.type)) {
			const p = assignParts(n);
			if (p) assignments.push(p);
		}
	});

	for (let pass = 0; pass < 5; pass++) {
		let changed = false;
		for (const a of assignments) {
			// A target is tainted if its value calls a source, reads a source
			// attribute (os.environ), or references an already-tainted variable.
			// "sensitive" dominates "input".
			let kind: SourceKind | null = subtreeSourceKind(a.value, spec);
			if (kind !== "sensitive") {
				for (const id of collectIdentifiers(a.value, spec)) {
					const k = tainted.get(id);
					if (k === "sensitive") {
						kind = "sensitive";
						break;
					}
					if (k) kind = "input";
				}
			}
			// Interprocedural: `x = helper(...)` where helper returns tainted data.
			if (kind !== "sensitive") {
				kind = strongerKind(
					kind,
					interReturnKind(a.value, spec, summaries, tainted),
				);
			}
			if (!kind) continue;
			for (const t of a.targets) {
				const prev = tainted.get(t);
				if (prev === kind || (prev === "sensitive" && kind === "input"))
					continue;
				tainted.set(t, kind);
				changed = true;
			}
		}
		if (!changed) break;
	}

	// 2. Sink inspection.
	for (const call of collectCallees(root, spec)) {
		const isNetwork = calleeMatches(call.name, spec.networkSinks);
		const isExec = calleeMatches(call.name, spec.execSinks);
		if (!isNetwork && !isExec) continue;

		const argsNode = call.node.childForFieldName("arguments") || call.node;
		const kinds = new Set<SourceKind>();
		// A source (call OR attribute like os.environ) used directly in the args.
		const direct = subtreeSourceKind(argsNode, spec);
		if (direct) kinds.add(direct);
		for (const id of collectIdentifiers(argsNode, spec)) {
			const k = tainted.get(id);
			if (k) kinds.add(k);
		}
		// Interprocedural: a source-returning function called directly in the args,
		// e.g. `requests.post(u, get_secret())`.
		const inter = interReturnKind(argsNode, spec, summaries, tainted);
		if (inter) kinds.add(inter);
		if (kinds.size === 0) continue;

		const line = call.node.startPosition.row + 1;
		let description: string | null = null;
		if (isNetwork && kinds.has("sensitive")) {
			description = `Sensitive data (credentials/file/env) flows into a network call '${call.name}' — possible data exfiltration.`;
		} else if (isExec && kinds.has("input")) {
			description = `Externally-controlled input flows into a command/exec sink '${call.name}' — possible injection.`;
		} else if (isExec && kinds.has("sensitive")) {
			description = `Sensitive data flows into an exec sink '${call.name}'.`;
		}
		if (!description) continue;

		const source: TaintNode = {
			file: filePath,
			line,
			label: kinds.has("sensitive") ? "sensitive-source" : "input-source",
			type: "source",
		};
		const sink: TaintNode = {
			file: filePath,
			line,
			label: call.name,
			type: "sink",
		};
		sources.push(source);
		sinks.push(sink);
		flows.push({
			source,
			sink,
			path: [description],
			severity: riskySeverity(),
			description,
		});
	}

	// 3. Interprocedural param-to-sink: a call to a same-file function whose
	// parameter reaches an internal sink, passed a tainted argument.
	for (const call of collectCallees(root, spec)) {
		const summ = summaries.get(call.name);
		if (!summ || summ.paramSinks.size === 0) continue;
		const args = callArgs(call.node);
		summ.paramSinks.forEach((sinkKind, i) => {
			const a = args[i];
			if (!a) return;
			const k = argKind(a, spec, tainted);
			if (!k) return;
			const isNetwork = sinkKind === "network";
			const isExec = sinkKind === "exec";
			let description: string | null = null;
			if (isNetwork && k === "sensitive") {
				description = `Sensitive data flows through '${call.name}()' into an internal network sink — possible data exfiltration.`;
			} else if (isExec && k === "input") {
				description = `Externally-controlled input flows through '${call.name}()' into an internal exec sink — possible injection.`;
			} else if (isExec && k === "sensitive") {
				description = `Sensitive data flows through '${call.name}()' into an internal exec sink.`;
			}
			if (!description) return;
			const line = call.node.startPosition.row + 1;
			const source: TaintNode = {
				file: filePath,
				line,
				label: k === "sensitive" ? "sensitive-source" : "input-source",
				type: "source",
			};
			const sink: TaintNode = { file: filePath, line, label: call.name, type: "sink" };
			sources.push(source);
			sinks.push(sink);
			flows.push({
				source,
				sink,
				path: [description],
				severity: riskySeverity(),
				description,
			});
		});
	}

	return { flows, sources, sinks };
}
