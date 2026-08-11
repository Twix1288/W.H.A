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
		// Bare HTTP-verb methods so ANY receiver matches — catches
		// `s = requests.Session(); s.post(...)` and `import requests as r; r.post(...)`
		// (previously only the literal `session.post`/`requests.post` matched). `get`
		// is deliberately excluded (would false-positive on `dict.get`).
		"post",
		"put",
		"patch",
		"send",
		"sendall",
		"socket.send",
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
};

const BASH: LangSpec = {
	sensitiveSources: ["cat", "printenv", "env", "head", "less", "read"],
	inputSources: ["read", "curl", "wget"],
	networkSinks: ["curl", "wget", "nc", "netcat", "ssh", "scp"],
	execSinks: ["eval", "sh", "bash", "source", "exec"],
	callTypes: ["command", "command_substitution"],
	assignTypes: ["variable_assignment"],
	identifierTypes: ["variable_name", "word", "simple_expansion", "expansion"],
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
function calleeMatches(callee: string, patterns: string[]): boolean {
	return patterns.some(
		(p) =>
			callee === p || callee.endsWith("." + p) || callee.endsWith("::" + p),
	);
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

	return { flows, sources, sinks };
}
