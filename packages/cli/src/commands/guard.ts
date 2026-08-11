import { appendFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import * as path from "node:path";
import { parseSource } from "../core-scanner/parser";
import {
	RUNTIME_CATEGORIES,
	scanText,
} from "../core-scanner/patterns/index";
import { type Finding, RULES, runRules } from "../core-scanner/rules";
import { analyzeTaint, isTaintSupported } from "../core-scanner/taint/index";
import type { Severity } from "../core-scanner/types";

// ─── Profiles ─────────────────────────────────────────────────────────────
// A profile maps the worst finding severity to a decision. `deny` blocks the
// tool call; `ask` defers to the human; `allow` lets it run. The deterministic
// engine is always the gate — guard can't be prompt-injected the way an ML-only
// detector can, and it runs BEFORE the tool executes.
export type GuardProfile = "strict" | "default" | "permissive";
export type Decision = "allow" | "deny" | "ask";

const SEVERITY_RANK: Record<Severity, number> = {
	critical: 4,
	high: 3,
	medium: 2,
	low: 1,
	info: 0,
};

// For each profile, the minimum severity that triggers deny / ask.
const PROFILE_THRESHOLDS: Record<
	GuardProfile,
	{ deny: number; ask: number }
> = {
	strict: { deny: SEVERITY_RANK.high, ask: SEVERITY_RANK.medium },
	default: { deny: SEVERITY_RANK.critical, ask: SEVERITY_RANK.high },
	permissive: { deny: SEVERITY_RANK.critical, ask: SEVERITY_RANK.critical + 1 },
};

// ─── Tool-call → analyzable code ────────────────────────────────────────────
// Map a Claude Code tool call to the code/command it is about to run, plus the
// language extension to analyze it as. Tools with nothing executable to inspect
// return null (→ allow). This is where guard closes the "command patterns work
// except when the agent writes and executes code" hole: a Bash command or a
// Write/Edit of a script is analyzed by the SAME taint+rule engine as `check`,
// before it runs.
interface ExtractedCode {
	readonly content: string;
	readonly ext: string;
	readonly what: string;
}

export function extractCode(
	toolName: string,
	toolInput: Record<string, unknown>,
): ExtractedCode | null {
	const extOf = (p: unknown): string => {
		const e = typeof p === "string" ? path.extname(p) : "";
		return e || ".txt";
	};
	switch (toolName) {
		case "Bash": {
			const cmd = toolInput.command;
			return typeof cmd === "string" && cmd.trim()
				? { content: cmd, ext: ".sh", what: "Bash command" }
				: null;
		}
		case "Write": {
			const c = toolInput.content;
			return typeof c === "string"
				? {
						content: c,
						ext: extOf(toolInput.file_path),
						what: `Write ${toolInput.file_path ?? ""}`.trim(),
					}
				: null;
		}
		case "Edit": {
			const c = toolInput.new_string;
			return typeof c === "string"
				? {
						content: c,
						ext: extOf(toolInput.file_path),
						what: `Edit ${toolInput.file_path ?? ""}`.trim(),
					}
				: null;
		}
		case "MultiEdit": {
			const edits = Array.isArray(toolInput.edits) ? toolInput.edits : [];
			const joined = edits
				.map((e) =>
					e && typeof (e as any).new_string === "string"
						? (e as any).new_string
						: "",
				)
				.join("\n");
			return joined.trim()
				? {
						content: joined,
						ext: extOf(toolInput.file_path),
						what: `MultiEdit ${toolInput.file_path ?? ""}`.trim(),
					}
				: null;
		}
		case "NotebookEdit": {
			const c = toolInput.new_source;
			return typeof c === "string" && c.trim()
				? { content: c, ext: ".py", what: "NotebookEdit cell" }
				: null;
		}
		default:
			return null;
	}
}

// ─── Analysis ────────────────────────────────────────────────────────────────
export interface GuardVerdict {
	readonly decision: Decision;
	readonly worst: Severity | null;
	readonly reason: string;
	readonly findings: ReadonlyArray<{ ruleId: string; severity: string; message: string }>;
}

function rank(sev: string): number {
	return SEVERITY_RANK[sev as Severity] ?? 0;
}

/**
 * Run the deterministic rule + taint engine on a piece of code and decide.
 * Analysis errors fail CLOSED (deny) — like `check` should — because a security
 * gate must never wave through code it could not analyze. (Unknown/inert tool
 * calls never reach here; they are allowed upstream.)
 */
export function analyzeCode(
	code: ExtractedCode,
	profile: GuardProfile,
): GuardVerdict {
	let findings: Finding[] = [];
	try {
		// Shared, tunable rule packs first (reverse shells incl. script-body forms,
		// download-and-exec, credential-file exfil, injection, secrets, sensitive
		// paths) — the runtime attacks the AST rules don't all cover. The active
		// profile selects which pack rules apply.
		findings.push(...scanText(code.content, { profile, categories: RUNTIME_CATEGORIES }));
		const parseResult = parseSource(code.content, code.ext);
		findings.push(...runRules(parseResult, RULES));
		if (isTaintSupported(`x${code.ext}`)) {
			const taint = analyzeTaint([{ path: `x${code.ext}`, content: code.content }]);
			for (const flow of taint.flows) {
				findings.push({
					ruleId: "taint-dataflow",
					name: "Tainted data flow",
					severity: flow.severity,
					category: "data-flow",
					message: flow.description,
					line: flow.source.line ?? 0,
					fixable: false,
				});
			}
		}
	} catch (err) {
		const msg = err instanceof Error ? err.message : String(err);
		return {
			decision: "deny",
			worst: "high",
			reason: `analysis failed (${msg}) — blocking rather than running unanalyzed code`,
			findings: [],
		};
	}

	if (findings.length === 0) {
		return { decision: "allow", worst: null, reason: "no findings", findings: [] };
	}

	const worstRank = Math.max(...findings.map((f) => rank(f.severity)));
	const worst = findings.find((f) => rank(f.severity) === worstRank);
	const thresholds = PROFILE_THRESHOLDS[profile];
	let decision: Decision = "allow";
	if (worstRank >= thresholds.deny) decision = "deny";
	else if (worstRank >= thresholds.ask) decision = "ask";

	const summary = findings
		.slice()
		.sort((a, b) => rank(b.severity) - rank(a.severity))
		.slice(0, 3)
		.map((f) => `[${f.severity}] ${f.message}`)
		.join("; ");

	return {
		decision,
		worst: (worst?.severity as Severity) ?? null,
		reason: summary,
		findings: findings.map((f) => ({
			ruleId: f.ruleId,
			severity: f.severity,
			message: f.message,
		})),
	};
}

// ─── Durable local audit trail ────────────────────────────────────────────────
function auditDir(): string {
	return process.env.AGENTSHIELD_HOME ?? path.join(homedir(), ".wh-agent");
}

function appendAudit(entry: Record<string, unknown>): void {
	try {
		const dir = auditDir();
		if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
		appendFileSync(path.join(dir, "guard-audit.jsonl"), `${JSON.stringify(entry)}\n`);
	} catch {
		// Auditing is best-effort; never let a logging failure change the decision.
	}
}

// ─── Hook payload I/O ─────────────────────────────────────────────────────────
function readStdin(): Promise<string> {
	return new Promise((resolve) => {
		let data = "";
		process.stdin.setEncoding("utf-8");
		process.stdin.on("data", (c) => {
			data += c;
		});
		process.stdin.on("end", () => resolve(data));
		// If nothing is piped in, don't hang forever.
		if (process.stdin.isTTY) resolve("");
	});
}

interface GuardOptions {
	readonly profile?: string;
	readonly nowIso?: string; // injectable for tests
}

/**
 * `wh-agent guard` — evaluate a Claude Code PreToolUse hook payload on stdin and
 * emit an allow/ask/deny decision on stdout in the hook's JSON contract. This is
 * the in-path runtime enforcement layer: every tool call is screened by the
 * deterministic engine before it executes. Backend-free and local.
 */
export async function guard(options: GuardOptions): Promise<void> {
	const profile: GuardProfile = (["strict", "default", "permissive"] as const).includes(
		options.profile as GuardProfile,
	)
		? (options.profile as GuardProfile)
		: "default";

	const raw = await readStdin();
	let payload: Record<string, unknown>;
	try {
		payload = JSON.parse(raw);
	} catch {
		// We couldn't parse the hook payload itself — this is not a tool call we
		// understand, so allow (fail-open) rather than brick the agent on malformed
		// input. (Analysis errors on code we DID extract fail closed; see analyzeCode.)
		emitDecision("allow", "unparseable hook payload — not screened");
		return;
	}

	const toolName = String(payload.tool_name ?? "");
	const toolInput = (payload.tool_input as Record<string, unknown>) ?? {};
	const code = extractCode(toolName, toolInput);

	if (!code) {
		emitDecision("allow", `no executable content in ${toolName || "tool call"}`);
		return;
	}

	const verdict = analyzeCode(code, profile);
	appendAudit({
		ts: options.nowIso ?? new Date().toISOString(),
		tool: toolName,
		what: code.what,
		profile,
		decision: verdict.decision,
		worst: verdict.worst,
		reason: verdict.reason,
		session_id: payload.session_id ?? null,
	});
	emitDecision(verdict.decision, `${verdict.reason}`, code.what);
}

function emitDecision(decision: Decision, reason: string, what?: string): void {
	const prefix = what ? `W.H.Agent (${what}): ` : "W.H.Agent: ";
	const permissionDecisionReason =
		decision === "allow"
			? `${prefix}${reason}`
			: `${prefix}${decision === "deny" ? "blocked" : "needs review"} — ${reason}`;
	// Claude Code PreToolUse contract: exit 0 and print the decision as JSON.
	const out = {
		hookSpecificOutput: {
			hookEventName: "PreToolUse",
			permissionDecision: decision,
			permissionDecisionReason,
		},
	};
	process.stdout.write(`${JSON.stringify(out)}\n`);
	// On deny, also surface the reason on stderr for humans / non-JSON consumers.
	if (decision === "deny") process.stderr.write(`${permissionDecisionReason}\n`);
}

// ─── Installer ──────────────────────────────────────────────────────────────
const GUARD_MATCHER = "Bash|Write|Edit|MultiEdit|NotebookEdit";

/**
 * `wh-agent guard install [dir]` — register the guard as a PreToolUse hook in a
 * Claude Code settings.json, merging into any existing config (never clobbering).
 * A backup is written before any change.
 */
export async function guardInstall(
	targetDir: string | undefined,
	options: { profile?: string },
): Promise<void> {
	const dir = targetDir
		? path.resolve(targetDir)
		: existsSync(path.resolve(".claude"))
			? path.resolve(".claude")
			: path.join(homedir(), ".claude");
	if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
	const settingsPath = path.join(dir, "settings.json");

	let settings: Record<string, any> = {};
	if (existsSync(settingsPath)) {
		try {
			settings = JSON.parse(readFileSync(settingsPath, "utf-8"));
		} catch (err) {
			console.error(
				`❌ ${settingsPath} exists but is not valid JSON (${err instanceof Error ? err.message : err}). Refusing to overwrite. Add this hook manually:`,
			);
			console.error(guardHookSnippet(options.profile));
			process.exit(1);
		}
		// Never silently clobber a file the user maintains.
		writeFileSync(`${settingsPath}.bak`, readFileSync(settingsPath));
	}

	settings.hooks ??= {};
	const pre: any[] = Array.isArray(settings.hooks.PreToolUse)
		? settings.hooks.PreToolUse
		: [];
	const cmd = guardCommand(options.profile);
	const already = pre.some((block) =>
		Array.isArray(block?.hooks)
			? block.hooks.some((h: any) => typeof h?.command === "string" && h.command.includes("wh-agent guard"))
			: false,
	);
	if (already) {
		console.log("✓ wh-agent guard is already registered as a PreToolUse hook.");
		return;
	}
	pre.push({
		matcher: GUARD_MATCHER,
		hooks: [{ type: "command", command: cmd }],
	});
	settings.hooks.PreToolUse = pre;
	writeFileSync(settingsPath, `${JSON.stringify(settings, null, 2)}\n`);
	console.log(`✓ Registered wh-agent guard (PreToolUse) in ${settingsPath}`);
	if (existsSync(`${settingsPath}.bak`))
		console.log(`  (backup: ${settingsPath}.bak)`);
	console.log(
		`  Every ${GUARD_MATCHER} tool call is now screened by the deterministic engine before it runs.`,
	);
}

function guardCommand(profile?: string): string {
	return profile && profile !== "default"
		? `wh-agent guard --profile ${profile}`
		: "wh-agent guard";
}

function guardHookSnippet(profile?: string): string {
	return JSON.stringify(
		{
			hooks: {
				PreToolUse: [
					{ matcher: GUARD_MATCHER, hooks: [{ type: "command", command: guardCommand(profile) }] },
				],
			},
		},
		null,
		2,
	);
}
