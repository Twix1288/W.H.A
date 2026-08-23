import { appendFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import * as path from "node:path";
import { parseSource } from "../core-scanner/parser";
import {
	detectCredentialExfil,
	detectStagedDownloadExec,
	isCredentialPath,
	normalizeShellCommand,
} from "../core-scanner/shell/normalize";
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
	/**
	 * "code" — content is source/commands to analyze.
	 * "path" — content is a filesystem path the tool is about to READ. Screened
	 *   against the sensitive-path rules; a direct read of credential material is
	 *   promoted to critical, because unlike a path appearing inside code, the tool
	 *   call itself is the intent to read that exact file.
	 */
	readonly kind?: "code" | "path";
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
		// Read-like tools have no executable content, so they used to return null and
		// were ALLOWED unconditionally — including `Read ~/.ssh/id_rsa`, which is the
		// exact scenario the product's own README opens with. They carry no code, but
		// they do carry a target path, and that path is screenable.
		case "Read":
		case "NotebookRead": {
			const p = toolInput.file_path ?? toolInput.notebook_path;
			return typeof p === "string" && p.trim()
				? { content: p, ext: ".path", what: `Read ${p}`, kind: "path" }
				: null;
		}
		case "Glob":
		case "Grep": {
			// A glob/grep can exfiltrate by targeting a credential directory.
			const parts = [toolInput.path, toolInput.pattern, toolInput.glob]
				.filter((v): v is string => typeof v === "string" && v.trim().length > 0);
			return parts.length
				? {
						content: parts.join(" "),
						ext: ".path",
						what: `${toolName} ${parts[0]}`,
						kind: "path",
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
	const isShell = code.ext === ".sh" || code.ext === ".bash";
	const isPath = code.kind === "path";
	try {
		if (isPath) {
			// A direct read of credential material. The sensitive-path pack rates these
			// `high` at 0.7 confidence because "a path reference alone isn't proof of
			// intent" — but a Read tool call IS the intent, so it ranks critical and the
			// default profile blocks it. Lower-signal paths (.env and friends) still go
			// through the pack at their own severity below.
			if (isCredentialPath(code.content)) {
				findings.push({
					ruleId: "path-credential-read",
					name: "Direct read of credential material",
					severity: "critical",
					category: "sensitive-path",
					message: `Reads credential material: ${code.content}`,
					line: 1,
					fixable: false,
				});
			}
		}
		// Shared, tunable rule packs first (reverse shells incl. script-body forms,
		// download-and-exec, credential-file exfil, injection, secrets, sensitive
		// paths) — the runtime attacks the AST rules don't all cover. The active
		// profile selects which pack rules apply.
		findings.push(...scanText(code.content, { profile, categories: RUNTIME_CATEGORIES }));

		if (isShell) {
			// Match the rule packs a SECOND time against the shell-normalized form.
			// Bash resolves quoting before executing, so `cu""rl`, `cur\l` and `'c'url`
			// all run curl while defeating a raw-text match. Scanning both forms keeps
			// every pattern that depends on raw syntax working while closing the
			// quote-splitting bypass. Findings are de-duplicated below.
			const normalized = normalizeShellCommand(code.content);
			if (normalized && normalized !== code.content) {
				findings.push(
					...scanText(normalized, { profile, categories: RUNTIME_CATEGORIES }),
				);
			}

			// Credential material reaching an egress command. The regex rule requires
			// the network tool to appear BEFORE the path, so the canonical
			// `cat ~/.ssh/id_rsa | curl …` ordering never matched it.
			const exfil = detectCredentialExfil(code.content);
			if (exfil) {
				findings.push({
					ruleId: "shell-credential-exfil",
					name: "Credential file piped to a network command",
					severity: "critical",
					category: "command",
					message: `Credential material '${exfil.path}' reaches '${exfil.egress}' in the same pipeline — this sends secrets off the machine.`,
					line: 1,
					fixable: false,
				});
			}

			// Download-then-execute split across commands is a flow, not a syntax
			// shape, so no pattern catches it: `curl … -o /tmp/x; bash /tmp/x`.
			const staged = detectStagedDownloadExec(code.content);
			if (staged) {
				findings.push({
					ruleId: "shell-staged-download-exec",
					name: "Downloaded file executed",
					severity: "critical",
					category: "command",
					message: `Downloads '${staged.path}' and then executes it (\`${staged.execCommand}\`) — remote code execution split across commands to evade a pipe-to-shell match.`,
					line: 1,
					fixable: false,
				});
			}
		}
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

	// Scanning both the raw and normalized forms can report the same rule twice.
	// Collapse by (ruleId, message) so the reason string stays readable.
	{
		const seen = new Set<string>();
		findings = findings.filter((f) => {
			const key = `${f.ruleId}\u0000${f.message}`;
			if (seen.has(key)) return false;
			seen.add(key);
			return true;
		});
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
/** Hard cap on hook payload size (bytes) — prevents unbounded memory growth. */
const MAX_PAYLOAD_BYTES = 8 * 1024 * 1024;
/** Wall-clock cap on reading stdin. */
const STDIN_TIMEOUT_MS = 5000;

/**
 * Read the hook payload from stdin.
 *
 * This runs in the agent's critical path, so it must be impossible to hang here:
 * a `guard` that never returns blocks every subsequent tool call indefinitely. The
 * TTY check alone was not enough — an open pipe that is never closed (a wrapper
 * that forgets to end stdin, a crashed writer) produced neither 'end' nor 'error'.
 * We therefore also bound by time and by size.
 */
function readStdin(): Promise<string> {
	return new Promise((resolve) => {
		let data = "";
		let settled = false;
		const finish = (value: string): void => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			resolve(value);
		};
		const timer = setTimeout(() => finish(data), STDIN_TIMEOUT_MS);
		// Don't hold the event loop open just for this timer.
		if (typeof timer.unref === "function") timer.unref();

		process.stdin.setEncoding("utf-8");
		process.stdin.on("data", (c) => {
			data += c;
			if (data.length > MAX_PAYLOAD_BYTES) {
				// Oversized payloads are truncated rather than buffered without bound;
				// JSON.parse will then fail and the caller decides (allow, unscreened).
				finish(data.slice(0, MAX_PAYLOAD_BYTES));
			}
		});
		process.stdin.on("end", () => finish(data));
		process.stdin.on("error", () => finish(data));
		// If nothing is piped in, don't hang forever.
		if (process.stdin.isTTY) finish("");
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
