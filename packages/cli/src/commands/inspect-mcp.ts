import { execFileSync } from "node:child_process";
import { writeStdoutSync } from "../util/stdout.js";
import { sanitizeForDisplayInline } from "../util/untrusted-text.js";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import chalk from "chalk";
import { calculateScore } from "../core-scanner/reporter/score.js";
import { renderTerminalReport } from "../core-scanner/reporter/terminal.js";
import { getBuiltinRules } from "../core-scanner/rules/index.js";
import { analyzeMcpToolText } from "../core-scanner/rules/mcp-tool-poisoning.js";
import { discoverConfigFiles } from "../core-scanner/scanner/index.js";
import type {
	ConfigFile,
	Finding,
	SecurityReport,
} from "../core-scanner/types.js";

export interface InspectMcpOptions {
	config?: string;
	server?: string;
	transport?: string;
	live?: boolean;
	ui?: boolean;
	format?: string;
	output?: string;
	timeout?: string;
}

interface ServerEntry {
	command?: string;
	args?: string[];
	env?: Record<string, string>;
	description?: string;
	url?: string;
	[k: string]: unknown;
}

interface ResolvedTarget {
	label: string; // human-facing
	serverName: string; // key used in the synthetic config
	entry: ServerEntry;
	// Arguments to pass to the Inspector CLI immediately after `--cli`.
	connection: string[];
	sourceConfigPath?: string; // config file the server was resolved from
}

// Common global MCP config locations, checked when a bare name isn't found in
// the current project. Keeps `inspect-mcp <name>` working for globally-installed
// servers without the user having to pass a path.
function globalConfigCandidates(): string[] {
	const home = os.homedir();
	return [
		path.join(home, ".claude.json"),
		path.join(home, ".claude", "mcp.json"),
		path.join(home, ".claude", "settings.json"),
		path.join(home, ".cursor", "mcp.json"),
		path.join(
			home,
			"Library",
			"Application Support",
			"Claude",
			"claude_desktop_config.json",
		),
		path.join(home, ".config", "Claude", "claude_desktop_config.json"),
	];
}

function readServersFrom(filePath: string): Record<string, ServerEntry> | null {
	try {
		const parsed = JSON.parse(fs.readFileSync(filePath, "utf-8"));
		const servers = parsed?.mcpServers;
		if (servers && typeof servers === "object" && !Array.isArray(servers)) {
			// Strip the prototype so no lookup can ever reach Object.prototype.
			return Object.assign(Object.create(null), servers) as Record<
				string,
				ServerEntry
			>;
		}
	} catch {
		// ignore unreadable/invalid config
	}
	return null;
}

// Collect every declared MCP server across the project (discovered configs) and
// the well-known global locations, so we can resolve a name and list options.
function collectAllServers(): {
	byName: Map<string, { entry: ServerEntry; configPath: string }>;
} {
	const byName = new Map<string, { entry: ServerEntry; configPath: string }>();

	const addFrom = (configPath: string, servers: Record<string, ServerEntry>) => {
		for (const [name, entry] of Object.entries(servers)) {
			if (!byName.has(name)) byName.set(name, { entry: entry ?? {}, configPath });
		}
	};

	try {
		const discovered = discoverConfigFiles(process.cwd());
		for (const f of discovered.files) {
			if (f.type !== "mcp-json" && f.type !== "settings-json") continue;
			try {
				const parsed = JSON.parse(f.content);
				if (parsed?.mcpServers && typeof parsed.mcpServers === "object") {
					addFrom(path.resolve(f.path), parsed.mcpServers);
				}
			} catch {
				// skip invalid JSON
			}
		}
	} catch {
		// discovery may throw on odd cwd; fall through to globals
	}

	for (const candidate of globalConfigCandidates()) {
		if (!fs.existsSync(candidate)) continue;
		const servers = readServersFrom(candidate);
		if (servers) addFrom(candidate, servers);
	}

	return { byName };
}

function looksLikeUrl(s: string): boolean {
	return /^https?:\/\//i.test(s);
}

const KNOWN_RUNNERS = new Set([
	"npx", "node", "bunx", "bun", "deno", "python", "python3", "uv", "uvx",
	"docker", "podman", "sh", "bash", "pnpm", "yarn",
]);

function looksLikeCommand(s: string): boolean {
	if (s.includes(" ")) return true;
	const first = s.split(/\s+/)[0];
	if (KNOWN_RUNNERS.has(first)) return true;
	if (s.startsWith("/") || s.startsWith("./") || s.startsWith("~/")) return true;
	return false;
}

function resolveTarget(
	target: string | undefined,
	options: InspectMcpOptions,
): ResolvedTarget {
	// 1. Explicit --config + --server (mirrors the Inspector's own flags).
	if (options.config && options.server) {
		const cfgPath = path.resolve(options.config);
		if (!fs.existsSync(cfgPath)) {
			fail(`Config file not found: ${cfgPath}`);
		}
		const servers = readServersFrom(cfgPath);
		// Object.hasOwn, not a bare index: `servers["toString"]` on a plain object
		// parsed from JSON returns Object.prototype.toString — a truthy function —
		// so `--server toString` (or constructor, valueOf, __proto__ …) resolved to
		// an inherited property and was inspected as if it were a real server,
		// producing a grade-A "no issues found" report for a server that does not
		// exist.
		const entry =
			servers && Object.hasOwn(servers, options.server)
				? servers[options.server]
				: undefined;
		if (!entry || typeof entry !== "object") {
			fail(
				`Server "${options.server}" not found in ${cfgPath}.` +
					(servers ? ` Available: ${Object.keys(servers).join(", ") || "(none)"}` : ""),
			);
		}
		return {
			label: options.server,
			serverName: options.server,
			entry: entry as ServerEntry,
			connection: ["--config", cfgPath, "--server", options.server],
			sourceConfigPath: cfgPath,
		};
	}

	if (!target) {
		fail(
			"Provide an MCP server name, a command, or a URL — e.g.\n" +
				"  wh-agent inspect-mcp github\n" +
				"  wh-agent inspect-mcp --config ./mcp.json --server github\n" +
				'  wh-agent inspect-mcp "npx -y @modelcontextprotocol/server-github"\n' +
				"  wh-agent inspect-mcp https://my-server.example.com --transport http",
		);
	}

	// 2. Remote URL.
	if (looksLikeUrl(target as string)) {
		return {
			label: target as string,
			serverName: target as string,
			entry: { url: target as string },
			connection: [target as string],
		};
	}

	// 3. Named server resolved from project/global configs (the common case).
	const { byName } = collectAllServers();
	const found = byName.get(target as string);
	if (found) {
		const e = found.entry;
		const connection = e.url
			? [e.url]
			: ["--config", found.configPath, "--server", target as string];
		return {
			label: target as string,
			serverName: target as string,
			entry: e,
			connection,
			sourceConfigPath: found.configPath,
		};
	}

	// 4. Raw command string.
	if (looksLikeCommand(target as string)) {
		const parts = (target as string).split(/\s+/).filter(Boolean);
		return {
			label: target as string,
			serverName: parts[0] ?? "server",
			entry: { command: parts[0], args: parts.slice(1) },
			connection: parts,
		};
	}

	// 5. Bare word that isn't a known server or a command.
	const names = [...byName.keys()];
	fail(
		`No MCP server named "${target}" was found in your project or global configs` +
			(names.length ? `.\n   Known servers: ${names.join(", ")}` : " (no MCP servers configured).") +
			`\n   Pass a full command instead, e.g.: wh-agent inspect-mcp "npx -y ${target}"`,
	);
}

function fail(msg: string): never {
	console.error(chalk.red(`❌ ${msg}`));
	process.exit(1);
}

// ─── Live enumeration via the official Anthropic MCP Inspector ────────────

interface LiveTool {
	name?: string;
	description?: string;
	inputSchema?: unknown;
}

function runInspector(
	connection: string[],
	method: string,
	transport: string | undefined,
	timeoutMs: number,
): unknown {
	const args = [
		"--yes",
		"@modelcontextprotocol/inspector",
		"--cli",
		...connection,
		"--method",
		method,
	];
	if (transport) args.push("--transport", transport);
	// execFile (argv array) — never a shell string, so nothing in the command or
	// server name can be interpreted by a shell.
	const out = execFileSync("npx", args, {
		encoding: "utf-8",
		timeout: timeoutMs,
		maxBuffer: 16 * 1024 * 1024,
		stdio: ["ignore", "pipe", "pipe"],
	});
	return JSON.parse(out);
}

function liveFindings(
	target: ResolvedTarget,
	options: InspectMcpOptions,
): { findings: Finding[]; toolCount: number; succeeded: boolean; error: string | null } {
	const findings: Finding[] = [];
	// `Number("abc")` is NaN and `Math.max(5000, NaN)` is NaN, which execFileSync
	// rejects with ERR_OUT_OF_RANGE — so `--timeout abc` silently skipped live
	// enumeration entirely while still reporting a clean result.
	const rawTimeout = Number(options.timeout ?? "45");
	if (!Number.isFinite(rawTimeout) || rawTimeout <= 0) {
		const message = `invalid --timeout "${String(options.timeout)}" (expected a positive number of seconds)`;
		console.error(chalk.red(`   ⚠️  ${message}`));
		return { findings, toolCount: 0, succeeded: false, error: message };
	}
	const timeoutMs = Math.max(5000, rawTimeout * 1000);

	console.error(
		chalk.yellow.bold(
			"\n⚠️  --live EXECUTES the MCP server to enumerate its tools (this runs arbitrary\n" +
				"   code from the server). Only use --live on servers you are willing to run.\n",
		),
	);
	console.error(chalk.gray(`   Connecting via the MCP Inspector CLI...`));

	let tools: LiveTool[] = [];
	try {
		const result = runInspector(
			target.connection,
			"tools/list",
			options.transport,
			timeoutMs,
		) as { tools?: LiveTool[] };
		tools = Array.isArray(result?.tools) ? result.tools : [];
	} catch (err) {
		const msg = err instanceof Error ? err.message : String(err);
		const firstLine = msg.split("\n")[0] ?? msg;
		console.error(
			chalk.red(
				`   ⚠️  Live enumeration failed (${firstLine}).\n` +
					"   Static findings above still apply. Ensure npx is available and the server starts.",
			),
		);
		// This failure used to be written ONLY to stderr while the report still
		// scored grade A and exited 0. Any CI job consuming -f json/-f sarif — or
		// any user who redirects stderr — got an authoritative "clean" verdict for
		// a server that was never inspected. Worse, the server being audited
		// controls the trigger: emitting more than maxBuffer of tools/list output
		// causes ENOBUFS, so a malicious server can suppress its own live analysis.
		// The failure is now a finding, so it appears in every output format.
		findings.push({
			id: "mcp-live-enumeration-failed",
			severity: "high",
			category: "mcp",
			title: "Live enumeration was requested but did not complete",
			description:
				`--live was requested but the server's tools could not be enumerated (${sanitizeForDisplayInline(firstLine, 300)}). ` +
				"No live tool descriptions were analysed, so this report covers the static configuration ONLY. " +
				"A server can trigger this deliberately (for example by returning more output than the inspector will buffer) to suppress analysis of its own tools.",
			file: target.label,
			evidence: sanitizeForDisplayInline(firstLine, 200),
			fix: {
				description:
					"Re-run --live after confirming npx is available and the server starts, and treat this server as un-inspected until it succeeds",
				before: "live enumeration did not complete",
				after: "live enumeration completes and tool descriptions are analysed",
				auto: false,
			},
		});
		return { findings, toolCount: 0, succeeded: false, error: firstLine };
	}

	for (const tool of tools) {
		const schemaText = tool.inputSchema
			? JSON.stringify(tool.inputSchema)
			: "";
		const hits = analyzeMcpToolText(
			tool.name ?? "",
			tool.description ?? "",
			schemaText,
		);
		for (const hit of hits) {
			findings.push({
				id: "mcp-live-tool-poisoning",
				severity: hit.severity,
				category: "mcp",
				title: hit.title,
				description: hit.description,
				file: `${target.label} (live tool: ${tool.name ?? "?"})`,
				evidence: hit.evidence,
			});
		}
	}

	console.error(
		chalk.gray(
			`   Enumerated ${tools.length} live tool(s); ${findings.length} issue(s) found in tool metadata.`,
		),
	);
	return { findings, toolCount: tools.length, succeeded: true, error: null };
}

// ─── Output ───────────────────────────────────────────────

function toSarif(report: SecurityReport): string {
	return JSON.stringify(
		{
			version: "2.1.0",
			$schema: "http://json.schemastore.org/sarif-2.1.0-rtm.5",
			runs: [
				{
					tool: { driver: { name: "W.H.Agent inspect-mcp" } },
					results: report.findings.map((f) => ({
						ruleId: f.id,
						level: f.severity === "critical" ? "error" : f.severity === "info" ? "note" : "warning",
						message: { text: `${f.title} — ${f.description}` },
						locations: [
							{
								physicalLocation: {
									artifactLocation: { uri: f.file },
									...(f.line ? { region: { startLine: f.line } } : {}),
								},
							},
						],
					})),
				},
			],
		},
		null,
		2,
	);
}

export async function inspectMcp(
	target: string | undefined,
	options: InspectMcpOptions,
): Promise<void> {
	const format = options.format || "terminal";
	const resolved = resolveTarget(target, options);

	// --ui: hand off to the official Inspector web UI for interactive exploration.
	if (options.ui) {
		console.log(
			chalk.yellow(
				"⚠️  Launching the MCP Inspector web UI — this EXECUTES the server. Ctrl+C to stop.\n",
			),
		);
		try {
			execFileSync(
				"npx",
				["--yes", "@modelcontextprotocol/inspector", ...resolved.connection],
				{ stdio: "inherit" },
			);
		} catch (err) {
			fail(`Failed to launch the Inspector UI: ${err instanceof Error ? err.message : String(err)}`);
		}
		return;
	}

	if (format === "terminal") {
		console.log(
			chalk.blue(`\n🔍 Inspecting MCP server: ${chalk.bold(resolved.label)}`),
		);
		if (resolved.sourceConfigPath) {
			console.log(chalk.gray(`   Resolved from: ${resolved.sourceConfigPath}`));
		}
	}

	// 1. Static analysis — reuse the full built-in rule set on the resolved entry.
	const synthetic: ConfigFile = {
		path: `${resolved.label} (resolved MCP config)`,
		type: "mcp-json",
		content: JSON.stringify(
			{ mcpServers: { [resolved.serverName]: resolved.entry } },
			null,
			2,
		),
	};
	const findings: Finding[] = [];
	for (const rule of getBuiltinRules()) {
		try {
			findings.push(...rule.check(synthetic, [synthetic]));
		} catch {
			// a single misbehaving rule must not abort the whole inspection
		}
	}

	// 2. Live analysis (opt-in).
	let liveToolCount = 0;
	let liveStatus: {
		requested: boolean;
		succeeded: boolean;
		error: string | null;
		toolsEnumerated: number;
	} = { requested: false, succeeded: false, error: null, toolsEnumerated: 0 };
	if (options.live) {
		const live = liveFindings(resolved, options);
		findings.push(...live.findings);
		liveToolCount = live.toolCount;
		liveStatus = {
			requested: true,
			succeeded: live.succeeded,
			error: live.error,
			toolsEnumerated: live.toolCount,
		};
	}

	// 3. Build + render the report (same model as `scan`).
	const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
	findings.sort((a, b) => order[a.severity] - order[b.severity]);
	const report = calculateScore({
		target: { path: resolved.label, files: [synthetic] },
		findings,
	});

	if (format === "json") {
		// The envelope records whether live enumeration ran, so a consumer can never
		// mistake "we did not look" for "we looked and it was clean".
		const out = JSON.stringify({ ...report, liveEnumeration: liveStatus }, null, 2);
		if (options.output) fs.writeFileSync(options.output, out);
		// writeStdoutSync, not console.log: process.exit() discards pending async
		// pipe writes, which truncated this report at the pipe buffer whenever the
		// consumer was another process.
		else writeStdoutSync(out);
	} else if (format === "sarif") {
		const out = toSarif(report);
		if (options.output) fs.writeFileSync(options.output, out);
		else writeStdoutSync(out);
	} else {
		console.log(renderTerminalReport(report));
		if (!options.live) {
			console.log(
				chalk.gray(
					"\nℹ️  This was a STATIC inspection (server not executed). Add --live to enumerate\n" +
						"   the server's actual tools/resources and scan their descriptions for poisoning.",
				),
			);
		} else {
			console.log(chalk.gray(`\nLive tools enumerated: ${liveToolCount}`));
		}
		if (report.summary.critical > 0) {
			console.error(chalk.red(`\n🚨 CRITICAL findings — do not trust this MCP server as-is.`));
		} else if (report.summary.totalFindings > 0) {
			console.log(chalk.yellow(`\n⚠️  Findings present — review before trusting this server.`));
		} else {
			console.log(chalk.green(`\n✅ No issues found in the inspected configuration.`));
		}
	}

	// Exit status.
	//   2 = critical findings
	//   1 = high findings, or --live was requested and did not complete
	//   0 = clean
	// Previously this was `critical > 0 ? 2 : 0`, so a config piping ~/.ssh/id_rsa
	// to a webhook — a HIGH finding — exited 0 and passed any CI gate. An
	// incomplete live analysis also exited 0 with a grade-A score.
	if (report.summary.critical > 0) process.exit(2);
	if (report.summary.high > 0) process.exit(1);
	if (liveStatus.requested && !liveStatus.succeeded) process.exit(1);
	process.exit(0);
}
