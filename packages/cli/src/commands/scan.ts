import { writeStdoutSync } from "../util/stdout.js";
import {
	escapeMarkdown,
	sanitizeForDisplayInline,
} from "../util/untrusted-text.js";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { pathToFileURL } from "node:url";
import chalk from "chalk";
import { discoverGlobalAgents } from "../core-scanner/discovery.js";
import { calculateScore } from "../core-scanner/reporter/score.js";
import { renderTerminalReport } from "../core-scanner/reporter/terminal.js";
import { getDiscoverySkips } from "../core-scanner/scanner/discovery.js";
import { scan } from "../core-scanner/scanner/index.js";
import type { Finding, SecurityReport } from "../core-scanner/types.js";

interface ScanOptions {
	global?: boolean;
	format?: string;
	output?: string;
}

// ─── Watchdog State Tracking ──────────────────────────────────────────────

const STATE_FILE = path.join(os.homedir(), ".wh-agent", "state.json");

interface WatchdogState {
	lastScanTimestamp: string;
	findingHashes: string[];
}

function loadState(): WatchdogState | null {
	try {
		if (fs.existsSync(STATE_FILE)) {
			const data = fs.readFileSync(STATE_FILE, "utf-8");
			return JSON.parse(data);
		}
	} catch (_err) {
		// Ignore read errors
	}
	return null;
}

function saveState(state: WatchdogState) {
	try {
		const dir = path.dirname(STATE_FILE);
		if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
		fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));
	} catch (err) {
		console.error(`⚠️ Failed to save Watchdog state: ${err}`);
	}
}

function hashFinding(f: Finding): string {
	// Create a stable hash based on core attributes (ignoring volatile fields)
	const payload = `${f.id}:${f.file}:${f.line ?? 0}:${f.severity}`;
	return crypto.createHash("sha256").update(payload).digest("hex");
}

// ─── Output Formatters ──────────────────────────────────────────────────

/**
 * GitHub code scanning ranks findings by `security-severity`, not by SARIF level.
 * Without it every finding is filed as an undifferentiated "warning".
 */
const SECURITY_SEVERITY: Record<string, string> = {
	critical: "9.5",
	high: "8.0",
	medium: "5.0",
	low: "3.0",
	info: "1.0",
};

const CLI_VERSION: string = (() => {
	try {
		// eslint-disable-next-line @typescript-eslint/no-var-requires
		return require("../../package.json").version ?? "0.0.0";
	} catch {
		return "0.0.0";
	}
})();

function formatJson(
	reports: { agent: string; path: string; report: SecurityReport }[],
	failedTargets: ReadonlyArray<{ agent: string; path: string; error: string }> = [],
): string {
	// Coverage is part of the result, not a side note. Previously a target that
	// could not be read at all produced `findings: [], score: {grade: "A",
	// numericScore: 100}` — an authoritative all-clear for something never opened.
	// Any CI job consuming this JSON got a green light on an unaudited target.
	const entries = reports.map((r) => ({
		...r,
		status: r.report.summary.filesScanned > 0 ? "complete" : "empty",
		// A grade is only meaningful if something was actually analysed.
		...(r.report.summary.filesScanned === 0
			? {
					report: {
						...r.report,
						score: null,
						scoreSuppressedReason:
							"no files were analysed — this is not an all-clear",
					},
				}
			: {}),
	}));

	const failures = failedTargets.map((f) => ({
		agent: f.agent,
		path: f.path,
		status: "failed",
		error: f.error,
		report: null,
	}));

	return JSON.stringify([...entries, ...failures], null, 2);
}

function formatMarkdown(
	reports: { agent: string; path: string; report: SecurityReport }[],
	failedTargets: ReadonlyArray<{ agent: string; path: string; error: string }> = [],
): string {
	// Every interpolated value below comes from the scanned target, so all of it is
	// escaped. Unescaped, a scanned repo could emit its own headings, tables and
	// raw HTML into the report describing it — including a forged
	// "## No issues found" section.
	let md = "# W.H.Agent Security Scan Report\n\n";

	if (failedTargets.length > 0) {
		md += `> **${failedTargets.length} target(s) could not be scanned and are NOT audited.** `;
		md += "This report does not cover them.\n\n";
		for (const f of failedTargets) {
			md += `- \`${escapeMarkdown(f.agent)}\` (\`${escapeMarkdown(f.path)}\`): ${escapeMarkdown(f.error)}\n`;
		}
		md += "\n";
	}

	for (const r of reports) {
		md += `## ${escapeMarkdown(r.agent)} (${escapeMarkdown(r.path)})\n`;
		if (r.report.summary.filesScanned === 0) {
			md += "- **Score:** not applicable — no files were analysed (this is NOT an all-clear)\n";
		} else {
			md += `- **Score:** ${r.report.score.numericScore}/100 (Grade ${r.report.score.grade})\n`;
		}
		md += `- **Files scanned:** ${r.report.summary.filesScanned}\n`;
		md += `- **Critical:** ${r.report.summary.critical}\n`;
		md += `- **High:** ${r.report.summary.high}\n`;
		md += `- **Medium:** ${r.report.summary.medium}\n\n`;
		for (const f of r.report.findings) {
			md += `### [${f.severity.toUpperCase()}] ${escapeMarkdown(f.title)}\n`;
			md += `**File:** ${escapeMarkdown(f.file)}${f.line ? `:${f.line}` : ""}\n`;
			md += `${escapeMarkdown(f.description)}\n\n`;
		}
	}
	return md;
}

function formatSarif(
	reports: { agent: string; path: string; report: SecurityReport }[],
	failedTargets: ReadonlyArray<{ agent: string; path: string; error: string }> = [],
): string {
	const severityToLevel = (sev: string): string => {
		if (sev === "critical" || sev === "high") return "error";
		if (sev === "medium") return "warning";
		if (sev === "low" || sev === "info") return "note";
		return "none";
	};

	// SARIF requires every referenced ruleId to be declared in tool.driver.rules.
	// It was hardcoded to [] while every result carried a ruleId, so consumers
	// (GitHub code scanning included) had no rule metadata to attach — no name, no
	// description, no severity mapping.
	const ruleIndex = new Map<string, number>();
	const rules: unknown[] = [];
	const results: unknown[] = [];

	for (const r of reports) {
		for (const f of r.report.findings) {
			const ruleId = f.id;
			if (!ruleIndex.has(ruleId)) {
				ruleIndex.set(ruleId, rules.length);
				rules.push({
					id: ruleId,
					name: ruleId,
					shortDescription: { text: sanitizeForDisplayInline(f.title, 200) },
					fullDescription: { text: sanitizeForDisplayInline(f.description, 1000) },
					defaultConfiguration: { level: severityToLevel(f.severity) },
					properties: {
						"security-severity": SECURITY_SEVERITY[f.severity] ?? "0.0",
						tags: ["security", f.category].filter(Boolean),
					},
				});
			}

			// artifactLocation.uri must be a URI a consumer can resolve. Absolute
			// filesystem paths (and paths relative to the scanned config directory
			// rather than the repo root) do not attach to any file in GitHub code
			// scanning, so findings silently vanish from the PR view. Emit a repo-root
			// relative URI plus an explicit uriBaseId.
			const abs = path.isAbsolute(f.file) ? f.file : path.join(r.path, f.file);
			const rel = path.relative(process.cwd(), abs);
			const insideRepo = Boolean(rel) && !rel.startsWith("..") && !path.isAbsolute(rel);
			// Only claim a base id when the URI is genuinely relative to it. A target
			// outside the working directory gets an absolute file:// URI instead —
			// claiming %SRCROOT% for an absolute path makes the location unresolvable.
			const artifactLocation = insideRepo
				? { uri: rel.split(path.sep).join("/"), uriBaseId: "%SRCROOT%" }
				: { uri: pathToFileURL(abs).href };

			results.push({
				ruleId,
				ruleIndex: ruleIndex.get(ruleId),
				level: severityToLevel(f.severity),
				message: { text: sanitizeForDisplayInline(f.title, 1000) },
				locations: [
					{
						physicalLocation: {
							artifactLocation,
							// SARIF forbids startLine < 1; omit the region rather than emit 0.
							...(f.line && f.line > 0
								? { region: { startLine: f.line } }
								: {}),
						},
					},
				],
			});
		}
	}

	// A scan that could not read its target is a failed invocation, not a clean
	// run. `executionSuccessful: false` is the standard way to say so, and it stops
	// consumers treating an empty results array as "no problems found".
	const notifications = failedTargets.map((f) => ({
		level: "error",
		message: {
			text: `Target could not be scanned and is NOT audited: ${sanitizeForDisplayInline(`${f.agent} (${f.path}): ${f.error}`, 500)}`,
		},
	}));
	const scannedAnything = reports.some((r) => r.report.summary.filesScanned > 0);
	if (!scannedAnything && reports.length > 0) {
		notifications.push({
			level: "error",
			message: {
				text: "No files were analysed — an empty result set here does not mean the target is clean.",
			},
		});
	}

	const sarif = {
		version: "2.1.0",
		$schema:
			"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		runs: [
			{
				tool: {
					driver: {
						name: "W.H.Agent",
						version: CLI_VERSION,
						informationUri: "https://github.com/wh-agent/wh-agent",
						rules,
					},
				},
				invocations: [
					{
						executionSuccessful:
							failedTargets.length === 0 && (scannedAnything || reports.length === 0),
						...(notifications.length > 0
							? { toolExecutionNotifications: notifications }
							: {}),
					},
				],
				results,
			},
		],
	};
	return JSON.stringify(sarif, null, 2);
}

// ─── Main Scanner Engine ────────────────────────────────────────────────

export async function scanConfig(
	targetPath: string | undefined,
	options: ScanOptions,
) {
	const isGlobal = options.global || false;
	const format = options.format || "terminal";

	let targets: { agent: string; path: string }[] = [];

	// Human-facing progress lines must go to STDERR in machine-readable formats,
	// otherwise they corrupt the JSON/SARIF/markdown document on stdout (a CI
	// pipeline doing `scan --global --format json | jq` would fail to parse).
	const isMachineFormat = format === "json" || format === "sarif";
	const progress = (msg: string) => {
		if (isMachineFormat) process.stderr.write(`${msg}\n`);
		else console.log(msg);
	};

	if (isGlobal) {
		progress(chalk.blue(`\n🔍 Auto-discovering global agent configurations...`));
		const discovered = discoverGlobalAgents();
		if (discovered.length === 0) {
			progress(chalk.yellow(`No supported agents found on the system.`));
			process.exit(0);
		}
		targets = discovered.map((d) => ({ agent: d.name, path: d.path }));
		progress(chalk.green(`Found ${targets.length} agent environments.\n`));
	} else {
		const p = targetPath ? path.resolve(targetPath) : process.cwd();
		if (!fs.existsSync(p)) {
			console.error(chalk.red(`❌ Path not found: ${p}`));
			process.exit(1);
		}
		targets = [{ agent: "Local Project", path: p }];
	}

	const reports: { agent: string; path: string; report: SecurityReport }[] = [];
	let totalCritical = 0;
	let totalFindings = 0;
	let totalFilesScanned = 0;
	// Targets whose scan threw. These used to be printed and then FORGOTTEN: with
	// `--global`, an agent environment that failed to scan left the run reporting
	// "Scan passed" and exiting 0, so an entire un-audited environment looked clean.
	// A scanner that could not look must never report a pass.
	const failedTargets: { agent: string; path: string; error: string }[] = [];
	// Files discovery could not open (oversize, symlink, permission denied).
	const skipped: { path: string; reason: string }[] = [];

	for (const target of targets) {
		try {
			const result = scan(target.path);
			const report = calculateScore(result);
			reports.push({ agent: target.agent, path: target.path, report });

			totalCritical += report.summary.critical;
			totalFindings += report.summary.totalFindings;
			totalFilesScanned += report.summary.filesScanned;
			for (const s of getDiscoverySkips()) skipped.push({ path: s.path, reason: s.reason });
		} catch (err) {
			const message = err instanceof Error ? err.message : String(err);
			failedTargets.push({ agent: target.agent, path: target.path, error: message });
			console.error(
				chalk.red(`❌ Failed to scan ${target.agent} (${target.path}): ${message}`),
			);
		}
	}

	// Handle State Tracking / Watchdog Diffing
	const previousState = loadState();
	const currentHashes = new Set<string>();
	let newFindingsCount = 0;

	for (const r of reports) {
		for (const f of r.report.findings) {
			const h = hashFinding(f);
			currentHashes.add(h);
			if (previousState && !previousState.findingHashes.includes(h)) {
				newFindingsCount++;
			}
		}
	}

	// Save new state
	saveState({
		lastScanTimestamp: new Date().toISOString(),
		findingHashes: Array.from(currentHashes),
	});

	// Honest empty-result guard — applied to EVERY format, BEFORE the machine-format
	// dispatch. A 0-file scan is NOT an all-clear (it usually means scan was pointed
	// at a leaf folder rather than an agent config root). Previously this guard sat
	// AFTER the json/sarif/markdown block, so machine consumers got a misleading
	// "Grade A / exit 0" green. Now it fails closed with a non-zero exit in all
	// formats; machine formats still emit a structured body (to stdout) plus a
	// human warning on stderr so a pipeline both gets data and learns nothing ran.
	if (totalFilesScanned === 0) {
		const where = isGlobal
			? "the discovered agent environments"
			: targetPath
				? path.resolve(targetPath)
				: process.cwd();
		const warn = [
			`\n⚠️  No agent configuration files were found in ${where}.`,
			`   Nothing was scanned — this is NOT an all-clear. Point scan at a project root or a .claude directory`,
			`   (e.g. 'wh-agent scan ~/.claude'), or use --global. To deep-scan a single script, use 'wh-agent check <file>'.`,
		];
		if (format === "terminal") {
			console.log(chalk.yellow(warn[0]));
			console.log(chalk.gray(warn.slice(1).join("\n")));
		} else {
			for (const l of warn) process.stderr.write(`${l}\n`);
			let outputStr = "";
			if (format === "json") outputStr = formatJson(reports, failedTargets);
			else if (format === "markdown") outputStr = formatMarkdown(reports, failedTargets);
			else if (format === "sarif") outputStr = formatSarif(reports, failedTargets);
			if (options.output) {
				try {
					fs.writeFileSync(options.output, outputStr);
				} catch {
					// Never lose the report because the destination was unwritable.
					if (outputStr) writeStdoutSync(outputStr);
				}
			} else if (outputStr) writeStdoutSync(outputStr);
		}
		process.exit(1);
	}

	// ─── Coverage reporting ──────────────────────────────────────────────────
	// Print what we could NOT analyze before any pass/fail verdict, so the verdict
	// is always read alongside its coverage.
	if (skipped.length > 0) {
		console.error(
			chalk.yellow(
				`\n⚠️  ${skipped.length} file(s) were not analyzed (not counted as clean):`,
			),
		);
		for (const s of skipped.slice(0, 10)) {
			console.error(chalk.gray(`     - ${s.path} — ${s.reason}`));
		}
		if (skipped.length > 10) {
			console.error(chalk.gray(`     … and ${skipped.length - 10} more`));
		}
	}
	if (failedTargets.length > 0) {
		console.error(
			chalk.red(
				`\n🛑 ${failedTargets.length} of ${targets.length} target(s) FAILED to scan and are un-audited:`,
			),
		);
		for (const f of failedTargets) {
			console.error(chalk.gray(`     - ${f.agent} (${f.path}): ${f.error}`));
		}
	}

	/**
	 * Exit status. A scan that could not complete is an ERROR, not a pass — even if
	 * every target it *did* manage to read came back clean.
	 */
	const scanExitCode = (): number => {
		if (failedTargets.length > 0) return 1;
		return totalCritical > 0 ? 2 : 0;
	};

	// Handle Custom Output Formats
	if (format !== "terminal") {
		let outputStr = "";
		if (format === "json") outputStr = formatJson(reports, failedTargets);
		else if (format === "markdown") outputStr = formatMarkdown(reports, failedTargets);
		else if (format === "sarif") outputStr = formatSarif(reports, failedTargets);
		else {
			console.error(chalk.red(`❌ Unsupported format: ${format}`));
			process.exit(1);
		}

		if (options.output) {
			// A failed write must not destroy the report or mask the findings. This
			// used to throw into the generic "Scan failed" handler, which discarded
			// the entire report AND replaced the findings-based exit code with a
			// generic one — so an unwritable path turned a CRITICAL result into an
			// indistinguishable tooling error. Fall back to stdout so the analysis
			// is never lost, and keep the findings-based status.
			try {
				fs.writeFileSync(options.output, outputStr);
				console.error(chalk.green(`✅ Report written to ${options.output}`));
			} catch (err) {
				const message = err instanceof Error ? err.message : String(err);
				console.error(
					chalk.red(
						`⚠️  Could not write ${options.output} (${message}). Emitting the report on stdout instead so it is not lost.`,
					),
				);
				writeStdoutSync(outputStr);
			}
		} else {
			writeStdoutSync(outputStr);
		}
		process.exit(scanExitCode());
	}

	// Terminal Reporting
	if (isGlobal) {
		// Print Summary Table
		console.log(chalk.bold("System-Wide Agent Security Posture"));
		console.log("━".repeat(110));
		console.log(
			`${"AGENT".padEnd(20)} | ${"PATH".padEnd(45)} | ${"SCORE".padEnd(6)} | ${"CRIT".padEnd(5)} | ${"HIGH".padEnd(5)} | ${"MED".padEnd(4)} | ${"LOW".padEnd(4)}`,
		);
		console.log("━".repeat(110));

		for (const r of reports) {
			const pStr =
				r.path.length > 45
					? `...${r.path.substring(r.path.length - 42)}`
					: r.path.padEnd(45);
			const s = r.report.summary;
			const scoreColor =
				r.report.score.numericScore >= 90
					? chalk.green
					: r.report.score.numericScore >= 70
						? chalk.yellow
						: chalk.red;

			console.log(
				`${r.agent.padEnd(20)} | ${pStr} | ${scoreColor(r.report.score.grade.padEnd(6))} | ${s.critical.toString().padEnd(5)} | ${s.high.toString().padEnd(5)} | ${s.medium.toString().padEnd(4)} | ${s.low.toString().padEnd(4)}`,
			);
		}
		console.log("━".repeat(110));

		if (previousState && newFindingsCount > 0) {
			console.log(
				chalk.bgRed.white.bold(
					` ⚠️ WATCHDOG ALERT: ${newFindingsCount} NEW configuration vulnerabilities detected since last scan! `,
				),
			);
		}
		console.log(
			chalk.gray(
				`\nHint: Use --format json --output report.json to export detailed findings.`,
			),
		);
	} else {
		// Single local project: print the normal full report
		const renderedReport = renderTerminalReport(reports[0].report);
		console.log(renderedReport);

		if (previousState && newFindingsCount > 0) {
			console.log(
				chalk.bgRed.white.bold(
					`\n ⚠️ WATCHDOG ALERT: ${newFindingsCount} NEW vulnerabilities detected since last scan! `,
				),
			);
		}
	}

	if (totalCritical > 0) {
		console.error(chalk.red(`\n🚨 Scan finished with CRITICAL findings!`));
		process.exit(2);
	} else if (failedTargets.length > 0) {
		// Never claim a pass when a target could not be read.
		console.error(
			chalk.red(
				`\n🛑 Scan INCOMPLETE: ${failedTargets.length} target(s) could not be audited. This is not a pass.`,
			),
		);
		process.exit(1);
	} else if (totalFindings > 0) {
		console.log(chalk.yellow(`\n⚠️ Scan finished with findings.`));
	} else if (skipped.length > 0) {
		console.log(
			chalk.yellow(
				`\n⚠️ No vulnerabilities found in what was analyzed, but ${skipped.length} file(s) were skipped (see above).`,
			),
		);
	} else {
		console.log(
			chalk.green(`\n✅ Scan passed! No configuration vulnerabilities found.`),
		);
	}
}
