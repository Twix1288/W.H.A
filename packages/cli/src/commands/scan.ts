import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import * as crypto from "node:crypto";
import chalk from "chalk";
import { scan } from "../core-scanner/scanner/index.js";
import { calculateScore } from "../core-scanner/reporter/score.js";
import { renderTerminalReport } from "../core-scanner/reporter/terminal.js";
import { discoverGlobalAgents, DiscoveredAgent } from "../core-scanner/discovery.js";
import type { SecurityReport, Finding } from "../core-scanner/types.js";

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
  } catch (err) {
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

function formatJson(reports: { agent: string; path: string; report: SecurityReport }[]): string {
  return JSON.stringify(reports, null, 2);
}

function formatMarkdown(reports: { agent: string; path: string; report: SecurityReport }[]): string {
  let md = "# W.H.Agent Security Scan Report\n\n";
  for (const r of reports) {
    md += `## ${r.agent} (${r.path})\n`;
    md += `- **Score:** ${r.report.score.numericScore}/100 (Grade ${r.report.score.grade})\n`;
    md += `- **Critical:** ${r.report.summary.critical}\n`;
    md += `- **High:** ${r.report.summary.high}\n`;
    md += `- **Medium:** ${r.report.summary.medium}\n\n`;
    for (const f of r.report.findings) {
      md += `### [${f.severity.toUpperCase()}] ${f.title}\n`;
      md += `**File:** ${f.file}${f.line ? `:${f.line}` : ''}\n`;
      md += `${f.description}\n\n`;
    }
  }
  return md;
}

function formatSarif(reports: { agent: string; path: string; report: SecurityReport }[]): string {
  // Basic SARIF structure
  const sarif: any = {
    version: "2.1.0",
    $schema: "http://json.schemastore.org/sarif-2.1.0-rtm.5",
    runs: [
      {
        tool: {
          driver: {
            name: "W.H.Agent",
            version: "1.0.0",
            rules: [], // Ideally populated with unique rules
          },
        },
        results: [],
      },
    ],
  };

  for (const r of reports) {
    for (const f of r.report.findings) {
      sarif.runs[0].results.push({
        ruleId: f.id,
        level: f.severity === "critical" ? "error" : f.severity === "high" ? "error" : f.severity === "medium" ? "warning" : "note",
        message: { text: f.title },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: f.file },
              region: f.line ? { startLine: f.line } : undefined,
            },
          },
        ],
      });
    }
  }
  return JSON.stringify(sarif, null, 2);
}

// ─── Main Scanner Engine ────────────────────────────────────────────────

export async function scanConfig(targetPath: string | undefined, options: ScanOptions) {
  const isGlobal = options.global || false;
  const format = options.format || "terminal";

  let targets: { agent: string; path: string }[] = [];

  if (isGlobal) {
    console.log(chalk.blue(`\n🔍 Auto-discovering global agent configurations...`));
    const discovered = discoverGlobalAgents();
    if (discovered.length === 0) {
      console.log(chalk.yellow(`No supported agents found on the system.`));
      process.exit(0);
    }
    targets = discovered.map((d) => ({ agent: d.name, path: d.path }));
    console.log(chalk.green(`Found ${targets.length} agent environments.\n`));
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

  for (const target of targets) {
    try {
      const result = scan(target.path);
      const report = calculateScore(result);
      reports.push({ agent: target.agent, path: target.path, report });

      totalCritical += report.summary.critical;
      totalFindings += report.summary.totalFindings;
    } catch (err) {
      console.error(chalk.red(`❌ Failed to scan ${target.agent} (${target.path}): ${err}`));
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

  // Handle Custom Output Formats
  if (format !== "terminal") {
    let outputStr = "";
    if (format === "json") outputStr = formatJson(reports);
    else if (format === "markdown") outputStr = formatMarkdown(reports);
    else if (format === "sarif") outputStr = formatSarif(reports);
    else {
      console.error(chalk.red(`❌ Unsupported format: ${format}`));
      process.exit(1);
    }

    if (options.output) {
      fs.writeFileSync(options.output, outputStr);
      console.log(chalk.green(`✅ Report written to ${options.output}`));
    } else {
      console.log(outputStr);
    }
    process.exit(totalCritical > 0 ? 2 : 0);
  }

  // Terminal Reporting
  if (isGlobal) {
    // Print Summary Table
    console.log(chalk.bold("System-Wide Agent Security Posture"));
    console.log("━".repeat(110));
    console.log(
      `${"AGENT".padEnd(20)} | ${"PATH".padEnd(45)} | ${"SCORE".padEnd(6)} | ${"CRIT".padEnd(5)} | ${"HIGH".padEnd(5)} | ${"MED".padEnd(4)} | ${"LOW".padEnd(4)}`
    );
    console.log("━".repeat(110));

    for (const r of reports) {
      const pStr = r.path.length > 45 ? "..." + r.path.substring(r.path.length - 42) : r.path.padEnd(45);
      const s = r.report.summary;
      const scoreColor = r.report.score.numericScore >= 90 ? chalk.green : r.report.score.numericScore >= 70 ? chalk.yellow : chalk.red;
      
      console.log(
        `${r.agent.padEnd(20)} | ${pStr} | ${scoreColor(r.report.score.grade.padEnd(6))} | ${s.critical.toString().padEnd(5)} | ${s.high.toString().padEnd(5)} | ${s.medium.toString().padEnd(4)} | ${s.low.toString().padEnd(4)}`
      );
    }
    console.log("━".repeat(110));

    if (previousState && newFindingsCount > 0) {
      console.log(chalk.bgRed.white.bold(` ⚠️ WATCHDOG ALERT: ${newFindingsCount} NEW configuration vulnerabilities detected since last scan! `));
    }
    console.log(chalk.gray(`\nHint: Use --format json --output report.json to export detailed findings.`));

  } else {
    // Single local project: print the normal full report
    const renderedReport = renderTerminalReport(reports[0].report);
    console.log(renderedReport);

    if (previousState && newFindingsCount > 0) {
      console.log(chalk.bgRed.white.bold(`\n ⚠️ WATCHDOG ALERT: ${newFindingsCount} NEW vulnerabilities detected since last scan! `));
    }
  }

  if (totalCritical > 0) {
    console.error(chalk.red(`\n🚨 Scan finished with CRITICAL findings!`));
    process.exit(2);
  } else if (totalFindings > 0) {
    console.log(chalk.yellow(`\n⚠️ Scan finished with findings.`));
  } else {
    console.log(chalk.green(`\n✅ Scan passed! No configuration vulnerabilities found.`));
  }
}
