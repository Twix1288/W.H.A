#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { Command } from "commander";

import { checkAgent } from "./commands/check";
import { inspectMcp } from "./commands/inspect-mcp";
import { installAgent } from "./commands/install";
import { runAgent } from "./commands/run";
import { scanConfig } from "./commands/scan";
import { setup } from "./commands/setup";
import { watchConfig } from "./commands/watch";

// Read the real version from package.json (dist/ sits next to it once built and
// once published), so `--version` never drifts from the shipped release.
function resolveVersion(): string {
	try {
		return JSON.parse(
			readFileSync(join(__dirname, "..", "package.json"), "utf-8"),
		).version;
	} catch {
		return "0.0.0";
	}
}

const program = new Command();

program
	.name("shield")
	.description("W.H.Agent CLI - Security platform for AI agents")
	.version(resolveVersion());

program
	.command("install")
	.description("Securely fetch and install an agent via npm (with AST/typosquat checking)")
	.argument("<package>", "package name to install")
	.option("--pkg-version <version>", "version to install", "latest")
	.option("-r, --registry-url <url>", "custom registry URL")
	.option("-f, --force", "force install despite quarantine warnings", false)
	.option("--dry-run", "run checks without actually installing", false)
	.option(
		"--allow-low-score",
		"allow install of packages with low conformance score",
		false,
	)
	.action((pkg, options) => {
		installAgent(pkg, options).catch((err) => {
			console.error("Failed to install:", err.message);
			process.exit(1);
		});
	});

program
	.command("setup")
	.description(
		"Set up the W.H.Agent Secure Container Envelope and fetch dependencies",
	)
	.action(() => {
		setup().catch((err) => {
			console.error("Setup failed:", err.message);
			process.exit(1);
		});
	});

program
	.command("check")
	.description("Statically analyze files for dangerous patterns using universal AST scanner")
	.argument("[files...]", "paths to the files to analyze (leave empty to scan all supported files in cwd)")
	.option("--fix", "automatically fix fixable vulnerabilities")
	.option("--format <format>", "output format (text, json, sarif)", "text")
	.option("-o, --output <path>", "path to write the output file")
	.action((files, options) => {
		checkAgent(files, options).catch((err) => {
			console.error("Check failed:", err.message);
			process.exit(1);
		});
	});

program
	.command("run")
	.description("[experimental] Safely execute an agent in the Secure Container Envelope")
	.argument("<script>", "path to the script to execute")
	.option(
		"-e, --envelope <path>",
		"path to envelope.yaml configuration",
		"envelope.yaml",
	)
	.option("--ast-hash <hash>", "expected AST hash from golden snapshot to prevent TOCTOU bypasses")
	.option("--experimental", "acknowledge this command is experimental")
	.addHelpText(
		'after',
		`\nEnvironment Variables:\n  WH_SANDBOX_BACKEND    Selects the Linux backend. Both currently FAIL CLOSED\n                        (they refuse to run rather than provide fake isolation):\n                        - "landlock": not yet implemented\n                        - "gvisor":   not yet securely isolated (host FS exposed)\n                        macOS always uses native sandbox-exec (this var is ignored);\n                        it is the only backend that isolates untrusted code today.`
	)
	.action((script, options) => {
		if (!options.experimental) {
			console.log(`⚠️  'run' is experimental and requires the --experimental flag to use.`);
			return;
		}

		runAgent(script, options.envelope, options.astHash).catch((err) => {
			console.error("Run failed:", err.message);
			process.exit(1);
		});
	});

program
	.command("scan")
	.description("Scan an AI agent configuration directory for security issues")
	.argument("[path]", "path to the agent config directory (e.g., .claude)")
	.option(
		"-g, --global",
		"auto-discover and scan all agent configurations on the system",
	)
	.option(
		"-f, --format <type>",
		"output format (terminal, json, markdown, sarif)",
		"terminal",
	)
	.option("-o, --output <file>", "file to write the report to")
	.action((targetPath, options) => {
		scanConfig(targetPath, options).catch((err) => {
			console.error("Scan failed:", err.message);
			process.exit(1);
		});
	});

program
	.command("inspect-mcp")
	.description(
		"Inspect an MCP server for security issues (supply chain, tool poisoning, prompt injection)",
	)
	.argument(
		"[target]",
		"MCP server name (from your config), a command, or a URL",
	)
	.option("--config <path>", "path to an MCP config file (used with --server)")
	.option("--server <name>", "server name inside --config")
	.option(
		"--live",
		"execute the server and enumerate its live tools (runs untrusted code — opt-in)",
		false,
	)
	.option("--ui", "launch the official MCP Inspector web UI (interactive)", false)
	.option("--transport <type>", "transport for remote URLs (sse or http)")
	.option("--timeout <seconds>", "timeout for --live enumeration", "45")
	.option("-f, --format <type>", "output format (terminal, json, sarif)", "terminal")
	.option("-o, --output <file>", "file to write the report to")
	.action((target, options) => {
		inspectMcp(target, options).catch((err) => {
			console.error("Inspect failed:", err.message);
			process.exit(1);
		});
	});

program
	.command("watch")
	.description(
		"Continuously watch an agent config directory and alert on security drift (config changes)",
	)
	.argument(
		"[path]",
		"directory to watch (default: ./.claude, then ~/.claude, then cwd)",
	)
	.option("--debounce <ms>", "debounce interval in milliseconds", "500")
	.option("--alert <mode>", "alert mode: terminal, webhook, both", "terminal")
	.option("--webhook <url>", "webhook URL for alerts (required for webhook/both)")
	.option(
		"--min-severity <severity>",
		"minimum severity to track: critical, high, medium, low, info",
		"info",
	)
	.option(
		"--block",
		"exit non-zero if the initial scan has critical findings (for CI)",
		false,
	)
	.action((targetPath, options) => {
		watchConfig(targetPath, options).catch((err) => {
			console.error("Watch failed:", err.message);
			process.exit(1);
		});
	});

program.parse();
