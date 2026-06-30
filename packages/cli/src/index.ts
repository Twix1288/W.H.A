#!/usr/bin/env node
import { Command } from "commander";
import * as os from "node:os";
import { checkAgent } from "./commands/check";
import { installAgent } from "./commands/install";
import { runAgent } from "./commands/run";
import { scanConfig } from "./commands/scan";
import { setup } from "./commands/setup";

const program = new Command();

program
	.name("shield")
	.description("W.H.Agent CLI - Security platform for AI agents")
	.version("1.0.0");

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
	.option("--experimental", "acknowledge this command is experimental")
	.action((script, options) => {
		if (!options.experimental) {
			console.log(`⚠️  'run' is experimental and requires the --experimental flag to use.`);
			return;
		}

		if (os.platform() !== "darwin") {
			console.error(`❌ 'run' currently only supports macOS (sandbox binary is macOS-only).`);
			console.error(`   Linux/Windows support is planned — see issue #42.`);
			process.exit(1);
		}

		runAgent(script, options.envelope).catch((err) => {
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

program.parse();
