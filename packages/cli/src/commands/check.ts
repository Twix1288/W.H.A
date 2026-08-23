import { writeStdoutSync } from "../util/stdout.js";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import chalk from "chalk";
import { glob } from "glob";
import { astFingerprint, parseFile } from "../core-scanner/parser";
import { scanText } from "../core-scanner/patterns/index";
import { applyRemediations } from "../core-scanner/remediator";
import { type Finding, RULES, runRules } from "../core-scanner/rules";
import { analyzeTaint, isTaintSupported } from "../core-scanner/taint/index";


/**
 * Path as shown to the user and embedded in JSON/SARIF reports.
 *
 * `path.relative(cwd, target)` is only useful when the target is INSIDE the
 * working directory. For anything else it produced strings like
 * `../../../../../../../private/tmp/x/payload.py`, which is unreadable in the
 * terminal and, worse, is emitted as the SARIF `artifactLocation.uri` — a
 * relative URI escaping the repo root is not resolvable by GitHub code scanning,
 * so findings silently fail to attach to any file. Fall back to the absolute path
 * whenever the relative form would climb out of the working directory.
 */
function displayPath(absolutePath: string): string {
	const rel = path.relative(process.cwd(), absolutePath);
	if (!rel || rel.startsWith("..") || path.isAbsolute(rel)) return absolutePath;
	return rel;
}

export async function checkAgent(
	files: string[],
	options: { fix?: boolean; format?: string; output?: string },
) {
	const format = options.format || "text";

	if (format === "text") {
		console.log(
			`🛡️ W.H.Agent: Running AST-based universal vulnerability check...\n`,
		);
	}

	let targetFiles = files;

	if (!targetFiles || targetFiles.length === 0) {
		// dot: true so scripts bundled inside dot-directories — most importantly
		// `.claude/skills/<name>/scripts/*.py` and `.claude/agents/*` — are checked
		// by default. Without it, a malicious bundled skill/agent script would be
		// silently skipped when a user just runs `wh-agent check` in their project.
		targetFiles = await glob("**/*.{py,js,ts,tsx,sh,bash,rs}", {
			dot: true,
			ignore: [
				"**/node_modules/**",
				"**/dist/**",
				"**/build/**",
				"**/.git/**",
				"**/.venv/**",
				"**/venv/**",
				"**/.cache/**",
				"**/coverage/**",
			],
		});
	}

	if (targetFiles.length === 0) {
		if (format === "text") {
			console.log(chalk.yellow(`⚠️  No coding files found to check.`));
		}
		process.exit(0);
	}

	const allFindings: { file: string; finding: Finding }[] = [];
	let totalFixes = 0;

	const fileStatuses: {
		file: string;
		taintSupported: boolean;
		astHash: string;
		failed?: boolean;
	}[] = [];
	let analysisErrorCount = 0;

	for (const file of targetFiles) {
		const absolutePath = path.resolve(file);
		try {
			const stat = await fs.stat(absolutePath);
			if (!stat.isFile()) {
				// A path that exists but is not a regular file (a directory, a socket,
				// a device) can't be analyzed. `fs.stat` SUCCEEDS here, so this never
				// reaches the catch — fail closed explicitly instead of silently
				// `continue`-ing (which, if it were the only target, produced an empty
				// clean pass with exit 0).
				throw new Error("not a regular file (cannot analyze)");
			}

			const relativePath = displayPath(absolutePath);

			const parseResult = await parseFile(absolutePath);
			const findings = runRules(parseResult, RULES);
			// Shared, tunable rule packs (commands / injection / secrets /
			// sensitive-paths) — the same detections `guard` and `scan` use. Merged into
			// the AST-rule findings, deduped by category:line so an overlapping pattern
			// isn't double-reported. Pack findings are not auto-fixable, so `--fix` skips them.
			{
				const seenAt = new Set(findings.map((f) => `${f.category}:${f.line}`));
				for (const f of scanText(parseResult.source, { profile: "default" })) {
					const key = `${f.category}:${f.line}`;
					if (seenAt.has(key)) continue;
					seenAt.add(key);
					findings.push(f);
				}
			}

			// Golden-snapshot fingerprint the caller can pin via `run --ast-hash`.
			const astHash = astFingerprint(
				parseResult.source,
				path.extname(absolutePath),
			);
			fileStatuses.push({
				file: relativePath,
				taintSupported: isTaintSupported(absolutePath),
				astHash,
			});

			if (options.fix && parseResult.type === "ast") {
				const fixesApplied = await applyRemediations(absolutePath, findings);
				totalFixes += fixesApplied;
			}

			for (const finding of findings) {
				allFindings.push({ file: relativePath, finding });
			}

			// Data-flow (taint) analysis: catch source→sink exfiltration/injection
			// that pattern rules miss. This is the flagship "tracks how variables
			// flow through the code" capability, surfaced on the files the user is
			// actually checking.
			if (isTaintSupported(absolutePath)) {
				const taint = analyzeTaint([
					{ path: relativePath, content: parseResult.source },
				]);
				for (const flow of taint.flows) {
					allFindings.push({
						file: relativePath,
						finding: {
							ruleId: "taint-dataflow",
							name: "Tainted data flow",
							severity: flow.severity,
							category: "data-flow",
							message: flow.description,
							line: flow.source.line ?? 0,
							fixable: false,
						},
					});
				}
			}
		} catch (err: any) {
			// FAIL CLOSED. A file the scanner could not analyze (parse crash, stack
			// overflow on pathological nesting, unreadable file, ...) must NEVER be
			// silently reported as clean — that is the difference between "I checked
			// this and it's safe" and "I couldn't check this". Previously the error was
			// swallowed (logged only in text mode), so JSON/SARIF emitted `[]` with
			// exit 0. Now we (a) surface it as a finding in every format, (b) mark the
			// file's status analysis_failed, and (c) force a non-zero exit.
			const relativePath = displayPath(absolutePath);
			const message = err?.message ?? String(err);
			analysisErrorCount++;
			const existingIdx = fileStatuses.findIndex((f) => f.file === relativePath);
			if (existingIdx >= 0) fileStatuses.splice(existingIdx, 1);
			fileStatuses.push({
				file: relativePath,
				taintSupported: false,
				astHash: "n/a",
				failed: true,
			});
			allFindings.push({
				file: relativePath,
				finding: {
					ruleId: "analysis-error",
					name: "File could not be analyzed",
					severity: "high",
					category: "analysis-error",
					message: `Analysis failed (${message}). This file is UNSCANNED — treat as not-clean, not safe.`,
					line: 0,
					fixable: false,
				},
			});
			if (format === "text") {
				console.error(
					chalk.red(
						`❌ Error analyzing ${file}: ${message} — reported as an analysis-error (fail-closed), not a clean pass.`,
					),
				);
			}
		}
	}

	const hasCritical = allFindings.some(
		(f) => f.finding.severity === "critical",
	);
	// An analysis error is a hard fail-closed signal: a security gate must exit
	// non-zero when it could not scan something, exactly as it would for a critical.
	const exitCode =
		hasCritical || analysisErrorCount > 0
			? 2
			: allFindings.length > 0
				? 1
				: 0;

	if (format === "json") {
		const jsonOutput = allFindings.map((f) => ({
			file: f.file,
			rule_id: f.finding.ruleId,
			threat_name: f.finding.name,
			severity: f.finding.severity,
			category: f.finding.category,
			message: f.finding.message,
			line: f.finding.line,
			fixable: f.finding.fixable,
		}));

		if (options.output) {
			await fs.writeFile(options.output, JSON.stringify(jsonOutput, null, 2));
		} else {
			writeStdoutSync(JSON.stringify(jsonOutput, null, 2));
		}
		process.exit(exitCode);
	}

	if (format === "json-v2") {
		const jsonOutput = {
			files_status: fileStatuses.map((f) => ({
				file: f.file,
				status: f.failed
					? "analysis_failed"
					: f.taintSupported
						? "scanned_full"
						: "unsupported_taint_tracking",
				ast_hash: f.astHash,
			})),
			findings: allFindings.map((f) => ({
				file: f.file,
				rule_id: f.finding.ruleId,
				threat_name: f.finding.name,
				severity: f.finding.severity,
				category: f.finding.category,
				message: f.finding.message,
				line: f.finding.line,
				fixable: f.finding.fixable,
			})),
		};

		if (options.output) {
			await fs.writeFile(options.output, JSON.stringify(jsonOutput, null, 2));
		} else {
			writeStdoutSync(JSON.stringify(jsonOutput, null, 2));
		}
		process.exit(exitCode);
	}

	if (format === "sarif") {
		const sarifOutput = {
			version: "2.1.0",
			$schema: "http://json.schemastore.org/sarif-2.1.0-rtm.5",
			runs: [
				{
					tool: {
						driver: {
							name: "W.H.Agent",
							informationUri: "https://github.com/wh-agent/wh-agent",
							rules: RULES.map((r) => ({
								id: r.id,
								name: r.name,
								shortDescription: { text: `${r.category}: ${r.name}` },
							})),
						},
					},
					artifacts: fileStatuses.map((f) => ({
						location: { uri: f.file },
						properties: {
							status: f.failed
								? "analysis_failed"
								: f.taintSupported
									? "scanned_full"
									: "unsupported_taint_tracking",
							astHash: f.astHash,
						},
					})),
					results: allFindings.map((f) => ({
						ruleId: f.finding.ruleId,
						level: f.finding.severity === "critical" ? "error" : "warning",
						message: { text: f.finding.message },
						locations: [
							{
								physicalLocation: {
									artifactLocation: { uri: f.file },
									region: { startLine: f.finding.line },
								},
							},
						],
					})),
				},
			],
		};

		if (options.output) {
			await fs.writeFile(options.output, JSON.stringify(sarifOutput, null, 2));
		} else {
			writeStdoutSync(JSON.stringify(sarifOutput, null, 2));
		}
		process.exit(exitCode);
	}

	// Default 'text' format

	const unsupportedFiles = fileStatuses.filter((f) => !f.taintSupported);
	if (unsupportedFiles.length > 0) {
		console.warn(
			chalk.yellow(
				`\nℹ️  AST Universal Vulnerability Check completed. Taint tracking covers Python, JavaScript, TypeScript, Bash, and Rust; the files below use other extensions and were scanned with rule-based checks only:`,
			),
		);
		unsupportedFiles
			.slice(0, 5)
			.forEach((f) => {
				console.warn(chalk.gray(`     - ${f.file}`));
			});
		if (unsupportedFiles.length > 5)
			console.warn(
				chalk.gray(`     - ... and ${unsupportedFiles.length - 5} more.`),
			);
	}

	if (fileStatuses.length > 0) {
		console.log(
			chalk.gray(
				`\n🔒 Golden Snapshot fingerprints (pin with 'wh-agent run --ast-hash <hash>'):`,
			),
		);
		fileStatuses
			.slice(0, 10)
			.forEach((f) => {
				console.log(chalk.gray(`   ${f.file}: ${f.astHash}`));
			});
		if (fileStatuses.length > 10)
			console.log(chalk.gray(`   ... and ${fileStatuses.length - 10} more.`));
	}

	if (allFindings.length > 0) {
		console.warn(
			chalk.redBright(
				`\n🚨 Check Failed: Found ${allFindings.length} vulnerabilities.`,
			),
		);

		for (const { file, finding } of allFindings) {
			const severityColor =
				finding.severity === "critical" ? chalk.red : chalk.yellow;
			console.warn(
				`\n[${severityColor(finding.severity.toUpperCase())}] ${finding.category} in ${file} (Line ${finding.line}):`,
			);
			console.warn(`  - ${finding.name}: ${finding.message}`);
			if (finding.fixable) {
				if (options.fix) {
					console.warn(
						chalk.green(`  ✓ Automatically fixed (${finding.fixStrategy}).`),
					);
				} else {
					console.warn(
						chalk.cyan(`  👉 Fixable: Run with --fix to auto-remediate.`),
					);
				}
			}
		}

		if (options.fix) {
			console.log(
				chalk.greenBright(`\n✨ Applied ${totalFixes} automatic fixes.`),
			);
		}

		if (hasCritical) {
			console.error(
				chalk.redBright(
					`\n👉 Critical vulnerabilities found! Do NOT run this natively. Use 'wh-agent run' to safely execute it in the Secure Container Envelope.`,
				),
			);
		}
	} else {
		console.log(
			chalk.greenBright(
				`\n✅ Passed: No syntax or AST-level vulnerabilities found.`,
			),
		);
		console.log(
			chalk.gray(
				`👉 Static analysis limits obvious risk. Use 'wh-agent run' to sandbox residual runtime risk.`,
			),
		);
	}

	process.exit(exitCode);
}
