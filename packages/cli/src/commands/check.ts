import { execSync } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";
import chalk from "chalk";

function hasPython3(): boolean {
	try {
		execSync("python3 --version", { stdio: "ignore" });
		return true;
	} catch {
		return false;
	}
}


export async function checkAgent(scriptPath: string) {
	console.log(
		`🛡️ W.H.Agent: Running AST-based vulnerability check on ${scriptPath}...\n`,
	);

	const absolutePath = path.resolve(scriptPath);
	if (!fs.existsSync(absolutePath)) {
		console.error(`❌ File not found: ${absolutePath}`);
		process.exit(1);
	}

	if (!scriptPath.endsWith(".py")) {
		console.log(chalk.yellow(`⚠️  wh-agent check currently only supports Python files.`));
		return;
	}

	if (!hasPython3()) {
		console.error(chalk.red(`❌ python3 is required for 'wh-agent check' but was not found on your PATH.`));
		console.error(chalk.red(`   Install Python 3: https://www.python.org/downloads/`));
		process.exit(1);
	}

	const checkerPath = path.join(__dirname, "../src/scripts/ast_checker.py");

	try {
		const output = execSync(`python3 "${checkerPath}" "${absolutePath}"`, {
			encoding: "utf-8",
		});
		const vulnerabilities = JSON.parse(output);

		if (vulnerabilities.length > 0) {
			console.warn(
				`🚨 Check Failed: Found ${vulnerabilities.length} potential vulnerabilities.`,
			);
			vulnerabilities.forEach((vuln: any) => {
				console.warn(
					`\n[${vuln.severity}] ${vuln.category} (Line ${vuln.line}):`,
				);
				console.warn(`  - ${vuln.message}`);
			});
			console.error(
				`\n👉 Recommendation: Do NOT run this natively. Use 'shield run ${scriptPath}' to safely execute it in the Secure Container Envelope.`,
			);
			process.exit(1);
		} else {
			console.log(`✅ Passed: No syntax or AST-level vulnerabilities found.`);
			console.log(
				`👉 Static analysis limits obvious risk. Use 'shield run ${scriptPath}' to sandbox residual runtime risk.`,
			);
		}
	} catch (err) {
		console.error(`❌ Failed to run AST analyzer: ${err}`);
		process.exit(1);
	}
}
