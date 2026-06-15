import * as fs from "fs";
import * as path from "path";

import { execSync } from "child_process";

export async function checkAgent(scriptPath: string) {
    console.log(`🛡️ W.H.Agent: Running AST-based vulnerability check on ${scriptPath}...\n`);

    const absolutePath = path.resolve(scriptPath);
    if (!fs.existsSync(absolutePath)) {
        console.error(`❌ File not found: ${absolutePath}`);
        process.exit(1);
    }

    if (!scriptPath.endsWith(".py")) {
        console.warn(`[WARNING] Static AST analysis currently only supports Python files.`);
        console.warn(`👉 Proceeding with caution. Use 'shield run' for safe container execution.\n`);
        return;
    }

    const checkerPath = path.join(__dirname, "../src/scripts/ast_checker.py");
    
    try {
        const output = execSync(`python3 "${checkerPath}" "${absolutePath}"`, { encoding: "utf-8" });
        const vulnerabilities = JSON.parse(output);

        if (vulnerabilities.length > 0) {
            console.warn(`🚨 Check Failed: Found ${vulnerabilities.length} potential vulnerabilities.`);
            vulnerabilities.forEach((vuln: any) => {
                console.warn(`\n[${vuln.severity}] ${vuln.category} (Line ${vuln.line}):`);
                console.warn(`  - ${vuln.message}`);
            });
            console.error(`\n👉 Recommendation: Do NOT run this natively. Use 'shield run ${scriptPath}' to safely execute it in the Secure Container Envelope.`);
            process.exit(1);
        } else {
            console.log(`✅ Passed: No syntax or AST-level vulnerabilities found.`);
            console.log(`👉 Static analysis limits obvious risk. Use 'shield run ${scriptPath}' to sandbox residual runtime risk.`);
        }
    } catch (err) {
        console.error(`❌ Failed to run AST analyzer: ${err}`);
        process.exit(1);
    }
}
