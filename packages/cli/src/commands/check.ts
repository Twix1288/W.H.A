import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { glob } from 'glob';
import chalk from 'chalk';
import { parseFile } from '../core-scanner/parser';
import { RULES, runRules, Finding } from '../core-scanner/rules';
import { applyRemediations } from '../core-scanner/remediator';
import { isTaintSupported } from '../core-scanner/taint/index';

export async function checkAgent(
  files: string[],
  options: { fix?: boolean; format?: string; output?: string }
) {
  const format = options.format || 'text';
  
  if (format === 'text') {
    console.log(
      `🛡️ W.H.Agent: Running AST-based universal vulnerability check...\n`
    );
  }

  let targetFiles = files;

  if (!targetFiles || targetFiles.length === 0) {
    targetFiles = await glob('**/*.{py,js,ts,tsx,sh,bash,rs}', {
      ignore: ['node_modules/**', 'dist/**', 'build/**', '.git/**'],
    });
  }

  if (targetFiles.length === 0) {
    if (format === 'text') {
      console.log(chalk.yellow(`⚠️  No coding files found to check.`));
    }
    process.exit(0);
  }

  const allFindings: { file: string; finding: Finding }[] = [];
  let totalFixes = 0;

  const fileStatuses: { file: string; taintSupported: boolean }[] = [];

  for (const file of targetFiles) {
    const absolutePath = path.resolve(file);
    try {
      const stat = await fs.stat(absolutePath);
      if (!stat.isFile()) continue;

      const relativePath = path.relative(process.cwd(), absolutePath);
      
      fileStatuses.push({
        file: relativePath,
        taintSupported: isTaintSupported(absolutePath)
      });

      const parseResult = await parseFile(absolutePath);
      const findings = runRules(parseResult, RULES);

      if (options.fix && parseResult.type === 'ast') {
        const fixesApplied = await applyRemediations(absolutePath, findings);
        totalFixes += fixesApplied;
      }

      for (const finding of findings) {
        allFindings.push({ file: relativePath, finding });
      }
    } catch (err: any) {
      if (format === 'text') {
        console.error(chalk.red(`❌ Error analyzing ${file}: ${err.message}`));
      }
    }
  }

  const hasCritical = allFindings.some(f => f.finding.severity === 'critical');
  const exitCode = hasCritical ? 2 : (allFindings.length > 0 ? 1 : 0);

  if (format === 'json') {
    const jsonOutput = allFindings.map(f => ({
      file: f.file,
      rule_id: f.finding.ruleId,
      threat_name: f.finding.name,
      severity: f.finding.severity,
      category: f.finding.category,
      message: f.finding.message,
      line: f.finding.line,
      fixable: f.finding.fixable
    }));
    
    if (options.output) {
      await fs.writeFile(options.output, JSON.stringify(jsonOutput, null, 2));
    } else {
      console.log(JSON.stringify(jsonOutput, null, 2));
    }
    process.exit(exitCode);
  }

  if (format === 'json-v2') {
    const jsonOutput = {
      files_status: fileStatuses.map(f => ({
        file: f.file,
        status: f.taintSupported ? 'scanned_full' : 'unsupported_taint_tracking'
      })),
      findings: allFindings.map(f => ({
        file: f.file,
        rule_id: f.finding.ruleId,
        threat_name: f.finding.name,
        severity: f.finding.severity,
        category: f.finding.category,
        message: f.finding.message,
        line: f.finding.line,
        fixable: f.finding.fixable
      }))
    };
    
    if (options.output) {
      await fs.writeFile(options.output, JSON.stringify(jsonOutput, null, 2));
    } else {
      console.log(JSON.stringify(jsonOutput, null, 2));
    }
    process.exit(exitCode);
  }

  if (format === 'sarif') {
    const sarifOutput = {
      version: "2.1.0",
      $schema: "http://json.schemastore.org/sarif-2.1.0-rtm.5",
      runs: [{
        tool: {
          driver: {
            name: "W.H.Agent",
            informationUri: "https://github.com/wh-agent/wh-agent",
            rules: RULES.map(r => ({
              id: r.id,
              name: r.name,
              shortDescription: { text: `${r.category}: ${r.name}` }
            }))
          }
        },
        artifacts: fileStatuses.map(f => ({
          location: { uri: f.file },
          properties: {
            status: f.taintSupported ? 'scanned_full' : 'unsupported_taint_tracking'
          }
        })),
        results: allFindings.map(f => ({
          ruleId: f.finding.ruleId,
          level: f.finding.severity === 'critical' ? 'error' : 'warning',
          message: { text: f.finding.message },
          locations: [{
            physicalLocation: {
              artifactLocation: { uri: f.file },
              region: { startLine: f.finding.line }
            }
          }]
        }))
      }]
    };
    
    if (options.output) {
      await fs.writeFile(options.output, JSON.stringify(sarifOutput, null, 2));
    } else {
      console.log(JSON.stringify(sarifOutput, null, 2));
    }
    process.exit(exitCode);
  }

  // Default 'text' format
  
  const unsupportedFiles = fileStatuses.filter(f => !f.taintSupported);
  if (unsupportedFiles.length > 0) {
    console.warn(
      chalk.yellow(`\nℹ️  AST Universal Vulnerability Check completed. Note: Deep Taint Tracking is currently limited to JS/TS files.`)
    );
    console.warn(
      chalk.gray(`   The following files were scanned for dangerous rules, but skipped for deep taint tracking:`)
    );
    unsupportedFiles.slice(0, 5).forEach(f => console.warn(chalk.gray(`     - ${f.file}`)));
    if (unsupportedFiles.length > 5) console.warn(chalk.gray(`     - ... and ${unsupportedFiles.length - 5} more.`));
  }

  if (allFindings.length > 0) {
    console.warn(
      chalk.redBright(`\n🚨 Check Failed: Found ${allFindings.length} vulnerabilities.`)
    );

    for (const { file, finding } of allFindings) {
      const severityColor = finding.severity === 'critical' ? chalk.red : chalk.yellow;
      console.warn(`\n[${severityColor(finding.severity.toUpperCase())}] ${finding.category} in ${file} (Line ${finding.line}):`);
      console.warn(`  - ${finding.name}: ${finding.message}`);
      if (finding.fixable) {
        if (options.fix) {
           console.warn(chalk.green(`  ✓ Automatically fixed (${finding.fixStrategy}).`));
        } else {
           console.warn(chalk.cyan(`  👉 Fixable: Run with --fix to auto-remediate.`));
        }
      }
    }
    
    if (options.fix) {
       console.log(chalk.greenBright(`\n✨ Applied ${totalFixes} automatic fixes.`));
    }

    if (hasCritical) {
      console.error(
        chalk.redBright(`\n👉 Critical vulnerabilities found! Do NOT run this natively. Use 'wh-agent run' to safely execute it in the Secure Container Envelope.`)
      );
    }
  } else {
    console.log(chalk.greenBright(`\n✅ Passed: No syntax or AST-level vulnerabilities found.`));
    console.log(
      chalk.gray(`👉 Static analysis limits obvious risk. Use 'wh-agent run' to sandbox residual runtime risk.`)
    );
  }
  
  process.exit(exitCode);
}
