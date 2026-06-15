#!/usr/bin/env node
import { Command } from 'commander';
import { installAgent } from './commands/install';
import { runAgent } from './commands/run';
import { checkAgent } from './commands/check';
import { setup } from './commands/setup';
import { scanConfig } from './commands/scan';

const program = new Command();

program
  .name('shield')
  .description('W.H.Agent CLI - Security platform for AI agents')
  .version('1.0.0');

program
  .command('install')
  .description('Install an agent package securely')
  .argument('<package>', 'package name to install')
  .option('--pkg-version <version>', 'version to install', 'latest')
  .option('-r, --registry-url <url>', 'custom registry URL')
  .option('-f, --force', 'force install despite quarantine warnings', false)
  .option('--allow-low-score', 'allow install of packages with low conformance score', false)
  .action((pkg, options) => {
    installAgent(pkg).catch((err) => {
      console.error('Failed to install:', err.message);
      process.exit(1);
    });
  });

program
  .command('setup')
  .description('Set up the W.H.Agent Secure Container Envelope and fetch dependencies')
  .action(() => {
    setup().catch((err) => {
      console.error('Setup failed:', err.message);
      process.exit(1);
    });
  });

program
  .command('check')
  .description('Statically analyze a script for dangerous patterns')
  .argument('<script>', 'path to the python script')
  .action((script) => {
    checkAgent(script).catch((err) => {
      console.error('Check failed:', err.message);
      process.exit(1);
    });
  });

program
  .command('run')
  .description('Safely execute an agent in the Secure Container Envelope')
  .argument('<script>', 'path to the script to execute')
  .option('-e, --envelope <path>', 'path to envelope.yaml configuration', 'envelope.yaml')
  .action((script, options) => {
    runAgent(script, options.envelope).catch((err) => {
      console.error('Run failed:', err.message);
      process.exit(1);
    });
  });

program
  .command('scan')
  .description('Scan an AI agent configuration directory for security issues')
  .argument('[path]', 'path to the agent config directory (e.g., .claude)')
  .option('-g, --global', 'auto-discover and scan all agent configurations on the system')
  .option('-f, --format <type>', 'output format (terminal, json, markdown, sarif)', 'terminal')
  .option('-o, --output <file>', 'file to write the report to')
  .action((targetPath, options) => {
    scanConfig(targetPath, options).catch((err) => {
      console.error('Scan failed:', err.message);
      process.exit(1);
    });
  });

program.parse();
