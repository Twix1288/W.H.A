<p align="center">
  <h1 align="center">W.H.Agent (White Hat Agent)</h1>
</p>

<p align="center">
  An antivirus and execution sandbox for your local AI agents.
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/wh-agent-cli"><img src="https://img.shields.io/npm/v/wh-agent-cli" alt="NPM Version" /></a>
  <a href="https://github.com/wh-agent/wh-agent/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-FCL--1.0--ALv2-blue.svg" alt="License" /></a>
  <a href="https://github.com/wh-agent/wh-agent/actions"><img src="https://img.shields.io/badge/build-passing-brightgreen.svg" alt="Build Status" /></a>
</p>

---

## Why this exists

We keep giving autonomous AI agents full terminal access to our laptops. If an agent hallucinates, or if it falls victim to a prompt injection attack, it can silently read your SSH keys or overwrite your project files. W.H.Agent provides boundaries. It scans agent configurations for vulnerabilities and runs their tools inside a strict, isolated OS sandbox so they cannot access files they shouldn't.

## How it works

W.H.Agent protects your machine in two stages: static scanning (finding bad code on disk) and runtime sandboxing (trapping the execution).

### 1. The Scanners (Production Ready)
- **Global Agent Auto-Discovery:** It acts as a watchdog. It scans your entire machine and finds configurations for Cursor, Windsurf, VS Code, Claude Desktop, Gemini CLI, and others.
- **AST Taint Tracking:** Instead of using regex, we parse agent scripts into Abstract Syntax Trees (AST). The scanner analyzes Python, JavaScript, TypeScript, Bash, and Rust. It tracks how variables flow through the code to catch data exfiltration logic before it runs.
- **Supply Chain Checks:** The `install` command safely downloads npm packages, checking for typosquatting and hardcoded secrets before anything reaches your terminal.

### 2. The Runtime Sandbox (Experimental)
When an agent tries to run a tool, W.H.Agent intercepts the command and isolates the subprocess using native OS primitives. We do not use heavy Docker containers; we use the exact primitives built into your operating system.

- **macOS:** Dynamically generated Seatbelt profiles (`sandbox-exec`).
- **Linux:** Swappable backends. You can toggle between native `Landlock` enforcement or full `gVisor` containers using the `WH_SANDBOX_BACKEND` environment variable.
- **Windows:** Support is currently planned and not yet available.

**Golden Snapshots:** To prevent an agent from silently overwriting its own tool script on disk *after* the security scan finishes, we compute an AST hash of the tool and freeze it. If the file on disk changes before execution, W.H.Agent blocks the process instantly.

## ⚠️ Transparency Note
We want to be entirely clear about what works today. 
The static scanners (`wh-agent scan`, `wh-agent check`, `wh-agent install`) are stable and production-ready. 
The runtime sandbox (`wh-agent run`) physically intercepts payloads and correctly isolates files on macOS and Linux. However, it is still experimental. Windows support is pending, and the system for passing dynamic arguments into a frozen sandbox snapshot (parameter IPC) is currently a prototype.

---

## Quick Start

### Installation

Install the CLI globally via npm or bun:

```bash
npm install -g wh-agent-cli
# or
bun install -g wh-agent-cli
```

## Command Reference

### 1. Global System Scan (`scan`)
Find and audit every agent installed on your machine. It searches common installation directories for known agent configurations (Cursor, Claude, etc.) and analyzes their permissions and prompts.

**Usage:**
```bash
wh-agent scan [options]
```

**Options:**
- `--global`: Run a system-wide scan across all known agent directories instead of just the current workspace.
- `--format <type>`: Choose the output format. Options are `table` (default), `json`, `markdown`, or `sarif`.
- `--output <file>`: Write the results to a specific file (e.g., `report.json`).

**Example:**
```bash
wh-agent scan --global --format sarif --output ci-report.sarif
```

### 2. Universal Static Analysis Check (`check`)
Run the AST-level vulnerability check on specific scripts. This is useful for analyzing custom MCP tools or scripts before deploying them.

**Usage:**
```bash
wh-agent check <filepath> [options]
```

**Arguments:**
- `<filepath>`: The path to the script you want to analyze (supports `.py`, `.js`, `.ts`, `.sh`, `.rs`).

**Options:**
- `--fix`: Automatically attempt to rewrite the code to remove the vulnerability (e.g., removing hardcoded secrets).
- `--format <type>`: Choose the output format (`table`, `json`, `markdown`, `sarif`).

**Example:**
```bash
wh-agent check ./tools/database_query.py --fix
```

### 3. Secure Install (`install`)
Download a package safely with built-in typosquatting and supply chain scanning.

**Usage:**
```bash
wh-agent install <package_name>
```

**Arguments:**
- `<package_name>`: The npm or system package you want to install.

**Example:**
```bash
wh-agent install mcp-postgres-server
```

### 4. Secure Execution (`run`)
Wrap an untrusted script inside the OS sandbox. The sandbox physically intercepts risky system calls based on the active backend.

**Usage:**
```bash
WH_SANDBOX_BACKEND=<backend> wh-agent run <executable> [args...] --experimental
```

**Arguments:**
- `<executable>`: The script or binary to run.
- `[args...]`: Any arguments to pass to the script.

**Options & Environment Variables:**
- `--experimental`: **Required.** Acknowledges that the runtime sandbox is still in prototyping phase.
- `WH_SANDBOX_BACKEND`: Controls the isolation engine. 
  - Set to `landlock` (Linux) for unprivileged native restriction.
  - Set to `gvisor` (Linux) for a full userspace kernel container.
  - Omit on macOS to default to `sandbox-exec` (Seatbelt).

**Example (Linux):**
```bash
WH_SANDBOX_BACKEND=landlock wh-agent run ./malicious-agent.js --experimental
```

---

## 🎯 The Breakout Challenge

We want to prove this holds up against real attacks. If you can break out of the AI agent sandbox, we will permanently add your name and LinkedIn profile to the top of the contributors section of this README.

If you can write an MCP tool or agent script that successfully bypasses the Linux or macOS isolation layer and reads a protected host file, the spot is yours. 

To test it:
1. Wrap your malicious payload: `WH_SANDBOX_BACKEND=landlock wh-agent run payload.py --experimental`
2. Open an issue explaining how you broke it, and submit a PR with the fix. If your fix works, you are in.

## Contributors

🏆 **Breakout Challenge Winners:**
- [AbhinavGGarg](https://github.com/AbhinavGGarg)

## Contributing

We welcome contributions. Review [CONTRIBUTING.md](CONTRIBUTING.md) to get started.

## License

Licensed under the FCL-1.0-ALv2 License. See the [LICENSE](LICENSE) file for details.
