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
- **AST Taint Tracking:** Instead of using regex, we parse agent scripts into Abstract Syntax Trees (AST). The scanner analyzes Python, JavaScript, TypeScript, Bash, and Rust, and tracks how variables flow through the code — from sources (env/secret/file reads, user input) to sinks (network calls, `exec`/subprocess) — to catch data-exfiltration and injection logic before it runs. All five languages get real source→sink dataflow (JS/TS via the TypeScript compiler, Python/Bash/Rust via tree-sitter).
- **Supply Chain Checks:** The `install` command scans an npm package (typosquatting, hardcoded secrets, native binaries, lifecycle scripts) *before* installing, and then runs `npm install --ignore-scripts` so a malicious `preinstall`/`postinstall` can't execute arbitrary code on your machine during installation.

### 2. The Runtime Sandbox (Experimental)
When an agent tries to run a tool, W.H.Agent intercepts the command and isolates the subprocess using native OS primitives. We do not use heavy Docker containers; we use the exact primitives built into your operating system.

- **macOS:** Dynamically generated Seatbelt profiles (`sandbox-exec`). **This is the only backend that provides real isolation today.**
- **Linux:** Both backends (`Landlock` and `gVisor`, selected via `WH_SANDBOX_BACKEND`) currently **fail closed** — they refuse to execute rather than run untrusted code without genuine isolation. Native Landlock enforcement and an isolated-rootfs gVisor bundle are planned; until they land, use the macOS backend to run untrusted code.
- **Windows:** Support is currently planned and not yet available.

**Golden Snapshots:** To prevent an agent from silently overwriting its own tool script on disk *after* the security scan finishes, we compute a real **AST fingerprint** of the tool (structure + identifiers/literals, insensitive to comments and formatting). `wh-agent check` prints it; pass it to `wh-agent run --ast-hash <hash>` and execution is blocked instantly if the file's AST no longer matches — i.e. the code changed after it was scanned. The bytes that are hashed are the exact bytes handed to the sandbox (read once), so there is no check-vs-execute gap.

## ⚠️ Transparency Note
We want to be entirely clear about what works today.
The static scanners (`wh-agent scan`, `wh-agent check`, `wh-agent install`) are stable and production-ready; AST taint tracking covers all five languages, and `install` disables install-time lifecycle scripts by default.
The runtime sandbox (`wh-agent run`) physically intercepts payloads and correctly isolates files **on macOS** (verified against host-file-read, write-then-exec, network-egress, subprocess-timeout and env-leak escapes). It is still experimental: on Linux both backends **fail closed** (they refuse to run rather than provide fake isolation) pending a real Landlock/gVisor implementation, Windows also **fails closed** pending Job Object confinement, and the system for passing dynamic arguments into a frozen sandbox snapshot (parameter IPC) is a prototype.

## 🆕 What's new in v1.3.0
- **Real AST hash for Golden Snapshots** — replaces the previous raw-text hash; comment/format-insensitive, semantics-sensitive, wired through `check` → `run --ast-hash`.
- **Taint tracking for all five languages** — Python, Bash, and Rust now get real source→sink dataflow on the tree-sitter AST, at parity with JS/TS (previously JS/TS only).
- **Sandbox hardening (macOS)** — fixed an output-file symlink exfiltration escape; the timeout now kills the whole process tree (a spawned subprocess can no longer outlive it); a strict env allow-list blocks interpreter/linker hijacking (`DYLD_*`, `LD_PRELOAD`, `PYTHONPATH`, …) and never inherits host secrets; output is size-capped.
- **Safer `install`** — `--ignore-scripts` by default, no-shell invocation (removes a command-injection surface), and typosquatting data is now bundled so the check actually runs in the published CLI.
- **Fail-closed everywhere untrusted code can't be contained** — Linux (Landlock + gVisor) and Windows backends refuse to execute rather than pretend to isolate.

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
- `WH_SANDBOX_BACKEND`: Controls the Linux isolation engine.
  - `landlock` (Linux): **not yet implemented — fails closed** (refuses to execute).
  - `gvisor` (Linux): **not yet securely isolated — fails closed** (`runsc do` exposes the host filesystem; blocked until an isolated-rootfs bundle lands).
  - On macOS the backend is always `sandbox-exec` (Seatbelt) and this variable is ignored.

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
