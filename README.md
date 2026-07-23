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

## What you can do

| Command | What it does | Example |
|---|---|---|
| `wh-agent scan [path]` | Audit an agent's **config** (permissions, secrets, MCP servers, hooks, skills). Recurses into `skills/`/`agents/`. Defaults to the current dir; `--global` scans every agent on the machine. | `wh-agent scan ~/.claude` |
| `wh-agent check [files...]` | Deep-scan **source/scripts** with AST rules **+ taint dataflow** (exfiltration/injection). No args = every supported file in the current dir, including `.claude` bundled scripts. | `wh-agent check ./tool.py` |
| `wh-agent inspect-mcp <name>` | Inspect an **MCP server** for supply-chain risk, tool poisoning, and prompt injection. Static by default; `--live` enumerates the server's real tools via the MCP Inspector. | `wh-agent inspect-mcp github` |
| `wh-agent run <script> --experimental` | Execute an untrusted script inside the **OS sandbox** (macOS). Pin `--ast-hash` to block tampered files. | `wh-agent run ./agent.py --experimental` |
| `wh-agent install <pkg>` | Vet an npm package (typosquat, secrets, lifecycle scripts) **before** installing, then install with `--ignore-scripts`. | `wh-agent install mcp-postgres-server` |
| `wh-agent watch [path]` | **Continuously** re-scan an agent config and alert when its security posture drifts (a new MCP server, widened permissions, a new hook/secret). Local, cross-platform, no backend. | `wh-agent watch ~/.claude` |

> ⏱️ **Performance:** the deep taint pass (`check`) and `scan --global` on a large config can take from a second to a couple of minutes — they read and analyze every file. Single-file `check` and a scoped `scan <path>` are typically sub-second. `inspect-mcp --live` also spends a few seconds downloading/starting the Inspector and the server.

## How it works

W.H.Agent protects your machine in two stages: static scanning (finding bad code on disk) and runtime sandboxing (trapping the execution).

### 1. The Scanners (Production Ready)
- **Agent Config Auto-Discovery (`scan`):** Point it at a directory (or use `--global` to search the well-known agent locations for Cursor, Claude, VS Code, etc.). It discovers the `.claude/`-style structure — `settings.json`, `mcp.json`, `CLAUDE.md`, and the `agents/`, `skills/`, `hooks/`, `commands/`, `rules/` folders — and **recurses into subfolders**, so the standard `skills/<name>/SKILL.md` layout and any scripts bundled inside a skill are found, not just top-level files. It audits permissions, secrets, MCP servers, hooks, and skill health. It does **not** run code-level taint on source (that's `check`).
- **AST Taint Tracking (`check`):** Instead of using regex, `wh-agent check` parses scripts into Abstract Syntax Trees. It analyzes Python, JavaScript, TypeScript, Bash, and Rust, and tracks how variables flow — from sources (env/secret/file reads, user input) to sinks (network calls, `exec`/subprocess) — to catch data-exfiltration and injection logic before it runs. All five languages get real source→sink dataflow (JS/TS via the TypeScript compiler; Python/Bash/Rust via tree-sitter). This is the command to run on a specific tool/script (or a bundled skill script) to find malicious code.
- **Supply Chain Checks (`install`):** The `install` command scans an npm package (typosquatting, hardcoded secrets, native binaries, lifecycle scripts) *before* installing, and then runs `npm install --ignore-scripts` so a malicious `preinstall`/`postinstall` can't execute arbitrary code on your machine during installation.
- **MCP Inspection (`inspect-mcp`):** Point it at an MCP server (by name from your config, a command, or a URL) to check it for supply-chain risk (npx/git commands, known-malicious packages), tool-poisoning and prompt-injection patterns, over-broad file access, and exfiltration endpoints. Static by default (no execution); with `--live` it enumerates the server's actual tools via the official Anthropic MCP Inspector and scans their descriptions/schemas for poisoning.
- **Config Drift Watch (`watch`):** Establish a baseline from an initial scan, then watch the config directory and re-scan on every change, alerting (terminal or webhook) when new findings appear or the score regresses. Fully local and cross-platform (macOS/Linux/Windows), no backend. `--block` exits non-zero if the initial scan has critical findings (useful in CI).

> **`scan` vs `check`:** `scan` audits agent *configuration* directories (and discovers nested skills/agents/bundled files); `check` runs the AST rules + taint dataflow on the *source files* you point it at. Use `scan` to inventory and vet an agent install; use `check` to deep-scan a specific script for exfiltration/injection.

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

Continuous monitoring (`wh-agent watch`) is config-drift detection built on the same scanners — cross-platform and fully local. A future opt-in runtime-network source (Linux eBPF, via the experimental `shield-agent`) is on the [roadmap](ROADMAP.md) but **not shipped**; `watch` today means config drift.

## 🆕 What's new in v1.4.0
- **Continuous monitoring (`wh-agent watch`)** — establish a baseline, then watch an agent config and alert on security drift. Cross-platform, local, no backend. `--block` gates CI on critical findings.
- **Production-hardened drift engine** — the file watcher now attaches error handlers (a deleted watched dir or inotify limit no longer crashes the process), proactively falls back to per-directory watching on Linux + Node < 20 (where recursive `fs.watch` is silently ignored), and serializes rescans so overlapping changes can't diff against a stale baseline.
- **Repo cleanup** — experimental prototypes (`shield-agent`, the Python guardrail) moved to `experimental/`; `packages/` now holds only what ships (`cli`, `sandbox-service`). `ARCHITECTURE.md`/`ROADMAP.md` now describe the real system.
- **Experimental Python guardrail** — a backend-free library that screens RAG documents for prompt-injection risk in-process (`experimental/sdk-python`). Not part of the shipping CLI.

## 🆕 What's new in v1.3.0
- **MCP inspection (`inspect-mcp`)** — inspect an MCP server by name/command/URL for supply-chain risk, tool poisoning, and prompt injection. Static by default; `--live` enumerates the server's real tools via the official Anthropic MCP Inspector and scans them.
- **Real AST hash for Golden Snapshots** — replaces the previous raw-text hash; comment/format-insensitive, semantics-sensitive, wired through `check` → `run --ast-hash`.
- **Taint tracking for all five languages** — Python, Bash, and Rust now get real source→sink dataflow on the tree-sitter AST, at parity with JS/TS (previously JS/TS only).
- **Sandbox hardening (macOS)** — fixed an output-file symlink exfiltration escape; the timeout now kills the whole process tree (a spawned subprocess can no longer outlive it); a strict env allow-list blocks interpreter/linker hijacking (`DYLD_*`, `LD_PRELOAD`, `PYTHONPATH`, …) and never inherits host secrets; output is size-capped.
- **Safer `install`** — `--ignore-scripts` by default, no-shell invocation (removes a command-injection surface). Typosquat detection now actually works: the reference list was corrupt (contained no real top packages) and wasn't bundled into the published CLI — both fixed with a curated list of the most-typosquatted packages.
- **Taint now runs in `check`** — previously the data-flow analyzer was never invoked by `check`, so an exfiltration script reported "no vulnerabilities". `check` now runs taint on every supported file and reports source→sink flows.
- **`scan` recurses into skill/agent subfolders** — the standard `skills/<name>/SKILL.md` layout and scripts bundled inside a skill were being skipped; they're now discovered and analyzed.
- **Fail-closed everywhere untrusted code can't be contained** — Linux (Landlock + gVisor) and Windows backends refuse to execute rather than pretend to isolate.
- **Correct `--version`** — was hardcoded to `1.0.0`; now reports the real package version.

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

**Arguments:**
- `[path]`: Optional path to an agent config directory (e.g., `.claude`). Defaults to the current directory; discovery recurses into `skills/`, `agents/`, `hooks/`, etc.

**Options:**
- `-g, --global`: Search all known agent directories on the machine instead of just the given/current path.
- `-f, --format <type>`: Output format — `terminal` (default), `json`, `markdown`, or `sarif`.
- `--output <file>`: Write the results to a specific file (e.g., `report.json`).

**Example:**
```bash
wh-agent scan ./my-agent/.claude --format sarif --output ci-report.sarif
```

### 2. Universal Static Analysis Check (`check`)
Run the AST-level vulnerability check (rules **+ taint dataflow**) on specific scripts. This is the command for analyzing custom MCP tools, agent scripts, or bundled skill scripts before deploying them. It also prints a Golden Snapshot AST fingerprint you can pin with `run --ast-hash`.

**Usage:**
```bash
wh-agent check [files...] [options]
```

**Arguments:**
- `[files...]`: One or more files to analyze (supports `.py`, `.js`, `.ts`/`.tsx`, `.sh`/`.bash`, `.rs`). If omitted, every supported file in the current directory is checked.

**Options:**
- `--fix`: Automatically attempt to rewrite the code to remove a vulnerability (e.g., removing hardcoded secrets). Applies to rule-based, fixable findings only.
- `--format <type>`: Output format — `text` (default), `json`, `json-v2`, or `sarif`.

**Example:**
```bash
wh-agent check ./tools/database_query.py --fix
# deep-scan a skill's bundled script for exfiltration:
wh-agent check ~/.claude/skills/my-skill/scripts/helper.py
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

### 4. MCP Inspection (`inspect-mcp`)
Inspect a Model Context Protocol server for security issues before you trust it. Resolves a server by name from your MCP configs (`mcp.json`, `.claude.json`, `claude_desktop_config.json`, project or global), or takes a raw command or URL.

**Usage:**
```bash
wh-agent inspect-mcp <name|command|url> [options]
```

**Options:**
- `--config <path> --server <name>`: point at a specific config file + server (mirrors the MCP Inspector's own flags).
- `--live`: **executes the server** and enumerates its real tools/resources via the official Anthropic MCP Inspector, then scans their descriptions and schemas for poisoning. Opt-in because running an untrusted server is arbitrary code execution.
- `--ui`: launch the official MCP Inspector **web UI** for interactive exploration.
- `--transport <sse|http>`: transport for remote URLs.
- `--timeout <seconds>`: timeout for `--live` enumeration (default 45).
- `-f, --format <type>`: `terminal` (default), `json`, or `sarif`.

**Examples:**
```bash
wh-agent inspect-mcp github                              # static scan of a configured server
wh-agent inspect-mcp --config ./mcp.json --server github
wh-agent inspect-mcp "npx -y @modelcontextprotocol/server-github"
wh-agent inspect-mcp github --live                      # also enumerate & scan its live tools
```

> `--live` requires `npx` (it fetches the MCP Inspector on first use) and will run the server, so only use it on servers you're willing to execute. Static inspection never runs the server.

### 5. Secure Execution (`run`)
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

### 6. Continuous Monitoring (`watch`)
Establish a baseline from an initial scan, then watch a config directory and re-scan on every change, alerting when the security posture drifts. Fully local, cross-platform, no backend.

**Usage:**
```bash
wh-agent watch [path] [options]
```

**Arguments:**
- `[path]`: Directory to watch. Defaults to `./.claude`, then `~/.claude`, then the current directory.

**Options:**
- `--debounce <ms>`: Debounce interval before re-scanning (default `500`, minimum `100`).
- `--alert <mode>`: `terminal` (default), `webhook`, or `both`.
- `--webhook <url>`: Webhook URL (required when `--alert` is `webhook` or `both`).
- `--min-severity <severity>`: Minimum severity to track — `critical`, `high`, `medium`, `low`, `info` (default `info`).
- `--block`: Exit non-zero if the **initial** scan has critical findings (for CI).

**Example:**
```bash
wh-agent watch ~/.claude --min-severity high --alert both --webhook https://hooks.example/wh
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

## Experimental & roadmap

Some components live under [`experimental/`](experimental/) and are **not** part of the shipping CLI:
- **`shield-agent`** — an eBPF runtime-telemetry prototype (Linux). Observe-only today; the seed of a future runtime-enforcement layer.
- **`sdk-python`** — a backend-free Python guardrail that screens RAG documents for prompt-injection risk in-process.

See [ARCHITECTURE.md](ARCHITECTURE.md) for what ships today and [ROADMAP.md](ROADMAP.md) for where these are headed.

## Contributing

We welcome contributions. Review [CONTRIBUTING.md](CONTRIBUTING.md) to get started.

## License

Licensed under the FCL-1.0-ALv2 License. See the [LICENSE](LICENSE) file for details.
