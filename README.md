<p align="center">
  <h1 align="center">W.H.Agent (White Hat Agent)</h1>
</p>

<p align="center">
  The State-of-the-Art Security Platform for Autonomous AI Agents.<br/>
  Discover, scan, and securely sandbox agent components, MCP servers, and skills.
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/wh-agent-cli"><img src="https://img.shields.io/npm/v/wh-agent-cli" alt="NPM Version" /></a>
  <a href="https://github.com/wh-agent/wh-agent/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-FCL--1.0--ALv2-blue.svg" alt="License" /></a>
  <a href="https://github.com/wh-agent/wh-agent/actions"><img src="https://img.shields.io/badge/build-passing-brightgreen.svg" alt="Build Status" /></a>
</p>

---

## 🛡️ The AI Threat Landscape has Evolved

The transition from stateless LLMs to autonomous, stateful AI agents embedded directly in developers' environments has opened up an unprecedented attack surface. Traditional software boundaries no longer apply to agents that dynamically execute code, retrieve sensitive context, and trigger downstream operations via tools like the Model Context Protocol (MCP).

**W.H.Agent** is designed to provide enterprise-grade pre-execution and runtime defenses, directly neutralizing advanced persistent threats like **Prompt Injection**, **Malicious Tool Use**, and **Silent Memory Poisoning**.

## ✨ Key Features

W.H.Agent uniquely pairs static configuration analysis with a blazing-fast, OS-native execution sandbox.

### 🔍 1. Global Agent Auto-Discovery
Don't just scan an isolated project. `W.H.Agent` acts as a central watchdog for your entire machine, automatically discovering and auditing configurations for the industry's most popular AI platforms across System, User, and Workspace scopes.
**Supported Integrations:** Cursor, Windsurf, VS Code, Claude Desktop, Claude Code, Gemini CLI, OpenClaw, and Antigravity.

### 🦠 2. Deep Threat-Hunting & Payload Detection
W.H.Agent doesn't just look for bad code in scripts—it actively hunts for reverse shells, data exfiltration attacks (`curl | bash`), and indicators of compromise (IOCs) hidden deep within `.md` instructions, agent definitions, and `SKILL.md` files. We focus on true, critical malware, cutting through the noise of generic linting.

### 🧠 3. AST Intra-Procedural Taint Tracking
We abandoned noisy regex engines for precision. W.H.Agent dynamically compiles and parses agent scripts into Abstract Syntax Trees (AST). **It now fully supports and analyzes Python, JavaScript, TypeScript, Bash, and Rust.** It tracks the intra-procedural flow of variables to detect data exfiltration and toxic control flows before they ever execute—with zero false positives.

### ⚙️ 4. Sub-Millisecond OS-Native Sandboxing
When executing agent skills, heavy Docker containers create unacceptable friction. W.H.Agent isolates subprocess trees instantly using the exact native sandboxing primitives built into your operating system:
- **macOS:** Dynamically generated Seatbelt profiles (`sandbox-exec`) *(Available)*
- **Linux:** Swappable backends supporting both native `Landlock` enforcement and full `gVisor` containers, toggled instantly via the `WH_SANDBOX_BACKEND` env var. *(Available)*
- **Windows:** Job Objects and AppContainer (Low Box tokens) *(Planned)*

### 🔒 5. Golden Snapshots & Hash Binding
We compute a deterministic AST hash of your agent tools and freeze them. If an attacker tries to silently rewrite a script on your disk later, the signature check fails and execution gets blocked instantly.

### 🚨 6. Watchdog Configuration Drift Detection
Persistent agent memory and hidden MCP profiles are prime targets for attackers. W.H.Agent implements persistent state tracking—hashing your vulnerabilities locally and throwing immediate alerts if a malicious skill is silently installed or your sandbox policy drifts over time.

## 🏗️ Project Architecture

W.H.Agent is a monorepo consisting of high-level TypeScript tooling and high-performance Go OS-native sandboxing. If you are looking to understand where all the code that does the work lives, please read our [Architecture Document](ARCHITECTURE.md).

## 🚀 Quick Start

### Command Status

| Command | Status |
|---------|--------|
| `wh-agent scan` | **Production-ready** — global agent discovery, JSON/SARIF/Markdown export |
| `wh-agent check` | **Production-ready** — Universal tree-sitter AST scanning (Python, JS, TS, Bash, Rust) with auto-remediation |
| `wh-agent setup` | **Requires Docker Desktop** |
| `wh-agent install`| **Secure install** via npm, AST and typosquat checking |
| `wh-agent run` | **Experimental** — requires `--experimental` flag. Sandboxing is fully functional on macOS and Linux. |

### Installation

Install the CLI globally via npm or bun:

```bash
npm install -g wh-agent-cli
# or
bun install -g wh-agent-cli
```

### 1. Global System Scan (Production Ready)

Auto-discover and scan every agent installed on your machine. This renders an elegant summary table without polluting your terminal:

```bash
wh-agent scan --global
```

Export deep, verbose findings directly to a JSON or SARIF file for your security pipeline:

```bash
wh-agent scan --global --format json --output report.json
```

### 2. Universal Static Analysis Check (AST-level)

Run AST-level static vulnerability checks and threat-hunting on Python, JavaScript, TypeScript, Rust, and Bash files. Includes auto-remediation for dangerous execution and secret exposures!

```bash
wh-agent check script.py --fix --format sarif
```

### 3. Secure Install

Install a package safely via npm with built-in typosquatting and supply chain scanning:

```bash
wh-agent install <package>
```

### 4. Secure Execution (Experimental)

Wrap an untrusted agent or script execution inside W.H.Agent's OS-native sandbox. Requires the `--experimental` flag. 

⚠️ **Transparency Note:** The runtime sandbox physically intercepts payloads and works robustly on macOS (Seatbelt) and Linux (Landlock/gVisor). Windows support is still pending. While we have tests proving the isolation works and catches tampered files, passing dynamic arguments into a frozen sandbox snapshot (parameterization IPC) is still in the prototyping phase.

```bash
wh-agent run ./malicious-agent.js --experimental
```

---

## 🎯 The Breakout Challenge (Hall of Fame)

If you can break out of the AI agent sandbox we just built, we will put your name at the very top of this README.

We want to prove this holds up against real attacks. If you can write an MCP tool or agent script that successfully bypasses the Linux or macOS isolation layer and reads a protected host file, you get the top spot in our Hall of Fame. 
To test it:
1. Wrap your malicious payload: `WH_SANDBOX_BACKEND=landlock wh-agent run payload.py --experimental`
2. Open an issue with your bypass method.

## 🛠️ Output Formats

W.H.Agent supports multiple output formats natively:
- **Terminal:** Elegant summary tables for human readability.
- **JSON:** Fully structured data array of all findings and grades.
- **Markdown:** Clean, readable text format for GitHub issue creation.
- **SARIF:** Industry-standard format for native GitHub Advanced Security and CI/CD ingestion.

## 🤝 Contributing

We welcome contributions! Please review our [CONTRIBUTING.md](CONTRIBUTING.md) to get started.

## 📄 License

This project is licensed under the FCL-1.0-ALv2 License. See the [LICENSE](LICENSE) file for details.
