# W.H.Agent Architecture

W.H.Agent is designed as a modern, high-performance monorepo utilizing a mix of Node.js (TypeScript) for high-level tooling and Go for low-level, high-performance OS-native sandboxing and shielding.

This document serves as a map to "where all the code that does the work" lives, to help contributors quickly onboard and navigate the project.

## High-Level Repository Structure

```text
wh-agent/
├── packages/           # Core applications, libraries, and services
│   ├── cli/            # The main `wh-agent` CLI application (TypeScript)
│   ├── sandbox-service/# OS-Native execution sandbox (Go)
│   ├── shield-agent/   # Runtime system shield / eBPF service (Go)
│   ├── sdk-python/     # Python integration SDK
│   ├── middleware-sdk/ # Node.js integration SDK
│   └── red-team-engine/# Offensive security testing engine
└── services/           # Supporting infrastructure services (Docker/Config)
```

## Core Components Deep-Dive

### 1. `packages/cli` (The Entry Point)
This is the heart of the user experience and the static analysis engine. It is written in TypeScript and executed via Node.js.
- **`src/commands/`**: Contains the logic for the different CLI actions you can take (`scan`, `check`, `install`, `run`, `setup`).
- **`src/core-scanner/`**: The core of the AST-based (Abstract Syntax Tree) static analyzer. It parses code to find dangerous variables, data exfiltration attempts, and logic flaws before execution.
- **`src/vm/` & `src/ipc/`**: Orchestrates secure communication and manages the lifecycle of the underlying sandbox services.

### 2. `packages/sandbox-service` (The Sandbox)
This is the OS-native execution sandbox, written in Go to maintain sub-millisecond execution speeds and strong isolation.
- **`cmd/wh-sandbox/main.go`**: The entry point for the standalone sandbox binary. When the CLI invokes a `run` command, it spins up this binary to isolate the untrusted code.
- **`internal/executor/` & `internal/vm/`**: Contains the platform-specific isolation logic (e.g., macOS Seatbelt profiles, Linux Landlock/seccomp-bpf, Windows Job Objects).

### 3. `packages/shield-agent` (The Runtime Shield)
A specialized Go service utilizing eBPF (Extended Berkeley Packet Filter) and Linux native primitives to intercept system calls and detect or block malicious runtime behaviors that bypass static analysis.

### 4. Developer SDKs
- **`packages/sdk-python/`**: SDK allowing developers building Python agents (like LangChain/LlamaIndex) to embed W.H.Agent's security checks.
- **`packages/middleware-sdk/`**: SDK for Node.js based agents to integrate directly with the W.H.Agent platform.

### 5. `services/` (Infrastructure)
This directory contains configuration files and deployment scripts for supporting infrastructure, enabling W.H.Agent to integrate with:
- **PostgreSQL / Redis**: State tracking and configuration drift detection caching.
- **Vault**: Secure secret management.
- **OPA (Open Policy Agent)**: Centralized policy enforcement.
- **Kafka**: High-throughput telemetry and audit log streaming.

## How the Pieces Fit Together

1. **Static Analysis Phase**: When a user runs `wh-agent check` or `wh-agent scan`, the `cli` component dynamically parses the target agent's code into an AST and evaluates intra-procedural logic, all within Node.js.
2. **Execution Phase**: When a user runs `wh-agent run <script>`, the `cli` spawns the `wh-sandbox` binary (from `sandbox-service`), injecting the required policies via IPC. The untrusted script is executed directly within this OS-isolated layer, preventing unauthorized file system or network access.
