# W.H.Agent Architecture

W.H.Agent ships as **two components that work together**:

1. **`packages/cli`** — the `wh-agent` CLI (TypeScript, published to npm as `wh-agent-cli`). This is the product surface and the entire static-analysis engine: `scan`, `check`, `inspect-mcp`, `install`, and `run`.
2. **`packages/sandbox-service`** — a small Go binary, `wh-sandbox`, that the CLI spawns to execute untrusted code inside an OS-native sandbox. Real isolation is implemented on **macOS (Seatbelt)**; Linux and Windows currently **fail closed** — they refuse to execute rather than pretend to isolate.

Everything else in the repo is either an **experimental prototype** or **scaffolding for a future control plane** — see [Experimental & not-yet-wired](#experimental--not-yet-wired) and [ROADMAP.md](./ROADMAP.md). This document describes only what runs today.

## Repository structure

```text
wh-agent/
├── packages/
│   ├── cli/               # [shipping]      wh-agent CLI + static analysis engine (TypeScript)
│   └── sandbox-service/   # [shipping]      wh-sandbox OS-sandbox binary (Go); macOS real, Linux/Windows fail-closed
├── experimental/          # prototypes — NOT shipped, NOT in CI (see experimental/README.md)
│   ├── shield-agent/      # eBPF network-telemetry prototype (Go, Linux-only)
│   └── sdk-python/        # early LangChain middleware SDK — needs a backend not in this repo
├── services/              # [scaffolding]   config only: OPA policy, Postgres schema, Kafka topics — no consumer yet
├── scripts/               # bootstrap + maintenance scripts
└── Makefile               # build orchestration (see "Building")
```

## The CLI — `packages/cli`

TypeScript, bundled with `tsup` into `dist/index.js` (exposed as both `wh-agent` and `shield`).

- **`src/commands/`** — one module per command: `scan` (audit an agent config), `check` (AST rules + taint dataflow on source), `inspect-mcp` (MCP server risk), `install` (supply-chain-vetted npm install), `run` (spawn the sandbox).
- **`src/core-scanner/`** — the analysis engine:
  - `rules/` — detection rule packs (permissions, secrets, MCP tool-poisoning, MCP-CVE, prompt-defense, hooks, skills, package-manager, agents).
  - `taint/` — source→sink dataflow. JS/TS via the TypeScript compiler; Python/Bash/Rust via tree-sitter.
  - `parser.ts` / `fingerprint.ts` — AST parsing and the "Golden Snapshot" AST fingerprint used by `run --ast-hash`.
  - `reporter/` — terminal, JSON, SARIF, and HTML output.
  - `supply-chain/`, `threat-intel/`, `injection/`; `opus/` (optional LLM deep-scan, bring-your-own `ANTHROPIC_API_KEY`); `miniclaw/` (deterministic prompt-injection router).
- **`src/vm/` + `src/ipc/`** — client-side plumbing for the *runtime shield* prototype (a Unix-socket client plus Lima/WSL/gVisor VM providers that expect `shield-agent`). **This path is experimental** and is separate from the macOS `run` path below.
- **`bin/wh-sandbox`** — the compiled Go sandbox binary, produced by the build and shipped with the npm package. Built, not committed (see [Building](#building)).

## The sandbox — `packages/sandbox-service`

A standalone Go binary (module `wh-agent/sandbox-service`).

- **`cmd/wh-sandbox/main.go`** — reads an `ExecRequest` as JSON on **stdin** (`{ Code, Language, TimeoutMs, Env }`), runs it under the platform sandbox, and writes an execution result as JSON on **stdout**.
- **`internal/vm/`** — platform backends:
  - `vm_darwin.go` — macOS Seatbelt via `sandbox-exec`. Real isolation, tested against host-read, write-then-exec, network-egress, subprocess-timeout, and env-leak escapes.
  - `vm_linux.go`, `vm_windows.go` — **fail closed**, pending real Landlock/gVisor and Job Object implementations.
- **`internal/executor/`** — process lifecycle: a timeout that kills the whole process tree, output size caps, and a strict env allow-list.

## How the two fit together

```text
wh-agent run script.py
   │
   ├─ CLI (run.ts): read the file once, compute the AST fingerprint
   │  (optionally enforce a pinned --ast-hash), build an ExecRequest
   │
   └─ spawnSync( packages/cli/bin/wh-sandbox )
          │  stdin  → ExecRequest JSON  { Code, Language, TimeoutMs, Env }
          │  stdout ← Result JSON       { Stdout, Stderr, ExitCode, ExecutionMs, Killed }
          │
          └─ wh-sandbox: generate a Seatbelt profile → exec under sandbox-exec (macOS)
```

The static commands (`scan` / `check` / `inspect-mcp` / `install`) run entirely inside the CLI and never touch the Go binary.

## Building

Both components are built by the `Makefile` (and mirrored in CI):

```bash
make build          # build the Go sandbox binary into packages/cli/bin, then build the TS packages
make build-sandbox  # just the Go binary  (cd packages/sandbox-service && go build ./cmd/wh-sandbox)
make build-cli      # just the TypeScript (pnpm turbo build)
make test           # go vet + go test (sandbox) and turbo test (TypeScript)
```

The binary lands at `packages/cli/bin/wh-sandbox`, exactly where `run.ts` resolves it, and the CLI's `package.json` ships it via its `files` list (and rebuilds it in `prepublishOnly`). Because real isolation is macOS-only today, a **release binary must be built on macOS**; CI additionally validates the sandbox on a macOS runner.

## Experimental & not-yet-wired

These exist in the tree but are **not part of the shipping product** today:

- **`experimental/shield-agent`** — a Go eBPF prototype that attaches a `sys_enter_connect` tracepoint and streams network events over `/tmp/shield-agent.sock`. Requires Linux + a compatible kernel; not built or tested in CI. It is the seed of a runtime-enforcement layer, not a finished one.
- **`experimental/sdk-python`** — an early LangChain middleware SDK that polls a `posture-service` HTTP backend. That backend does not exist in this repo, so the SDK is non-functional standalone.
- **`services/`** — config artifacts only: an OPA `package_install.rego` policy, Postgres migrations, and Kafka topic definitions. No code in the repo consumes them yet.

The intended future for these components — and the commercial roadmap — lives in [ROADMAP.md](./ROADMAP.md).
