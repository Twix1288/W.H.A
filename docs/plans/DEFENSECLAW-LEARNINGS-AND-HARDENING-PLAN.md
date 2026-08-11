# Plan — Sandbox hardening + a runtime guardrail layer (learning from DefenseClaw)

Status: **proposed**. Two intertwined tracks. Additive only — nothing that ships today changes behavior.

This plan does two things the user asked for, in order:
1. **Track A — harden the sandbox** and make `run` genuinely usable (the original ask).
2. **Track B — add the runtime enforcement layer** wh-agent lacks, adopting the *good ideas* from Cisco's [DefenseClaw](https://github.com/cisco-ai-defense/defenseclaw) **without** copying its enterprise weight.

---

## What DefenseClaw is, and what we take vs. leave

DefenseClaw = "security governance for agentic runtimes": a **Go gateway** that sits **in the agent's runtime path** (as a proxy or via native **hooks**), gated by **OPA/rego policy** + **tunable YAML guardrail rule packs**, with a **durable audit store**, an optional **LLM judge**, and a full **observability stack** (Splunk/OTel/Grafana/Loki/Tempo). It's an *enforcement + evidence* layer — explicitly "does not prove an agent is risk-free."

wh-agent today = **static scan** (`scan`/`check`/`inspect-mcp`/`install`) + a **one-shot hermetic sandbox** (`run`). It has a strong deterministic engine but **no runtime layer**: nothing governs a *live* agent as it makes tool calls.

### TAKE (fits wh-agent's local, no-backend, deterministic identity — and every piece maps to code we already have)

| Idea from DefenseClaw | Their mechanism | wh-agent reuse point (already exists) |
|---|---|---|
| **In-path runtime enforcement** | gateway hooks / `fetch-interceptor.ts` intercept each tool call & egress | `runRules()` + `analyzeTaint([{path,content}])` already accept in-memory content — feed them a tool-call payload |
| **Tunable YAML rule packs** | `policies/guardrail/{default,permissive,strict}/rules/*.yaml`, each rule `{id,pattern,title,severity,confidence,tags}` by category (commands, secrets, c2, sensitive-paths, trust-exploit, cognitive) | `core-scanner/rules/*` — externalize into the same tiered YAML format |
| **Policy-as-code → sandbox scope** | `policies/rego/sandbox.rego`: `requested_endpoints`/`requested_permissions` → allowed/denied | `core-scanner/policy/` (loadPolicy/evaluatePolicy/exceptions) + the dead `envelope.yaml` |
| **Durable audit / evidence** | `internal/audit/`, `audit.rego` | `core-scanner/logger/history.ts` (built, unwired) → append-only JSONL |
| **Optional LLM judge** | `policies/guardrail/*/judge/*.yaml` (tool-injection, injection, pii) | `core-scanner/opus/` ATTACKER/AUDITOR/DEFENDER pipeline (BYO key) |
| **Sensitive-tool result inspection** | `sensitive-tools.yaml` + `min_entities_for_alert` (mass-enumeration → alert) | new small detector; directly answers the "agent enumerated all my repos" concern |
| **Suppressions as a first-class file** | `suppressions.yaml` | `policy/` already models `PolicyException`; surface a `.wh-agent/suppressions.yaml` |

### LEAVE (copying these would make wh-agent *worse* — they betray the "local, no-backend, deterministic" wedge)

- The **Go gateway / proxy / connector matrix** for dozens of runtimes, the **v8 schema/proto machinery**, **HITL server**, **Windows native app**.
- The **observability backend** (Splunk/OTel/Grafana/Loki/Tempo). wh-agent's promise is *no code leaves the machine*; a telemetry backend is roadmap rung 4, not now.
- **OPA/rego runtime dependency.** We already have a TypeScript policy engine (`core-scanner/policy/`). Adopt rego's *model* (declarative allow/deny with data), not the `opa` binary.

---

## Track A — Sandbox hardening (verified findings + fixes)

All findings below were reproduced directly against `packages/cli/bin/wh-sandbox` this session.

> **Status: A1 + A2 SHIPPED & verified.** `vm_darwin.go` now wraps the interpreter in a
> `sh -c 'ulimit -t/-f/-u …; exec …'` limits shell and sweeps `setsid`-detached survivors by
> their scratch cwd (`reapByScratchCwd`, using `lsof`), reporting `DetachedReaped` up through
> `run.ts`. The setsid escape is closed (3/3 + double-detach reaped end-to-end), `RLIMIT_FSIZE`
> bounds disk-fill, and `RLIMIT_CPU` (inherited across setsid) backstops CPU. Three Go regression
> tests added; full `make test` (Go `-race` + TS) green. `RLIMIT_AS`/memory is documented as a
> Darwin limitation, not faked. Remaining in Track A: A3 (id leak, doc), A4 (exec-root tighten),
> A5 (scoped `run`/envelope) — not yet started.

### A1. CRITICAL — `setsid` detached process escapes the timeout + reaper; sandbox reports clean success
- **Repro (confirmed):** a payload that `fork()`s, `setsid()`s, and exits the parent returns in ~56 ms with `Killed=false, ExitCode=0`, while the detached child runs on (found alive 2 s past a 1000 ms timeout via `pgrep`).
- **Root cause:** `vm_darwin.go` teardown does `syscall.Kill(-pgid, SIGKILL)` (a new session is unreachable), and `cmd.Wait()` returns the instant the direct child exits (output goes to files, not pipes).
- **Fix (mechanism proven this session):** launch the payload through a limits wrapper —
  `sh -c 'ulimit -t <cpu> -f <fsize> ...; exec <interp> <script>'`. **`RLIMIT_CPU` is enforced on macOS AND inherited across `setsid`** — it kills a detached CPU-spinner even after it escapes the process group. Combined with the existing Seatbelt confinement (no host reads, no network) and `RemoveAll` of scratch, a detached survivor is reduced to a CPU/file/network/fs-bounded, harmless, short-lived process.
- **Honesty fix:** stop reporting `ExitCode=0, Killed=false` as proof of clean completion when the payload forked. Add a best-effort scratch-scoped sweep before return and reflect "descendants may have been detached" in the result rather than asserting success.

### A2. HIGH — no memory / process / disk limits
- **Repro (confirmed):** 400 MB allocation succeeds; 30 rapid forks succeed; no `RLIMIT_*` set.
- **Fix + honest boundary (verified on this macOS):**
  - `RLIMIT_CPU` (`ulimit -t`): **enforced** → bound CPU (foreground *and* detached).
  - `RLIMIT_FSIZE` (`ulimit -f`): **enforced** → bound single-file disk fill.
  - `RLIMIT_NPROC` (`ulimit -u`): **enforced but per-uid** → set a generous cap computed from the current limit (never below current usage) to stop runaway forks without breaking a busy machine.
  - `RLIMIT_AS` (`ulimit -v`): **ignored by Darwin** (empirically confirmed) → **document** that hard memory capping needs a container (the roadmap's gVisor/Landlock rung). Wire `MaxMemMB`/`MaxCPUPct` to the limits that *do* work; stop silently accepting fields nothing enforces.

### A3. LOW — host identity leak (hostname/uid/OS via `bsd.sb` sysctl). Document; mitigate opportunistically.

### A4. Defense-in-depth — exec-allow of user-writable `/opt/homebrew/bin` & `/usr/local`
- **Repro (confirmed):** a binary pre-planted in user-writable `/opt/homebrew/bin` executes inside the sandbox (two-stage; requires prior unsandboxed write, so lower severity). In-invocation write-then-exec stays correctly blocked.
- **Fix:** prefer allowing exec of the *resolved interpreter path* over broad `/opt`+`/usr/local` subtrees where feasible; at minimum add a regression test + doc note. Don't break Homebrew-Python users.

> **Status: A5 SHIPPED & verified.** `run --envelope` is now live: `envelope.yaml`
> `storage.mounts` (ro/rw) become canonicalized Seatbelt subtree grants (read/write
> only, never exec), `network.egress_proxy` narrows the default deny to a single
> local proxy, and the first opened path becomes the working directory so
> project-relative paths resolve. Verified end-to-end: scope to a project → its files
> readable/writable, sibling project denied, egress reaches only the proxy, and no
> envelope → the prior hermetic default. 4 Go regression tests added; full `make
> test` green. New: `src/commands/envelope.ts` (parser), `vm.go` (`PathRule`/
> `AllowPaths`/`EgressProxy`), `vm_darwin.go` (scoped SBPL + workdir), `run.ts`.

### A5. Make `run` actually usable — resurrect the envelope (ties into Track B policy)
- Today `--envelope` is dead (`_envelopePath`), the profile only allows the ephemeral scratch dir, and no args reach the script → `run` can only execute a hermetic throwaway. **Spiked and verified this session:** Seatbelt cleanly supports (a) scoping reads/writes to a specific project subtree while denying siblings (no directory restructuring), and (b) allowing egress **only** to a local proxy port. Parse `envelope.yaml` → `AllowPaths []PathRule` + `EgressProxy` in `ExecRequest` → templated Seatbelt clauses (canonicalized with `EvalSymlinks`, deny-wins). This is what turns `run` from "throwaway script box" into "run my real tool, scoped."

---

## Track B — Runtime guardrail layer (the DefenseClaw idea, native + backend-free)

> **Status: B1 SHIPPED & verified; B2 first slice landed.** `wh-agent guard` reads a
> Claude Code PreToolUse payload on stdin, extracts the code a Bash/Write/Edit/MultiEdit/
> NotebookEdit call will run, screens it with the SAME rule+taint engine as `check` (via the
> new in-memory `parseSource`), and emits an allow/ask/deny decision in the hook's JSON
> contract — with a durable local audit trail (`~/.wh-agent/guard-audit.jsonl`) and
> `strict`/`default`/`permissive` profiles. Fails closed on analysis error, fails open on an
> unparseable payload (won't brick the agent). `wh-agent guard install` merges the hook into
> settings.json (never clobbers; writes `.bak`; idempotent). As a first slice of B2, a small,
> high-precision runtime command-pattern set (reverse shells via /dev/tcp, nc -e, interpreter
> socket one-liners, download-and-exec, credential-file exfil — adapted from DefenseClaw's
> `commands.yaml`) closes attacks the AST rules miss. Verified end-to-end: reverse shells /
> curl|bash / secret-exfil Write → deny/ask; benign commands → allow (no false positives).
> 18 new tests; full `make test` green. New: `src/commands/guard.ts`, `guard.nodetest.ts`,
> `parser.ts` (`parseSource`), `index.ts` (`guard` + `guard install`). Remaining B2: externalize
> the full rule set into tunable `default/permissive/strict` YAML packs shared with scan/check.

### B1. `wh-agent guard` — an in-path PreToolUse/PostToolUse hook (the core win)
- A new command that installs itself into an agent's native hook system (Claude Code first: `.claude/settings.json` `PreToolUse`/`PostToolUse`). On each tool call it reads the hook JSON on stdin (`tool_name`, `tool_input`), runs wh-agent's **existing** rule + taint engine on the actual command/code the agent is about to execute, evaluates it against the active **policy profile**, and returns an allow / ask / deny decision (Claude Code contract: `permissionDecision` JSON or exit-2 block).
- **Why it's the win:** it closes the exact hole the field feedback named — *"command patterns work except when the agent writes and executes code."* A `Bash`/`Write` tool call carrying a reverse shell or a secret-exfil snippet is taint-analyzed **before** it runs. Deterministic, local, no backend.
- **Reuse:** `runRules`, `analyzeTaint([{path,content}])`, `policy/evaluate`. New code is the hook I/O adapter + a fast single-payload path + the installer.

> **Status: B2 SHIPPED & verified.** Detection is now externalized into tunable YAML
> packs under `packages/cli/packs/` — `commands`, `injection`, `secrets`, `sensitive-paths`
> — each rule `{id, pattern, flags?, title, severity, confidence, tags, profiles?}` with
> `permissive`/`default`/`strict` profiles. A shared engine (`core-scanner/patterns/`:
> loader + `scanText`) loads the shipped packs (robust path resolution + fail-safe builtin
> fallback) PLUS user overrides/suppressions from `~/.wh-agent/rules/` and `./.wh-agent/rules/`.
> **All three commands consume it**: `guard` (replacing its inline patterns), `check` (merged
> into per-file findings, deduped), and `scan` (over bundled script files — closing the
> "skill scripts never analyzed" gap). This also closed the adversarial-verification breakages:
> script-body reverse shells (dup2/pty.spawn), mkfifo/nc + dotless-`/dev/tcp`, base64
> decode-exec, and the broadened "ignore ALL previous instructions" injection phrase.
> 8 pack tests + the wired command tests; full `make test` green (43 tsx + bun + Go `-race`).
> Remaining/optional: migrate the AST/structural config rules (permissions/mcp-structure) —
> those stay as code (not regex-expressible); the *pattern* layer is what's externalized.

### B2. Tunable YAML rule packs (adopt their format)
- Externalize detection into `rules/packs/{default,permissive,strict}/{commands,secrets,c2,sensitive-paths,trust-exploit,cognitive}.yaml`, each rule `{id, pattern, title, severity, confidence, tags}` — DefenseClaw's exact shape. **Both** `scan`/`check` (static) **and** `guard` (runtime) consume the same packs, so detection is unified and user-tunable. Ship the three profiles; default to `default`.

### B3. Durable local audit trail (`.wh-agent/audit.jsonl`)
- Extend `logger/history.ts` into an append-only JSONL record of every `guard`/`scan` decision (timestamp, tool, rule hits, decision, profile). This is the "evidence" a security team wants — held **locally**, exportable to SARIF/JSON. No backend.

### B4. Suppressions + policy profiles
- Surface `.wh-agent/suppressions.yaml` (reusing `policy/`'s `PolicyException`) so a team can silence a known-benign pattern without disabling a rule globally — the real-world need static scanners must have.

### B5. Optional LLM judge (opt-in, BYO key) — reuse `opus/`
- For ambiguous `guard` decisions and for **intent-vs-action** ("did this tool call do what the user asked?"), escalate to the existing `opus/` ATTACKER/AUDITOR/DEFENDER pipeline. Off by default; deterministic engine is always the primary gate so `guard` can't be prompt-injected the way an ML-only detector can.

### B6. Mass-enumeration / sensitive-tool detector
- Adopt `sensitive-tools.yaml` + `min_entities_for_alert`: in PostToolUse, flag when a tool returns a mass of entities (the "agent listed every git repo / every contact" case). Small, high-signal, directly answers a named field concern.

---

## Sequencing (small, independently-shippable, green the whole way)

1. **A1+A2 (sandbox hardening)** — rlimits wrapper + honest reporting + tests. Self-contained Go change; mechanism already proven. *Ship first.*
2. **B2 (rule packs)** — externalize rules to tiered YAML; `scan`/`check` consume them (no behavior change if the default pack mirrors today's rules). Foundation for B1.
3. **B1 (`guard` hook)** — the headline runtime layer, built on B2 + the existing engine.
4. **B3+B4 (audit + suppressions)** — evidence + tuning.
5. **A5 (envelope/scoped run + egress proxy)** — makes `run` usable; consumes the policy model.
6. **B5+B6 (judge + mass-enumeration)** — opt-in depth.

## Compatibility guarantee ("works with the current system")
- Every item reuses an existing module (verified this session): the taint/rule engine already takes `{path, content}`; `policy/`, `logger/`, `opus/` already exist. New commands are additive; `scan`/`check`/`inspect-mcp`/`install`/`run`/`watch` keep their behavior.
- Gate: `make test` (turbo test + go test) green after every step; add tests per step (setsid-reap regression, rule-pack parity, `guard` allow/deny, envelope scoping).

## Explicitly out of scope (would make wh-agent worse)
- The Go gateway/proxy/connector matrix, HITL server, Windows-native app.
- The Splunk/OTel/Grafana observability backend (breaks "nothing leaves the machine").
- An `opa` binary runtime dependency (we have a TS policy engine).
