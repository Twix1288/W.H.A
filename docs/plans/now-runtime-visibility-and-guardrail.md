# Plan — "Now" step: Runtime Visibility + Local Guardrail

Status: **proposed** · Scope: the first ("Now") rung of [ROADMAP.md](../../ROADMAP.md) · No backend required.

## Objective

Expand the product with two near-term capabilities that make vetting **continuous** and extend it **into agents people build** — without a backend, and without touching anything that already ships:

- **A. `wh-agent watch`** — runtime visibility: continuously watch an agent's config for security drift, and (opt-in, Linux) stream live network activity from `shield-agent`.
- **B. Local guardrail library** — salvage the working RAG-provenance scorer from `experimental/sdk-python` into a clean, backend-free Python guardrail that screens documents/tool I/O for injection inside a running agent.

## Non-negotiable constraints ("works with everything already working")

1. **Additive only.** No changes to the behaviour of `scan`, `check`, `inspect-mcp`, `install`, `run`, or `setup`.
2. **Works on macOS today.** The default `watch` experience must run on the maintainer's platform with zero Linux/eBPF dependency.
3. **shield-agent stays optional.** The runtime-network source is opt-in and **degrades gracefully** when eBPF/shield-agent isn't present — never a hard dependency, never a crash.
4. **Experimental stays experimental.** The Python guardrail lives under `experimental/`, isolated from the shipping TS build and the CI gate.
5. **Green the whole time.** `make test` (turbo test + go test) must pass before and after each step.

## What already exists (reuse map)

Most of this is **built and just not surfaced** — the work is wiring, not inventing.

| Piece | Location | Status |
|---|---|---|
| File-watch + debounce + rescan + diff loop | `packages/cli/src/core-scanner/watch/watcher.ts` (`startWatcher`) | ✅ built |
| Baseline snapshot + drift diff | `.../watch/diff.ts` (`createBaseline`, `diffBaseline`) | ✅ built |
| Persistent baseline files + CI gate | `.../baseline/compare.ts` (`saveBaseline`, `loadBaseline`, `evaluateGate`) | ✅ built |
| Terminal + webhook alerts | `.../watch/alerts.ts` (`dispatchAlert`, `renderTerminalAlert`) | ✅ built |
| Reference `watch` command (not shipped) | `.../core-scanner/index.ts` (legacy entry, ~line 1126) | ✅ exists to lift |
| shield-agent socket client (NDJSON, backoff) | `packages/cli/src/ipc/socket-client.ts` (`ShieldSocketClient`) | ✅ built |
| VM providers exposing the socket path | `packages/cli/src/vm/*` (`getSocketPath()`) | ✅ built |
| RAG provenance + injection scorer | `experimental/sdk-python/src/wh_agent/rag/provenance.py` | ✅ works (only clean module) |

---

## Workstream A — `wh-agent watch`

### A1. Surface the command (reuse, ~½ day)
- Create `packages/cli/src/commands/watch.ts` mirroring the shape of `scan.ts`/`install.ts`. Its handler calls the **already-built** `startWatcher(config)` from `core-scanner/watch`.
- Register a `watch` block in `packages/cli/src/index.ts` (mirrors the `scan` block): options `--path`, `--debounce`, `--min-severity`, `--alert <terminal|webhook|both>`, `--webhook <url>`, `--block` (CI: exit non-zero on new critical), `--format <terminal|json>`.
- Lift the input validation from the legacy `core-scanner/index.ts` watch block. Do **not** modify the legacy file (it's dormant, not shipped) — note it in "Follow-ups" for later consolidation.
- **Outcome:** on macOS, `wh-agent watch ~/.claude` re-scans on every config change and alerts on drift (new MCP server, widened permissions, a new hook/secret). This alone is the "ambient" stickiness win — cross-platform, no backend.

### A2. Optional Linux runtime-network source (opt-in, graceful)
- Add `--runtime` to `watch`. When set:
  - **Platform gate first:** if not Linux, print `runtime network telemetry requires Linux + shield-agent — continuing with config-drift only` and proceed (no 5 s hang, no crash).
  - On Linux, resolve a socket path (default `/tmp/shield-agent.sock`, or via a `vm/` provider's `getSocketPath()`), connect with the existing `ShieldSocketClient`, and fold `ShieldEvent`s into the same alert pipeline (`dispatchAlert`).
  - If the socket isn't there, `ShieldSocketClient` already times out after 5 s → catch it, warn, and keep config-drift running.
- **Dependency (does not block the macOS ship):** end-to-end Linux telemetry needs a *buildable* shield-agent — its `bpf2go` bindings aren't committed. Tracked as a separate task; `--runtime` ships as "wired + graceful-unavailable" until then.

### A3. Output & UX
- Reuse `renderTerminalAlert` for the human view; add a `--format json` path (newline-delimited drift/runtime events) so `watch` is scriptable and CI-friendly.
- Keep the summary-first convention already used by the other reporters.

### A4. Tests & verification
- Unit: baseline/diff already have logic; add a `watch.test.ts` covering config-drift detection (seed a config, mutate it, assert a new finding surfaces) and the graceful non-Linux `--runtime` path.
- Manual: `wh-agent watch` on `~/.claude` on macOS; confirm `--runtime` degrades cleanly.
- Regression: `make test` green.

**Files:** `+ src/commands/watch.ts`, `~ src/index.ts` (one block), `+ src/commands/watch.test.ts`. No other command touched.

---

## Workstream B — Local guardrail library (Python)

Goal: turn the currently-broken `experimental/sdk-python` into a **small, working, backend-free** guardrail, keeping only what functions.

### B1. Drop the backend dependency
- Remove `client.py` (the `posture-service` poller — invalid `class W.H.AgentClient`, and the backend doesn't exist).
- The public API becomes the valid, self-contained: `process_retrieved_documents`, `run_lexical_classifier` (from `rag/provenance.py`).

### B2. Fix packaging so it imports
- `pyproject.toml`: point the wheel target at the real package dir `src/wh_agent` (currently the invalid `src/wh-agent`).
- Add `src/wh_agent/langchain/__init__.py`; populate `src/wh_agent/__init__.py` exports.
- Verify: `python -c "import wh_agent"` succeeds and `python -m pytest` collects.

### B3. Backend-free LangChain guardrail (optional extra)
- Rewrite `langchain/callbacks.py` as `WHAgentGuardrail(AsyncCallbackHandler)` (valid name) that, on `on_retriever_end`, runs `process_retrieved_documents` and — using a **constructor `mode` + `risk_threshold`**, not a network poll — drops/flags documents above the threshold. Zero backend.
- Keep it an optional import so the core scorer has no LangChain dependency.

### B4. Tests
- Fix the import lines in `tests/test_sdk.py`; the two provenance tests (verified-source → 0.0; unverified injection → ≈0.9) pass with no external service.
- Add one guardrail test (enforce mode drops a high-risk doc; visibility mode only flags).

**Files:** `~ pyproject.toml`, `- client.py`, `~ langchain/callbacks.py` (+ `__init__.py`), `~ __init__.py`, `~ tests/test_sdk.py`, `~ README.md`. Entirely inside `experimental/` — no effect on the TS CLI.

---

## Compatibility & regression strategy

- **A** adds one new command + handler; every existing command path is untouched. The watch/baseline/alert libraries are already imported in the tree, so no new runtime dependencies.
- **shield-agent** is never required: config-drift is the default; `--runtime` is opt-in and self-heals when unavailable.
- **B** is pure Python under `experimental/`, invisible to `tsup`, `turbo`, and the shipping bin.
- **Gate:** run `make test` after A1, after A2, and after B. Ship each step only when green.
- **CI:** optionally add a *non-gating* `guardrail-python` job (pytest) so the experimental lib is checked without blocking the shipping pipeline — consistent with the "experimental stays out of the gate" rule.

## Sequencing (small, independently-shippable steps)

1. **A1** — surface `wh-agent watch` (config-drift). *Immediately useful on macOS.*
2. **B1–B4** — make the guardrail import + pass tests. *Fully parallel to A; zero CLI risk.*
3. **A2** — wire the optional Linux runtime source with graceful fallback.
4. **A3/A4** — JSON output + tests, then `make test`.

## Explicitly out of scope (later rungs)

- eBPF **enforcement** (LSM `socket_connect` blocking) — ROADMAP rung 3.
- Any **backend / persistence / dashboard** (SQLite "memory", hosted control plane) — the next ("memory") step.
- Fixing shield-agent's `bpf2go` build — separate task that lights up `--runtime` on Linux.
- Consolidating/removing the legacy `core-scanner/index.ts` entry point.
