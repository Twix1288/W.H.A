# W.H.Agent Roadmap

> This document is **forward-looking**: the product plan and the intended future of the experimental packages. For what actually ships today, see [ARCHITECTURE.md](./ARCHITECTURE.md).

## The product ladder

W.H.Agent grows along one axis: from **protecting one developer's laptop** to **protecting an organization's fleet of AI agents**. Each rung is a larger unit of value.

| Rung | Capability | State |
|---|---|---|
| **1. Local CLI** | `scan` / `check` / `inspect-mcp` / `install` + macOS sandbox | ✅ Shipping (free) |
| **2. CI/CD gate** | SARIF-based build gating + shared findings history for a team | ▶ Next |
| **3. Runtime enforcement** | Continuous, kernel-level containment of running agents (Linux) | 🔬 R&D — see [shield-agent](#component-shield-agent) |
| **4. Control plane** | Fleet dashboard, policy, audit, compliance attestation, SDK integrations | 🔮 Future — see [sdk-python](#component-sdk-python) |

**Commercial model:** open-core under the FCL-1.0-ALv2 license. The local CLI stays free and drives adoption; rungs 2–4 (team/org/enterprise) are the commercial surface. The license already reserves competitive hosted use.

---

## Component: `shield-agent`

**What it is today (verified):** a Go + eBPF **telemetry prototype**, Linux/x86-64 only. It attaches a `tracepoint/syscalls/sys_enter_connect` probe, captures outbound IPv4 `connect()` calls, and streams them as newline-delimited JSON over a Unix socket (`/tmp/shield-agent.sock`) to a single CLI client.

**Critical reality check — it does not enforce anything.** A `sys_enter` tracepoint is read-only by kernel design. There is no `bpf_override_return`, no BPF-LSM hook, no `bpf_send_signal`, no seccomp anywhere in `ebpf/network.c`. The `connect()` always proceeds. The events are even labelled `network_block` in `main.go`, but **nothing is blocked** — that name is aspirational.

**Known gaps / bugs found:**
- Observe-only (see above) — the single biggest gap between "prototype" and "the rung-3 product."
- Streams to exactly one client (`l.Accept()` called once, no loop).
- `Process: "agent.py"` is hardcoded/mocked, not resolved from `/proc`.
- The gVisor branch is a no-op and dereferences a nil `*ringbuf.Reader` on shutdown → panic.
- Generated eBPF bindings (`network_bpfel.go` from `bpf2go`) are **not committed**, so `main.go` doesn't compile without `go generate` (needs clang/llvm/libbpf on Linux). Not built or tested in CI.

**Viability verdict: KEEP — it is the seed of the most valuable rung (3), but treat the gap honestly.** Moving from telemetry → enforcement means switching to a **BPF-LSM hook** (e.g. `lsm/socket_connect` returning `-EPERM`) on kernels ≥ 5.7 with BPF LSM enabled, or an equivalent enforcement primitive. That is real kernel-security R&D — the hard technical core the platform is built on, not a weekend fix.

**How it interconnects:**
- It is **complementary to `sandbox-service`, not redundant.** The sandbox wraps *untrusted code you choose to run* (`wh-agent run`); shield-agent observes/enforces *a long-running agent already executing on the host*. Different threat, same product.
- **Intermediate monetizable step:** even observe-only telemetry is sellable as **"runtime visibility"** — a live feed of what every agent connects to, into the rung-4 dashboard — *before* enforcement lands. Ship visibility first, enforcement second.

**Near-term actions (to keep it warm without over-investing):** fix the nil-pointer shutdown panic; commit or CI-generate the bpf2go bindings; rename `network_block` → `network_event` until it can actually block; add a smoke test with a real assertion. Defer the LSM enforcement work to the funded rung-3 effort.

---

## Component: `sdk-python`

**What it is today (verified):** an early LangChain runtime-middleware SDK — and **it does not currently compile or install.** Intended surface: `WHAgentClient` (posture poller), a LangChain `AsyncCallbackHandler`, and RAG provenance helpers.

**Critical reality check — 3 of 4 modules have hard syntax errors** (verified with `py_compile`):
- `client.py`: `class W.H.AgentClient:` — dots are illegal in class names.
- `langchain/callbacks.py` & `tests/test_sdk.py`: `from wh-agent... import ...` — hyphens are illegal in module paths.
- The package dir is `src/wh_agent` (underscore) but imports and `pyproject.toml`'s wheel target say `wh-agent` (hyphen); `langchain/` has no `__init__.py`. These look like a botched global rename.
- The whole test suite collects **0 tests** because the test file itself is a `SyntaxError`.
- It also depends on a **`posture-service` HTTP backend** (`GET /agents/{id}/envelope/mode`, `POST /ingest`) that **does not exist in this repo**.

**The one salvageable piece:** `rag/provenance.py` compiles and works — it SHA-256-fingerprints retrieved documents and runs a (mock) lexical classifier to score prompt-injection risk, penalising unverified sources. That is a legitimate, self-contained idea: **screening RAG documents for injection before they reach the LLM.**

**Viability verdict: DEFER / QUARANTINE — building this now is backwards.** An SDK is a rung-4 integration play; it presupposes the control plane (posture-service, dashboard) that doesn't exist yet. Fixing the syntax is trivial but cosmetic — it still can't function without the backend. Building the backend to serve a not-yet-needed SDK would be effort spent far ahead of demand.

**How it interconnects:**
- The middleware/client belongs to **rung 4** — revisit it *after* the control plane exists, so it has something real to talk to. Sequence: backend → SDK, never the reverse.
- The **RAG-injection-scoring** idea (`provenance.py`) is the only near-term-viable fragment and is worth keeping. Note it is distinct from the CLI's static analysis: the CLI scans code *before deploy*; this scores documents *at query time*. Whether that becomes a CLI feature or a tiny standalone library is a product decision, not urgent.

**Near-term actions:** ✅ moved under `experimental/` so it no longer presents as a shipping SDK. Next: either delete the broken middleware/client or fix its syntax + packaging; preserve `rag/provenance.py` as the one idea to carry forward.

---

## Repository hygiene

Experimental prototypes live under [`experimental/`](./experimental/) — a clearly-labelled boundary kept out of the shipping build and CI, separate from the `cli` and `sandbox-service` packages. **`shield-agent` and `sdk-python` were moved there.** The `services/` config (OPA / Postgres / Kafka) still belongs with whichever control-plane effort actually consumes it, and should move there when that work starts — or be removed until then.
