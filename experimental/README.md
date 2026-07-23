# Experimental

Prototypes and research code that are **not part of the shipping product**. Nothing here is built by `make build`, published to npm, or run in CI. Treat it as a staging area: code graduates to `packages/` only once it is complete, tested, and wired into the product.

See [ROADMAP.md](../ROADMAP.md) for where each of these is headed.

## Contents

### `shield-agent/` — eBPF runtime telemetry (Go, Linux-only)
Attaches a `sys_enter_connect` tracepoint and streams outbound-connection events over a Unix socket. **Observe-only today** — it reports network activity but does not block it. It is the seed of the future runtime-enforcement layer ([ROADMAP](../ROADMAP.md) rung 3), which requires switching to a BPF-LSM enforcement hook. Requires Linux ≥ 5.8, root / `CAP_BPF`, and clang/llvm to generate the eBPF bindings (not committed).

### `sdk-python/` — LangChain middleware SDK (Python)
An early SDK for embedding W.H.Agent checks into LangChain agents. **Does not currently compile** (module/class naming errors) and depends on a `posture-service` backend that does not exist in this repo. The one self-contained, working piece is `rag/provenance.py` (RAG document provenance + injection scoring). Belongs to the future control-plane work ([ROADMAP](../ROADMAP.md) rung 4).
