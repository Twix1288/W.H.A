# W.H.Agent Guardrail (Python, experimental)

A small, **backend-free** guardrail that screens retrieved documents (and other
untrusted text) for prompt-injection risk inside a running agent. No service, no
network — everything runs in-process.

> **Experimental.** This lives under `experimental/` and is **not** part of the
> shipping `wh-agent` CLI. See the repo [ROADMAP.md](../../ROADMAP.md).

## What it does

- **`process_retrieved_documents(docs)`** — tag each LangChain `Document` with
  provenance + a prompt-injection risk score (`wh-agent_risk_score`,
  `wh-agent_injection_signals`, a content fingerprint, and source verification).
- **`filter_documents_by_risk(docs, risk_threshold=0.8)`** — the *enforcement*
  primitive: returns only the documents **below** the threshold, so you can drop
  likely-injection documents before they reach the LLM.
- **`WHAgentGuardrail`** — an optional LangChain `AsyncCallbackHandler` that
  *observes* retrieval and reports high-risk documents. LangChain callbacks
  cannot alter a retriever's output, so use `filter_documents_by_risk` for actual
  dropping; use the callback for observability/alerts.

## Usage

Enforcement in a retrieval pipeline:

```python
from wh_agent.rag.provenance import filter_documents_by_risk

docs = retriever.invoke(query)
safe_docs = filter_documents_by_risk(docs, risk_threshold=0.8)
# ...pass safe_docs to the LLM
```

Observability via a LangChain callback:

```python
from wh_agent.langchain import WHAgentGuardrail

guardrail = WHAgentGuardrail(on_event=lambda kind, payload: print(kind, payload))
chain.invoke(query, config={"callbacks": [guardrail]})
```

## Status & limitations

- `run_lexical_classifier` is a simple lexical heuristic today, **not** the CLI's
  full analysis engine — consolidating the two is future work (see ROADMAP).
- Requires `langchain-core`.

## Develop / test

```bash
pip install -e . pytest
pytest
```
