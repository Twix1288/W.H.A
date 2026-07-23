"""W.H.Agent guardrail SDK (experimental, backend-free).

Screens documents / untrusted text for prompt-injection risk inside a running
agent. No backend or network is required — everything runs in-process.
"""

from wh_agent.rag.provenance import (
    filter_documents_by_risk,
    process_retrieved_documents,
    run_lexical_classifier,
)

__all__ = [
    "filter_documents_by_risk",
    "process_retrieved_documents",
    "run_lexical_classifier",
]
