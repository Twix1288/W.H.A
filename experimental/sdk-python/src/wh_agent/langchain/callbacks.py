"""Backend-free LangChain guardrail for W.H.Agent (experimental).

LangChain callbacks are OBSERVERS: they cannot change the documents a retriever
returns. So this handler tags each retrieved document with provenance/risk
metadata and reports high-risk documents (via an optional ``on_event`` sink and
the ``wh_agent`` logger). To actually DROP risky documents, call
``wh_agent.rag.provenance.filter_documents_by_risk(...)`` on the retriever output
— no backend required.
"""

import logging
from typing import Any, Callable, Dict, Optional, Sequence

from langchain_core.callbacks import AsyncCallbackHandler
from langchain_core.documents import Document

from wh_agent.rag.provenance import process_retrieved_documents

logger = logging.getLogger("wh_agent")

EventSink = Callable[[str, Dict[str, Any]], None]


class WHAgentGuardrail(AsyncCallbackHandler):
    """Observes retrieved documents and flags likely prompt-injection content."""

    def __init__(
        self,
        risk_threshold: float = 0.8,
        on_event: Optional[EventSink] = None,
    ) -> None:
        self.risk_threshold = risk_threshold
        self._on_event = on_event

    def _emit(self, event_type: str, payload: Dict[str, Any]) -> None:
        if self._on_event is not None:
            self._on_event(event_type, payload)

    async def on_retriever_end(
        self, documents: Sequence[Document], **kwargs: Any
    ) -> None:
        processed = process_retrieved_documents(list(documents))
        for doc in processed:
            risk = doc.metadata.get("wh-agent_risk_score", 0.0)
            if risk >= self.risk_threshold:
                logger.warning(
                    "wh_agent: high-risk retrieved document (risk=%.2f, signals=%s)",
                    risk,
                    doc.metadata.get("wh-agent_injection_signals"),
                )
                self._emit(
                    "high_risk_document",
                    {
                        "source_id": doc.metadata.get("wh-agent_source_id"),
                        "risk_score": risk,
                        "signals": doc.metadata.get("wh-agent_injection_signals"),
                    },
                )
