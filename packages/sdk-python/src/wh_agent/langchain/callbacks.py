import asyncio
from typing import Any, Dict, List, Optional
from langchain_core.callbacks import AsyncCallbackHandler
from langchain_core.documents import Document

from wh-agent.client import W.H.AgentClient
from wh-agent.rag.provenance import process_retrieved_documents

class W.H.AgentCallbackHandler(AsyncCallbackHandler):
    def __init__(self, client: W.H.AgentClient, risk_threshold: float = 0.8):
        self.client = client
        self.risk_threshold = risk_threshold

    async def on_llm_start(
        self, serialized: Dict[str, Any], prompts: List[str], **kwargs: Any
    ) -> None:
        """Run when LLM starts running. Dispatch telemetry."""
        # We fire an event asynchronously via HTTP fire-and-forget
        self.client.dispatch_event("llm_start", {"prompts": prompts})

    async def on_tool_start(
        self, serialized: Dict[str, Any], input_str: str, **kwargs: Any
    ) -> None:
        """Run when tool starts running."""
        self.client.dispatch_event("tool_start", {"tool": serialized.get("name"), "input": input_str})

    async def on_retriever_end(
        self, documents: List[Document], *, run_id: str, parent_run_id: Optional[str] = None, **kwargs: Any
    ) -> List[Document]:
        """Run when Retriever ends running. Modifies documents and drops high risk in enforce mode."""
        # Run provenance tagger (sync CPU bound, but fast)
        processed_docs = process_retrieved_documents(documents)
        
        mode = self.client.mode
        
        safe_docs = []
        for doc in processed_docs:
            risk_score = doc.metadata.get("wh-agent_risk_score", 0.0)
            if mode == "enforce" and risk_score >= self.risk_threshold:
                # In enforce mode, drop the malicious document entirely
                self.client.dispatch_event("document_dropped", {
                    "source_id": doc.metadata.get("wh-agent_source_id"),
                    "risk_score": risk_score,
                    "signals": doc.metadata.get("wh-agent_injection_signals")
                })
                continue
            safe_docs.append(doc)
            
        return safe_docs
