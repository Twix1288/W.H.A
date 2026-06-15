import hashlib
from typing import List, Tuple
from langchain_core.documents import Document

def run_lexical_classifier(content: str) -> Tuple[float, List[str]]:
    # Mock lexical classifier for prompt injection signals
    signals = []
    score = 0.0
    lower_content = content.lower()
    
    if "ignore previous instructions" in lower_content:
        signals.append("ignore_instructions")
        score += 0.6
    if "system prompt" in lower_content:
        signals.append("system_prompt_reference")
        score += 0.3
        
    return min(1.0, score), signals

def process_retrieved_documents(documents: List[Document]) -> List[Document]:
    """
    Fingerprints and calculates risk for retrieved documents.
    Mutates document metadata (NOT page_content) with provenance tags.
    """
    for doc in documents:
        # 1. Fingerprint by content
        fingerprint_id = hashlib.sha256(doc.page_content.encode("utf-8")).hexdigest()
        
        # 2. Check for source URL
        source_url = doc.metadata.get("source")
        source_verified = bool(source_url)
        
        # 3. Lexical classification
        base_risk_score, signals = run_lexical_classifier(doc.page_content)
        
        # 4. Apply 1.5x penalty if unverified source
        risk_score = base_risk_score
        if not source_verified:
            risk_score = min(1.0, risk_score * 1.5)
            if risk_score > 0:
                signals.append("unverified_source_penalty")

        # 5. Tag metadata
        doc.metadata["wh-agent_source_id"] = fingerprint_id
        doc.metadata["wh-agent_source_verified"] = source_verified
        doc.metadata["wh-agent_risk_score"] = risk_score
        doc.metadata["wh-agent_injection_signals"] = signals

    return documents
