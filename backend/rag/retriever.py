"""
RAG Retriever Module
Provides query normalization, semantic vector retrieval, relevance filtering, and grounded citation generation.
"""

import re
import time
import logging
from typing import List, Dict, Any, Optional, Tuple

from .config import RAGConfig, default_config
from .chunking import DocumentChunk
from .embeddings import EmbeddingEngine
from .vector_store import PersistentVectorStore

logger = logging.getLogger("NetGuardAI.RAG.Retriever")


class RAGRetriever:
    """Production semantic retrieval layer for cybersecurity knowledge."""

    def __init__(
            self,
            config: Optional[RAGConfig] = None,
            embedding_engine: Optional[EmbeddingEngine] = None,
            vector_store: Optional[PersistentVectorStore] = None,
    ):
        self.config = config or default_config
        self.embedding_engine = embedding_engine or EmbeddingEngine(self.config)
        self.vector_store = vector_store or PersistentVectorStore(self.config)

        self._ensure_tfidf_vectorizer()

    def _ensure_tfidf_vectorizer(self):
        """Ensure the TF-IDF vectorizer matches the stored index before retrieval."""
        if not isinstance(self.embedding_engine, EmbeddingEngine):
            return
        provider = str(self.embedding_engine.provider).lower()
        if provider not in ("tfidf", "auto"):
            return
        if len(self.vector_store.chunks) == 0:
            return

        expected_dim = self.vector_store.embeddings.shape[1]
        vectorizer = self.embedding_engine._tfidf_vectorizer

        # If the vectorizer is missing or would project queries into a
        # different dimension, re-fit it on the exact stored corpus so query
        # embeddings live in the same vector space as the persisted index.
        # (The persisted vectorizer is a gitignored runtime artifact and may
        # be absent on deployments, causing a fresh fit-on-query -> wrong dim.)
        needs_refit = vectorizer is None
        if not needs_refit:
            try:
                probe_dim = vectorizer.transform(["probe"]).shape[1]
                needs_refit = probe_dim != expected_dim
            except Exception:
                needs_refit = True

        if needs_refit:
            corpus_texts = [c.text for c in self.vector_store.chunks]
            self.embedding_engine.fit_corpus(corpus_texts)
            logger.info(
                "Re-fitted TF-IDF vectorizer on %d stored chunks "
                "(expected dim %d).",
                len(corpus_texts),
                expected_dim,
            )

    def normalize_query(self, query: str) -> str:
        """Normalizes and enriches cybersecurity queries for enhanced semantic recall."""
        if not query:
            return ""

        q = query.strip()
        q_lower = q.lower()

        # Domain-specific synonym expansions to bridge user phrasing with technical docs
        expansions = []
        if re.search(r"slowloris", q_lower):
            expansions.append(
                "slow loris low and slow HTTP header exhaustion long flow duration "
                "CICIDS-2017 Flow Duration"
            )
        if re.search(r"\bddos\b", q_lower):
            expansions.append("distributed denial of service volumetric flood syn udp http")
        elif re.search(r"\bdos\b", q_lower):
            expansions.append("denial of service slowloris hulk neptune syn flood")
        if re.search(r"\bport\s*scan\b|\bprobe\b", q_lower):
            expansions.append("reconnaissance tcp syn scan connect fin xmas nmap")
        if re.search(r"SSH|port 22|credential guessing", q, re.IGNORECASE):
            expansions.append(
                "SSH-Patator automated credential guessing SSH port 22 brute force"
            )
        if re.search(r"\bbrute[\s\-]*force\b|\bpatator\b", q_lower):
            expansions.append("credential guessing ssh ftp rdp hydra authentication failed logins")
        if re.search(r"\bbotnet\b|\bc2\b|\bc&c\b", q_lower):
            expansions.append("command and control beaconing dns tunneling mirai ares")
        if re.search(r"\bsqli\b|\bsql\s*injection\b|\bxss\b|\bweb\s*attack\b", q_lower):
            expansions.append("web application exploit owasp parameter injection cross site scripting")
        if re.search(r"flow\s*duration|flow\s*bytes|flow\s*packets|iat|flag\s*count", q_lower):
            expansions.append(
                "CICIDS-2017 network flow features Flow Duration Flow Bytes/s "
                "Flow Packets/s Flow IAT SYN RST ACK flag count"
            )
        if re.search(r"\bcicids(?:[- ]?2017)?\b|\bcicids2017\b", q_lower):
            expansions.append(
                "CICIDS-2017 Canadian Institute for Cybersecurity Intrusion Detection System "
                "benchmark dataset network flow features flow duration flow bytes "
                "packets per second iat flag count"
            )
        if re.search(r"attack families|major attack families|r2l|u2r|probe", q_lower):
            expansions.append(
                "NSL-KDD attack families DoS Probe Denial of Service "
                "Remote to Local R2L User to Root U2R reconnaissance"
            )
        if re.search(r"\bnsl-kdd\b|\bnsl\s*kdd\b|\bkdd\b", q_lower):
            expansions.append(
                "NSL-KDD dataset intrusion detection benchmark refined KDD Cup 99 "
                "connection record 41 features DoS Probe R2L U2R "
                "protocol_type service flag src_bytes dst_bytes count srv_count"
            )
        if re.search(r"\bmitigat\b|\brespond\b|\bplaybook\b|\baction\b", q_lower):
            expansions.append("incident response containment iptables firewall rule defense remediation")

        # RAG / retrieval-augmented generation phrasing bridges to the system
        # architecture docs (retriever, evidence, grounding, citations).
        if re.search(r"\brag\b|retrieval[- ]augmented", q_lower):
            expansions.append(
                "retrieval augmented generation RAG knowledge base evidence grounding "
                "citations vector retrieval retriever chunks"
            )
        # Chunking / chunker questions bridge to the chunking doc vocabulary.
        if re.search(r"\bchunk", q_lower):
            expansions.append(
                "chunk chunker chunk size chunk overlap markdown section sliding window "
                "document splitting metadata provenance 500 words"
            )
        # NetGuard AI identity questions bridge to the project overview doc.
        if re.search(r"\bnetguard\b", q_lower):
            expansions.append(
                "NetGuard AI project network intrusion detection system Random Forest classifier "
                "NSL-KDD CICIDS-2017 FastAPI backend Streamlit dashboard chat assistant RAG knowledge base"
            )

        if expansions:
            return f"{q} ({' '.join(expansions)})"
        return q

    def retrieve(
            self,
            query: str,
            top_k: Optional[int] = None,
            similarity_threshold: Optional[float] = None,
            filter_category: Optional[str] = None,
            filter_attack_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Retrieves top-k relevant cybersecurity document chunks for the given query."""
        start_time = time.time()
        top_k = top_k or self.config.TOP_K
        threshold = similarity_threshold if similarity_threshold is not None else self.config.SIMILARITY_THRESHOLD

        if not query or not query.strip():
            return {
                "query": query,
                "retrieved_chunks": [],
                "sources": [],
                "context_text": "",
                "latency_ms": 0.0,
                "has_evidence": False,
            }

        # Step 1: Normalize query
        enriched_query = self.normalize_query(query)

        # Step 2: Embed query
        query_vector = self.embedding_engine.embed_query(enriched_query)

        # Step 3: Similarity search in vector store
        results: List[Tuple[DocumentChunk, float]] = self.vector_store.similarity_search(
            query_vector=query_vector,
            top_k=top_k,
            similarity_threshold=threshold,
            filter_category=filter_category,
            filter_attack_type=filter_attack_type,
        )

        latency_ms = round((time.time() - start_time) * 1000, 2)

        # Step 4: Construct sources and structured context
        sources = []
        context_parts = []
        retrieved_chunk_dicts = []

        for idx, (chunk, score) in enumerate(results, 1):
            source_info = {
                "citation_id": idx,
                "document_name": chunk.document_name,
                "section": chunk.section_title,
                "category": chunk.category,
                "attack_type": chunk.attack_type or "General",
                "similarity_score": round(score, 3),
                "source_path": chunk.source_path,
                "chunk_id": chunk.chunk_id,
            }
            sources.append(source_info)
            retrieved_chunk_dicts.append(chunk.to_dict())

            context_parts.append(
                f"--- EVIDENCE [{idx}] (Source: {chunk.document_name} | Section: {chunk.section_title} | Score: {score:.2f}) ---\n"
                f"{chunk.text}\n"
            )

        context_text = "\n".join(context_parts)

        # Enforce max context length limit
        if len(context_text) > self.config.MAX_CONTEXT_LENGTH:
            context_text = context_text[
                               :self.config.MAX_CONTEXT_LENGTH] + "\n...[Context truncated for token efficiency]..."

        has_evidence = len(results) > 0

        return {
            "query": query,
            "enriched_query": enriched_query,
            "retrieved_chunks": retrieved_chunk_dicts,
            "sources": sources,
            "context_text": context_text,
            "latency_ms": latency_ms,
            "has_evidence": has_evidence,
            "result_count": len(results),
        }
