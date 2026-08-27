"""NetGuard AI RAG public API."""

from .config import RAGConfig, default_config
from .chunking import DocumentChunk, DocumentChunker
from .embeddings import EmbeddingEngine
from .vector_store import PersistentVectorStore
from .ingestion import RAGIngestionPipeline
from .retriever import RAGRetriever
from .generator import (
    build_general_prompt,
    build_prediction_prompt,
    build_offline_fallback,
    call_llm,
    is_cybersecurity_domain,
    is_out_of_domain,
)
from .prompts import OUT_OF_DOMAIN_REFUSAL

__all__ = [
    "RAGConfig", "default_config", "DocumentChunk", "DocumentChunker",
    "EmbeddingEngine", "PersistentVectorStore", "RAGIngestionPipeline",
    "RAGRetriever", "build_general_prompt", "build_prediction_prompt",
    "build_offline_fallback", "call_llm",
    "is_cybersecurity_domain", "is_out_of_domain", "OUT_OF_DOMAIN_REFUSAL",
]
