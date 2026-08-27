"""
RAG Ingestion Pipeline Module
Orchestrates document loading, text cleaning, chunking, embedding generation, and vector indexing.
"""

import time
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

from .config import RAGConfig, default_config
from .chunking import DocumentChunker, DocumentChunk
from .embeddings import EmbeddingEngine
from .vector_store import PersistentVectorStore

logger = logging.getLogger("NetGuardAI.RAG.Ingestion")


class RAGIngestionPipeline:
    """Full-cycle ingestion pipeline from raw documents to indexed vector store."""

    def __init__(
        self,
        config: Optional[RAGConfig] = None,
        chunker: Optional[DocumentChunker] = None,
        embedding_engine: Optional[EmbeddingEngine] = None,
        vector_store: Optional[PersistentVectorStore] = None,
    ):
        self.config = config or default_config
        self.chunker = chunker or DocumentChunker(
            chunk_size=self.config.CHUNK_SIZE,
            chunk_overlap=self.config.CHUNK_OVERLAP,
        )
        self.embedding_engine = embedding_engine or EmbeddingEngine(self.config)
        self.vector_store = vector_store or PersistentVectorStore(self.config)

    def run(self, force_rebuild: bool = False) -> Dict[str, Any]:
        """Runs document ingestion across the documents directory."""
        start_time = time.time()
        docs_dir = self.config.DOCUMENTS_DIR

        if not docs_dir.exists():
            docs_dir.mkdir(parents=True, exist_ok=True)
            return {
                "success": False,
                "error": f"Documents directory {docs_dir} was empty or just created.",
                "total_documents": 0,
                "total_chunks": 0,
            }

        # Check if already populated and rebuild is not forced
        if not force_rebuild and not self.vector_store.is_empty():
            stats = self.vector_store.get_stats()
            logger.info(f"Vector store already contains {len(self.vector_store.chunks)} chunks. Skipping re-indexing.")
            return {
                "success": True,
                "duration_seconds": 0.0,
                "documents_processed": stats.get("documents", []),
                "total_documents_found": len(stats.get("documents", [])),
                "total_chunks_indexed": stats.get("total_chunks", 0),
                "categories": stats.get("categories", []),
                "attack_types": stats.get("attack_types", []),
                "embedding_dimension": stats.get("embedding_dimension", 0),
                "storage_path": stats.get("storage_path", ""),
            }

        # Find all markdown and text files
        doc_files = list(docs_dir.rglob("*.md")) + list(docs_dir.rglob("*.txt"))
        if not doc_files:
            return {
                "success": False,
                "error": f"No .md or .txt documents found in {docs_dir}.",
                "total_documents": 0,
                "total_chunks": 0,
            }

        if force_rebuild:
            logger.info("Force rebuild requested. Clearing vector store...")
            self.vector_store.clear()

        # Step 1: Chunk all documents
        all_chunks: List[DocumentChunk] = []
        processed_files = []

        for doc_file in doc_files:
            try:
                chunks = self.chunker.chunk_document(doc_file)
                if chunks:
                    all_chunks.extend(chunks)
                    processed_files.append(doc_file.name)
            except Exception as e:
                logger.error(f"Error processing {doc_file}: {e}")

        if not all_chunks:
            return {
                "success": False,
                "error": "No chunks generated from documents.",
                "total_documents": len(doc_files),
                "total_chunks": 0,
            }

        # Step 2: Fit embedding corpus
        corpus_texts = [c.text for c in all_chunks]
        self.embedding_engine.fit_corpus(corpus_texts)

        # Step 3: Generate embeddings
        embeddings = self.embedding_engine.embed_texts(corpus_texts)

        # Step 4: Add to persistent vector store
        self.vector_store.add_chunks(all_chunks, embeddings)

        duration = time.time() - start_time
        stats = self.vector_store.get_stats()

        logger.info(f"Ingestion complete in {duration:.2f}s. {len(all_chunks)} chunks indexed across {len(processed_files)} documents.")

        return {
            "success": True,
            "duration_seconds": round(duration, 3),
            "documents_processed": processed_files,
            "total_documents_found": len(doc_files),
            "total_chunks_indexed": stats["total_chunks"],
            "categories": stats["categories"],
            "attack_types": stats["attack_types"],
            "embedding_dimension": stats["embedding_dimension"],
            "storage_path": stats["storage_path"],
        }
