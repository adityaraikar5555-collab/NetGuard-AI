"""
Persistent Vector Store Module
Provides fast vector indexing, cosine similarity search, metadata filtering, and persistent on-disk storage.
"""

import json
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
import numpy as np

from .config import RAGConfig, default_config
from .chunking import DocumentChunk

logger = logging.getLogger("NetGuardAI.RAG.VectorStore")


class PersistentVectorStore:
    """Lightweight, highly performant on-disk vector database."""

    def __init__(self, config: Optional[RAGConfig] = None):
        self.config = config or default_config
        self.db_dir = self.config.VECTOR_DB_DIR
        self.metadata_file = self.db_dir / "chunks_metadata.json"
        self.embeddings_file = self.db_dir / "embeddings.npy"
        self.info_file = self.db_dir / "index_info.json"

        self.chunks: List[DocumentChunk] = []
        self.embeddings: np.ndarray = np.empty((0, 0), dtype=np.float32)
        self.index_info: Dict[str, Any] = {}

        # Auto-load existing index if present
        self.load()

    def is_empty(self) -> bool:
        """Returns True if no chunks are currently indexed."""
        return len(self.chunks) == 0

    def get_stats(self) -> Dict[str, Any]:
        """Returns index statistics."""
        categories = list({c.category for c in self.chunks if c.category})
        attack_types = list({c.attack_type for c in self.chunks if c.attack_type})
        documents = list({c.document_name for c in self.chunks})

        return {
            "status": "ready" if len(self.chunks) > 0 else "empty",
            "total_chunks": len(self.chunks),
            "total_documents": len(documents),
            "documents": documents,
            "categories": categories,
            "attack_types": attack_types,
            "embedding_dimension": int(self.embeddings.shape[1]) if self.embeddings.ndim == 2 and self.embeddings.shape[0] > 0 else 0,
            "last_indexed": self.index_info.get("last_indexed", "Never"),
            "storage_path": str(self.db_dir),
        }

    def add_chunks(self, chunks: List[DocumentChunk], embeddings: np.ndarray):
        """Adds new chunks and their corresponding embeddings to the store."""
        if not chunks or embeddings is None or len(chunks) == 0:
            return

        if len(chunks) != embeddings.shape[0]:
            raise ValueError(f"Mismatch: {len(chunks)} chunks vs {embeddings.shape[0]} embeddings")

        # Deduplication check
        existing_hashes = {c.content_hash for c in self.chunks}
        existing_ids = {c.chunk_id for c in self.chunks}

        new_chunks = []
        new_emb_indices = []

        for i, chunk in enumerate(chunks):
            if chunk.content_hash not in existing_hashes and chunk.chunk_id not in existing_ids:
                new_chunks.append(chunk)
                new_emb_indices.append(i)
                existing_hashes.add(chunk.content_hash)
                existing_ids.add(chunk.chunk_id)

        if not new_chunks:
            logger.info("All chunks already exist in vector store. No additions made.")
            return

        filtered_embeddings = embeddings[new_emb_indices]

        # Normalize embeddings to unit norm for exact cosine similarity
        norms = np.linalg.norm(filtered_embeddings, axis=1, keepdims=True)
        norms[norms == 0] = 1.0
        filtered_embeddings = filtered_embeddings / norms

        if len(self.chunks) == 0:
            self.chunks = new_chunks
            self.embeddings = filtered_embeddings
        else:
            self.chunks.extend(new_chunks)
            if self.embeddings.shape[1] == filtered_embeddings.shape[1]:
                self.embeddings = np.vstack([self.embeddings, filtered_embeddings])
            else:
                logger.warning("Embedding dimension mismatch. Resetting embeddings with new vector size.")
                self.embeddings = filtered_embeddings

        self.index_info = {
            "last_indexed": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_chunks": len(self.chunks),
            "embedding_dimension": int(self.embeddings.shape[1]),
        }

        self.save()
        logger.info(f"Added {len(new_chunks)} chunks to vector store. Total chunks: {len(self.chunks)}")

    def similarity_search(
        self,
        query_vector: np.ndarray,
        top_k: int = 4,
        similarity_threshold: float = 0.0,
        filter_category: Optional[str] = None,
        filter_attack_type: Optional[str] = None,
    ) -> List[Tuple[DocumentChunk, float]]:
        """Performs cosine similarity search against indexed chunks."""
        if len(self.chunks) == 0 or self.embeddings.shape[0] == 0:
            return []

        # Ensure query vector is 1D and normalized
        q_vec = query_vector.flatten()
        q_norm = np.linalg.norm(q_vec)
        if q_norm > 0:
            q_vec = q_vec / q_norm
        else:
            return []

        if q_vec.shape[0] != self.embeddings.shape[1]:
            logger.warning(f"Query dimension {q_vec.shape[0]} does not match index dimension {self.embeddings.shape[1]}")
            return []

        # Cosine similarity is dot product of unit-normalized vectors
        scores = np.dot(self.embeddings, q_vec)

        # Apply metadata filters if specified
        valid_indices = []
        for idx, chunk in enumerate(self.chunks):
            if filter_category and chunk.category != filter_category:
                continue
            if filter_attack_type and chunk.attack_type != filter_attack_type:
                continue
            valid_indices.append(idx)

        if not valid_indices:
            return []

        filtered_scores = scores[valid_indices]
        valid_indices_arr = np.array(valid_indices)

        # Get top-k indices
        sorted_order = np.argsort(filtered_scores)[::-1]
        top_indices = valid_indices_arr[sorted_order[:top_k]]
        top_scores = scores[top_indices]

        results = []
        for idx, score in zip(top_indices, top_scores):
            score_float = float(score)
            if score_float >= similarity_threshold:
                results.append((self.chunks[idx], score_float))

        return results

    def save(self):
        """Persists the vector index and metadata to disk."""
        self.db_dir.mkdir(parents=True, exist_ok=True)
        try:
            # 1. Save metadata JSON
            chunks_data = [c.to_dict() for c in self.chunks]
            with open(self.metadata_file, "w", encoding="utf-8") as f:
                json.dump(chunks_data, f, indent=2, ensure_ascii=False)

            # 2. Save dense embeddings array
            np.save(self.embeddings_file, self.embeddings)

            # 3. Save index info
            with open(self.info_file, "w", encoding="utf-8") as f:
                json.dump(self.index_info, f, indent=2)

            logger.info(f"Vector store persisted to {self.db_dir}")
        except Exception as e:
            logger.error(f"Failed to persist vector store: {e}")

    def load(self) -> bool:
        """Loads index from disk if available."""
        if not (self.metadata_file.exists() and self.embeddings_file.exists()):
            return False

        try:
            with open(self.metadata_file, "r", encoding="utf-8") as f:
                chunks_data = json.load(f)
            self.chunks = [DocumentChunk.from_dict(item) for item in chunks_data]
            self.embeddings = np.load(self.embeddings_file)

            if self.info_file.exists():
                with open(self.info_file, "r", encoding="utf-8") as f:
                    self.index_info = json.load(f)

            logger.info(f"Vector store loaded successfully with {len(self.chunks)} chunks.")
            return True
        except Exception as e:
            logger.warning(f"Error loading vector store: {e}. Index will be rebuilt on ingestion.")
            return False

    def clear(self):
        """Clears the in-memory and on-disk index."""
        self.chunks = []
        self.embeddings = np.empty((0, 0), dtype=np.float32)
        self.index_info = {}
        if self.metadata_file.exists():
            self.metadata_file.unlink(missing_ok=True)
        if self.embeddings_file.exists():
            self.embeddings_file.unlink(missing_ok=True)
        if self.info_file.exists():
            self.info_file.unlink(missing_ok=True)
        logger.info("Vector store index cleared.")
