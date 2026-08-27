# RAG Vector Store (Persistence & Similarity Search)

> **Scope note (how to read this document):** This file documents the **persistent vector store** of the NetGuard AI RAG subsystem (`backend/rag/vector_store.py`). It is the on-disk index that makes the knowledge base searchable without recomputing embeddings on every request.

---

## Overview

The **vector store** is where the knowledge base actually lives after ingestion: it holds every chunk's text together with its embedding vector and provenance metadata, and it answers the retriever's "find chunks closest to this query" calls.

It is **persistent**, meaning ingestion results survive across application restarts. When the application starts, the store loads its existing index from disk instead of re-chunking and re-embedding all documents; in fact the ingestion pipeline skips re-indexing entirely when the store already contains data, unless a rebuild is explicitly forced.

---

## Definition

- **Vector store:** A database-like structure that stores text chunks paired with their embedding vectors and metadata, supporting fast similarity search.
- **Indexing:** Recording each chunk's vector and metadata so it can be found by similarity later.
- **Similarity search:** Given a query vector, returning the chunks whose vectors are closest under cosine similarity.
- **Rebuild (force):** Clearing the existing index and re-ingesting all documents from scratch.

**Related terms:** embeddings index, persistent index, cosine search, metadata filters.

---

## Key Concepts

### On-Disk Layout
The store lives under `backend/rag/vector_store/` and persists:
- **`chunks_metadata.json`** - every chunk's full metadata and text (document name, section title, category, attack type, source path, chunk id, text).
- **`embeddings.npy`** - the numpy array of embedding vectors, one row per chunk, in the same order as the metadata.
- **`index_info.json`** - index-level information such as embedding dimension and last-indexed timestamp.

Loading the store reconstructs the correspondence between vectors and metadata from these three files.

### Similarity Scoring
Because embeddings are L2-normalized (see `rag_embeddings.md`), cosine similarity reduces to a dot product. `similarity_search` scores every chunk, applies the caller's **top-k** and **similarity threshold**, optionally applies **category/attack-type filters**, and returns the surviving `(chunk, score)` pairs sorted by score descending.

### Why Persistence Matters
Without persistence the application would have to re-run TF-IDF fitting, re-embed hundreds of chunks, and rebuild the index on every startup. Persistence keeps startup fast and keeps the retrieval behavior stable and reproducible across runs.

---

## Technical Details

### Main Operations
- **`add_chunks(chunks, embeddings)`:** Appends the given chunks and vectors to the index and saves everything to disk.
- **`similarity_search(query_vector, top_k, similarity_threshold, filter_category, filter_attack_type)`:** Scores all stored vectors against the query and returns matching chunks with scores.
- **`get_stats()`:** Reports total chunk count, list of source documents, distinct categories, distinct attack types, embedding dimension, storage path, and last-indexed time.
- **`is_empty()`:** Whether the index contains any chunks (used by the ingestion pipeline to decide whether re-indexing is needed).
- **`clear()`:** Wipes the on-disk index; used when a rebuild is forced.

### Relationship to the Ingestion Pipeline
`RAGIngestionPipeline.run(force_rebuild=False)`:
1. If the store already has data and `force_rebuild` is false, it skips work and reports the existing stats.
2. If `force_rebuild` is true, it calls `clear()` first, then re-chunks all documents, re-fits the embedding corpus, re-embeds, and re-indexes.

This is the documented way to refresh the knowledge base after adding or editing documents.

---

## Related Knowledge Base Documents

- `rag_system.md` - the pipeline that feeds the store.
- `rag_embeddings.md` - what the stored vectors are.
- `rag_retriever.md` - who consumes the store's search results.
- `rag_chunking.md` - what each stored chunk contains.