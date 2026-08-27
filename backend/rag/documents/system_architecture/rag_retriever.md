# RAG Retriever (Relevance Search & Citations)

> **Scope note (how to read this document):** This file documents the **RAG retriever** - the component that decides which knowledge-base passages are relevant to the user's question. The details below are grounded in the actual implementation (`backend/rag/retriever.py`) and its configuration (`backend/rag/config.py`).

---

## Overview

The **retriever** is the "search" stage of the RAG pipeline. Its purpose is simple: given a user's question, find the most relevant passages in the knowledge base and package them (with scores and source metadata) so the answer generator can produce a grounded, cited response.

It matters because the quality of the final answer depends almost entirely on what gets retrieved: if the wrong passages are retrieved, even a strong LLM will answer badly; if nothing relevant is retrieved, the system should say so instead of guessing.

---

## Definition

- **Retriever:** The component that takes a query string and returns the top relevant document chunks.
- **Query normalization:** Rewriting/enriching a raw user question so it better matches the technical vocabulary used in the knowledge base.
- **Cosine similarity:** The score used to rank how similar a query embedding is to each chunk embedding; higher is more similar.
- **Evidence:** A retrieved chunk, its relevance score, and its source metadata, ready to be cited in an answer.

**Related terms:** semantic search, vector search, top-k retrieval, relevance threshold, citation/source attribution.

---

## Key Concepts

### Query Normalization (Domain Expansions)
Before searching, the retriever inspects the lowercased query and appends domain-specific synonym expansions when it detects known topics:

- `slowloris` queries are expanded with vocabulary about low-and-slow HTTP header exhaustion and CICIDS-2017 Flow Duration.
- `ddos` queries gain denial-of-service and volumetric flood vocabulary; `dos` queries gain the classic attack family vocabulary.
- Probing/reconnaissance phrasing gains scanning-and-fingerprinting vocabulary.
- SSH/port-22/credential-guessing phrasing gains automated credential-guessing vocabulary.
- Credential-cracking phrasing (`brute force` or similar) expands to authentication-failure terminology.
- Botnet/C2 phrasing expands to command-and-control vocabulary.
- Web-attack phrasing (SQL injection, cross-site scripting, web attacks) expands to application-exploitation vocabulary.
- Flow-feature phrasing (Flow Duration, Flow Bytes, Flow Packets, IAT, flag counts) expands to the CICIDS-2017 flow-feature vocabulary.
- CICIDS/CICIDS-2017/cicids2017 mentions expand with the dataset identity and flow-feature terms (this makes compact `cicids2017` spellings work).
- Attack-family phrasing (R2L, U2R, Probe, etc.) expands to the NSL-KDD family vocabulary.
- NSL-KDD/KDD mentions expand with the dataset identity and its core feature vocabulary.
- Mitigation/response/action phrasing expands with incident-response and defense vocabulary.

The expanded query is what gets embedded and searched, which "bridges" casual user phrasing onto the technical wording used inside the documents.

### Relevance Filtering
- A configurable **top-k** (default 4) controls how many chunks are returned.
- A **similarity threshold** (default 0.26) acts as a relevance floor. Queries that score below the floor on every chunk are treated as having **no evidence**, which triggers the LEVEL 3 "not enough reliable information / refuse off-topic" behavior.
- Optional filters restrict the search to a specific category or attack type when the caller needs them.

### Citation Metadata
Each returned chunk carries: its source document name, markdown section title, knowledge-base category, attack type (or "General"), similarity score, source file path, and stable chunk id. This metadata becomes the citation list in the final answer, so every grounded claim can be traced back to a file.

---

## Technical Details

### The `retrieve()` Flow
```
retrieve(query, top_k?, similarity_threshold?, filter_category?, filter_attack_type?)
  1. enrich_query = normalize_query(query)        # append domain expansions
  2. query_vector  = embedding_engine.embed_query(enriched_query)
  3. results       = vector_store.similarity_search(query_vector, top_k, threshold, filters)
  4. build sources[] + context_text ("--- EVIDENCE [n] (Source: file | Section: X | Score: Y) ---")
  5. return { query, enriched_query, retrieved_chunks, sources, context_text,
             latency_ms, has_evidence, result_count }
```

### Evidence Format in the Prompt
The retrieved chunks are formatted as visible `EVIDENCE` blocks labeled with the source document, section title, and score. The generator prompt explicitly tells the LLM to answer primarily from these blocks and to cite only the documents listed there. The evidence block is capped at `MAX_CONTEXT_LENGTH` (default 3000) to control token usage.

### Interaction With the Rest of the Pipeline
- **Chunking** determines what granularity of text is searchable.
- **Embeddings** determine what the query and chunks look like as vectors.
- **Vector store** performs the actual similarity search and returns `(chunk, score)` pairs.
- **Generator** turns the evidence into a grounded prompt and post-processes the answer.

Because retrieval quality is decisive for the whole answer, the retriever is also where domain fixes like the `cicids2017` synonym expansion live.

---

## Related Knowledge Base Documents

- `rag_system.md` - where the retriever fits in the pipeline.
- `rag_embeddings.md` - how query/chunk vectors are produced.
- `rag_vector_store.md` - the search index behind `similarity_search`.
- `rag_chunking.md` - the granularity of what gets retrieved.