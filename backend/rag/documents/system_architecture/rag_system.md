# RAG System (NetGuard AI Knowledge Assistant)

> **Scope note (how to read this document):** This file describes how the **Retrieval-Augmented Generation (RAG)** subsystem inside **NetGuard AI** is built and how it behaves. All details are grounded in the actual implementation under `backend/rag/`. Embedding dimension, chunk sizes, thresholds, and provider ordering are as-configured in the project (environment variables override the defaults).

---

## Overview

**RAG (Retrieval-Augmented Generation)** combines two things so that an LLM can answer questions grounded in a controlled source of truth:

1. **Retrieval** of the most relevant passages from a local knowledge base for the user's question.
2. **Generation** of an answer by an LLM that is instructed to answer only from those retrieved passages and to cite them.

NetGuard AI uses this so the chat assistant answers consistent, in-scope, verifiable answers about cybersecurity, the benchmark datasets, SOC procedures, and the project itself - instead of relying on the LLM's unconstrained training memory.

---

## Definition

- **RAG:** A pipeline that retrieves relevant document chunks for a query, injects them into the LLM prompt as "evidence", and makes the LLM answer grounded in that evidence with source citations.
- **Knowledge base:** The set of markdown documents under `backend/rag/documents/`, organized by topic (definitions and concepts, system architecture, network security, datasets and machine learning, SOC procedures).
- **Evidence:** A retrieved chunk along with the score and source metadata used to support an answer.

**Related terms:** grounding, citations, source attribution, vector retrieval, prompt engineering.

---

## Key Concepts

### The Pipeline Stages
1. **Ingestion** (`ingestion.py`): every `.md` document in the knowledge base is read, cleaned, split into chunks (`chunking.py`), embedded as numeric vectors (`embeddings.py`), and indexed into a persistent vector store (`vector_store.py`). Re-indexing is skipped automatically when the store already has data unless a rebuild is forced.
2. **Retrieval** (`retriever.py`): the user's query is normalized/enriched with domain synonyms, embedded with the same vectorizer, and searched against the vector store to return the top relevant chunks plus metadata.
3. **Prompt construction** (`generator.py`): the retrieved chunks are formatted into an evidence block with prominent source headings and given to a prompt builder that encodes the grounding rules.
4. **Generation**: the prompt is sent to the configured LLM provider (auto mode: Gemini, then Groq, then OpenAI, then Ollama), with a deterministic **offline fallback** that serves the retrieved knowledge directly if no provider answers.
5. **Grounding check**: the answer must follow the three-level evidence strategy (see below); unsupported facts, inventions, and off-topic answers are refused.

### Three-Level Evidence Strategy
- **LEVEL 1 (full coverage):** The retrieved context directly answers the question; the LLM gives a grounded answer citing only the retrieved documents.
- **LEVEL 2 (partial coverage):** Context covers part of the question; the LLM states what is supported and what is not, without inventing the rest.
- **LEVEL 3 (no evidence):** No chunk passed the similarity threshold; the LLM must say the knowledge base does not contain enough reliable information and must refuse clearly out-of-domain questions.

### Configuration-Driven Behavior
- `CHUNK_SIZE` (default 500 words) and `CHUNK_OVERLAP` (default 80) control chunking granularity.
- `TOP_K` (default 4) controls how many chunks are returned.
- `SIMILARITY_THRESHOLD` (default 0.26) is the relevance floor: chunks scoring below it are treated as no evidence. TF-IDF out-of-scope queries tend to top out around 0.21-0.25 while in-domain cyber queries score ~0.27+.
- `MAX_CONTEXT_LENGTH` (default 3000) truncates the evidence block for token efficiency.
- `EMBEDDING_PROVIDER` (default `tfidf`) selects the embedding backend; `EMBEDDING_DIMENSION` is 1024 for the TF-IDF vectorizer.

---

## Technical Details

### Data Flow (end to end)
```
documents/*.md
   -> DocumentChunker (split by markdown headers, ~500-word windows, 80-word overlap)
   -> EmbeddingEngine (fit TF-IDF corpus, L2-normalized 1024-d vectors)
   -> PersistentVectorStore (chunks_metadata.json + embeddings.npy + index_info.json)
   -> RAGRetriever.retrieve(query)
        normalize_query() -> embed_query() -> similarity_search(top_k=4, threshold=0.26)
        -> sources[] + context_text with "EVIDENCE" blocks
   -> build_general_prompt() / build_prediction_prompt()
   -> call_llm() [Gemini -> Groq -> OpenAI -> Ollama -> offline fallback]
   -> grounded, cited answer (or explicit "no evidence" refusal)
```

### Persistence
The vector store lives in `backend/rag/vector_store/` and the fitted TF-IDF vectorizer is cached at `backend/rag/cache/`. Because embeddings depend on the fitted vocabulary, the TF-IDF vectorizer is persisted so query vectors are always produced by the same vocabulary that indexed the documents. Embedding cache entries are intentionally not reused across providers to avoid dimension mismatches.

### Provider Fallback Behavior
`call_llm()` in auto mode tries providers in order until one returns text:
1. **Gemini** (rest API, generous model string fallbacks, single quick retry on 429/503).
2. **Groq** (OpenAI-compatible chat completions) - usually sub-second to a few seconds.
3. **OpenAI** (if a key is configured).
4. **Ollama** (local, if the server is running).
5. **Offline fallback** - deterministic knowledge-base snippet, no LLM.

Each live call has a hard wall-clock timeout so a hung provider can never block the chat endpoint indefinitely.

---

## Related Knowledge Base Documents

- `rag_retriever.md` - how retrieval and relevance scoring work.
- `rag_embeddings.md` - how text is converted to vectors (TF-IDF).
- `rag_vector_store.md` - where vectors and chunks are persisted.
- `rag_chunking.md` - how documents are split into chunks.