# NetGuard AI - Project Overview

> **Scope note (how to read this document):** This file describes the **NetGuard AI** project itself. Everything here is grounded in the actual project files: the README, the training/evaluation scripts in `src/`, the prediction engine, and the RAG chat backend. Statements that would imply undocumented capabilities are deliberately omitted.

---

## Overview

**NetGuard AI** is a **Machine Learning-based Network Intrusion Detection System (NIDS)**. Its core job is to automatically classify network traffic as either **normal** or **malicious (attack)** using a supervised **Random Forest classifier**. It is trained on two widely used benchmark datasets - **NSL-KDD** and **CICIDS-2017** - and is packaged as an application with three major surfaces:

1. **A prediction backend (FastAPI)** that loads the trained models and classifies network flow/capture data.
2. **A dashboard (Streamlit)** for interactive, visual sysop/monitoring use.
3. **A RAG-grounded chat assistant** that answers cybersecurity questions using a local knowledge base plus an LLM provider (Gemini primary, Groq fallback), with a clean offline fallback when no provider is configured.

---

## Definition

- **NetGuard AI:** The name of this project - a Random Forest NIDS for network anomaly/intrusion detection with a chat Q&A assistant.
- **NIDS:** Network Intrusion Detection System - monitors network traffic and flags behavior that looks like an intrusion.
- **RAG:** Retrieval-Augmented Generation - the chat assistant answers using both a retrieved local knowledge base and an LLM, and cites its sources.

**Related terms:** network anomaly detection, intrusion detection, Random Forest classification, traffic classification.

---

## Key Concepts

### Trained Models
The project trains and persists, under the `models/` directory:
- `nsl-kdd_anomaly_model.pkl` - Random Forest trained on NSL-KDD (41 connection-record features).
- `cicids_anomaly_model.pkl` - Random Forest trained on CICIDS-2017 (~78-80 per-flow features).
- `nsl-kdd_label_encoder.pkl` and `cicids_label_encoder.pkl` - encoders mapping predicted class labels to readable names.

Models are RandomForestClassifiers configured with `max_features="sqrt"`, saved with `joblib`.

### Datasets
- **NSL-KDD:** 41 numeric/categorical connection-record features; labels `normal` or one of the attack families. Used for training the NSL-KDD classifier.
- **CICIDS-2017:** bidirectional network flow features (~78-80 numeric columns) plus a class label, covering modern attack categories and `BENIGN` traffic. Used for training the CICIDS classifier.

### Reported Results (from the README, single-run)
- NSL-KDD: training accuracy 99.97%, testing accuracy 99.91%, precision 99.95%, recall 99.86%, F1 99.90%, ROC-AUC 0.999992.
- CICIDS-2017: training accuracy 99.99%, testing accuracy 99.85%, precision 99.93%, recall 99.88%, F1 99.91%, ROC-AUC 0.999936.

---

## Technical Details

### Source Layout
- `src/nsl_kdd_preprocessing.py`, `src/nsl_kdd_train_model.py`, `src/nsl_kdd_model_evaluation.py` - NSL-KDD pipeline.
- `src/cicids_preprocessing.py`, `src/cicids_train_model.py`, `src/cicids_model_evaluation.py` - CICIDS-2017 pipeline.
- `src/prediction_engine.py` - loads both models and exposes prediction helpers (including per-dataset feature checks such as the exactly 41 NSL-KDD features and ~78 CICIDS features).
- `backend/` - FastAPI application; `backend/rag/` contains the RAG chat subsystem.
- `examples/`, `reports/`, `notebooks/` - exploratory notebooks, model reports, and example captures.

### Technology Stack
Python, Pandas, NumPy, Scikit-Learn (Random Forest), Joblib (model persistence), Matplotlib/Seaborn (evaluation plots), FastAPI (backend), Streamlit (dashboard), and scikit-learn TF-IDF vectorization for the local RAG embeddings.

### Prediction Flow
1. Raw datasets are cleaned, categorical features are encoded, and binary labels are derived.
2. Data is split into train/test sets.
3. Random Forest is trained and saved, then evaluated (accuracy, precision, recall, F1, ROC-AUC, confusion matrix, feature importance).
4. At runtime `prediction_engine` loads the models and classifies new traffic records, producing a predicted class plus confidence for a NetGuard AI-style severity/confidence assessment.

---

## How the RAG Chat Assistant Works

The chat assistant (`backend/rag/`) is a retrieval-augmented generation pipeline:

1. **Ingestion** (`ingestion.py`): markdown knowledge-base documents are chunked (`chunking.py`), embedded as TF-IDF vectors (`embeddings.py`), and persisted in a local vector store (`vector_store.py`).
2. **Retrieval** (`retriever.py`): the user's question is normalized and embedded, the top relevant chunks are retrieved, and a structured context block with source citations is built.
3. **Generation** (`generator.py`): a carefully grounded prompt (system prompt, query, retrieved evidence) is sent to the configured LLM provider. Provider order in auto mode is Gemini, then Groq, then OpenAI, then Ollama, and finally a deterministic offline fallback.
4. The answer follows a three-level evidence strategy: cite only retrieved sources when they fully answer the question, state partial coverage explicitly, and refuse/invent nothing when there is no evidence.

The knowledge base covers datasets and machine learning, network security topics, and SOC procedures. See the `rag_system.md`, `rag_retriever.md`, `rag_embeddings.md`, `rag_vector_store.md`, and `rag_chunking.md` documents in this knowledge base for the internals.

---

## Related Knowledge Base Documents

- `network_anomaly_detection.md` - the core detection concept.
- `cicids2017_guide.md`, `nsl_kdd_guide.md` - the datasets used for training.
- `severity_and_confidence.md` - severity/confidence scoring of predictions.
- `rag_system.md` and the other `rag_*.md` documents - RAG internals.