# 🛡️ NetGuard AI — Network Anomaly Detection & SOC Platform

> **AI-Powered Network Intrusion Detection System (NIDS) + Security Operations Center (SOC) Platform**
> Built for the **Major Project** (Bachelor of Engineering — Computer Science) by **Aditya Raikar**.

![Python](https://img.shields.io/badge/Python-3.11-blue?logo=python)
![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688?logo=fastapi)
![Streamlit](https://img.shields.io/badge/UI-Streamlit-FF4B4B?logo=streamlit)
![Scikit-Learn](https://img.shields.io/badge/ML-Scikit--Learn-orange?logo=scikitlearn)
![RandomForest](https://img.shields.io/badge/Algorithm-Random%20Forest-green)
![RAG](https://img.shields.io/badge/LLM-RAG%20Assistant-a855f7)
![Agentic AI](https://img.shields.io/badge/Agentic%20AI-Autonomous%20SOC%20Swarm-blueviolet)
![Status](https://img.shields.io/badge/Status-Completed-success)
![Render](https://img.shields.io/badge/Backend%20Deployed-Render-46E3B7?logo=render)
![Streamlit](https://img.shields.io/badge/Frontend%20Deployed-Streamlit%20Cloud-FF4B4B?logo=streamlit)

---

## 📌 Table of Contents

1. [Project Overview](#-project-overview)
2. [Key Features](#-key-features)
3. [System Architecture](#-system-architecture)
4. [Project Structure](#-project-structure)
5. [Datasets Used](#-datasets-used)
6. [Machine Learning Pipeline](#-machine-learning-pipeline)
7. [Model Performance](#-model-performance)
7a. [Live Deployment](#-live-deployment)
8. [RAG Knowledge Base](#-rag-knowledge-base-agentic-soc-assistant)
8a. [Agentic AI Architecture (Autonomous SOC & Swarm)](#-agentic-ai-architecture-autonomous-soc--multi-agent-swarm)
9. [API Endpoints](#-api-endpoints)
10. [Installation & Setup](#-installation--setup)
11. [Running the Application](#-running-the-application)
12. [Testing](#-testing)
13. [Results & Visualizations](#-results--visualizations)
14. [Web Application Screenshots](#-web-application-screenshots)
15. [Technologies Used](#-technologies-used)
16. [Future Enhancements](#-future-enhancements)
17. [Author](#-author)

---

## 📖 Project Overview

Cyber attacks are increasing rapidly, making automated network security more critical than ever. **NetGuard AI** is a complete, end-to-end **Network Intrusion Detection System (NIDS)** and **Security Operations Center (SOC)** platform that automatically classifies network traffic as **Normal / Benign** or **Malicious (Attack)** using **Machine Learning**.

The platform is trained and evaluated on two benchmark cybersecurity datasets:

- **NSL-KDD** (KDDTrain+ / KDDTest-21)
- **CICIDS-2017**

using the **Random Forest Classifier**. On top of the ML core, the project ships a production-style **FastAPI backend** and a rich **Streamlit SOC dashboard**, plus a **RAG-powered AI assistant** that answers security questions from a curated local knowledge base.

The system classifies traffic, computes **attack probability**, **confidence**, **risk scores**, and **severity**, and surfaces everything through an interactive threat-detection console.

---

## ✨ Key Features

- **Dual-Dataset Anomaly Detection**
  - Trained models for both **CICIDS-2017** (78 features) and **NSL-KDD** (41 features).
  - Binary classification: `BENIGN/NORMAL` vs `ATTACK`.

- **Production FastAPI Backend**
  - REST endpoints for single-flow prediction and CSV file analysis.
  - Automatic dataset-type detection (CICIDS vs NSL-KDD).
  - CORS enabled, health/status endpoints, structured error handling.

- **RAG-Powered SOC AI Assistant**
  - Retrieval-Augmented Generation over a curated **markdown knowledge base**.
  - Embedding + vector-store retrieval with a **Three-Level Evidence Strategy**.
  - Multi-provider LLM support: **Gemini, OpenAI, Groq, Ollama**, with automatic fallback and offline mode.
  - **Out-of-domain refusal** — politely declines unrelated questions.

- **Autonomous Agentic AI & Multi-Agent Swarm**
  - **Tier-2 ReAct Incident Copilot**: Autonomous reasoning loop (`Thought -> Action -> Observation`) using 6 cyber security tools (Threat Intel, XAI feature attribution, multiclass classifier, MITRE ATT&CK mapping, SOAR containment, and RAG SOC search).
  - **Autonomous Threat Hunter & Concept Drift Agent**: Population Stability Index (PSI) drift monitoring and sub-threshold ($0.35 \le p \le 0.65$) stealth anomaly cluster discovery with SIEM query generation.
  - **Hierarchical Multi-Agent Swarm**: Four specialized agents (`SupervisorAgent`, `ForensicsAgent`, `ThreatIntelAgent`, `RemediationAgent`) collaborating to produce STIX 2.1 incident bundles and blast-radius validated containment scripts.
  - **Multi-LLM Failover**: Seamless auto-failover across Gemini, Groq, and deterministic policy execution with zero-crash guarantees.

- **Live PCAP / Wireshark File Ingestion & Deep Packet Inspection (DPI)**
  - Built-in pure-Python binary PCAP/PCAPNG packet parser (`src/pcap_extractor.py`).
  - Reconstructs raw packets into bidirectional 5-tuple flows and extracts 28 statistical flow features (duration, packet counts, bytes/sec, SYN/FIN/RST flags, inter-arrival times).
  - Direct integration into `POST /analyze/pcap` for zero-setup Wireshark traffic analysis.

- **Interactive MITRE ATT&CK® Enterprise Matrix Navigator**
  - Full Cyber Kill Chain matrix spanning all 14 official enterprise tactics (`TA0043` through `TA0040`).
  - Dynamic threat heatmaps with active technique alert badges and glow borders.
  - Deep Technique Inspector surfacing threat actors (APTs), detection signatures, and automated SOAR playbooks (`iptables` + Snort rules).
  - Available as a dedicated command-center page (`🛡️ MITRE ATT&CK Matrix`) and contextual tab in `Threat Detection`.

- **Rich Streamlit SOC Dashboard**
  - Dark cyber / light enterprise **theme system** with glassmorphism + neon glow.
  - 14 navigation pages: Home, Overview, Live Traffic, Traffic Analytics, Threat Detection, **🛡️ MITRE ATT&CK Matrix**, **⚡ Agentic SOC Copilot (3 War-Room Tabs)**, Network Topology (3D), ML Insights, SOC AI Assistant, Dataset Analysis, Data Visualization Explorer, Prediction History, System Status & About.
  - **Interactive 3D neural topology visualizer** (WebGL/Canvas).
  - Severity badges, threat status radar panels, KPI metric cards, live SOC activity feed.
  - 10+ color presets including **Colorblind-Safe (Okabe-Ito)**.

- **Risk & Severity Scoring**
  - Each prediction includes `confidence`, `attack_probability`, `risk_score (0–100)` and `severity (MINIMAL/LOW/MEDIUM/HIGH/CRITICAL)`.

- **Threshold Tuning**
  - NSL-KDD attack threshold is configurable; validated against KDDTest-21 to balance precision/recall.

---

## 🏗️ System Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│          STREAMLIT SOC DASHBOARD (Frontend · Streamlit Cloud)          │
│  Overview · Live Traffic · Threat Detection · ⚡ Agentic SOC Copilot   │
│  (ReAct Copilot · Threat Hunter & Drift · Multi-Agent Swarm Command)   │
│  3D Topology · ML Insights · SOC AI Assistant · Dataset Analysis       │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │  HTTPS (requests) / Local :8000
┌───────────────────────────────────▼────────────────────────────────────┐
│                       FASTAPI BACKEND (frontend/app.py)                │
│  /predict/* · /analyze/* · /chat · /agent/investigate · /agent/hunt    │
│  /agent/swarm · /api/status · /health                                  │
└───────┬───────────────────────────┬────────────────────────────┬───────┘
        │                           │                            │
┌───────▼────────────────┐ ┌────────▼────────────────┐ ┌─────────▼──────────────┐
│  ML INFERENCE ENGINE   │ │  RAG KNOWLEDGE RETRIEVER│ │   AGENTIC SOC ENGINES  │
│ (src/prediction_engine)│ │   (backend/rag)         │ │   (src/agents)         │
│  • CICIDS-2017 RF      │ │   • Chunking & VectorStore│ • Native ReAct Agent   │
│  • NSL-KDD RF (tuned)  │ │   • Hybrid TF-IDF / St. │ │ • Drift & Threat Hunter│
│  • Risk / Severity Map │ │   • Grounded Generation │ │ • Multi-Agent Swarm    │
└───────┬────────────────┘ └────────┬────────────────┘ └─────────┬──────────────┘
        │                           │                            │
┌───────▼─────────────┐    ┌────────▼─────────────┐    ┌─────────▼──────────────┐
│ MODELS & ENCODERS   │    │  CYBERSECURITY DOCS  │    │ SECURITY TOOLS REGISTRY│
│  • .pkl Artifacts   │    │  • 12+ SOC markdown  │    │  • Threat Intel (IOCs) │
│  • Label Encoders   │    │    knowledge bases   │    │  • XAI SHAP Attribution│
│  • Scalers & Schema │    │  • MITRE ATT&CK refs │    │  • MITRE & SOAR Rules  │
└─────────────────────┘    └──────────────────────┘    └────────────────────────┘
```

**Flow:**
1. The **Streamlit SOC Dashboard** triggers detection, interactive triage, or autonomous investigations.
2. The **FastAPI Backend** (`frontend/app.py` & `backend/main.py`) routes requests to the ML inference engine, the RAG knowledge retriever, or the Agentic SOC engines.
3. The **ML Inference Engine** evaluates network flow vectors for anomalous behavior, computing attack probability, risk score, and severity tiers.
4. The **Agentic SOC Engines** provide multi-layered autonomous response:
   - **ReAct Copilot**: Synthesizes structured `IncidentDossier` reports by invoking tools iteratively.
   - **Threat Hunter**: Computes Population Stability Index (PSI) drift and reveals stealth attacks in the 0.35–0.65 probability grey zone.
   - **Swarm Command**: Dispatches specialized agents (`Supervisor`, `Forensics`, `ThreatIntel`, `Remediation`) to validate blast radius and formulate STIX 2.1 bundles.
5. All agent operations leverage multi-LLM failover (Gemini -> Groq -> Rule Policy) with zero-crash deterministic fallbacks.


---

## 📂 Project Structure

```text
Network Anamoly Detection/
│
├── backend/                      # Backend services
│   ├── main.py                   # Legacy FastAPI entry point
│   ├── app.py                    # (moved to frontend/app.py — primary API)
│   ├── predictor.py              # Model API adapter + validation
│   ├── dataset_analyzer.py       # Uploaded dataset inspection/type detection
│   ├── rag/                      # RAG subsystem
│   │   ├── config.py             # Central RAG + LLM configuration
│   │   ├── chunking.py           # Document chunking
│   │   ├── embeddings.py         # Embedding engine (TF-IDF / multi-provider)
│   │   ├── vector_store.py       # Persistent vector store
│   │   ├── ingestion.py          # Ingestion pipeline (docs → index)
│   │   ├── retriever.py          # Similarity retrieval
│   │   ├── generator.py          # Prompt builders + LLM dispatch
│   │   ├── prompts.py            # Prompt templates / system prompts
│   │   ├── documents/            # 🔎 Curated markdown knowledge base
│   │   ├── documents_backup/     # Backup of knowledge-base docs
│   │   ├── vector_store/         # Pre-built index (chunks/embeddings)
│   │   └── cache/                # Embedding / vectorizer caches
│   │
├── frontend/                     # Application layer
│   ├── app.py                    # ⭐ Primary FastAPI backend (all endpoints + /agent/*)
│   ├── dashboard.py              # ⭐ Streamlit SOC dashboard (13 pages incl. Agentic SOC)
│   ├── ui_components.py          # Cyber design system & triage components
│   └── api.py                    # Streamlit → Backend API client wrapper
│
├── src/                          # Core ML & Agentic AI
│   ├── prediction_engine.py      # Central inference engine
│   ├── agents/                   # ⚡ Autonomous Agentic AI Framework
│   │   ├── tools.py              # 6 Cyber tools registry (IOCs, SHAP, MITRE, SOAR, RAG)
│   │   ├── soc_agent.py          # Native ReAct SOC Tier-2 Copilot & Dossier Synthesizer
│   │   ├── drift_hunter_agent.py # Concept Drift (PSI) & Stealth Anomaly Hunter
│   │   └── multi_agent_swarm.py  # Hierarchical Multi-Agent Swarm (4 Specialists)
│   ├── cicids_analyzer.py        # CICIDS CSV analysis
│   ├── nsl_kdd_analyzer.py       # NSL-KDD file analysis + statistics
│   ├── cicids_preprocessing.py   # CICIDS load/clean/label-encode
│   ├── cicids_train_model.py     # Train CICIDS model
│   ├── cicids_model_evaluation.py# Evaluate CICIDS model
│   ├── nsl_kdd_preprocessing.py  # NSL-KDD load/encode/split
│   ├── nsl_kdd_train_model.py    # Train NSL-KDD model
│   └── nsl_kdd_model_evaluation.py # Evaluate NSL-KDD model
│
├── data/                         # Datasets
│   ├── NSL-KDD/                  # KDDTrain+.txt, KDDTest-21.txt
│   └── CICIDS-2017/              # Per-day pcap_ISCX CSV files + samples
│
├── models/                       # Trained model artifacts (.pkl)
│   ├── cicids_anomaly_model.pkl
│   ├── cicids_label_encoder.pkl
│   ├── nsl-kdd_anomaly_model.pkl
│   └── nsl-kdd_label_encoder.pkl
│
├── notebooks/                    # Jupyter training notebooks
│   ├── cicids2017_model_train.ipynb
│   └── nsl-kdd_model_train.ipynb
│
├── reports/                      # Generated evaluation artifacts
│   ├── cicids_model_metrics.txt
│   ├── nsl-kdd_model_metrics.txt
│   ├── *confusion_matrix.png
│   ├── *roc_curve.png
│   └── *feature_importance.png
│
├── tests/                        # Engine & integration checks
│   ├── test_prediction_engine.py
│   ├── test_real_predictions.py
│   └── test_soc_agent.py         # ⚡ Comprehensive test suite for all 3 Agent engines
│
├── run_soc.bat                   # 🚀 1-Click Windows Launcher (FastAPI :8000 + Streamlit :8501)
├── check_threshold.py            # NSL-KDD attack-threshold tuning utility
├── requirements.txt              # Python dependencies
├── .streamlit/config.toml        # Streamlit theme/server config
├── .env                          # API keys (see .env.example)
└── README.MD                     # This file
```

> The application entry points are **`frontend/app.py`** (FastAPI backend) and **`frontend/dashboard.py`** (Streamlit UI), or launch both together via **`run_soc.bat`**. The pre-built RAG vector store is already included under `backend/rag/vector_store/`, so the chatbot and agents work out of the box.

---

## 🗂️ Datasets Used

### NSL-KDD
A refined version of the classic KDD'99 dataset that removes redundant records, enabling fair and reliable evaluation.

- `KDDTrain+.txt` — training set
- `KDDTest-21.txt` — validation/testing set
- **41 network-traffic features** + attack `label` + `difficulty` level.
- Binary task: `normal` vs `attack`.

### CICIDS-2017
A modern intrusion-detection dataset built from real-world captured network traffic using the CICFlowMeter tool.

- Contains **78 numerical flow features**.
- Attack classes consolidated to binary: `BENIGN` vs `ATTACK`.

Attack categories covered include:

| Category | Example |
|----------|---------|
| **DDoS** | Distributed Denial of Service |
| **DoS** | Denial of Service |
| **Port Scan** | Reconnaissance scanning |
| **Web Attacks** | SQL injection / XSS / brute force |
| **Infiltration** | Data exfiltration |
| **Brute Force** | Credential attacks |
| **Botnet** | C2 / bot coordination |
| **Normal** | Benign traffic |

---

## ⚙️ Machine Learning Pipeline

```
Raw Dataset
      │
      ▼
Data Cleaning        (strip columns, drop NaN, handle Inf)
      │
      ▼
Feature Encoding     (LabelEncoder for categorical, numeric coercion)
      │
      ▼
Binary Label         (BENIGN/NORMAL → 0, ATTACK → 1)
      │
      ▼
Train-Test Split     (stratified)
      │
      ▼
Random Forest Training
      │
      ▼
Prediction           (predict + predict_proba)
      │
      ▼
Risk & Severity      (attack_probability → risk_score → severity)
      │
      ▼
Evaluation           (accuracy, precision, recall, F1, ROC-AUC)
      │
      ▼
Outputs              (confusion matrix, ROC curve, feature importance)
```

### Why Random Forest?
- High accuracy and robustness against overfitting.
- Handles large, high-dimensional datasets efficiently.
- Built-in feature-importance analysis.
- Fast training and very fast prediction (suitable for real-time SOC use).
- Works well with `predict_proba` for confidence/risk scoring.

---

## 📊 Model Performance

Metrics exported from the evaluation reports in `reports/`.

### NSL-KDD Results

| Metric | Score |
|------------|------------|
| Training Accuracy | **99.96%** |
| Testing Accuracy | **99.91%** |
| Precision | **99.95%** |
| Recall | **99.86%** |
| F1 Score | **99.90%** |
| ROC-AUC | **0.999992** |
| Confusion Matrix | `[[13463 6] [17 11709]]` |

### CICIDS-2017 Results

| Metric | Score |
|------------|------------|
| Training Accuracy | **99.91%** |
| Testing Accuracy | **99.89%** |
| Precision | **99.97%** |
| Recall | **99.89%** |
| F1 Score | **99.93%** |
| ROC-AUC | **1.0000** |

> Model files, encoders, and full metric reports are stored in `models/` and `reports/`.

---

## 🌍 Live Deployment

The platform is **deployed and publicly accessible**:

| Component | Platform | URL |
|-----------|----------|-----|
| **FastAPI Backend** | Render | [`https://netguard-ai-nd5e.onrender.com`](https://netguard-ai-nd5e.onrender.com) |
| **API Docs (Swagger UI)** | Render | [`https://netguard-ai-nd5e.onrender.com/docs`](https://netguard-ai-nd5e.onrender.com/docs) |
| **SOC Dashboard (Frontend)** | Streamlit Cloud | [`https://netguard-ai.streamlit.app`](https://netguard-ai.streamlit.app) |

The live backend serves all endpoints described in [API Endpoints](#%F0%9F%8C%90-api-endpoints), including model predictions and the RAG SOC assistant. The streamlit dashboard hits this deployed Render API (see `frontend/api.py` and `API_URL` in `frontend/dashboard.py`), so **no local setup is required to try the live demo**.

> **Note:** On free-tier hosts (Render / Streamlit) the services may go to sleep after inactivity; the first request after waking up may take a few extra seconds.

---

## 🧠 RAG Knowledge Base (Agentic SOC Assistant)

The **SOC AI Assistant** (`/chat`) answers cybersecurity questions using **Retrieval-Augmented Generation** over a curated local knowledge base at `backend/rag/documents/`.

### Knowledge Base Categories

- **System Architecture** — NetGuard AI overview, RAG chunking, embeddings, retriever, vector store.
- **Datasets & ML** — CICIDS-2017 and NSL-KDD guides, severity/confidence guidance.
- **Network Security** — botnets & C2, brute-force credentials, DoS/DDoS attacks, reconnaissance/scanning, web & infiltration.
- **SOC Procedures** — incident response, mitigation & hardening.
- **Definitions & Concepts** — network anomaly detection fundamentals.

### How It Works

1. **Ingestion** — documents are chunked (configurable `CHUNK_SIZE`/`OVERLAP`) and embedded into a persistent vector store.
2. **Retrieval** — embeddings are compared to the query; the top-K most similar chunks above a **similarity threshold** are selected (`RAG_SIMILARITY_THRESHOLD`, default `0.26`).
3. **Three-Level Evidence Strategy** — answers are grounded in retrieved context (Level 1), partial coverage is qualified (Level 2), or a knowledgeable response is withheld when no reliable evidence exists (Level 3).
4. **LLM Generation** — the grounded prompt is sent to the configured provider (`gemini`, `openai`, `groq`, `ollama`, or `auto`), with a hard timeout and automatic multi-provider fallback.
5. **Offline / Refusal** — if the LLM is unavailable, a clean local knowledge-base answer is returned; clearly out-of-domain questions are politely refused.

### Configuration (`.env`)

| Variable | Default | Purpose |
|----------|---------|---------|
| `LLM_PROVIDER` | `gemini` | `auto`, `gemini`, `openai`, `groq`, `ollama`, `offline_soc` |
| `GEMINI_API_KEY` | — | Gemini API key |
| `OPENAI_API_KEY` | — | OpenAI API key |
| `GROQ_API_KEY` | — | Groq API key |
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Local Ollama endpoint |
| `RAG_SIMILARITY_THRESHOLD` | `0.26` | Retrieval similarity floor |
| `RAG_TOP_K` | `4` | Number of retrieved chunks |
| `RAG_EMBEDDING_PROVIDER` | `tfidf` | `auto`, `tfidf`, `sentence_transformers`, `gemini`, `openai` |
| `LLM_TIMEOUT` | `3` | Hard cap (s) on each LLM call |
| `LLM_TEMPERATURE` | `0.2` | Generation temperature |
| `LLM_MAX_TOKENS` | `700` | Max output tokens |

---

## ⚡ Agentic AI Architecture (Autonomous SOC & Multi-Agent Swarm)

NetGuard AI features a production-grade **Agentic AI platform** (`src/agents/`) designed to elevate automated intrusion detection to autonomous SOC operations. It is composed of three interconnected agent tiers with multi-LLM failover and deterministic safety fallbacks:

```
                          ┌──────────────────────────┐
                          │   Incoming Threat Alert  │
                          └─────────────┬────────────┘
                                        │
           ┌────────────────────────────┼────────────────────────────┐
           │                            │                            │
           ▼                            ▼                            ▼
┌──────────────────────┐   ┌──────────────────────┐   ┌──────────────────────┐
│  Tier-2 ReAct Agent  │   │ Drift & Hunter Agent │   │  Multi-Agent Swarm   │
│  (soc_agent.py)      │   │ (drift_hunter.py)    │   │ (multi_agent_swarm)  │
│                      │   │                      │   │                      │
│ • ReAct Loop         │   │ • PSI Drift Calc     │   │ • Supervisor Agent   │
│ • 6 Security Tools   │   │ • Stealth Clusters   │   │ • Forensics Agent    │
│ • Dossier Synthesis  │   │ • SIEM Query Builder │   │ • Threat Intel Agent │
│ • Multi-LLM Failover │   │ • Hunting Hypothesis │   │ • Remediation Agent  │
└──────────┬───────────┘   └──────────┬───────────┘   └──────────┬───────────┘
           │                          │                          │
           └──────────────────────────┼──────────────────────────┘
                                      ▼
                      ┌───────────────────────────────┐
                      │    SECURITY TOOLS REGISTRY    │
                      │       (src/agents/tools.py)   │
                      │                               │
                      │ • threat_intel_lookup         │
                      │ • xai_explain_flow            │
                      │ • multiclass_classify         │
                      │ • soar_mitre_mapping          │
                      │ • soar_generate_containment   │
                      │ • rag_search_knowledge        │
                      └───────────────────────────────┘
```

### 1. Tier-2 Autonomous ReAct Incident Responder (`soc_agent.py`)
- **Reasoning Loop**: Operates on a native ReAct (`Thought -> Action: tool(args) -> Observation -> Thought -> Final Verdict`) cycle without bulky external agent frameworks.
- **Tools Registry (`tools.py`)**:
  - `threat_intel_lookup`: Verifies IP/domain/hash reputation against simulated threat intelligence feeds.
  - `xai_explain_flow`: Tree/SHAP-based feature attribution isolating top anomalous dimensions.
  - `multiclass_classify`: Categorizes generic anomalies into specific attack vectors (DDoS, PortScan, Infiltration, Brute Force).
  - `soar_mitre_mapping`: Correlates attack types to enterprise MITRE ATT&CK tactics, techniques, and IDs.
  - `soar_generate_containment`: Synthesizes ready-to-execute firewall rules (`iptables`, `UFW`, `PowerShell NetSecurity`, `Snort IDS`).
  - `rag_search_knowledge`: Performs semantic similarity lookup in the local 12-document SOC vector database.
- **Multi-LLM Failover**: Automatically cascades from **Gemini 1.5 Flash** to **Groq (`llama-3.3-70b-versatile` / `openai/gpt-oss-120b`)**, and finally to an embedded deterministic **Policy Fallback**. The agent will never fail or return blank outputs.
- **Output**: Generates a standardized `IncidentDossier` containing executive summary, root cause, MITRE tags, blast radius, and one-click containment scripts.

### 2. Autonomous Threat Hunting & Concept Drift Agent (`drift_hunter_agent.py`)
- **Population Stability Index (PSI)**: Monitors incoming flow feature distributions against baseline reference distributions:
  $$\text{PSI} = \sum \Big( (\text{Actual}\% - \text{Baseline}\%) \times \ln\big(\frac{\text{Actual}\%}{\text{Baseline}\%}\big) \Big)$$
  - $\text{PSI} < 0.10$: Minimal drift (Normal distribution).
  - $0.10 \le \text{PSI} < 0.25$: Moderate drift (Warning).
  - $\text{PSI} \ge 0.25$: Significant data drift detected (Retraining advised).
- **Stealth Anomaly Hunting**: Uncovers low-and-slow reconnaissance and evasion attempts hidden in the model's confidence "grey zone" ($0.35 \le p \le 0.65$).
- **Hypothesis & SIEM Generation**: Synthesizes hypothesis tickets with query syntax for **Splunk SPL** and **Elasticsearch DSL**.

### 3. Hierarchical Multi-Agent SOC Swarm (`multi_agent_swarm.py`)
- **Specialist Agent Delegation**:
  - **SupervisorAgent**: Coordinates triage execution, verifies evidence completeness, and drafts the executive brief.
  - **ForensicsAgent**: Deep dive into flow statistics, duration, packet length variance, and SHAP attribution.
  - **ThreatIntelAgent**: Correlates IPs against C2 infrastructure and maps behavior to MITRE tactics.
  - **RemediationAgent**: Validates blast radius against production subnets and formulates containment playbooks.
- **STIX 2.1 Serialization**: Outputs structured STIX 2.1 JSON incident bundles for enterprise SIEM/SOAR ingestion.

---

## 🌐 API Endpoints

Primary backend: **`frontend/app.py`** (FastAPI). **Deployed URL:** `https://netguard-ai-nd5e.onrender.com` · Local (dev): `http://127.0.0.1:8000`.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | App metadata & status |
| `GET` | `/health` | Health check + ML engine readiness |
| `GET` | `/model-info` | Loaded models, feature counts, classes |
| `GET` | `/api/status` | Full service/model/endpoint status |
| `POST` | `/predict/cicids` | Predict single CICIDS-2017 flow |
| `POST` | `/predict/nsl-kdd` | Predict single NSL-KDD flow |
| `POST` | `/analyze/cicids` | Analyze uploaded CICIDS CSV file |
| `POST` | `/analyze/nsl-kdd` | Analyze uploaded NSL-KDD file |
| `POST` | `/analyze/dataset` | Inspect/detect an uploaded dataset |
| `POST` | `/chat` | Ask the RAG-powered SOC assistant |
| `POST` | `/agent/investigate` | ⚡ Autonomous ReAct investigation on threat alert |
| `POST` | `/agent/hunt` | 🎯 Autonomous threat hunting & PSI concept drift |
| `POST` | `/agent/swarm` | 🐝 Hierarchical Multi-Agent Swarm incident triage |

### Example — ReAct SOC Agent Investigation

```bash
curl -X POST http://127.0.0.1:8000/agent/investigate \
  -H "Content-Type: application/json" \
  -d '{
    "alert_row": {
      "Source IP": "192.168.1.105",
      "Destination IP": "10.0.0.1",
      "Destination Port": 80,
      "Protocol": "tcp",
      "attack_probability": 0.94,
      "severity": "CRITICAL"
    },
    "dataset": "CICIDS-2017",
    "max_iterations": 5
  }'
```

### Example — Threat Hunting & Concept Drift Analysis

```bash
curl -X POST http://127.0.0.1:8000/agent/hunt \
  -H "Content-Type: application/json" \
  -d '{
    "dataset_name": "CICIDS-2017",
    "records": [
      {"Destination Port": 4444, "Protocol": "tcp", "Flow Duration": 120000, "attack_probability": 0.52}
    ]
  }'
```

### Example — Multi-Agent Swarm Triage

```bash
curl -X POST http://127.0.0.1:8000/agent/swarm \
  -H "Content-Type: application/json" \
  -d '{
    "alert": {
      "source_ip": "172.16.0.45",
      "target_ip": "10.0.0.5",
      "target_port": 445,
      "severity": "HIGH",
      "attack_type": "Infiltration"
    }
  }'
```


**Prediction response fields:** `dataset`, `prediction`, `confidence`, `attack_probability`, `is_attack`, `risk_score`, `severity`.

---

## 💻 Installation & Setup

### 1. Clone the repository

```bash
git clone <your-repo-url>
cd "Network Anamoly Detection"
```

### 2. (Recommended) Create a virtual environment

```bash
python -m venv .venv
.venv\Scripts\activate        # Windows
source .venv/bin/activate     # macOS / Linux
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment (optional, for the AI assistant)

Create a `.env` file in the project root and add your API key(s):

```env
# LLM providers (the assistant works offline without these)
LLM_PROVIDER=auto
GEMINI_API_KEY=your_gemini_key
OPENAI_API_KEY=your_openai_key
GROQ_API_KEY=your_groq_key

# Optional RAG tuning
RAG_SIMILARITY_THRESHOLD=0.26
RAG_TOP_K=4
```

The platform runs fully **without** any API keys — the SOC assistant auto-falls back to local knowledge-base answers, and the ML detection requires no keys at all.

---

## ▶️ Running the Application

> **🚀 Prefer the live demo?** The platform is already deployed and can be used immediately:
> - **SOC Dashboard:** [`https://netguard-ai.streamlit.app`](https://netguard-ai.streamlit.app)
> - **FastAPI Backend / API Docs:** [`https://netguard-ai-nd5e.onrender.com/docs`](https://netguard-ai-nd5e.onrender.com/docs)
>
> Skip straight to [Live Deployment](#-live-deployment). The steps below run the app **locally** for development.

### Option A — 1-Click Launcher (Windows)

Double click `run_soc.bat` or run:

```bat
run_soc.bat
```

This starts the FastAPI backend (`http://127.0.0.1:8000`), waits for health check confirmation, launches the Streamlit SOC Dashboard (`http://localhost:8501`), and opens your default browser automatically.

### Option B — Manual Multi-Terminal Launch

**Terminal 1 — FastAPI Backend:**
```bash
uvicorn frontend.app:app --reload --port 8000
```
> The backend auto-loads the ML models and indexes the RAG knowledge base on startup.

**Terminal 2 — Streamlit SOC Dashboard:**
```bash
streamlit run frontend/dashboard.py
```
> Open `http://localhost:8501` to access all 13 SOC command-center pages, including the new **⚡ Agentic SOC Copilot** war room.

---

## 🧪 Testing

Run the full automated test suite for the **Agentic AI Platform** (ReAct agent, tool execution, threat hunting PSI, and multi-agent swarm):

```bash
python -m unittest tests/test_soc_agent.py
```

Verify the prediction engine loads and correctly rejects invalid input:

```bash
python tests/test_prediction_engine.py
```

Validate real predictions against actual dataset rows:

```bash
python tests/test_real_predictions.py
```

Tune the NSL-KDD attack threshold:

```bash
python check_threshold.py
```

---

## 📈 Results & Visualizations

Generated evaluation artifacts live in `reports/`.

### NSL-KDD — Confusion Matrix
![NSL-KDD Confusion Matrix](reports/nsl-kdd_confusion_matrix.png)

### NSL-KDD — ROC Curve
![NSL-KDD ROC Curve](reports/nsl-kdd_roc_curve.png)

### NSL-KDD — Feature Importance
![NSL-KDD Feature Importance](reports/nsl-kdd_feature_importance.png)

### CICIDS-2017 — Confusion Matrix
![CICIDS Confusion Matrix](reports/cicids_confusion_matrix.png)

### CICIDS-2017 — ROC Curve
![CICIDS ROC Curve](reports/cicids_roc_curve.png)

### CICIDS-2017 — Feature Importance
![CICIDS Feature Importance](reports/cicids_feature_importance.png)

---

## 🖼️ Web Application Screenshots

Screenshots of the running **Streamlit dashboard** (`http://localhost:8501`). Categories 11 & 12 correspond to the **FastAPI** endpoints (`http://127.0.0.1:8000/docs` and `/api/status`); re-capture those from the running backend to complete the gallery.

### 1. Dashboard Overview (Home)
Full dashboard landing view — hero header, live status pills, 3D spatial threat matrix, and the Overview page with its KPI cards.

![1 - Dashboard Overview](screenshots/01_dashboard_overview.png)

### 2. Live Traffic Monitor
The **Live Traffic** page — real-time flow feed and threat status panel.

![2 - Live Traffic Monitor](screenshots/02_live_traffic.png)

### 3. Traffic Analytics
The **Traffic Analytics** page — plotly charts (traffic volume, protocol distribution, time-series trends).

![3 - Traffic Analytics](screenshots/03_traffic_analytics.png)

### 4. Threat Detection (Results)
The **Threat Detection** page — threat status radar panel, severity badges, attack-rate statistics, and the prediction results table.

![4 - Threat Detection](screenshots/04_threat_detection.png)

### 5. Network Topology (3D)
The **Network Topology** page — interactive **3D neural/cybernetic topology visualizer** (WebGL/Canvas, drag to rotate).

![5 - Network Topology 3D](screenshots/05_network_topology_3d.png)

### 6. ML Insights
The **ML Insights** page — model info, feature importance, and inference telemetry for the selected dataset.

![6 - ML Insights](screenshots/06_ml_insights.png)

### 7. SOC AI Assistant (RAG Chatbot)
The **SOC AI Assistant** page — chat with the RAG-powered assistant on a cybersecurity question.

![7 - SOC AI Assistant](screenshots/07_soc_ai_assistant.png)

### 8. Dataset Analysis
The **Dataset Analysis** page — uploaded-file analysis summary, normal vs attack breakdown, and row-level predictions.

![8 - Dataset Analysis](screenshots/08_dataset_analysis.png)

### 9. Data Visualization Explorer
The **Data Visualization Explorer** page — histogram/bar chart explorer for any column of the uploaded dataset.

![9 - Data Visualization Explorer](screenshots/09_data_visualization_explorer.png)

### 10. System Status
The **System Status** page — API health, ML engine readiness, RAG knowledge-base index, and endpoint list.

![10 - System Status](screenshots/10_system_status.png)

### 11. FastAPI Swagger UI (`/docs`)
The auto-generated **FastAPI interactive API documentation** — all endpoints browsable and testable in the browser.

> ⏳ **Pending** — no screenshot captured yet. Capture `http://127.0.0.1:8000/docs` and save as `screenshots/11_fastapi_swagger.png`.

### 12. FastAPI `/api/status` — JSON
Raw JSON response of the `/api/status` endpoint showing service/model/endpoint readiness.

> ⏳ **Pending** — no screenshot captured yet. Capture `http://127.0.0.1:8000/api/status` and save as `screenshots/12_api_status.png`.

### Recommended capture checklist

| # | Screenshot | Where to capture | Purpose |
|---|-----------|------------------|---------|
| 1 | `01_dashboard_overview.png` | Streamlit · Overview page | Project hero shot |
| 2 | `02_live_traffic.png` | Streamlit · Live Traffic | Live monitoring |
| 3 | `03_traffic_analytics.png` | Streamlit · Traffic Analytics | Analytics dashboards |
| 4 | `04_threat_detection.png` | Streamlit · Threat Detection | Detection results |
| 5 | `05_network_topology_3d.png` | Streamlit · Network Topology | 3D visualization |
| 6 | `06_ml_insights.png` | Streamlit · ML Insights | ML telemetry |
| 7 | `07_soc_ai_assistant.png` | Streamlit · SOC AI Assistant | RAG chatbot |
| 8 | `08_dataset_analysis.png` | Streamlit · Dataset Analysis | File analysis |
| 9 | `09_data_visualization_explorer.png` | Streamlit · Data Viz Explorer | Exploratory viz |
| 10 | `10_system_status.png` | Streamlit · System Status | Health/status |
| 11 | `11_fastapi_swagger.png` | `http://127.0.0.1:8000/docs` | API docs |
| 12 | `12_api_status.png` | `http://127.0.0.1:8000/api/status` | API JSON |

> **Tip:** Categories 11 & 12 are pending — capture those two endpoints from the running FastAPI backend (`http://127.0.0.1:8000/docs` and `/api/status`) and drop the PNGs into `screenshots/` as `11_fastapi_swagger.png` and `12_api_status.png` to complete the full 12-item gallery.

---

## 🛠️ Technologies Used

- **Python 3.11**
- **Scikit-Learn** — Random Forest, preprocessing, evaluation
- **Pandas / NumPy** — data handling & numerical computation
- **Joblib** — model serialization (`.pkl`)
- **FastAPI + Uvicorn** — REST API backend
- **Streamlit** — interactive SOC dashboard
- **Plotly** — interactive charts & visualizations
- **Requests** — frontend↔backend communication
- **RAG stack** — chunking, embeddings, vector store, retrieval, LLM
- **Jupyter Notebook** — model training experiments
- **Matplotlib / Seaborn** — evaluation figures
- **WebGL / Canvas** — interactive 3D topology visualizer

---

## 🔮 Future Enhancements

- **Real-time packet capture** (live network monitoring via pcap/online streaming).
- **Deep Learning models** (CNN / LSTM / transformers) for higher fidelity.
- **Explainable AI (SHAP / LIME)** for model interpretability.
- **Multi-class attack classification** (beyond binary normal/attack).
- **Streaming/message-queue ingestion** and horizontal scaling.
- **Authentication, role-based access & audit logging** for production SOC teams.
- **Alerting & notification** (email, Slack, SIEM integration).
- **Containerized deployment** (Docker) with CI/CD.

---

## 👨‍💻 Author

**Aditya Raikar**

- **Degree:** Bachelor of Engineering (Computer Science)
- **Project Type:** Major Project
- **Title:** Network Anomaly Detection using Machine Learning — *NetGuard AI SOC Platform*

---

> **Disclaimer:** This project is an educational cybersecurity demonstration. It is intended for network research, academic study, and SOC prototype use. Always deploy with proper authorization and security review in production environments.
