---
title: NetGuard AI Backend
emoji: 🛡️
colorFrom: blue
colorTo: purple
sdk: docker
pinned: false
license: mit
short_description: FastAPI backend for AI-powered network anomaly detection + SOC RAG assistant
---

# NetGuard AI — Backend

FastAPI backend for the **NetGuard AI** Network Anomaly Detection & SOC platform.

Serves the ML inference engine (CICIDS-2017 & NSL-KDD, Random Forest) and the RAG-powered SOC AI assistant.

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | App metadata |
| `GET` | `/health` | Health check + ML engine readiness |
| `GET` | `/model-info` | Loaded model details |
| `GET` | `/api/status` | Full service/model/endpoint status |
| `POST` | `/predict/cicids` | Predict a CICIDS-2017 flow |
| `POST` | `/predict/nsl-kdd` | Predict an NSL-KDD flow |
| `POST` | `/analyze/cicids` | Analyze a CICIDS CSV file |
| `POST` | `/analyze/nsl-kdd` | Analyze an NSL-KDD file |
| `POST` | `/analyze/dataset` | Inspect/detect a dataset |
| `POST` | `/chat` | Ask the SOC AI assistant |

Interactive API docs: `/docs`

## Configuration (Secrets)

Set these in **Settings → Variables and secrets**:

- `LLM_PROVIDER` (default `auto`)
- `GEMINI_API_KEY`
- `OPENAI_API_KEY`
- `GROQ_API_KEY`

The platform works **without any API keys** — the SOC assistant falls back to the local knowledge base.
