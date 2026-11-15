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

Serves the ML inference engine (CICIDS-2017 & NSL-KDD, Random Forest), real-time flow detection, live traffic monitoring, multi-channel alerts, and the RAG-powered SOC AI assistant.

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | App metadata |
| `GET` | `/health` | Health check + ML engine readiness |
| `GET` | `/model-info` | Loaded model details |
| `GET` | `/api/status` | Full service/model/endpoint status |
| `POST` | `/auth/register` | Register new user account |
| `POST` | `/auth/login` | Authenticate user & issue JWT token |
| `GET` | `/auth/history` | Retrieve user alert history |
| `POST` | `/predict/cicids` | Predict a CICIDS-2017 flow |
| `POST` | `/predict/nsl-kdd` | Predict an NSL-KDD flow |
| `POST` | `/analyze/cicids` | Analyze a CICIDS CSV file |
| `POST` | `/analyze/nsl-kdd` | Analyze an NSL-KDD file |
| `POST` | `/analyze/pcap` | DPI flow analysis from PCAP file |
| `POST` | `/analyze/dataset` | Inspect/detect a dataset |
| `GET` | `/monitor/interfaces` | List network capture interfaces |
| `POST` | `/monitor/start` | Start live packet sniffer |
| `POST` | `/monitor/stop` | Stop live packet sniffer |
| `POST` | `/agent/investigate` | Autonomous ReAct threat investigation |
| `POST` | `/agent/hunt` | Autonomous threat hunting & PSI drift |
| `POST` | `/agent/swarm` | Multi-agent incident triage swarm |
| `POST` | `/chat` | Ask the SOC AI assistant |

Interactive API docs: `/docs`

## Configuration (Secrets)

Set these in **Settings → Variables and secrets**:

- `LLM_PROVIDER` (default `groq` or `auto`)
- `GROQ_API_KEY`
- `GEMINI_API_KEY`
- `OPENAI_API_KEY`
- `NETGUARD_JWT_SECRET`

The platform works **without any API keys** — the SOC assistant falls back to the local knowledge base, and the ML detection requires no external connections.
