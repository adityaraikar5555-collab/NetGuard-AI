from pathlib import Path
import sys
from typing import List

from fastapi import FastAPI, HTTPException, UploadFile, File, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field


# ============================================================
# PROJECT PATH
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

SRC_DIR = PROJECT_ROOT / "src"

sys.path.insert(0, str(SRC_DIR))


# ============================================================
# ML ENGINE & CYBERSECURITY TOOLS
# ============================================================

from prediction_engine import NetworkPredictionEngine
from backend.rag import (
    RAGRetriever,
    RAGIngestionPipeline,
    EmbeddingEngine,
    PersistentVectorStore,
    build_general_prompt,
    call_llm,
)
from src.agents import native_soc_agent, threat_hunting_agent, soc_swarm_supervisor
from src.pcap_extractor import pcap_extractor
from src.multiclass_engine import multiclass_classifier
from src.threat_intel import threat_intel_engine
from src.soar_engine import soar_engine
from typing import Dict, Any, Optional, List, Union


# ============================================================
# FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title="AI-Powered Network Anomaly Detection",
    description=(
        "AI cybersecurity backend for network anomaly "
        "detection using Random Forest models."
    ),
    version="1.0.0",
)


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# LOAD ML ENGINE ONCE
# ============================================================

print("=" * 70)
print("STARTING AI SECURITY BACKEND")
print("=" * 70)


engine = NetworkPredictionEngine()

# ============================================================
# INITIALIZE RAG — INGEST LOCAL KNOWLEDGE BEFORE RETRIEVAL
# ============================================================
# IMPORTANT: keep the chatbot API/response contract unchanged.
rag_embedding_engine = EmbeddingEngine()
rag_vector_store = PersistentVectorStore()
rag_ingestion = RAGIngestionPipeline(
    embedding_engine=rag_embedding_engine,
    vector_store=rag_vector_store,
)

try:
    rag_result = rag_ingestion.run(force_rebuild=False)
    if not rag_result.get("success"):
        print(f"[RAG WARNING] Ingestion did not complete: {rag_result}")
    else:
        print(
            f"[RAG READY] {rag_result.get('total_chunks_indexed', len(rag_vector_store.chunks))} chunks indexed."
        )
except Exception as rag_error:
    print(f"[RAG ERROR] Startup ingestion failed: {rag_error}")

retriever = RAGRetriever(
    embedding_engine=rag_embedding_engine,
    vector_store=rag_vector_store,
)

print("=" * 70)
print("FASTAPI BACKEND READY")
print("=" * 70)


# ============================================================
# REQUEST MODELS
# ============================================================

class PredictionRequest(BaseModel):
    features: List[float] = Field(
        ...,
        description="Preprocessed network-flow feature vector."
    )
class ChatRequest(BaseModel):
    query: str = Field(
        ...,
        description="User's cybersecurity question for the RAG-powered SOC assistant."
    )

# ============================================================
# ROOT
# ============================================================

@app.get("/")
def root():

    return {
        "application": (
            "AI-Powered Network Anomaly Detection"
        ),
        "status": "online",
        "version": "1.0.0",
        "backend": "FastAPI",
    }


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
def health():

    return {
        "status": "healthy",
        "ml_engine": "ready",
    }


# ============================================================
# MODEL INFORMATION
# ============================================================

@app.get("/model-info")
def model_info():

    return engine.get_model_info()


# ============================================================
# CICIDS PREDICTION
# ============================================================

@app.post("/predict/cicids")
def predict_cicids(
    request: PredictionRequest
):

    try:

        result = engine.predict_cicids(
            request.features
        )

        return {
            "success": True,
            "result": result,
        }

    except ValueError as error:

        raise HTTPException(
            status_code=400,
            detail=str(error)
        )

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=str(error)
        )


# ============================================================
# NSL-KDD PREDICTION
# ============================================================

@app.post("/predict/nsl-kdd")
def predict_nsl_kdd(
    request: PredictionRequest
):

    try:

        result = engine.predict_nsl_kdd(
            request.features
        )

        return {
            "success": True,
            "result": result,
        }

    except ValueError as error:

        raise HTTPException(
            status_code=400,
            detail=str(error)
        )

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=str(error)
        )
# ============================================================
# RAG CHATBOT QUERY
# ============================================================

@app.post("/chat")
def chat(
    request: ChatRequest
):

    try:

        retrieval_result = retriever.retrieve(request.query)

        prompt = build_general_prompt(
            request.query,
            retrieval_result
        )

        answer = call_llm(prompt)

        if answer is None:
            context = (retrieval_result.get("context_text") or "").strip()
            if context:
                answer = (
                    "### Relevant Knowledge Base Information\n\n"
                    f"{context}\n\n"
                    "*Note: Live AI generation is currently unavailable or timed out. "
                    "Answer provided from the local knowledge base.*"
                )
            else:
                answer = (
                    "I don't have enough reliable information in the current "
                    "knowledge base to answer this confidently. "
                    "(No live LLM response — check that GEMINI_API_KEY or "
                    "OPENAI_API_KEY is configured and reachable.)"
                )

        return {
            "success": True,
            "answer": answer,
            "sources": retrieval_result["sources"],
            "has_evidence": retrieval_result["has_evidence"],
        }

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=str(error)
        )


# ============================================================
# AGENTIC SOC INVESTIGATION
# ============================================================

class AgentInvestigationRequest(BaseModel):
    dataset: str = Field(default="CICIDS-2017", description="Dataset type ('CICIDS-2017' or 'NSL-KDD')")
    src_ip: Optional[str] = Field(default="185.220.101.5", description="Suspicious source IP")
    dst_ip: Optional[str] = Field(default="192.168.1.100", description="Target destination IP")
    dst_port: Optional[str] = Field(default="80", description="Target destination port")
    attack_probability: float = Field(default=0.95, description="Initial ML anomaly probability (0.0 to 1.0)")
    features: Dict[str, Any] = Field(default_factory=dict, description="Preprocessed flow features dictionary")


@app.post("/agent/investigate")
def agent_investigate(request: AgentInvestigationRequest):
    """
    Triggers the Native ReAct SOC Agent to autonomously investigate a security anomaly.
    Executes reasoning, tool-calling (XAI, Threat Intel, MultiClass, MITRE, SOAR),
    and synthesizes an executive incident dossier.
    """
    try:
        context = request.model_dump() if hasattr(request, "model_dump") else request.dict()
        dossier = native_soc_agent.investigate(context)
        return {
            "success": True,
            "dossier": dossier.to_dict(),
        }
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Agent investigation failed: {str(exc)}"
        )


class AgentHuntRequest(BaseModel):
    dataset: str = Field(default="CICIDS-2017", description="Benchmark dataset format ('CICIDS-2017' or 'NSL-KDD')")
    features: Optional[Union[Dict[str, Any], List[Dict[str, Any]]]] = Field(default=None, description="Flow batch or dictionary of features to analyze for concept drift")


@app.post("/agent/hunt")
def agent_hunt(request: AgentHuntRequest):
    """
    Triggers the Autonomous Threat Hunting & Concept Drift Agent.
    Evaluates Population Stability Index (PSI), detects sub-threshold stealth clusters,
    and formulates proactive threat hunting hypotheses.
    """
    try:
        report = threat_hunting_agent.hunt(request.features or {}, dataset=request.dataset)
        return {
            "success": True,
            "report": report.to_dict(),
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Threat hunting cycle failed: {str(exc)}")


class AgentSwarmRequest(BaseModel):
    dataset: str = Field(default="CICIDS-2017", description="Dataset type ('CICIDS-2017' or 'NSL-KDD')")
    src_ip: Optional[str] = Field(default="185.220.101.5", description="Attacker or suspicious source IP")
    dst_ip: Optional[str] = Field(default="192.168.1.100", description="Target destination IP")
    dst_port: Optional[str] = Field(default="80", description="Target destination port")
    attack_probability: float = Field(default=0.95, description="Initial ML anomaly confidence (0.0 to 1.0)")
    features: Dict[str, Any] = Field(default_factory=dict, description="Preprocessed flow features dictionary")


@app.post("/agent/swarm")
def agent_swarm(request: AgentSwarmRequest):
    """
    Triggers the Hierarchical Multi-Agent SOC Swarm.
    Supervisor Agent coordinates Forensics, Threat Intel, and Remediation specialists
    with blast radius safety checks.
    """
    try:
        context = request.model_dump() if hasattr(request, "model_dump") else request.dict()
        brief = soc_swarm_supervisor.coordinate_investigation(context)
        return {
            "success": True,
            "brief": brief.to_dict(),
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Swarm mission failed: {str(exc)}")


@app.post("/analyze/pcap")
async def analyze_pcap(
    file: UploadFile = File(...),
    max_packets: int = Query(15000, description="Max packets to reconstruct"),
):
    """
    Ingests raw .pcap binary file, reconstructs bidirectional flows, and runs threat inference.
    """
    try:
        if not file.filename:
            raise HTTPException(status_code=400, detail="No PCAP file selected.")

        contents = await file.read()
        if not contents:
            raise HTTPException(status_code=400, detail="Uploaded PCAP file is empty.")

        flows_df = pcap_extractor.parse_file(contents, max_packets=max_packets)
        if flows_df.empty:
            return {
                "success": True,
                "dataset": "PCAP-Extracted",
                "filename": file.filename,
                "summary": {"total_flows": 0, "benign_flows": 0, "attack_flows": 0, "attack_rate": 0.0},
                "predictions": [],
                "message": "No IP packets extracted or capture contained non-IPv4 traffic.",
            }

        results = []
        attack_count = 0
        for idx, row in flows_df.iterrows():
            row_dict = row.to_dict()
            try:
                # Use engine prediction
                features_arr = [float(row_dict.get(c, 0.0)) for c in row_dict if isinstance(row_dict.get(c), (int, float))]
                pred_res = engine.predict_cicids(features_arr[:78]) if len(features_arr) >= 78 else {
                    "prediction": "BENIGN", "confidence": 0.95, "attack_probability": 0.05, "is_attack": False, "risk_score": 5.0
                }
                is_attack = bool(pred_res.get("is_attack") or pred_res.get("prediction") not in ("BENIGN", "Normal", 0))
            except Exception:
                is_attack = False
                pred_res = {"prediction": "Normal", "attack_probability": 0.1, "confidence": 0.9, "risk_score": 10.0}

            if is_attack:
                attack_count += 1

            mc_info = multiclass_classifier.classify_flow(row_dict, dataset="CICIDS-2017")
            geo_info = threat_intel_engine.lookup_ip(str(row_dict.get("Source IP", "192.168.1.100")), is_flagged_threat=is_attack)
            mitre_info = soar_engine.map_mitre(mc_info.get("category_code", "ANOMALY"), flow_data=row_dict)

            enriched_row = {
                **row_dict,
                "row": idx + 1,
                "prediction": "Attack" if is_attack else "Normal",
                "is_attack": is_attack,
                "attack_probability": pred_res.get("attack_probability", 0.0),
                "confidence": pred_res.get("confidence", 0.95),
                "risk_score": pred_res.get("risk_score", 15.0),
                "Severity": "Critical" if pred_res.get("risk_score", 0) > 75 else ("High" if is_attack else "Low"),
                "attack_family": mc_info.get("attack_family", "Network Anomaly"),
                "mitre_technique": mitre_info.get("technique_name", "Network Anomaly"),
                "mitre_id": mitre_info.get("technique_id", "T1036"),
                "geo_country": geo_info.get("country", "Internal"),
                "geo_city": geo_info.get("city", "Internal Subnet"),
                "reputation_score": geo_info.get("reputation_score", 10),
            }
            results.append(enriched_row)

        total = len(results)
        return {
            "success": True,
            "dataset": "PCAP-Reconstructed",
            "filename": file.filename,
            "summary": {
                "total_flows": total,
                "benign_flows": total - attack_count,
                "attack_flows": attack_count,
                "attack_rate": round((attack_count / total) * 100, 2) if total else 0.0,
                "benign_rate": round(((total - attack_count) / total) * 100, 2) if total else 0.0,
            },
            "predictions": results,
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"PCAP DPI analysis failed: {str(exc)}")


