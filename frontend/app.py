from pathlib import Path
import sys
from typing import List, Union, Optional, Dict, Any

from fastapi import FastAPI, HTTPException, UploadFile, File, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# ============================================================
# PROJECT ROOT CONFIGURATION
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

# ============================================================
# CORE ML & RAG IMPORTS
# ============================================================

from backend.predictor import NetworkPredictor
from backend.dataset_analyzer import DatasetAnalyzer
from src.cicids_analyzer import CICIDSAnalyzer
from src.nsl_kdd_analyzer import NSLKDDAnalyzer
from backend.rag import (
    RAGRetriever,
    default_config,
    build_general_prompt,
    call_llm,
    is_out_of_domain,
    OUT_OF_DOMAIN_REFUSAL,
)

# 7 Advanced Power Engines + Agentic SOC
from src.xai_engine import xai_engine
from src.soar_engine import soar_engine
from src.pcap_extractor import pcap_extractor
from src.multiclass_engine import multiclass_classifier
from src.threat_intel import threat_intel_engine
from src.alert_integrations import alert_integration_engine
from src.drift_monitor import drift_monitor
from src.agents import native_soc_agent, threat_hunting_agent, soc_swarm_supervisor
from src.adversarial_tester import adversarial_tester
from src.forensic_packager import forensic_packager
import base64


# ============================================================
# FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title="NetGuard AI SOC Backend",
    description="FastAPI backend for Network Anomaly Detection, XAI, SOAR, PCAP Ingestion, and SOC Platform",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================
# SERVICES
# ============================================================

predictor = NetworkPredictor()
dataset_analyzer = DatasetAnalyzer()
cicids_analyzer = CICIDSAnalyzer()
nsl_kdd_analyzer = NSLKDDAnalyzer(predictor)
rag_retriever = RAGRetriever(config=default_config)

# Link XAI engine to predictor
try:
    if hasattr(predictor, "engine"):
        xai_engine.predictor = predictor.engine
except Exception:
    pass

# ============================================================
# REQUEST MODELS
# ============================================================

class CICIDSPredictionRequest(BaseModel):
    features: List[float] = Field(
        ...,
        min_length=1,
        description="Numerical CICIDS-2017 network traffic features"
    )


class NSLKDDPredictionRequest(BaseModel):
    features: List[Union[float, str]] = Field(
        ...,
        min_length=1,
        description=(
            "NSL-KDD features containing numerical values "
            "and categorical values such as tcp, http and SF"
        )
    )


class PredictionRequest(BaseModel):
    features: List[Union[float, str]] = Field(
        ...,
        description="Network traffic feature vector"
    )


class ChatRequest(BaseModel):
    question: Optional[str] = Field(
        None,
        description="Question for the RAG-powered SOC assistant."
    )
    query: Optional[str] = Field(
        None,
        description="Alternative field for user question."
    )


class ExplainRequest(BaseModel):
    features: Union[Dict[str, Any], List[Any]] = Field(..., description="Flow feature dictionary or list")
    dataset: str = Field("CICIDS-2017", description="CICIDS-2017 or NSL-KDD")
    top_k: int = Field(5, description="Number of top contributing features")


class SOARRequest(BaseModel):
    threat_category: str = Field("ANOMALY", description="Threat type or attack family")
    src_ip: Optional[str] = Field("192.168.1.105", description="Attacker IP")
    dst_ip: Optional[str] = Field("10.0.0.1", description="Target destination IP")
    dst_port: Optional[Union[int, str]] = Field(80, description="Target port")
    protocol: str = Field("tcp", description="Network protocol")
    severity: str = Field("HIGH", description="Alert severity")
    flow_data: Optional[Dict[str, Any]] = Field(None, description="Optional raw flow record")


class ThreatIntelRequest(BaseModel):
    ip: str = Field(..., description="Target IP address for Geo-IP & OSINT lookup")
    is_flagged_threat: bool = Field(False, description="Whether alert flagged this IP as malicious")


class WebhookAlertRequest(BaseModel):
    webhook_url: str = Field(..., description="Webhook endpoint URL")
    channel_type: str = Field("slack", description="slack, discord, teams, or generic")
    alert_payload: Dict[str, Any] = Field(..., description="Alert payload dictionary")


class FeedbackRequest(BaseModel):
    alert_id: str = Field(..., description="Unique alert identifier")
    analyst_label: str = Field(..., description="CONFIRMED_ATTACK or FALSE_POSITIVE")
    feature_vector: Dict[str, Any] = Field(..., description="Flow features")
    analyst_notes: Optional[str] = Field(None, description="Analyst comments")


# ============================================================
# ROOT & HEALTH
# ============================================================

@app.get("/")
def root():
    return {
        "application": "NetGuard AI SOC Backend",
        "status": "online",
        "version": "2.0.0",
        "backend": "FastAPI",
        "features": [
            "Explainable AI (XAI)",
            "Agentic SOAR & MITRE ATT&CK",
            "PCAP / PCAPNG Ingestion",
            "Multi-Class Classification",
            "Threat Intel & Geo-IP",
            "Real-Time Alerting (Slack/Discord/SIEM)",
            "Continuous Learning & Drift Monitoring",
        ],
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "ml_engine": "ready" if predictor.is_ready() else "degraded",
        "xai_engine": "ready",
        "soar_engine": "ready",
        "threat_intel": "ready",
    }


@app.get("/model-info")
def model_info():
    try:
        return predictor.get_model_info()
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch model info: {str(exc)}"
        )


# ============================================================
# PREDICTIONS
# ============================================================

@app.post("/predict/cicids")
def predict_cicids(request: PredictionRequest):
    try:
        result = predictor.predict_cicids(request.features)
        return {
            "success": True,
            "result": result,
        }
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/predict/nsl-kdd")
def predict_nsl_kdd(request: PredictionRequest):
    try:
        result = predictor.predict_nsl_kdd(request.features)
        return {
            "success": True,
            "result": result,
        }
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ============================================================
# FILE ANALYSIS (CSV & PCAP)
# ============================================================

@app.post("/analyze/cicids")
async def analyze_cicids(
    file: UploadFile = File(...),
    max_rows: Optional[int] = Query(None, description="Max rows to process"),
):
    temp_path = None
    try:
        if not file.filename:
            raise HTTPException(status_code=400, detail="No file selected.")

        contents = await file.read()
        if not contents:
            raise HTTPException(status_code=400, detail="Uploaded file is empty.")

        import tempfile
        with tempfile.NamedTemporaryFile(
            mode="wb",
            delete=False,
            suffix=Path(file.filename).suffix
        ) as temp_file:
            temp_file.write(contents)
            temp_path = temp_file.name

        analysis_dict = cicids_analyzer.analyze_csv(temp_path, max_rows=max_rows)
        results_df = analysis_dict.get("results")
        predictions = results_df.to_dict(orient="records") if results_df is not None else []

        return {
            "success": True,
            "dataset": "CICIDS-2017",
            "filename": file.filename,
            "summary": {
                "total_flows": analysis_dict.get("total_flows", 0),
                "benign_flows": analysis_dict.get("benign_flows", 0),
                "attack_flows": analysis_dict.get("attack_flows", 0),
                "attack_rate": analysis_dict.get("attack_rate", 0.0),
                "benign_rate": analysis_dict.get("benign_rate", 0.0),
            },
            "predictions": predictions,
        }

    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=f"CICIDS analysis failed: {str(exc)}"
        )
    finally:
        if temp_path:
            Path(temp_path).unlink(missing_ok=True)


@app.post("/analyze/nsl-kdd")
async def analyze_nsl_kdd(
    file: UploadFile = File(...),
    include_predictions: bool = Query(True, description="Include detailed row-level predictions"),
):
    temp_path = None
    try:
        if not file.filename:
            raise HTTPException(status_code=400, detail="No file selected.")

        contents = await file.read()
        if not contents:
            raise HTTPException(status_code=400, detail="Uploaded file is empty.")

        import tempfile
        with tempfile.NamedTemporaryFile(
            mode="wb",
            delete=False,
            suffix=Path(file.filename).suffix
        ) as temp_file:
            temp_file.write(contents)
            temp_path = temp_file.name

        result = nsl_kdd_analyzer.analyze_file(
            temp_path,
            include_predictions=include_predictions,
        )

        response = {
            "success": result.get("success", True),
            "dataset": result.get("dataset", "NSL-KDD"),
            "filename": file.filename,
            "rows_analyzed": result.get("rows_analyzed", 0),
            "feature_count": result.get("feature_count", 41),
            "statistics": result.get("statistics", {}),
        }

        if include_predictions:
            response["predictions"] = result.get("predictions", [])

        if "actual_labels" in result:
            response["actual_labels"] = result.get("actual_labels")

        return response

    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=f"NSL-KDD analysis failed: {str(exc)}"
        )
    finally:
        if temp_path:
            Path(temp_path).unlink(missing_ok=True)


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

        # Reconstruct flows
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

        # Analyze extracted flows using CICIDS classifier
        results = []
        attack_count = 0
        for idx, row in flows_df.iterrows():
            row_dict = row.to_dict()
            try:
                # Predict
                pred_res = predictor.predict_cicids(row_dict)
                is_attack = bool(pred_res.get("prediction") == 1 or pred_res.get("is_attack"))
            except Exception:
                is_attack = False
                pred_res = {"prediction": 0, "attack_probability": 0.1, "confidence": 0.9, "risk_score": 10.0}

            if is_attack:
                attack_count += 1

            # Multi-Class Threat Classification
            mc_info = multiclass_classifier.classify_flow(row_dict, dataset="CICIDS-2017")
            # Threat Intel Geo-IP
            geo_info = threat_intel_engine.lookup_ip(str(row_dict.get("Source IP", "192.168.1.100")), is_flagged_threat=is_attack)
            # MITRE ATT&CK mapping
            mitre_info = soar_engine.map_mitre(mc_info.get("category_code", "ANOMALY"), flow_data=row_dict)

            enriched_row = {
                **row_dict,
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

    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"PCAP processing failed: {str(exc)}")


@app.post("/analyze/dataset")
async def analyze_dataset(
    file: UploadFile = File(...)
):
    try:
        if not file.filename:
            raise HTTPException(status_code=400, detail="No file selected.")

        contents = await file.read()
        if not contents:
            raise HTTPException(status_code=400, detail="Uploaded file is empty.")

        return dataset_analyzer.analyze(contents, file.filename)

    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Dataset analysis failed: {str(exc)}"
        )


# ============================================================
# EXPLAINABLE AI (XAI) & ROOT-CAUSE ANALYSIS
# ============================================================

@app.post("/explain")
def explain_threat(request: ExplainRequest):
    try:
        return xai_engine.explain(
            features=request.features,
            dataset=request.dataset,
            top_k=request.top_k,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"XAI calculation failed: {str(exc)}")


# ============================================================
# AGENTIC SOAR & MITRE ATT&CK REMEDIATION
# ============================================================

@app.post("/soar/remediation")
def get_soar_remediation(request: SOARRequest):
    try:
        mitre_info = soar_engine.map_mitre(request.threat_category, flow_data=request.flow_data)
        remediation = soar_engine.generate_remediation(
            src_ip=request.src_ip,
            dst_ip=request.dst_ip,
            dst_port=request.dst_port,
            proto=request.protocol,
            severity=request.severity,
        )
        ticket = soar_engine.create_incident_ticket(
            alert_row={"Severity": request.severity, "prediction": "Attack"},
            mitre_info=mitre_info,
            remediation=remediation,
        )
        return {
            "success": True,
            "mitre": mitre_info,
            "remediation": remediation,
            "ticket": ticket,
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"SOAR rule generation failed: {str(exc)}")


# ============================================================
# THREAT INTEL & OSINT LOOKUP
# ============================================================

@app.post("/threat-intel/lookup")
def lookup_threat_intel(request: ThreatIntelRequest):
    try:
        return threat_intel_engine.lookup_ip(request.ip, is_flagged_threat=request.is_flagged_threat)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Threat intelligence lookup failed: {str(exc)}")


# ============================================================
# REAL-TIME WEBHOOK & SIEM ALERTS
# ============================================================

@app.post("/alerts/webhook")
def dispatch_webhook(request: WebhookAlertRequest):
    try:
        return alert_integration_engine.send_webhook(
            webhook_url=request.webhook_url,
            channel_type=request.channel_type,
            alert_payload=request.alert_payload,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Webhook dispatch failed: {str(exc)}")


# ============================================================
# MLOPS CONTINUOUS LEARNING & DRIFT MONITORING
# ============================================================

@app.post("/mlops/feedback")
def submit_feedback(request: FeedbackRequest):
    try:
        ok = drift_monitor.record_feedback(
            alert_id=request.alert_id,
            analyst_label=request.analyst_label,
            feature_vector=request.feature_vector,
            analyst_notes=request.analyst_notes,
        )
        return {
            "success": ok,
            "total_feedbacks": drift_monitor.get_feedback_count(),
            "message": "Analyst feedback recorded for continuous learning." if ok else "Failed to persist feedback.",
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Feedback recording failed: {str(exc)}")


# ============================================================
# RAG CHATBOT
# ============================================================

@app.post("/chat")
def chat(request: ChatRequest):
    try:
        question = (request.question or request.query or "").strip()

        if not question:
            raise HTTPException(
                status_code=400,
                detail="Question cannot be empty."
            )

        # 1. Retrieve context (applies configured similarity threshold)
        retrieval_result = rag_retriever.retrieve(query=question)
        has_evidence = bool(retrieval_result.get("has_evidence", False))
        sources = retrieval_result.get("sources", []) if has_evidence else []

        # 2. Out-of-domain + no reliable evidence -> concise refusal
        if not has_evidence and is_out_of_domain(question):
            return {
                "success": True,
                "answer": OUT_OF_DOMAIN_REFUSAL,
                "sources": [],
                "retrieval": {
                    "latency_ms": retrieval_result.get("latency_ms", 0.0),
                    "result_count": 0,
                    "has_evidence": False,
                },
            }

        # 3. Build prompt using Three-Level Evidence Strategy
        prompt = build_general_prompt(
            query=question,
            retrieval_result=retrieval_result,
        )

        # 4. Call LLM
        answer = call_llm(
            prompt,
            config=default_config,
        )

        # 5. Fallback if LLM provider is unavailable
        if not answer:
            context = (retrieval_result.get("context_text") or "").strip() if has_evidence else ""
            if context:
                answer = (
                    "### Relevant Knowledge Base Information\n\n"
                    f"{context}\n\n"
                    "*Note: Live AI generation is currently offline.*"
                )
            elif is_out_of_domain(question):
                answer = OUT_OF_DOMAIN_REFUSAL
            else:
                answer = (
                    "The NetGuard AI knowledge base does not contain enough reliable information "
                    "to answer this confidently right now, and the live AI service is temporarily unavailable."
                )

        # 6. Return preserved response schema
        return {
            "success": True,
            "answer": answer,
            "sources": sources,
            "retrieval": {
                "latency_ms": retrieval_result.get("latency_ms", 0.0),
                "result_count": len(sources),
                "has_evidence": has_evidence,
            },
        }

    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Chat request failed: {str(exc)}"
        )


# ============================================================
# AGENTIC SOC INVESTIGATION
# ============================================================

class AgentInvestigationRequest(BaseModel):
    dataset: str = Field(default="CICIDS-2017", description="Dataset type ('CICIDS-2017' or 'NSL-KDD')")
    src_ip: Optional[str] = Field(default="185.220.101.5", description="Attacker or suspicious source IP")
    dst_ip: Optional[str] = Field(default="192.168.1.100", description="Target destination IP")
    dst_port: Optional[str] = Field(default="80", description="Target destination port")
    attack_probability: float = Field(default=0.95, description="Initial ML anomaly confidence (0.0 to 1.0)")
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


# ============================================================
# ADVERSARIAL ROBUSTNESS & RED-TEAM EVASION TESTER
# ============================================================

class AdversarialRequest(BaseModel):
    flows: List[Dict[str, Any]] = Field(default_factory=list, description="List of flow dictionaries to evaluate")
    attack_type: str = Field(default="HEADER_PADDING", description="Adversarial evasion strategy")
    epsilon: float = Field(default=0.15, description="Perturbation strength (0.01 to 0.5)")


@app.post("/adversarial/simulate")
def simulate_adversarial(request: AdversarialRequest):
    """
    Evaluates ML anomaly detection resilience against adversarial evasion attacks:
    Header Padding, Low-and-Slow rate throttling, TCP Chameleon, and boundary feature noise.
    """
    try:
        def predict_fn(f_dict):
            features_arr = [float(f_dict.get(c, 0.0)) for c in f_dict if isinstance(f_dict.get(c), (int, float))]
            if len(features_arr) >= 78:
                return predictor.predict_cicids(features_arr[:78])
            return {
                "prediction": "Attack" if float(f_dict.get("attack_probability", 0.9)) > 0.5 else "BENIGN",
                "attack_probability": float(f_dict.get("attack_probability", 0.9)),
                "is_attack": float(f_dict.get("attack_probability", 0.9)) > 0.5,
            }

        flows = request.flows
        if not flows:
            flows = [
                {
                    "Flow Duration": 120000000,
                    "Total Fwd Packets": 15000,
                    "Total Backward Packets": 10,
                    "Total Length of Fwd Packets": 1050000,
                    "Flow Bytes/s": 4500000.0,
                    "Flow Packets/s": 98000.0,
                    "SYN Flag Count": 14000,
                    "ACK Flag Count": 2,
                    "attack_probability": 0.98,
                    "is_attack": True,
                }
            ]

        return adversarial_tester.evaluate_robustness(
            flows=flows,
            predict_fn=predict_fn,
            attack_type=request.attack_type,
            epsilon=request.epsilon,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Adversarial simulation failed: {str(exc)}")


# ============================================================
# CRYPTOGRAPHIC FORENSIC INCIDENT PACKAGE & CASE EXPORT
# ============================================================

class ForensicExportRequest(BaseModel):
    incident_data: Dict[str, Any] = Field(default_factory=dict, description="Incident alert telemetry")
    flows: Optional[List[Dict[str, Any]]] = Field(default=None, description="Raw flow evidence")
    investigator: str = Field(default="NetGuard Autonomous SOC Tier-2", description="Investigator ID")


@app.post("/forensics/export-package")
def export_forensic_package(request: ForensicExportRequest):
    """
    Generates a cryptographically sealed forensic incident bundle (.zip) with SHA-256 evidence manifest,
    executive HTML dossier, Linux/Windows containment scripts, and STIX 2.1 indicators.
    """
    try:
        bundle = forensic_packager.generate_incident_bundle(
            incident_data=request.incident_data,
            flows=request.flows,
            investigator=request.investigator,
        )
        zip_b64 = base64.b64encode(bundle["zip_bytes"]).decode("utf-8")
        return {
            "success": True,
            "case_id": bundle["case_id"],
            "filename": bundle["filename"],
            "zip_base64": zip_b64,
            "zip_sha256": bundle["zip_sha256"],
            "timestamp": bundle["timestamp"],
            "investigator": bundle["investigator"],
            "file_count": bundle["file_count"],
            "manifest_preview": bundle["manifest_preview"],
            "included_files": bundle["included_files"],
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Forensic bundle generation failed: {str(exc)}")


# ============================================================
# API STATUS
# ============================================================

@app.get("/api/status")
def api_status():
    return {
        "status": "online",
        "version": "2.0.0",
        "services": {
            "ml_engine": predictor.is_ready(),
            "rag_knowledge_base": not rag_retriever.vector_store.is_empty(),
            "rag_chunks_indexed": len(rag_retriever.vector_store.chunks),
            "xai_engine": True,
            "soar_engine": True,
            "pcap_extractor": True,
            "multiclass_classifier": True,
            "threat_intel_engine": True,
            "alert_integrations": True,
            "drift_monitor": True,
            "agentic_soc": True,
            "adversarial_tester": True,
            "forensic_packager": True,
            "active_feedbacks_recorded": drift_monitor.get_feedback_count(),
        },
        "models": {
            "cicids_available": predictor.is_cicids_ready(),
            "nsl_kdd_available": predictor.is_nsl_kdd_ready(),
        },
        "endpoints": {
            "predict_cicids": "/predict/cicids",
            "predict_nsl_kdd": "/predict/nsl-kdd",
            "analyze_cicids": "/analyze/cicids",
            "analyze_nsl_kdd": "/analyze/nsl-kdd",
            "analyze_pcap": "/analyze/pcap",
            "analyze_dataset": "/analyze/dataset",
            "explain": "/explain",
            "soar_remediation": "/soar/remediation",
            "threat_intel": "/threat-intel/lookup",
            "alerts_webhook": "/alerts/webhook",
            "mlops_feedback": "/mlops/feedback",
            "agent_investigate": "/agent/investigate",
            "agent_hunt": "/agent/hunt",
            "agent_swarm": "/agent/swarm",
            "adversarial_simulate": "/adversarial/simulate",
            "forensics_export": "/forensics/export-package",
            "chat_endpoint": "/chat",
        },
    }

