from pathlib import Path
import sys
from typing import List, Union, Optional

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

# ============================================================
# FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title="NetGuard AI SOC Backend",
    description="FastAPI backend for Network Anomaly Detection and SOC RAG AI Assistant",
    version="1.0.0",
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


# ============================================================
# ROOT & HEALTH
# ============================================================

@app.get("/")
def root():
    return {
        "application": "NetGuard AI SOC Backend",
        "status": "online",
        "version": "1.0.0",
        "backend": "FastAPI",
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "ml_engine": "ready" if predictor.is_ready() else "degraded",
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
# FILE ANALYSIS
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

        # 2. Out-of-domain + no reliable evidence → concise refusal (no weak chunks to LLM)
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
# API STATUS
# ============================================================

@app.get("/api/status")
def api_status():
    return {
        "status": "online",
        "services": {
            "ml_engine": predictor.is_ready(),
            "rag_knowledge_base": not rag_retriever.vector_store.is_empty(),
            "rag_chunks_indexed": len(rag_retriever.vector_store.chunks),
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
            "analyze_dataset": "/analyze/dataset",
            "chat_endpoint": "/chat",
        },
    }
