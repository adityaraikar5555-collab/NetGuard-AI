"""
NetGuard AI — RAG Response Generator

Responsible for:
    1. Building LLM prompts from retrieved RAG context using the Three-Level Evidence Strategy.
    2. Building prediction-aware prompts from ML telemetry when present.
    3. Calling configured LLM providers with multi-model fallback and fast execution.
    4. Supporting Gemini, OpenAI, Ollama, and clean offline fallback.

The public API and response contracts are strictly maintained for compatibility.
"""

from typing import Dict, Any, Optional, List
import time
import threading
import requests

from .prompts import (
    SOC_SYSTEM_PROMPT,
    GENERAL_QUERY_PROMPT,
    PREDICTION_EXPLANATION_PROMPT,
    OFFLINE_SOC_TEMPLATE,
    CYBERSECURITY_DOMAIN_TERMS,
)


# ============================================================
# DOMAIN HELPERS
# ============================================================

def is_cybersecurity_domain(query: str) -> bool:
    """
    Lightweight check: True when the query appears related to cybersecurity,
    network security, IDS datasets, network traffic, SOC work, or NetGuard AI.
    """
    if not query or not str(query).strip():
        return False
    q = str(query).lower()
    return any(term in q for term in CYBERSECURITY_DOMAIN_TERMS)


def is_out_of_domain(query: str) -> bool:
    """True when the query is clearly outside the NetGuard AI assistant scope."""
    return not is_cybersecurity_domain(query)


# ============================================================
# PROMPT BUILDERS
# ============================================================

def build_general_prompt(
    query: str,
    retrieval_result: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Build the full prompt for a cybersecurity question following the Three-Level Evidence Strategy.

    retrieval_result:
        Output returned by RAGRetriever.retrieve(query)
    """
    retrieval_result = retrieval_result or {}
    has_evidence = bool(retrieval_result.get("has_evidence", False))
    context_text = (retrieval_result.get("context_text") or "").strip()
    sources = retrieval_result.get("sources", [])

    if has_evidence and context_text:
        source_names = ", ".join(list(dict.fromkeys(
            s.get("document_name", "") for s in sources if s.get("document_name")
        ))) or "Retrieved documentation"

        context_block = (
            f"Retrieved Knowledge Base Documents ({source_names}):\n"
            f"{context_text}\n\n"
            "Guidance: Answer primarily from this retrieved context. "
            "Apply LEVEL 1 when it directly addresses the question (grounded answer + cite only these sources). "
            "Apply LEVEL 2 when coverage is partial — state what the context supports and what it does not. "
            "Do not invent unsupported technical claims or cite documents that are not listed above."
        )
    else:
        context_block = (
            "Retrieved Knowledge Base Documents:\n"
            "None matching the query with sufficient similarity.\n\n"
            "Guidance: Apply LEVEL 3. There is no reliable knowledge-base evidence. "
            "Do not invent facts, sources, or NetGuard AI capabilities. "
            "If this is a cybersecurity / NetGuard AI question, explicitly say the knowledge base "
            "does not contain enough reliable information to answer confidently. "
            "If this question is unrelated to cybersecurity, network security, intrusion detection, "
            "datasets, network traffic, SOC operations, or NetGuard AI, refuse briefly and professionally "
            "without answering the off-topic request."
        )

    return (
        SOC_SYSTEM_PROMPT
        + "\n\n"
        + GENERAL_QUERY_PROMPT.format(
            query=query,
            context_block=context_block,
        )
    )


def build_prediction_prompt(
    query: str,
    retrieval_result: Optional[Dict[str, Any]] = None,
    prediction: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Build the full prompt for explaining an ML prediction telemetry event.

    prediction:
        Dictionary containing ML classifier telemetry.
    """
    retrieval_result = retrieval_result or {}
    prediction = prediction or {}
    has_evidence = bool(retrieval_result.get("has_evidence", False))
    context_text = (retrieval_result.get("context_text") or "").strip()
    sources = retrieval_result.get("sources", [])

    if has_evidence and context_text:
        source_names = ", ".join(list(dict.fromkeys(
            s.get("document_name", "") for s in sources if s.get("document_name")
        ))) or "Retrieved documentation"
        context_block = (
            f"Retrieved Knowledge Base Documents ({source_names}):\n"
            f"{context_text}"
        )
    else:
        context_block = "Retrieved Knowledge Base Documents:\nNone matching this specific telemetry signature."

    return (
        SOC_SYSTEM_PROMPT
        + "\n\n"
        + PREDICTION_EXPLANATION_PROMPT.format(
            query=query,
            dataset=prediction.get("dataset", "N/A"),
            filename=prediction.get("filename", "N/A"),
            total_flows=prediction.get("total_flows", "N/A"),
            normal_flows=prediction.get("normal_flows", "N/A"),
            attack_flows=prediction.get("attack_flows", "N/A"),
            threat_rate=prediction.get("threat_rate", "N/A"),
            top_threats=prediction.get("top_threats", "N/A"),
            severity=prediction.get("severity", "N/A"),
            confidence=prediction.get("confidence", "N/A"),
            sample_flow_features=prediction.get(
                "sample_flow_features",
                "N/A",
            ),
            context_block=context_block,
        )
    )


def build_offline_fallback(
    prediction: Optional[Dict[str, Any]] = None,
    retrieval_result: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Build a clean, deterministic SOC response when an external LLM is offline or unconfigured.
    """
    prediction = prediction or {}
    retrieval_result = retrieval_result or {}

    context = (retrieval_result.get("context_text") or "").strip()
    citations = ""
    if context:
        citations = f"\n\n---\n\n### 📚 Grounded Knowledge Evidence\n{context}"

    if prediction:
        return OFFLINE_SOC_TEMPLATE.format(
            dataset=prediction.get("dataset", "N/A"),
            severity=prediction.get("severity", "N/A"),
            confidence=prediction.get("confidence", "N/A"),
            technical_explanation=prediction.get(
                "technical_explanation",
                "Anomaly detection telemetry processed from network flow capture.",
            ),
            threat_impact=prediction.get(
                "threat_impact",
                "Flow anomalies may indicate malicious traffic or protocol abuse.",
            ),
            mitigation_actions=prediction.get(
                "mitigation_actions",
                "Inspect high-scoring anomalous flows, apply firewall filtering, and monitor affected network hosts.",
            ),
            citations_section=citations,
        )

    if context:
        return (
            "### Relevant Knowledge Base Information\n\n"
            f"{context}\n\n"
            "*Note: This summary is generated from available local documentation while the LLM service is offline.*"
        )

    return (
        "The NetGuard AI assistant is currently operating in offline mode. "
        "To enable full conversational answers, ensure an LLM provider (such as Gemini or OpenAI) is configured."
    )


# ============================================================
# GEMINI
# ============================================================

def _call_gemini(prompt: str, cfg, timeout: float = 15.0) -> Optional[str]:
    """
    Call Google Gemini using the REST API with ultra-fast models and automatic fallback.

    A hard wall-clock deadline (enforced via a worker thread) caps the entire
    attempt so a slow, hanging, or throttled network can never block the chat
    endpoint for minutes. If the provider does not answer within `timeout`
    seconds the call gives up and returns None, so the caller falls through to
    the fast offline / knowledge-base fallback.

    Returns:
        Generated text on success.
        None on failure.
    """

    api_key = getattr(cfg, "GEMINI_API_KEY", "")

    if not api_key:
        print("[GEMINI] API key not configured.")
        return None

    primary_model = getattr(
        cfg,
        "GEMINI_MODEL",
        "gemini-3.6-flash",
    )

    models_to_try = [primary_model]
    for alt in ("gemini-3.6-flash", "gemini-flash-latest"):
        if alt not in models_to_try:
            models_to_try.append(alt)

    max_tokens = getattr(cfg, "MAX_TOKENS", 700)
    temperature = getattr(cfg, "TEMPERATURE", 0.2)

    params = {"key": api_key}
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": temperature,
            "maxOutputTokens": max_tokens,
        },
    }

    result_box = {}

    def _worker():
        for model in models_to_try:
            url = (
                "https://generativelanguage.googleapis.com/"
                f"v1beta/models/{model}:generateContent"
            )
            try:
                response = requests.post(
                    url,
                    params=params,
                    json=payload,
                    timeout=timeout,
                )

                if response.status_code == 200:
                    data = response.json()
                    candidates = data.get("candidates", [])
                    text = ""
                    if candidates:
                        content = candidates[0].get("content", {})
                        parts = content.get("parts", [])
                        if parts:
                            text = parts[0].get("text", "")

                    if text:
                        print(f"[LLM] Gemini response generated using model={model}")
                        result_box["answer"] = text.strip()
                        return
                    print(f"[GEMINI] No text returned from model={model}")
                elif response.status_code in (429, 503):
                    # Provider overloaded / rate-limited and usually recovers
                    # within a second. Do a single quick retry, then fall
                    # through to the fast fallback provider so the end-to-end
                    # response time stays within the 3-5s target.
                    print(f"[GEMINI RETRY] model={model} status={response.status_code}")
                    for _ in range(1):
                        time.sleep(0.5)
                        try:
                            retry = requests.post(
                                url,
                                params=params,
                                json=payload,
                                timeout=timeout,
                            )
                            if retry.status_code == 200:
                                data = retry.json()
                                candidates = data.get("candidates", [])
                                text = ""
                                if candidates:
                                    content = candidates[0].get("content", {})
                                    parts = content.get("parts", [])
                                    if parts:
                                        text = parts[0].get("text", "")
                                if text:
                                    print(f"[LLM] Gemini response generated using model={model}")
                                    result_box["answer"] = text.strip()
                                    return
                            print(f"[GEMINI RETRY] model={model} status={retry.status_code}")
                        except requests.exceptions.RequestException as error:
                            print(f"[GEMINI RETRY ERROR] model={model}: {error}")
                    break
                else:
                    print(f"[GEMINI WARNING] model={model} returned status={response.status_code}")
            except requests.exceptions.Timeout:
                print(f"[GEMINI TIMEOUT] model={model}. Trying next model...")
            except requests.exceptions.RequestException as error:
                print(f"[GEMINI REQUEST ERROR] model={model}: {error}")
            except Exception as error:
                print(f"[GEMINI EXCEPTION] model={model}: {error}")
        result_box["answer"] = None

    worker = threading.Thread(target=_worker, daemon=True)
    worker.start()
    worker.join(timeout)

    if worker.is_alive():
        print(f"[GEMINI] Hard deadline ({timeout:.1f}s) hit; falling through to offline fallback.")
        return None

    return result_box.get("answer")


# ============================================================
# OPENAI
# ============================================================

def _call_openai(prompt: str, cfg) -> Optional[str]:
    """
    Call OpenAI Chat Completions API.
    """

    api_key = getattr(
        cfg,
        "OPENAI_API_KEY",
        "",
    )

    if not api_key:
        print("[OPENAI] API key not configured.")
        return None

    model = getattr(
        cfg,
        "OPENAI_MODEL",
        "gpt-4o-mini",
    )

    url = "https://api.openai.com/v1/chat/completions"

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    payload = {
        "model": model,
        "messages": [
            {
                "role": "user",
                "content": prompt,
            }
        ],
        "temperature": getattr(
            cfg,
            "TEMPERATURE",
            0.2,
        ),
        "max_tokens": getattr(
            cfg,
            "MAX_TOKENS",
            700,
        ),
    }

    try:
        response = requests.post(
            url,
            headers=headers,
            json=payload,
            timeout=20,
        )

        if response.status_code != 200:
            print(f"[OPENAI ERROR] status={response.status_code}")
            return None

        data = response.json()
        choices = data.get("choices", [])

        if not choices:
            print("[OPENAI ERROR] No choices returned.")
            return None

        message = choices[0].get("message", {})
        text = message.get("content", "")

        if not text:
            print("[OPENAI ERROR] Empty response.")
            return None

        print(f"[LLM] OpenAI response generated using model={model}")
        return text.strip()

    except requests.exceptions.Timeout:
        print("[OPENAI TIMEOUT]")
        return None
    except requests.exceptions.RequestException as error:
        print(f"[OPENAI REQUEST ERROR] {error}")
        return None
    except Exception as error:
        print(f"[OPENAI EXCEPTION] {error}")
        return None


# ============================================================
# OLLAMA
# ============================================================

def _call_ollama(prompt: str, cfg) -> Optional[str]:
    """
    Call a locally running Ollama instance.
    """

    base_url = getattr(
        cfg,
        "OLLAMA_BASE_URL",
        "http://localhost:11434",
    )

    model = getattr(
        cfg,
        "OLLAMA_MODEL",
        "llama3",
    )

    url = (
        base_url.rstrip("/")
        + "/api/generate"
    )

    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": getattr(
                cfg,
                "TEMPERATURE",
                0.2,
            ),
            "num_predict": getattr(
                cfg,
                "MAX_TOKENS",
                700,
            ),
        },
    }

    try:
        response = requests.post(
            url,
            json=payload,
            timeout=25,
        )

        if response.status_code != 200:
            print(f"[OLLAMA ERROR] status={response.status_code}")
            return None

        data = response.json()
        text = data.get("response", "")

        if not text:
            print("[OLLAMA ERROR] Empty response.")
            return None

        print(f"[LLM] Ollama response generated using model={model}")
        return text.strip()

    except requests.exceptions.ConnectionError:
        print("[OLLAMA] Ollama server is not running.")
        return None
    except requests.exceptions.Timeout:
        print("[OLLAMA TIMEOUT]")
        return None
    except Exception as error:
        print(f"[OLLAMA EXCEPTION] {error}")
        return None


# ============================================================
# GROQ
# ============================================================

def _call_groq(prompt: str, cfg, timeout: float = 20.0) -> Optional[str]:
    """
    Call Groq (OpenAI-compatible) with the configured model.

    Groq's free tier is fast (sub-second to a few seconds) and generous,
    so it makes a good automatic fallback when configured providers are
    rate-limited or overloaded. Uses the OpenAI chat completions schema.
    """

    api_key = getattr(cfg, "GROQ_API_KEY", "")

    if not api_key:
        print("[GROQ] API key not configured.")
        return None

    model = getattr(cfg, "GROQ_MODEL", "llama-3.3-70b-versatile")

    url = "https://api.groq.com/openai/v1/chat/completions"

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    payload = {
        "model": model,
        "messages": [
            {
                "role": "user",
                "content": prompt,
            }
        ],
        "temperature": getattr(cfg, "TEMPERATURE", 0.2),
        "max_tokens": getattr(cfg, "MAX_TOKENS", 700),
    }

    try:
        response = requests.post(
            url,
            headers=headers,
            json=payload,
            timeout=timeout,
        )

        if response.status_code == 200:
            data = response.json()
            choices = data.get("choices", [])
            if not choices:
                print("[GROQ ERROR] No choices returned.")
                return None
            message = choices[0].get("message", {})
            text = message.get("content", "")
            if not text:
                print("[GROQ ERROR] Empty response.")
                return None
            print(f"[LLM] Groq response generated using model={model}")
            return text.strip()

        print(f"[GROQ WARNING] status={response.status_code}")
        return None

    except requests.exceptions.Timeout:
        print("[GROQ TIMEOUT]")
        return None
    except requests.exceptions.RequestException as error:
        print(f"[GROQ REQUEST ERROR] {error}")
        return None
    except Exception as error:
        print(f"[GROQ EXCEPTION] {error}")
        return None


# ============================================================
# MAIN LLM DISPATCHER
# ============================================================

def call_llm(
    prompt: str,
    config=None,
) -> Optional[str]:
    """
    Send the assembled prompt to the configured LLM provider.

    Supported modes:
        auto
        gemini
        openai
        ollama
        offline_soc
    """

    from .config import default_config

    cfg = config or default_config

    provider = str(
        getattr(
            cfg,
            "LLM_PROVIDER",
            "auto",
        )
    ).strip().lower()

    # ========================================================
    # OFFLINE MODE
    # ========================================================

    if provider == "offline_soc":
        print("[LLM] Offline SOC mode selected.")
        return None

    # ========================================================
    # EXPLICIT GEMINI
    # ========================================================

    if provider == "gemini":
        if not getattr(cfg, "GEMINI_API_KEY", ""):
            print("[LLM ERROR] LLM_PROVIDER=gemini but GEMINI_API_KEY is missing.")
            return None

        return _call_gemini(prompt, cfg, timeout=getattr(cfg, "LLM_TIMEOUT", 3))

    # ========================================================
    # EXPLICIT OPENAI
    # ========================================================

    if provider == "openai":
        if not getattr(cfg, "OPENAI_API_KEY", ""):
            print("[LLM ERROR] LLM_PROVIDER=openai but OPENAI_API_KEY is missing.")
            return None

        return _call_openai(prompt, cfg)

    # ========================================================
    # EXPLICIT OLLAMA
    # ========================================================

    if provider == "ollama":
        return _call_ollama(prompt, cfg)

    # ========================================================
    # EXPLICIT GROQ
    # ========================================================

    if provider == "groq":
        if not getattr(cfg, "GROQ_API_KEY", ""):
            print("[LLM ERROR] LLM_PROVIDER=groq but GROQ_API_KEY is missing.")
            return None

        return _call_groq(prompt, cfg)

    # ========================================================
    # AUTO MODE
    # ========================================================

    if provider == "auto":
        # 1. Gemini
        if getattr(cfg, "GEMINI_API_KEY", ""):
            answer = _call_gemini(prompt, cfg, timeout=getattr(cfg, "LLM_TIMEOUT", 3))
            if answer:
                return answer
            print("[LLM AUTO] Gemini failed. Trying Groq.")

        # 2. Groq
        if getattr(cfg, "GROQ_API_KEY", ""):
            answer = _call_groq(prompt, cfg)
            if answer:
                return answer
            print("[LLM AUTO] Groq failed. Trying OpenAI.")

        # 3. OpenAI
        if getattr(cfg, "OPENAI_API_KEY", ""):
            answer = _call_openai(prompt, cfg)
            if answer:
                return answer
            print("[LLM AUTO] OpenAI failed. Trying Ollama.")

        # 4. Ollama
        answer = _call_ollama(prompt, cfg)
        if answer:
            return answer

        print("[LLM AUTO] No LLM provider successfully generated a response.")
        return None

    # ========================================================
    # UNKNOWN PROVIDER
    # ========================================================

    print(f"[LLM ERROR] Unknown LLM_PROVIDER='{provider}'.")
    return None
