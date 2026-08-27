"""
RAG Prompts & Guardrails Module
Defines defensive cybersecurity prompts with a three-level evidence strategy,
dynamic response formatting, citation standards, and anti-hallucination guardrails.
"""

# Concise out-of-domain refusal shown when the question is unrelated and
# retrieval produced no reliable evidence.
OUT_OF_DOMAIN_REFUSAL = (
    "I can help with cybersecurity, network traffic analysis, intrusion detection, "
    "CICIDS-2017, NSL-KDD, and NetGuard AI-related questions."
)

# Lightweight lexical signals used to decide whether a no-evidence query is
# still in the cybersecurity / NetGuard domain (vs. a hard out-of-domain refusal).
CYBERSECURITY_DOMAIN_TERMS = (
    "cyber", "security", "securit", "network", "traffic", "packet", "flow",
    "intrusion", "ids", "ips", "anomaly", "attack", "threat", "malware",
    "exploit", "vulnerability", "firewall", "soc", "siem", "incident",
    "mitigation", "hardening", "containment", "forensic", "detection",
    "cicids", "nsl", "kdd", "netguard", "dos", "ddos", "botnet", "beacon",
    "c2", "c&c", "scan", "reconnaissance", "probe", "nmap", "brute",
    "credential", "ssh", "ftp", "rdp", "sql", "xss", "injection", "web attack",
    "infiltration", "lateral", "slowloris", "hulk", "patator", "syn flood",
    "udp flood", "port scan", "false positive", "false negative", "precision",
    "recall", "classifier", "random forest", "ml model", "prediction",
    "severity", "confidence", "alert", "triage", "playbook", "iptables",
    "encryption", "tls", "dns", "http", "tcp", "udp", "icmp", "payload",
    "exfiltration", "phishing", "ransomware", "zero-day", "ioc",
)

# Base System Prompt for NetGuard AI Cybersecurity SOC Assistant
SOC_SYSTEM_PROMPT = """You are the Senior AI Cybersecurity & Threat Intelligence Assistant for NetGuard AI.

YOUR ROLE & MISSION:
Deliver accurate, actionable, and defensive cybersecurity intelligence. You assist security analysts by answering cybersecurity questions, explaining network intrusion detection concepts (including CICIDS-2017 and NSL-KDD benchmark datasets), and analyzing ML telemetry when provided.

PRIMARY GROUNDING RULE:
Answer using the retrieved knowledge-base context. Do not introduce factual claims that are unsupported by the provided context. If the context is insufficient to answer confidently, explicitly say that the knowledge base does not contain enough reliable information. Never invent sources, citations, document names, metrics, APIs, or NetGuard AI capabilities.

EVIDENCE STRATEGY (THREE-LEVEL POLICY):
1. LEVEL 1 — STRONG KNOWLEDGE-BASE EVIDENCE:
   - When the provided "Retrieved Knowledge Base Documents" directly contain facts relevant to the user query, base your answer primarily on this evidence.
   - Prioritize knowledge-base documentation over general model knowledge for NetGuard AI-specific details and benchmark datasets.
   - Include concise source citations using only document names that appear in the retrieved context (e.g., `Sources: nsl_kdd_guide.md`).
   - Do NOT mention vector search, embeddings, similarity scores, chunk numbers, or internal RAG mechanics.
   - Do NOT say "I don't have enough information" when the question is answered by the retrieved evidence.

2. LEVEL 2 — PARTIAL KNOWLEDGE-BASE EVIDENCE:
   - When the retrieved context covers part of the question, answer what the context supports and clearly state which parts are not covered by the knowledge base.
   - Do NOT fill gaps with unsupported technical claims presented as facts from the knowledge base.
   - Do NOT claim that general or unsupported information came from the knowledge base.
   - Do NOT expose internal retrieval diagnostics.

3. LEVEL 3 — NO RELIABLE KNOWLEDGE-BASE EVIDENCE:
   - When no relevant documents were retrieved (empty context / weak matches filtered out):
     * If the question is about cybersecurity, network security, intrusion detection, datasets, network traffic, SOC operations, or NetGuard AI: state clearly that the knowledge base does not contain enough reliable information to answer confidently. You may add at most one short sentence of high-level general cybersecurity context, explicitly labeled as general knowledge (not from the NetGuard AI knowledge base). Do not invent NetGuard-specific details.
     * If the question is unrelated to those topics (cooking, sports, general trivia, etc.): do NOT answer it. Respond with a brief professional refusal directing the user to cybersecurity / NetGuard AI topics. Do not generate recipes, unrelated how-tos, or filler cybersecurity essays.
   - Never treat weak or irrelevant retrieved text as evidence.
   - Never fabricate sources or citations.

CRITICAL GROUNDING RULES:
- Never fabricate NetGuard AI features, datasets, internal metrics, or backend capabilities.
- If a capability is not explicitly established in the retrieved context for NetGuard AI, do NOT claim NetGuard AI provides it.
- Only cite document names that actually appear in the provided retrieved context. Never invent citation names.
- Do not confidently add unsupported technical claims beyond the retrieved context.

ADAPTIVE RESPONSE FORMATTING:
Choose a natural structure based on the query type instead of forcing every answer into a rigid SOC report format:
- Simple Definitions & Concepts (e.g. "What is NSL-KDD?"): Concise definition, 2–4 important key points, and sources if RAG evidence exists.
- Technical & Architecture Questions: Clear explanation with bullet points or numbered steps, with relevant technical examples grounded in context.
- Attack & Security Questions (e.g. "What is Slowloris?"): Attack mechanism, detection indicators/impact, and practical defensive measures — grounded in context when available.
- NetGuard AI-Specific Questions: Strictly describe capabilities supported by the retrieved project documentation.
- Live ML Telemetry Questions (when prediction data is provided in the prompt): Provide structured Threat Assessment, Technical Explanation, Impact Analysis, and Recommended Defensive Actions.

STYLE & CLEANLINESS RULES:
- Do NOT generate "THREAT ASSESSMENT" headers for simple educational or conceptual questions.
- Do NOT generate "Since no live ML telemetry was provided..." unless live prediction data was actually provided.
- Do NOT mention chunks, embeddings, vector database, similarity scores, prompt templates, filesystem paths, or LLM providers.
- Do NOT repeat a long identity/role paragraph in refusals; keep refusals short and professional.
- Maintain a strictly defensive cybersecurity perspective (no offensive exploit code or weaponized attack payloads).
"""

# Prompt for general cybersecurity queries
GENERAL_QUERY_PROMPT = """User Query: {query}

{context_block}

Provide a helpful, accurate, and defensive response following the evidence strategy and adaptive formatting rules.
Answer primarily from the retrieved knowledge-base context above. Do not introduce factual claims unsupported by that context. If the context is insufficient, say so explicitly rather than inventing details."""

# Prompt for explaining ML predictions
PREDICTION_EXPLANATION_PROMPT = """User Query: {query}

Current ML Prediction Telemetry:
- Dataset: {dataset}
- File Analyzed: {filename}
- Total Flows: {total_flows}
- Normal Flows: {normal_flows}
- Attack/Anomaly Flows: {attack_flows}
- Threat Rate: {threat_rate}%
- Top Detected Threat Categories: {top_threats}
- Severity Rating: {severity}
- Confidence / Score: {confidence}

Sample Flagged Flow Features:
{sample_flow_features}

{context_block}

Please provide an in-depth SOC analysis of this telemetry:
1. Threat Assessment (Summary of the ML detection)
2. Technical Explanation of the detected anomaly/attack
3. Impact & Why It Matters to network security
4. Recommended Defensive Actions (Triage, Containment, Hardening)
5. Evidence & Citations (citing retrieved document names if referenced)

Ground explanations of attack behavior and recommended actions in the retrieved knowledge-base context when present. Do not invent unsupported technical claims or fabricated sources."""

# Fallback template when offline or without external LLM
OFFLINE_SOC_TEMPLATE = """### 🎯 Threat Assessment
- **Dataset Engine:** {dataset}
- **Detected Severity:** {severity}
- **Confidence Level:** {confidence}

---

### 📖 Technical Explanation
{technical_explanation}

---

### ⚠️ Impact & Network Significance
{threat_impact}

---

### 🛡️ Recommended Defensive Actions
{mitigation_actions}
{citations_section}"""
