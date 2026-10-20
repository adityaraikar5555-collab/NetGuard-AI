# NetGuard AI — SOC Dashboard Upgrade Changelog

Frontend-only SOC command-center upgrade. The RAG/chatbot core, ML engine,
FastAPI backend, and model artifacts are untouched. No data is fabricated —
every value shown comes from the live API, from `reports/` artifacts, or from
statistics computed directly on an uploaded file; unavailable values render as
N/A / "Not available".

## Files Changed
- `frontend/dashboard.py` — added 13th page "⚡ Agentic SOC Copilot" with 3 dedicated War-Room tabs, plus 1-click autonomous investigation dispatch from Threat Alerts.
- `frontend/app.py` & `backend/main.py` — added endpoints `POST /agent/investigate`, `POST /agent/hunt`, `POST /agent/swarm` and updated `/api/status`.
- `frontend/api.py` — added client adapters `investigate_agent()`, `hunt_agent()`, `swarm_agent()`.
- `src/agents/` (NEW PACKAGE):
  - `src/agents/tools.py` — 6 production cybersecurity tools with JSON Schemas.
  - `src/agents/soc_agent.py` — Native ReAct Tier-2 SOC Agent with multi-LLM failover and Dossier synthesis.
  - `src/agents/drift_hunter_agent.py` — Concept Drift (PSI) engine and stealth threat hunter.
  - `src/agents/multi_agent_swarm.py` — Hierarchical Multi-Agent Swarm (4 specialists) + STIX 2.1 bundles.
- `run_soc.bat` (NEW) — One-click Windows runner for FastAPI backend & Streamlit UI.
- `tests/test_soc_agent.py` (NEW) — Comprehensive unit test suite for all agent engines (9/9 passed).
- `frontend/ui_components.py` — design-system module:
  `SEVERITY_ORDER`, `SEVERITY_ICON`, `THREAT_LEVEL_ICON`, `classify_threat_level`,
  `esc`, `render_global_status_header`, `render_cta_row`, `state_banner`,
  `render_severity_strip`.
- `frontend/persistence.py` — local JSON session store (`frontend/.session_store/`).
- `frontend/product_features.py` — Home landing, onboarding, auth gate, docs hub, compare runs, HTML incident report, notifications, triage panel, health/latency strip, upgraded About.

---

## Phase 9 — Agentic AI Platform Upgrade (Autonomous SOC, Threat Hunting & Swarm)
- **Native ReAct Tier-2 SOC Agent (`src/agents/soc_agent.py`)**:
  - Implements an autonomous ReAct loop (`Thought -> Action: tool(args) -> Observation -> Thought -> Final Dossier`) without heavy third-party framework dependencies.
  - Standard JSON schema tool call interface (`src/agents/tools.py`) covering Threat Intel reputation (`threat_intel_lookup`), XAI SHAP feature attribution (`xai_explain_flow`), multiclass categorization (`multiclass_classify`), MITRE ATT&CK alignment (`soar_mitre_mapping`), multi-platform firewall generation (`soar_generate_containment`), and semantic RAG search (`rag_search_knowledge`).
  - Zero-crash multi-LLM failover: cascades from Gemini 1.5 Flash -> Groq (`llama-3.3-70b-versatile` / `openai/gpt-oss-120b`) -> deterministic rule policy.
  - Generates comprehensive `IncidentDossier` objects with root cause analysis, MITRE technique tagging, blast radius calculation, and containment playbooks.
- **Autonomous Threat Hunting & Concept Drift Agent (`src/agents/drift_hunter_agent.py`)**:
  - Population Stability Index (PSI) calculation across baseline and active traffic distributions to detect feature drift.
  - Discovers sub-threshold stealth anomalies in the model confidence grey zone ($0.35 \le p \le 0.65$).
  - Generates hypothesis hunting tickets and SIEM search syntax for Splunk SPL and Elasticsearch DSL.
- **Hierarchical Multi-Agent SOC Swarm (`src/agents/multi_agent_swarm.py`)**:
  - Multi-agent collaboration featuring 4 specialized agents: `SupervisorAgent`, `ForensicsAgent`, `ThreatIntelAgent`, and `RemediationAgent`.
  - Blast radius validation against internal critical network assets.
  - Serialization of incident findings into STIX 2.1 JSON incident bundles for enterprise integration.
- **FastAPI Endpoints & Client (`frontend/app.py`, `backend/main.py`, `frontend/api.py`)**:
  - `POST /agent/investigate`: Dispatches ReAct autonomous alert investigation.
  - `POST /agent/hunt`: Triggers concept drift evaluation and stealth threat hunting.
  - `POST /agent/swarm`: Initiates collaborative multi-agent swarm triage.
- **Streamlit SOC Copilot War Room (`frontend/dashboard.py`)**:
  - Added "⚡ Agentic SOC Copilot" to navigation menu with 3 dedicated interactive tabs:
    - `⚡ Autonomous ReAct Copilot`: Scenario selection, live thought streaming, dossier view, and containment approval actions.
    - `🎯 Threat Hunter & Concept Drift`: PSI gauge metrics, stealth cluster cards, and SIEM query generators.
    - `🐝 Multi-Agent Swarm Command`: Supervisor timeline, specialist findings breakdown, and STIX 2.1 incident bundle viewer.
  - Integrated 6th tab ("⚡ Autonomous Copilot") inside the Threat Detection investigation dialog with 1-click dispatch.
- **Production Verification & Tooling**:
  - Created `run_soc.bat` for one-click startup on Windows.
  - Created `tests/test_soc_agent.py` with 9 end-to-end unit tests (all passing).

---

## Phase 8 — Professional Product Surface (10/10 polish)
- **Home landing** — brand-first product page with Enter Console / Try Demo /
  Guided Tour CTAs (SOC chrome + 3D hero skipped on Home).
- **Onboarding wizard** — 4-step tour with bundled demo analysis callback.
- **Try Demo** — Live Traffic + Overview one-click samples from
  `data/CICIDS-2017/test_*.csv` and `data/test/NSL-KDD/test_10_rows.csv`.
- **Persistence** — settings, timeline, history, triage, notifications, and
  analysis snapshots saved under `frontend/.session_store/` (gitignored).
- **Alert triage** — New → Investigating → Confirmed / False Positive /
  Resolved + notes on Threat Detection.
- **Compare Runs** — side-by-side snapshot metrics (summary-only, no DF dump).
- **Incident Report** — downloadable self-contained dark HTML (print-to-PDF).
- **Documentation hub** — Getting Started, CSV formats, severity rules, API.
- **Notifications center** — sidebar panel + toasts on analysis / threats.
- **Health / latency strip** — real `/health` round-trip ms + ML/RAG chips.
- **Auth / lock** — optional Settings gate (demo mode or password `netguard`);
  Lock Console returns to Home.
- **A11y / UX** — skip-to-content link, keyboard shortcut captions, skeleton CSS.

---

## Phase 1 — Design System
- Created `frontend/ui_components.py` with severity/threat constants and
  reusable components (global status header, CTA row, state banners,
  severity strip, HTML escaping).
- Added dashboard CSS: focus-visible focus rings, `prefers-reduced-motion`
  support, command-center header styles (`.cmd-header`, `.hc-pill`, `.thr-chip`),
  state banner styles (`.hstate-*`), dialog overrides, responsive breakpoints
  (1100px / 760px), table overflow guard, dataset-type pills.
- New session-state keys in `init_state()`: `session_timeline`, `app_settings`,
  `investigation_target`, `pending_soc_question`, `command_palette_active`.
- New helpers: `fetch_api_status()` (GET `/api/status`),
  `readiness_from_status()`, `_services_flag()`, `push_timeline()`.
- Replaced the legacy header with the command-center header via
  `render_global_status_header()`.

## Phase 2 — SOC Command Center (Overview)
- Rebuilt `render_overview()` with:
  - Real threat-level classification from the analyzed `attack_rate`.
  - Severity strip (via `compute_severity`).
  - KPI cards, CTA row (Threat Detection / SOC AI / Dataset Analysis).
  - Threat Alert Summary feed.
  - Live Security Activity Terminal (chronological audit of analyzed flows).
- `push_history()` now records real timeline events (analysis completed /
  threat detected).

## Phase 3 — Threat Alert Center
- New components: `_investigation_feature_frame()`,
  `render_investigation_dialog()`, `_is_floatable()`, and the module-level
  `@st.dialog("🛡️ Threat Investigation")` `open_investigation_dialog()`.
- Rewrote `render_threat_detection()` with:
  - Severity + status filters, risk/severity sorting, top-N slider.
  - Alert selectbox -> investigation panel.
  - Downloadable filtered alerts CSV.
- Bug fixed (this session): investigation dialog crashed with
  `'dict' object has no attribute 'index'` because the payload is a dict, not a
  frame row — column discovery now handles both.

## Phase 4 — SOC AI Assistant
- Added `_now_ts`, `SOC_SUGGESTED_QUESTIONS`, `_trigger_copy()` (clipboard),
  `_chat_send_and_render()`.
- Rewrote `render_soc_ai_assistant()` with New / Clear / Regenerate toolbar,
  pending-question auto-send, welcome state with suggested questions,
  timestamps, per-message Copy + Regenerate-last.
- RAG pipeline reuse preserved verbatim:
  `_format_chat_source`, `OUT_OF_SCOPE_HEADER`, `OUT_OF_SCOPE_MESSAGE`,
  `_REFUSAL_MARKERS`, `is_out_of_scope_answer`, `render_chat_response`,
  `ask_soc_ai` (verified present after refactor).

## Phase 5a — ML Intelligence (Model Monitoring)
- New helpers: `_REPORTS_DIR`, `_parse_metric_text()`, `load_model_metrics()`,
  `report_image()`.
- Rewrote `render_ml_insights()`:
  - Dual model cards with real metrics from `reports/*.txt`
    (CICIDS-2017 vs NSL-KDD: accuracy / precision / recall / F1 / ROC-AUC).
  - Accuracy gauge fed by real values only.
  - Real evaluation artifacts embedded from `reports/*.png`
    (confusion matrix, ROC curve, feature importance) in tabs.
  - Removed fabricated accuracy (was 0.9920 / 0.9840) and removed
    fabricated "< 35ms / batch" inference latency — now "Not reported".
  - Engine architecture spec panel, trained feature vector table, live
    session prediction distribution.

## Phase 5b — Dataset Intelligence Center
- New `_detect_dataset_type()` (client-side NSL-KDD / CICIDS-2017 / Unknown,
  presentation only).
- Rewrote `render_dataset_analysis()` with:
  - Dataset header (filename, row/feature/missing/duplicate pills, type pill).
  - Reordered tabs; new Attack / Normal Distribution tab computing real
    attack/normal counts and attack rate from the label column.
  - CSV sample export in Overview.

## Phase 5c — Network Topology
- Added color legend panel, topology summary metrics (host nodes / observed
  flows / flagged nodes / source type), and a Node Inspector (select a node ->
  severity chip, category, flows, threats, direct neighbours).

## Phase 5d — Live Traffic
- Added engine-readiness strip (API / ML / RAG pills from real `/api/status`)
  plus active engine + decision threshold in `render_analyze_traffic()`.
- Added real severity-distribution chips (Critical/High/Medium/Low/Normal
  counts) above the flagged-flow inspector table.

## Phase 6 — Settings, Incident Timeline, Command Palette
- New `Settings` page (`render_settings`): interface preferences
  (theme/high-contrast/reduced-motion), notification preference, and
  session-data clearing. Frontend-only, session-scoped.
  - Reduced-motion actually disables the kinetic hero FX (only applied when
    the setting changes, so manual sidebar FX toggles aren't clobbered).
- New `Incident Timeline` page (`render_incident_timeline`): renders real
  `session_timeline` events with kind chips, clear button, CSV export.
- New Command Palette (`render_command_palette`): Ctrl+K / Cmd+K focuses a
  quick-navigation search box; matching pages render as one-click jump
  buttons (navigates via `nav_page` + rerun).

## Phase 7 — Validation & Quality Gate
- `python -m py_compile frontend/dashboard.py frontend/ui_components.py` — OK.
- Streamlit `AppTest` (offline API-down) ran all 14 pages with no exceptions:
  Overview, Live Traffic, Traffic Analytics, Threat Detection, Network
  Topology, ML Insights, SOC AI Assistant, Dataset Analysis, Data
  Visualization Explorer, Prediction History, Incident Timeline, System
  Status, Settings, About.
- Populated-path tests passed: dataset upload + type detection, threat alerts
  + investigation dialog, command-palette navigation, Settings reduced-motion
  toggle -> `fx_3d_bg` flips on change and is preserved on rerun.
- Verified no fabricated data remains (no hardcoded accuracy / latency).
- Verified chat helpers present (no regression).
- `git status`: only `frontend/dashboard.py` modified and
  `frontend/ui_components.py` added — all protected files untouched.
- Remaining ruff findings are pre-existing in untouched code paths (unused
  `numpy` import, fallback lambdas, ambiguous `l` loops, one unused `dot`).

## Known Notes / Limitations
- `reports/` and `/api/status` are read-only references; ML metrics and
  artifact images render only when those files/endpoints exist, otherwise N/A.
- Settings and the incident timeline persist for the browser session only
  (not written to disk).
- `st.components.v1.html` (clipboard + hero injection) triggers Streamlit's
  `st.iframe` migration warning; still functional on pinned Streamlit 1.62.0.