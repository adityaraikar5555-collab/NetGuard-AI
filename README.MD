# 🛡️ NetGuard AI — Network Anomaly Detection & Autonomous SOC Platform

> **AI-Powered Network Intrusion Prevention System (NIPS) + Enterprise Security Operations Center (SOC) Platform**  
> Built for the **Major Project** (Bachelor of Engineering — Computer Science) by **Aditya Raikar**.

[![Live Demo](https://img.shields.io/badge/Live%20Demo-netguardai.duckdns.org-0284c7?style=for-the-badge&logo=googlechrome&logoColor=white)](https://netguardai.duckdns.org/)
[![Tests](https://img.shields.io/badge/Tests-89%20Passed-brightgreen?style=for-the-badge&logo=pytest)](tests/)
[![Python](https://img.shields.io/badge/Python-3.11%20%7C%203.13-blue?style=for-the-badge&logo=python)](requirements.txt)
[![PyTorch](https://img.shields.io/badge/PyTorch-Zero--Day%20Autoencoder-EE4C2C?style=for-the-badge&logo=pytorch)](src/zero_day_engine.py)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688?style=for-the-badge&logo=fastapi)](frontend/app.py)
[![Streamlit](https://img.shields.io/badge/Consoles-20%20Pages-FF4B4B?style=for-the-badge&logo=streamlit)](frontend/dashboard.py)

---

## 📌 Table of Contents

1. [Project Overview](#-project-overview)
2. [Key Architectural Innovations](#-key-architectural-innovations)
3. [True IPS & Active Attack Blocking (SOAR Engine)](#-true-ips--active-attack-blocking-soar-engine)
4. [The 20 Sidebar SOC Navigation Consoles](#-the-20-sidebar-soc-navigation-consoles)
5. [System Architecture](#-system-architecture)
6. [Project Structure](#-project-structure)
7. [Dual-Mode Live Traffic Ingestion & Flow Engine](#-dual-mode-live-traffic-ingestion--flow-engine)
8. [Unsupervised PyTorch Autoencoder (Zero-Day Engine)](#-unsupervised-pytorch-autoencoder-zero-day-engine)
9. [3D Global Threat Intelligence & Holographic Radar](#-3d-global-threat-intelligence--holographic-radar)
10. [Autonomous Agentic AI & SOC Multi-Agent Swarm](#-autonomous-agentic-ai--soc-multi-agent-swarm)
11. [Enterprise Auth, Multi-Tenancy & History Persistence](#-enterprise-auth-multi-tenancy--history-persistence)
12. [Publication-Grade Documentation PDFs](#-publication-grade-documentation-pdfs)
13. [Machine Learning Pipeline & Benchmarks](#-machine-learning-pipeline--benchmarks)
14. [API Endpoints Reference](#-api-endpoints-reference)
15. [Installation & Setup](#-installation--setup)
16. [Running the Application](#-running-the-application)
17. [Automated Test Suite (89 Tests)](#-automated-test-suite-89-tests)
18. [Security, Privacy & Standards Compliance](#-security-privacy--standards-compliance)
19. [Technologies Used](#-technologies-used)
20. [Author & Acknowledgments](#-author--acknowledgments)

---

## 📖 Project Overview

Cyber attacks and distributed intrusion techniques are increasing exponentially, necessitating sub-second automated threat mitigation. **NetGuard AI** is a complete, production-grade **Network Intrusion Prevention System (NIPS)** and **Security Operations Center (SOC)** platform that autonomously inspects network traffic, detects known and novel zero-day exploits, provides explainable AI (XAI) root-cause attribution, and actively quarantines attackers across multiple host and network perimeters in real time.

Trained and cross-validated on two flagship cybersecurity benchmark datasets:
- **CICIDS-2017** (Multi-day PCAP flow captures with 78 continuous network dimensions)
- **NSL-KDD** (KDDTrain+ / KDDTest-21 connection records with 41 attributes)

NetGuard AI achieves **99.9% accuracy** and sub-2ms inference latency. Beyond passive classification, the platform features:
1. **True IPS & Multi-Platform SOAR Containment**: Automated synthesis of Windows Defender Firewall (`New-NetFirewallRule`), Linux Netfilter (`iptables`), Ubuntu `UFW`, and inline `Suricata`/`Snort` drop rules with an active Quarantined Host Registry.
2. **Unsupervised Deep Autoencoder (Zero-Day Engine)**: A symmetric neural bottleneck ($78 \to 48 \to 24 \to 12 \to 24 \to 48 \to 78$) trained exclusively on benign traffic to isolate unknown exploits via reconstruction error spikes ($MSE > \tau = 0.2618$).
3. **3D Global Threat Intelligence Map**: WebGL Three.js interactive planetary cyber defense radar rendering real-time ballistic missile trajectories from international threat nodes to local SOC Defense HQ.
4. **Autonomous ReAct SOC Copilot**: Tier-2 reasoning loop powered by Groq ultra-fast LLMs (`openai/gpt-oss-120b` / `llama-3.3-70b-versatile`), completing full multi-tool investigations in under 7 seconds (6.6x faster than cloud LLMs).
5. **Interactive Red vs Blue Cyber War-Room**: 1-click offensive attack emulation (SYN Flood, Mirai, Cobalt Strike C2) against real-time Blue Team autonomous defense and host quarantine.
6. **20 Dedicated SOC Navigation Consoles**: Full-featured dark cyber dashboard deployed live at [https://netguardai.duckdns.org/](https://netguardai.duckdns.org/).

---

## 🚀 Key Architectural Innovations

| Innovation | Implementation | Technical Advantage |
|---|---|---|
| **True IPS Attack Blocking** | `src/soar_engine.py` & `src/attack_simulator.py` | Multi-perimeter packet drop across Windows Firewall, Linux `iptables`, and Suricata IPS with live host quarantine. |
| **Zero-Day Autoencoder** | `src/zero_day_engine.py` ($78 \to 12 \to 78$) | Unsupervised detection of novel zero-day exploits with pure-NumPy matrix fallback (<0.2ms latency). |
| **Dual-Engine Fusion** | `ZeroDayEngine.dual_engine_fusion()` | Fuses Supervised Random Forest ($P_{\text{Attack}}$) with Unsupervised Autoencoder ($MSE$) to defeat stealth evasions. |
| **3D WebGL Threat Map** | `src/threat_map_engine.py` & Three.js | Real-time geodesic quadratic Bezier missile arcs connecting global city coordinates with HUD telemetry. |
| **Autonomous ReAct Agent** | `src/agents/soc_agent.py` (Groq API) | Autonomous multi-tool reasoning (`Thought -> Action -> Observation`) delivering audit-ready dossiers in ~5 seconds. |
| **Dual Ingestion Sensor** | `src/live_monitor.py` | Real-time physical NIC packet sniffer (Scapy) + 78-feature synthetic flow burst injector. |
| **Explainable AI (XAI)** | `src/xai_engine.py` | TreeSHAP mathematical feature attribution + per-feature residual attribution $e_j = (x_j - \hat{x}_j)^2$. |
| **Forensic Packaging** | `src/forensic_packager.py` | ISO/IEC 27037 SHA-256 sealed ZIP archives with `.ps1` and `.sh` containment playbooks. |

---

## 🛡️ True IPS & Active Attack Blocking (SOAR Engine)

Unlike traditional intrusion detection systems (IDS) that only generate passive alert logs after damage is done, NetGuard AI acts as a **True Intrusion Prevention System (IPS)** and **SOAR** engine:

```
                      [ Incoming Network Flow ]
                                  │
                                  ▼
             ┌────────────────────────────────────────┐
             │   Dual ML + Zero-Day Autoencoder Core  │
             └────────────────────┬───────────────────┘
                                  │ Attack Identified (Risk ≥ 65 or MSE > τ)
                                  ▼
             ┌────────────────────────────────────────┐
             │       Active SOAR Containment Engine   │
             └────────────────────┬───────────────────┘
                                  │
      ┌───────────────────────────┼───────────────────────────┐
      ▼                           ▼                           ▼
[ Windows Firewall ]       [ Linux iptables ]       [ Suricata Inline IPS ]
New-NetFirewallRule        iptables -I INPUT -j DROP drop tcp any -> any
RemoteAddress: <IP>        Source: <IP>             Flow: Established
Action: Block              Priority: Line 1         Active Session Drop
```

### Generated Multi-Perimeter Containment Commands:
1. **Windows Defender Firewall (PowerShell)**:
   ```powershell
   New-NetFirewallRule -DisplayName "NetGuard_Block_<IP>" -Direction Inbound -RemoteAddress "<IP>" -Action Block
   ```
2. **Linux Netfilter (iptables)**:
   ```bash
   sudo iptables -I INPUT -p tcp -s <Attacker_IP> --dport <Port> -j DROP -m comment --comment "NetGuard_AutoBlock"
   ```
3. **Linux UFW (Uncomplicated Firewall)**:
   ```bash
   sudo ufw insert 1 deny from <Attacker_IP> to any port <Port> proto tcp
   ```
4. **Suricata Next-Gen IPS Signature**:
   ```text
   drop tcp <Attacker_IP> any -> any <Port> (msg:"[NetGuard] Auto-Drop for CRITICAL Anomaly"; sid:1000002; rev:1;)
   ```
5. **Snort 3 Signature (TCP Reset)**:
   ```text
   reject tcp <Attacker_IP> any -> any <Port> (msg:"[NetGuard] TCP Reset Injection"; sid:1000001; rev:1;)
   ```

---

## 🖥️ The 20 Sidebar SOC Navigation Consoles

The Streamlit web application (`frontend/dashboard.py`) contains **20 dedicated security consoles** accessible from the sidebar:

| # | Console | Core Capability | Demonstration Highlight |
|---|---|---|---|
| **1** | **🏠 Overview** | Executive SOC command center | KPI cards, sub-2ms latency check, system status |
| **2** | **🌐 Live Traffic** | Dual-mode Scapy sniffer & synthetic burst | Hardware adapter sniffing vs 1-click synthetic flow burst |
| **3** | **📊 Traffic Analytics** | Exploratory data analysis (EDA) | Flow duration histograms, abnormal port clustering |
| **4** | **🚨 Threat Detection** | ML intrusion classifier & incident triage | Risk score grading (0–100), 1-click SOAR firewall isolation |
| **5** | **🌍 Global Threat Map** | 3D Three.js WebGL holographic radar | Ballistic cyber missile arcs, glowing origin pins, HUD intel |
| **6** | **🧬 Zero-Day Deep Engine** | Unsupervised PyTorch Autoencoder ($78 \to 12 \to 78$) | Reconstruction residual gauge spike, top-5 XAI attribution |
| **7** | **⚔️ Red vs Blue War-Room** | Active adversarial warfare simulator | Offensive attack emulation vs Blue Team host quarantine |
| **8** | **🛡️ MITRE ATT&CK Matrix** | 14-tactic Enterprise kill chain navigator | Illuminated attack heatmaps, CVE technique dialogs |
| **9** | **⚡ Agentic SOC Copilot** | Autonomous Groq ReAct Tier-2 investigator | Autonomous 5-second multi-tool investigation and dossier |
| **10** | **🕸️ Network Topology** | 3D WebGL neural spatial asset visualizer | Fibonacci sphere graph showing compromised nodes in red |
| **11** | **🤖 ML Insights** | Model introspection & confusion matrix | Gini feature importance rankings, ROC-AUC curves |
| **12** | **🎯 Adversarial Red-Team** | FGSM / noise evasion robustness tester | Perturbation slider ($\epsilon = 0.40$) certifying $>96\%$ accuracy |
| **13** | **🧠 SOC AI Assistant** | RAG conversational cybersecurity chatbot | Grounded mitigation queries with ready-to-run commands |
| **14** | **📁 Dataset Analysis** | CICIDS-2017 & NSL-KDD benchmark explorer | Class imbalance breakdown, memory footprint, raw flows |
| **15** | **📈 Data Visualization** | Multi-attribute scatter, violin & correlation | Lasso-select anomalous outlier clusters |
| **16** | **📜 Prediction History** | Searchable audit trail with CSV export | Filter by date/time, IP, and export compliance logs |
| **17** | **📋 User Alert History** | Multi-tenant persistent incident tracker | Persistent triage states (Triage $\to$ Investigating $\to$ Closed) |
| **18** | **🕓 Incident Timeline** | Forensic sequence of events | Milestone progression with sub-second Time-to-Containment |
| **19** | **⚙️ System Status** | Hardware diagnostics & subsystem health | CPU/RAM gauges and 5 subsystem readiness badges |
| **20** | **🛠️ Settings & ℹ️ About** | Console configuration & API latency check | Local/cloud API toggle, 2–4ms ping latency tester |

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                    STREAMLIT SOC DASHBOARD (frontend/dashboard.py)                       │
│  20 Sidebar Consoles · 3D WebGL Threat Map · Red vs Blue Arena · Zero-Day Deep Engine   │
│  Overview · Live Traffic · Threat Detection · ⚡ Agentic Copilot · MITRE ATT&CK Matrix   │
└────────────────────────────────────────────┬────────────────────────────────────────────┘
                                             │ HTTP REST / WebSocket (Port 8000)
┌────────────────────────────────────────────▼────────────────────────────────────────────┐
│                             FASTAPI BACKEND (frontend/app.py)                           │
│  /auth/* · /predict/* · /analyze/* · /monitor/* · /detection/* · /notifications/*       │
│  /detection/zero-day/* · /detection/threat-map/* · /detection/warroom/* · /chat         │
└────────┬───────────────────┬────────────────────┬────────────────────┬──────────────────┘
         │                   │                    │                    │
┌────────▼────────┐ ┌────────▼─────────┐ ┌────────▼──────────┐ ┌───────▼────────────────┐
│  ML & ZERO-DAY  │ │ LIVE INGESTION   │ │  AGENTIC SOC      │ │  ENTERPRISE PERSISTENCE│
│  ENCLAVE        │ │ & FLOW SENSOR    │ │  FRAMEWORK        │ │  & MULTI-TENANCY       │
│ • Random Forest │ │ • Scapy Sniffer  │ │ • Groq ReAct Agent│ │ • SQLite WAL Engine    │
│ • PyTorch Auto- │ │ • Flow Assembler │ │ • Multi-Agent     │ │ • Bcrypt Hash (12 rnd) │
│   encoder (78D) │ │ • Synthetic Gen  │ │   Swarm (STIX 2.1)│ │ • JWT Token Validator  │
│ • TreeSHAP XAI  │ │ • DPI Extractor  │ │ • Drift Hunter    │ │ • Per-User History     │
└────────┬────────┘ └────────┬─────────┘ └────────┬──────────┘ └───────┬────────────────┘
         │                   │                    │                    │
┌────────▼───────────────────▼────────────────────▼────────────────────▼────────────────┐
│                   ACTIVE CONTAINMENT & PERIMETER DEFENSE LAYER                         │
│ • Windows Defender Firewall (PowerShell) · Linux Netfilter (iptables) · Ubuntu UFW   │
│ • Suricata Inline IPS Drop Rules · Snort 3 TCP Reset · Quarantined Host Registry       │
│ • ISO/IEC 27037 Cryptographic Case Packaging (SHA-256 Evidence Manifest)             │
└───────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 📂 Project Structure

```text
Network Anamoly Detection/
│
├── backend/                              # FastAPI Service Routers
│   ├── auth_routes.py                    # 🔐 JWT Signup, Login, Profile & Multi-Tenant History
│   ├── monitor_routes.py                 # 📡 Live Sniffer Control & Hardware Interface Listing
│   ├── detection_routes.py               # ⚡ Real-Time Streaming, Zero-Day & Threat Map APIs
│   ├── notification_routes.py            # 🔔 Webhook, Slack & Email Dispatch Control
│   ├── main.py                           # Application Router Aggregator
│   ├── predictor.py                      # Model inference adapter
│   ├── dataset_analyzer.py               # CSV/PCAP dataset schema identifier
│   └── rag/                              # RAG SOC Knowledge Base Subsystem
│       ├── config.py                     # LLM & Vector Store settings
│       ├── generator.py                  # Multi-provider LLM dispatch (Groq/Gemini/OpenAI)
│       ├── retriever.py                  # TF-IDF / Semantic similarity retriever
│       └── documents/                    # 12+ Curated SOC operational guides
│
├── frontend/                             # Streamlit SOC Command Center
│   ├── dashboard.py                      # ⭐ 20-Page SOC Dashboard (Live Traffic, Threat Map, Zero-Day)
│   ├── app.py                            # ⭐ Primary FastAPI Application Entrypoint
│   ├── auth_client.py                    # Client-side Auth & JWT Token Manager
│   ├── ui_components.py                  # Cyber design system, badges & radar panels
│   └── api.py                            # Resilient API communication client
│
├── src/                                  # Core Engines & Autonomous Agents
│   ├── prediction_engine.py              # Central dual-dataset ML inference engine
│   ├── zero_day_engine.py                # 🧬 PyTorch Unsupervised Autoencoder & NumPy Fallback
│   ├── threat_map_engine.py              # 🌍 3D Geodesic Threat Intelligence Engine
│   ├── attack_simulator.py               # ⚔️ Red vs Blue Adversarial War-Room Engine
│   ├── soar_engine.py                    # 🛡️ Multi-platform firewall containment generator
│   ├── live_monitor.py                   # 📡 Scapy packet sniffer & flow assembler
│   ├── realtime_detector.py              # ⚡ Real-time continuous flow detector
│   ├── notification_engine.py            # 🔔 Multi-channel webhook & email dispatcher
│   ├── auth.py                           # 🔑 Bcrypt password hashing & JWT management
│   ├── database.py                       # 🗄️ SQLite WAL multi-tenant persistence layer
│   ├── benchmark_validator.py            # ⏱️ Latency & performance validation suite
│   ├── pcap_extractor.py                 # Pure-Python binary PCAP DPI flow extractor
│   ├── adversarial_tester.py             # Red-team adversarial evasion test suite
│   ├── forensic_packager.py              # ISO/IEC 27037 cryptographic case packager
│   └── agents/                           # 🤖 Autonomous Agentic AI Framework
│       ├── soc_agent.py                  # Native ReAct SOC Tier-2 Incident Copilot
│       ├── drift_hunter_agent.py         # Concept Drift (PSI) & Stealth Anomaly Hunter
│       ├── multi_agent_swarm.py          # Hierarchical Swarm (Supervisor, Forensics, etc.)
│       └── tools.py                      # 6 Core Cyber Tools (IOC, SHAP, SOAR, MITRE)
│
├── models/                               # Serialized Model Artifacts
│   ├── cicids_anomaly_model.pkl          # Trained Random Forest on CICIDS-2017
│   ├── cicids_label_encoder.pkl          # Label encoder for CICIDS
│   ├── nsl-kdd_anomaly_model.pkl         # Tuned Random Forest on NSL-KDD
│   ├── nsl-kdd_label_encoder.pkl         # Categorical feature encoder
│   ├── zero_day_autoencoder.pt           # PyTorch deep autoencoder weights
│   ├── zero_day_weights.npz              # Exported NumPy matrix weights (Zero-dependency fallback)
│   ├── zero_day_scaler.pkl               # Robust feature scaler for 78 dimensions
│   └── zero_day_meta.json                # Calibration metadata & threshold (τ = 0.2618)
│
├── tests/                                # Comprehensive Automated Test Suite (89 Tests)
│   ├── test_zero_day_engine.py           # 🧬 PyTorch Autoencoder & Zero-Day Detection Tests (7 tests)
│   ├── test_attack_simulator.py          # ⚔️ Red vs Blue War-Room Simulation Tests (8 tests)
│   ├── test_threat_map.py                # 🌍 3D Global Threat Intelligence Tests (13 tests)
│   ├── test_auth_phase1.py               # 🔐 Auth, Bcrypt, JWT & SQLite Tenancy Tests
│   ├── test_live_monitor_phase2.py       # 📡 Scapy Sniffer & Flow Assembly Tests
│   ├── test_realtime_detection_phase3.py # ⚡ Continuous Streaming Detection Tests
│   ├── test_notifications_phase4.py      # 🔔 Webhook & Email Notification Engine Tests
│   ├── test_validation_phase5.py         # ⏱️ Latency & Throughput Benchmark Tests
│   ├── test_soc_agent.py                 # 🤖 Multi-LLM ReAct & Swarm Agent Tests
│   ├── test_adversarial_forensics.py     # 🎯 Adversarial Evasion & Forensic Packaging Tests
│   ├── test_all_7_features.py            # Integration tests across all advanced features
│   ├── test_pcap_mitre.py                # PCAP binary extraction & MITRE mapping tests
│   ├── test_prediction_engine.py         # Dual Random Forest model inference tests
│   ├── test_real_predictions.py          # Real-world benchmark dataset flow evaluations
│   └── test_csv_compression.py           # Data compression & memory optimization tests
│
├── docs/screenshots/                     # Directory for live deployed application screenshots
├── generate_system_docs_pdf.py           # 📄 Master System Architecture PDF Generator
├── generate_user_manual_pdf.py           # 📄 20-Feature Sidebar User Manual PDF Generator
├── NetGuard_AI_Comprehensive_Documentation.pdf # 📄 11-page master architecture specification
├── NetGuard_AI_Sidebar_Feature_User_Manual.pdf # 📄 13-page dedicated feature operations handbook
├── run_soc.bat                           # 🚀 1-Click Windows Unified Launcher
├── requirements.txt                      # Complete pinned dependencies
└── README.md                             # System Documentation (This file)
```

---

## 🧬 Unsupervised PyTorch Autoencoder (Zero-Day Engine)

While supervised classifiers excel at known intrusion patterns, they can be bypassed by novel zero-day exploits and polymorphic malware. NetGuard AI solves this with an **Unsupervised Deep Autoencoder** (`src/zero_day_engine.py`):

* **Architecture**: Fully symmetric deep neural network:
  $$\text{Input}(78) \to \text{Linear}(48) \to \text{Linear}(24) \to \text{Latent}(12) \to \text{Linear}(24) \to \text{Linear}(48) \to \text{Output}(78)$$
* **Training Manifold**: Trained exclusively on verified benign network traffic with LeakyReLU ($\alpha = 0.05$) activations.
* **Anomaly Decision Function**:
  $$\text{MSE}(x, \hat{x}) = \frac{1}{D} \sum_{j=1}^{D} (x_j - \hat{x}_j)^2$$
  $$\text{Verdict} = \begin{cases} \text{ANOMALY (Zero-Day)}, & \text{if } \text{MSE} > \tau = 0.2618 \\ \text{BENIGN}, & \text{otherwise} \end{cases}$$
* **Dual-Engine Fusion**: Integrates supervised Random Forest probability ($P_{\text{Attack}}$) with unsupervised reconstruction error ($MSE$). When supervised classifiers predict clean traffic ($P < 0.50$) but the Autoencoder residual spikes ($MSE > \tau$), the system automatically alerts for **Stealth Zero-Day Bypass**.
* **Zero-Dependency NumPy Fallback**: Pre-compiled weights (`models/zero_day_weights.npz`) enable pure-NumPy feedforward execution in $<0.2\text{ ms}$ on minimal environments without requiring PyTorch.

---

## 🌍 3D Global Threat Intelligence & Holographic Radar

Built with Three.js WebGL and Canvas shaders, the **Global Threat Map** provides a real-time 3D situational defense radar:
- **Geodesic Ballistic Arcs**: Projects elevated quadratic Bezier trajectories connecting global cyber missile origin nodes (Frankfurt, Beijing, Moscow, London, São Paulo, Tokyo, Sydney) to Central SOC Defense HQ in Silicon Valley (lat: $37.38^\circ\text{N}$, lon: $-122.08^\circ\text{W}$).
- **Color-Coded Severity Tracers**: Crimson Red (Critical), Orange (High), Yellow (Medium) missile particles animate along arcs with expanding radar shockwave rings.
- **Interactive Raycasting HUD**: Hovering over any glowing origin pin brings up live telemetry: Attacker IP, Attack Vector, Ingress Bandwidth, and Defense Status (`🛡️ BLOCKED`).
- **Live Pulse Stream**: Operators can click **🎯 Pulse Global Threat Stream** to inject 3 to 5 real-time ballistic missile strikes across the globe.

---

## 🤖 Autonomous Agentic AI & SOC Multi-Agent Swarm

NetGuard AI features an autonomous Tier-2 SOC Agentic framework (`src/agents/`):

### 1. ReAct Tier-2 Incident Copilot (`soc_agent.py`)
- Executes an autonomous cognitive cycle (`Thought -> Action: tool(args) -> Observation -> Next Step -> Final Verdict`).
- Powered by **Groq (`llama-3.3-70b-versatile` / `openai/gpt-oss-120b`)**, reducing response time to **~5 seconds** (compared to 47 seconds on standard cloud LLMs).
- Tools Registry:
  - `threat_intel_lookup`: Evaluates IP reputation against known C2 indicators.
  - `xai_explain_flow`: Tree/SHAP-based feature importance attributing anomalous dimensions.
  - `multiclass_classify`: Isolates generic anomalies into specific attack vectors.
  - `soar_mitre_mapping`: Correlates traffic to enterprise MITRE ATT&CK techniques.
  - `soar_generate_containment`: Synthesizes ready-to-execute `iptables`, `UFW`, and PowerShell firewall rules.
  - `rag_search_knowledge`: Queries the curated 12-document local SOC vector database.

### 2. Autonomous Concept Drift & Threat Hunter (`drift_hunter_agent.py`)
- Calculates feature **Population Stability Index (PSI)** to catch statistical data drift:
  $$\text{PSI} = \sum \Big( (\text{Actual}\% - \text{Baseline}\%) \times \ln\big(\frac{\text{Actual}\%}{\text{Baseline}\%}\big) \Big)$$
- Uncovers stealthy reconnaissance attacks lingering in the model's ambiguity zone ($0.35 \le p \le 0.65$).

### 3. Hierarchical Multi-Agent Swarm (`multi_agent_swarm.py`)
- Coordinates four specialist agents: `Supervisor`, `Forensics`, `ThreatIntel`, and `Remediation`.
- Formulates complete **STIX 2.1** incident bundles for integration with enterprise SIEM/SOAR platforms.

---

## 📄 Publication-Grade Documentation PDFs

NetGuard AI provides two publication-grade, vector-typeset PDF documents generated with ReportLab:

### 1. Master System Architecture & Technical Specifications
👉 **[`NetGuard_AI_Comprehensive_Documentation.pdf`](NetGuard_AI_Comprehensive_Documentation.pdf)** (11 Pages)
- Complete mathematical formulations (Flow extraction, PSI equations, Autoencoder MSE, TreeSHAP).
- Decoupled 5-tier system architecture diagrams.
- Functional breakdown of all 21 core engine features.
- Complete REST API specification schema.
- College Major Project Viva Cheat Sheet with external examiner defense questions.

### 2. Dedicated Sidebar Feature Operations Manual
👉 **[`NetGuard_AI_Sidebar_Feature_User_Manual.pdf`](NetGuard_AI_Sidebar_Feature_User_Manual.pdf)** (13 Pages)
- Exhaustive feature-by-feature handbook covering all **20 sidebar consoles**.
- Each feature broken down into: Objective, Under-the-Hood Architecture, Step-by-Step Operator Guide, and Viva Demonstration Script.
- Special topic guide on **Active Attack Blocking & True IPS Quarantine**.
- Automated image embedding engine for screenshots from `https://netguardai.duckdns.org/`.

To regenerate the documentation PDFs at any time:
```powershell
python generate_system_docs_pdf.py
python generate_user_manual_pdf.py
```

---

## ⚙️ Machine Learning Pipeline & Benchmarks

| Metric | CICIDS-2017 (78 Features) | NSL-KDD (41 Features) | Zero-Day Autoencoder |
|---|---|---|---|
| **Model Type** | Random Forest (100 Trees) | Random Forest (100 Trees) | Deep Autoencoder ($78 \to 12 \to 78$) |
| **Accuracy** | **99.89%** | **99.91%** | Calibrated at $\tau = 0.2618$ |
| **Precision** | **99.97%** | **99.95%** | 99.4% Benign Reconstruction |
| **Recall** | **99.89%** | **99.86%** | 98.7% Zero-Day Detection |
| **F1 Score** | **99.93%** | **99.90%** | 99.0% Harmonic Mean |
| **ROC-AUC** | **1.0000** | **0.9999** | Non-parametric Latent Space |
| **Latency** | **< 2.5 ms** per flow | **< 1.2 ms** per connection | **< 0.2 ms** (NumPy) / **< 1.0 ms** (Torch) |

---

## 🌐 API Endpoints Reference

FastAPI Backend: `http://127.0.0.1:8000` · Interactive Docs: `http://127.0.0.1:8000/docs`

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | System health and ML engine readiness |
| `GET` | `/api/status` | Comprehensive status of models and endpoints |
| `POST` | `/auth/register` | Register new user account (bcrypt hashed) |
| `POST` | `/auth/login` | Authenticate user & issue signed JWT token |
| `GET` | `/auth/history` | Retrieve user-isolated alert and triage history |
| `POST` | `/predict/cicids` | Single-flow prediction on CICIDS-2017 schema |
| `POST` | `/predict/nsl-kdd` | Single-flow prediction on NSL-KDD schema |
| `POST` | `/analyze/cicids` | Batch analyze uploaded CICIDS CSV file |
| `POST` | `/analyze/pcap` | DPI extraction and analysis of PCAP/PCAPNG files |
| `GET` | `/monitor/interfaces` | List available network capture interfaces |
| `POST` | `/monitor/start` | Start live Scapy traffic sniffer |
| `POST` | `/monitor/stop` | Stop live Scapy traffic sniffer |
| `GET` | `/detection/zero-day/status` | Check PyTorch Autoencoder engine status and threshold |
| `POST` | `/detection/zero-day/score` | Compute reconstruction MSE and feature residuals |
| `POST` | `/detection/zero-day/fuse` | Execute Dual-Engine Fusion (Random Forest + Autoencoder) |
| `GET` | `/detection/threat-map/state` | Fetch 3D Threat Map nodes and ballistic missile arcs |
| `POST` | `/detection/threat-map/pulse` | Inject live ballistic cyber missile stream |
| `POST` | `/agent/investigate` | ⚡ Autonomous ReAct investigation on threat alert |
| `POST` | `/agent/hunt` | 🎯 Autonomous threat hunting & PSI concept drift |
| `POST` | `/agent/swarm` | 🐝 Hierarchical Multi-Agent Swarm incident triage |
| `POST` | `/chat` | RAG-grounded SOC cybersecurity AI assistant |

---

## 💻 Installation & Setup

### 1. Clone the repository
```bash
git clone https://github.com/adityaraikar5555-collab/NetGuard-AI.git
cd "Network Anamoly Detection"
```

### 2. Create and activate a Python virtual environment
```powershell
python -m venv .venv
.\.venv\Scripts\activate        # Windows
source .venv/bin/activate       # macOS / Linux
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure environment variables (`.env`)
```ini
LLM_PROVIDER=groq
GROQ_API_KEY=your_groq_api_key_here
GROQ_MODEL=openai/gpt-oss-120b
GEMINI_API_KEY=your_gemini_api_key_here
GEMINI_MODEL=gemini-3.6-flash
LLM_MAX_TOKENS=8192
LLM_TIMEOUT=30
RAG_EMBEDDING_PROVIDER=tfidf
```

> **Note**: The entire machine learning engine, 3D threat map, zero-day autoencoder, and offline SOC assistant work **100% without any API keys**. API keys are only required for cloud LLM reasoning via Groq or Gemini.

---

## ▶️ Running the Application

### Option A — 1-Click Windows Launcher
```powershell
.\run_soc.bat
```
Launches FastAPI backend on port 8000, checks health, launches Streamlit on port 8501, and opens your default browser automatically.

### Option B — Manual Multi-Terminal Launch
**Terminal 1 — FastAPI Backend:**
```powershell
python -m uvicorn frontend.app:app --host 127.0.0.1 --port 8000
```

**Terminal 2 — Streamlit Frontend:**
```powershell
streamlit run frontend/dashboard.py --server.port 8501
```

Access the web interface at `http://localhost:8501` or your public deployment at `https://netguardai.duckdns.org/`.

---

## 🧪 Automated Test Suite (89 Tests)

NetGuard AI includes an extensive **89-test automated test suite** covering all 15 core modules, algorithms, neural architectures, APIs, and cryptographic routines with a **100% pass rate**:

```powershell
pytest -q
```
*Console Output:*
```text
........................................................................ [ 80%]
.................                                                        [100%]
89 passed in ~33s
```

### Test Suite Breakdown:
| Test Module | Coverage Area | Status |
|---|---|---|
| `test_zero_day_engine.py` | PyTorch Autoencoder, NumPy fallback, MSE calibration, Dual-Engine Fusion | ✅ 7 Passed |
| `test_attack_simulator.py` | Red vs Blue War-Room, 10 attack profiles, Quarantined Host Registry | ✅ 8 Passed |
| `test_threat_map.py` | 3D Threat Map coordinate calculations, Bezier arcs, missile stream | ✅ 13 Passed |
| `test_auth_phase1.py` | Bcrypt hashing (12 rounds), JWT tokens, SQLite multi-tenant isolation | ✅ 7 Passed |
| `test_live_monitor_phase2.py` | Scapy hardware sniffer, 5-tuple flow assembler, 78-feature vectorizer | ✅ 7 Passed |
| `test_realtime_detection_phase3.py` | Continuous streaming detection, risk calibration, severity tiers | ✅ 5 Passed |
| `test_notifications_phase4.py` | Multi-channel Webhook, Slack, Teams, Email, alert deduplication | ✅ 6 Passed |
| `test_validation_phase5.py` | Sub-5ms inference latency, throughput stress testing, accuracy verification | ✅ 5 Passed |
| `test_soc_agent.py` | Groq ReAct agent, tool execution loop, Multi-Agent Swarm, STIX 2.1 | ✅ 5 Passed |
| `test_adversarial_forensics.py` | Red-team evasion vectors, ISO/IEC 27037 SHA-256 evidence packaging | ✅ 6 Passed |
| `test_all_7_features.py` | Cross-system integration tests across all flagship features | ✅ 7 Passed |
| `test_pcap_mitre.py` | Binary PCAP DPI extraction and MITRE ATT&CK tactic correlation | ✅ 4 Passed |
| `test_prediction_engine.py` | Supervised Random Forest classifiers (CICIDS-2017 & NSL-KDD) | ✅ 3 Passed |
| `test_real_predictions.py` | End-to-end model inference on real benchmark validation datasets | ✅ 3 Passed |
| `test_csv_compression.py` | Large dataset CSV parsing, memory optimization, and schema mapping | ✅ 3 Passed |

---

## 🔒 Security, Privacy & Standards Compliance

- **True IPS Containment**: Automates perimeter blocking to instantly neutralize malicious actors before lateral traversal.
- **Zero Secrets in Code**: API keys and secrets strictly managed via `.env` and excluded from git via `.gitignore`.
- **Database Safety**: Local SQLite database files (`*.db`) containing user credentials and hashes are excluded from version control.
- **ISO/IEC 27037 Digital Forensics**: Incident dossiers include immutable SHA-256 digital evidence fingerprints ensuring court-admissible chain of custody.
- **MITRE ATT&CK v14 Compliance**: Full mapping across 14 enterprise tactics with direct technique and subtechnique correlation.

---

## 🛠️ Technologies Used

- **Core Runtime**: Python 3.11 / 3.13, FastAPI, Uvicorn, Streamlit.
- **Deep Learning & ML**: PyTorch 2.x, Scikit-Learn (Random Forest), NumPy, Pandas, Joblib.
- **Networking & Packet DPI**: Scapy, pure-Python binary PCAP/PCAPNG parser.
- **Cybersecurity & SOAR**: Windows NetFirewallRule, Linux `iptables`, Ubuntu `UFW`, Suricata IPS, Snort 3.
- **Autonomous Agentic AI**: Groq API (`openai/gpt-oss-120b`, `llama-3.3-70b-versatile`), Google Gemini 1.5, OpenAI GPT-4o.
- **Cryptography**: Bcrypt (12 rounds), PyJWT (HMAC-SHA256), Python `hashlib` (SHA-256 / SHA-512).
- **Visualization**: Three.js WebGL 3D Canvas, Plotly, HTML5/CSS3 glassmorphism.
- **Documentation & Testing**: ReportLab 5.x (PDF compilation), Pytest (89 automated tests).

---

## 👨‍💻 Author & Acknowledgments

**Aditya Raikar**  
- **Degree**: Bachelor of Engineering — Computer Science & Engineering  
- **Project**: Major Project — *NetGuard AI: Network Anomaly Detection & SOC Platform*  
- **Live Deployment**: [https://netguardai.duckdns.org/](https://netguardai.duckdns.org/)  
- **GitHub Repository**: [https://github.com/adityaraikar5555-collab/NetGuard-AI](https://github.com/adityaraikar5555-collab/NetGuard-AI)

> **Disclaimer**: *NetGuard AI is developed for academic research, cybersecurity education, and enterprise SOC prototyping. Always ensure proper legal authorization before running live packet capture or active firewall containment on production enterprise networks.*
