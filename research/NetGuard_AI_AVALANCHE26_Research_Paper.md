# NetGuard AI: An Intelligent Network Intrusion Detection and Autonomous Security Operations Platform Using Machine Learning and Agentic AI

**Aditya M. Raikar**  
Department of Computer Science and Engineering, KLS Gogte Institute of Technology, Belagavi, Karnataka, India

## Abstract
Modern networks generate high-volume traffic while security teams must detect malicious activity, interpret alerts and coordinate responses. This paper presents NetGuard AI, a machine-learning-based network intrusion detection and security operations platform integrating supervised traffic classification with packet/flow ingestion, explainability, threat enrichment and assisted incident response. The implementation uses Random Forest models for two benchmark feature spaces: 78 numerical flow features from CICIDS-2017 and 41 connection features from NSL-KDD. A FastAPI service exposes prediction and analysis interfaces; a live-monitoring subsystem captures authorized traffic and assembles bidirectional flows; and a Streamlit interface presents security operations information. Additional modules provide behavioral attack categorization, feature explanations, retrieval-augmented cybersecurity question answering, ReAct-style SOC investigation, MITRE ATT&CK-oriented mapping, response-playbook generation, alert notifications, analyst authentication, drift indicators and adversarial perturbation testing. Project documentation reports high benchmark scores and sub-5-ms CICIDS-2017 inference; these are identified as project-reported values because a fully specified, independently reproducible evaluation protocol for every headline metric is not available in the repository.

**Index Terms—** Network intrusion detection, Random Forest, CICIDS-2017, NSL-KDD, explainable AI, retrieval-augmented generation, autonomous SOC, SOAR, network flow analysis.

## I. Introduction
Enterprise networks are exposed to denial-of-service activity, reconnaissance, credential attacks, botnet command-and-control traffic and web exploitation. Signature-driven monitoring can identify known patterns but may miss modified or previously unseen behavior. Machine-learning network intrusion detection systems (NIDS) learn statistical relationships in connection and flow records; however, a prediction alone is insufficient for a security operations center (SOC). Analysts also need context, explanations, prioritization and safe response procedures.

NetGuard AI addresses this broader workflow by combining supervised anomaly detection with a modular SOC platform. It is implemented in Python using scikit-learn for model inference, FastAPI for backend services and Streamlit for the operator interface. The design separates traffic acquisition, feature preparation, prediction, investigation and notification so that components can be tested independently. The main contribution is an integrated prototype connecting two established intrusion-detection feature spaces to a common SOC workflow. A language model does not replace the classifier or analyst: model outputs and structured security tools provide evidence, while retrieval and agentic components assist investigation.

## II. Problem Statement
A practical NIDS-to-SOC workflow faces four connected challenges: (1) raw packets must be converted into model-compatible features without changing feature order or semantics; (2) a binary anomaly score must be translated into useful context such as attack family, confidence and severity; (3) analysts need traceable explanations and supporting cybersecurity knowledge; and (4) alerts must be persisted and delivered without exposing one user's records to another. Evaluation is another challenge: very high benchmark accuracy can be misleading when class imbalance, duplicate records, train/test leakage or dataset-specific artifacts are not controlled.

This work designs and implements a modular prototype that accepts benchmark flow records and authorized packet captures, performs model-based classification, enriches detections and exposes investigation/alert workflows, while distinguishing measured results from unverified system claims.

## III. Literature Survey
Breiman introduced Random Forests as ensembles of randomized decision-tree predictors, combining votes from multiple trees and using feature subsampling to improve generalization [1]. The method is suitable for tabular network-flow features because it models nonlinear feature interactions and supports feature-importance analysis. Performance nevertheless depends on representative data, careful splitting and suitable class-level metrics.

Sharafaldin et al. presented CICIDS-2017 to address limitations in older intrusion-detection datasets and provide labeled benign and attack traffic with flow-level attributes [2]. NSL-KDD, introduced by Tavallaee et al., refines KDD Cup 1999 by addressing redundant records and improving evaluation characteristics [3]. Both remain useful for reproducible experiments, but their age and collection conditions limit their ability to represent all current networks.

Lundberg and Lee proposed SHAP, a unified framework for assigning feature-attribution values to individual model predictions [4]. Such explanations help analysts understand which traffic attributes contributed to a prediction, although attribution does not establish causation. Lewis et al. introduced retrieval-augmented generation (RAG), combining a language model with a retrievable knowledge source [5]. Yao et al.'s ReAct approach interleaves reasoning and actions, enabling language models to use tools during multi-step tasks [6]. These ideas motivate the knowledge assistant and investigation components in NetGuard AI.

## IV. Proposed System Architecture
The system is organized into six logical layers: data acquisition, feature processing, machine-learning inference, enrichment and explanation, SOC investigation and response, and presentation/identity/persistence. The primary deployment uses a FastAPI backend and Streamlit frontend. REST endpoints support model information, CICIDS/NSL-KDD predictions, uploaded dataset analysis, chat and investigation. Dedicated routers implement monitoring, live detections, WebSocket streaming, authentication and notification workflows.

### A. Data Acquisition and Flow Reconstruction
The live-monitoring subsystem uses Scapy to discover interfaces and capture packets on an explicitly authorized interface. Packets are grouped into bidirectional sessions using endpoint and protocol information. The flow assembler derives duration, forward/backward packet counts, byte totals, inter-arrival statistics and TCP flag counts. A separate PCAP parser accepts capture bytes or files and extracts Ethernet/IPv4 packet attributes before grouping packets into flows. Its documented implementation focuses on IPv4 Ethernet and TCP/UDP; it should not be interpreted as universal support for every link type, IPv6 or encapsulation.

### B. Feature Processing and Model Inference
The prediction engine loads serialized Random Forest model artifacts and encoders from the models directory. CICIDS-2017 inference expects the model's 78 features in training order. NSL-KDD inference expects 41 connection features and uses stored categorical encoders. Input validation checks feature counts and prepares values. The engine returns class predictions and derived probability/risk information. A vector with the correct length but incorrect feature order can still produce invalid predictions.

### C. Enrichment and Explainability
A behavioral classifier examines flow attributes and assigns a candidate family such as DoS/DDoS, port scan, brute force, botnet/C2, web attack or infiltration/exfiltration. The XAI component provides feature-contribution and root-cause information. Threat-intelligence enrichment can add IP reputation, geolocation and autonomous-system context. These outputs supplement the primary classifier; heuristic family labels and external reputation are not equivalent to a separately trained multi-class model.

### D. RAG Assistant and Agentic Investigation
The RAG subsystem ingests cybersecurity documents, chunks them, generates embeddings and stores chunk metadata with vectors. A retriever normalizes queries, performs similarity search and supplies selected evidence to a language-model prompt. The assistant returns an answer with source information where available. The SOC agent follows a ReAct-style sequence: select tools, observe results and synthesize an investigation dossier. Available tools include threat-intelligence lookup, flow explanation, multi-class classification, MITRE mapping, containment-playbook generation and knowledge-base retrieval. Generated conclusions remain advisory and require analyst review.

### E. SOAR, Alerts and Identity
The SOAR engine maps candidate behaviors to MITRE ATT&CK concepts and can generate containment commands or firewall rules for supported environments. The platform includes webhook/email alert dispatch and deduplication/rate limiting. Authentication uses bcrypt password hashing and signed JWT access tokens; SQLite persistence is configured for user-specific records. Generated containment commands must be reviewed and tested before execution.

### F. Drift and Adversarial Testing
The drift monitor calculates Population Stability Index (PSI) to compare incoming feature distributions with a reference baseline. The adversarial tester perturbs selected flow dimensions using header-padding/jitter, low-and-slow, TCP-field and bounded feature-noise scenarios, then compares clean and perturbed predictions. These facilities provide a stress-testing framework; they do not alone establish robustness against real adaptive adversaries.

## V. Methodology
The implementation follows a staged pipeline. First, benchmark records are loaded using dataset-specific schemas. For CICIDS-2017, column names are normalized, the exact feature names exposed by the trained model are selected, values are converted to numeric form, and invalid infinities or missing values are handled. For NSL-KDD, categorical fields are encoded using saved encoders and the 41-feature schema is preserved. Second, the loaded model predicts the class and probability. Third, the result is normalized into a common response containing prediction, attack probability/confidence and risk-related fields. Fourth, optional enrichment modules add candidate attack family, feature explanation, threat intelligence and MITRE context. Finally, results are made available to the dashboard, alert store and investigation agent.

For a binary classifier, let TP, TN, FP and FN denote true positives, true negatives, false positives and false negatives. Accuracy=(TP+TN)/(TP+TN+FP+FN); precision=TP/(TP+FP); recall=TP/(TP+FN); and F1=2·precision·recall/(precision+recall). ROC-AUC measures ranking performance across thresholds. In intrusion detection, recall and false-negative analysis are important because undetected attacks may have high operational cost. Per-class results and a confusion matrix should accompany aggregate metrics.

For drift monitoring, PSI is Σᵢ(pᵢ−qᵢ)ln(pᵢ/qᵢ), where pᵢ and qᵢ are baseline and current proportions in bin i. Smoothing is needed when a bin has zero observations. PSI indicates distribution shift, not proof that model accuracy has degraded; it should trigger investigation and validation rather than automatic retraining.

## VI. Implementation Details
The repository identifies Python, scikit-learn, pandas, NumPy, joblib, FastAPI, Pydantic, Streamlit and Scapy as core dependencies. The backend prediction adapter loads the central NetworkPredictionEngine and exposes readiness and model metadata. FastAPI provides /predict/cicids and /predict/nsl-kdd endpoints, dataset-analysis routes, a RAG /chat endpoint and agent-investigation routes. Separate monitoring routes list interfaces, authorize a capture interface, start/stop monitoring and return recent reconstructed flows. A WebSocket endpoint broadcasts live detection events and accepts heartbeat or test/simulation messages.

The codebase supports both captured traffic and synthetic flow injection. Synthetic injection is useful for controlled demonstrations and integration tests, but outputs from simulated flows must be labeled as simulation and must not be reported as evidence of live-network detection performance. Offline CSV/PCAP evaluation and continuous live capture are different experimental conditions and should be measured separately.

## VII. Results and Discussion
The repository README reports the following benchmark metrics for its trained models. These values are reproduced as project-documented results, not as an independent rerun performed for this paper.

| Dataset / model | Accuracy | Precision | Recall | F1 | ROC-AUC |
|---|---:|---:|---:|---:|---:|
| CICIDS-2017 Random Forest | 99.89% | 99.97% | 99.89% | 99.93% | 1.0000 |
| NSL-KDD Random Forest | 99.91% | 99.95% | 99.86% | 99.90% | 0.99999 |

The README also reports CICIDS-2017 inference latency below 5 ms per flow. This is a project-reported value; the repository material inspected for this paper does not specify hardware, warm-up policy, batch size, timing distribution or a measurement script needed to reproduce it. The README does not clearly state the precise train/test split, class balance, leakage controls or evaluation script for each headline metric. The table should therefore be interpreted as reported project performance rather than an independently verified benchmark.

An important reproducibility detail appears in the NSL-KDD inference code: the current attack threshold is 0.01, while a code comment records a KDDTest-21 validation point at threshold 0.10 of approximately 90.5% precision, 82.7% recall and 86.4% F1. This indicates that threshold choice materially affects the precision–recall trade-off. The headline README metrics must be tied to a clearly named split and threshold before publication; they must not be presented as KDDTest-21 results without supporting evidence.

At system level, the repository implements model loading, two dataset-specific prediction paths, PCAP parsing, authorized live monitoring, WebSocket events, a knowledge retriever, investigation agents, alerting and user authentication. These are implementation capabilities, not measured end-to-end service-level results. This paper does not claim a quantified detection rate on unseen live traffic, production false-positive rate or proven reduction in analyst response time.

## VIII. Limitations and Threats to Validity
CICIDS-2017 and NSL-KDD cannot represent the full diversity of contemporary enterprise traffic. Headline scores near 100% require checking for leakage, duplicates, class imbalance and preprocessing differences. The exact evaluation split and threshold for all README metrics are not fully documented in the material reviewed. The PCAP parser focuses on Ethernet/IPv4 and TCP/UDP. Behavioral attack-family rules can mislabel incomplete or ambiguous flows. RAG output can be incomplete or incorrect if retrieval misses relevant evidence or the language model generates unsupported statements. Generated SOAR actions can disrupt legitimate traffic if executed without approval.

The system should be treated as a research prototype and analyst-assistance platform, not an autonomous production prevention system. Before deployment, it requires independent evaluation on temporally separated and organization-specific traffic, calibrated thresholds, per-class metrics, false-positive analysis, capture-path validation, authorization review, audit logging and human approval for disruptive actions.

## IX. Conclusion and Future Work
This paper presented NetGuard AI, an integrated network intrusion detection and SOC prototype combining Random Forest classification for CICIDS-2017 and NSL-KDD with live/offline traffic ingestion, flow reconstruction, explainability, threat enrichment, RAG-based cybersecurity assistance, agentic investigation, SOAR-oriented playbooks, alerting and identity-aware persistence. Its engineering contribution is the integration of detection and downstream investigation workflows while maintaining modular interfaces between components.

Future work will focus on reproducible evaluation: publish exact dataset versions, preprocessing scripts, split definitions, random seeds, confusion matrices and per-class metrics; independently validate the NSL-KDD KDDTest-21 threshold; benchmark latency under specified hardware and load; and compare against baseline algorithms. Further work should validate reconstructed flow features against a trusted flow extractor, expand IPv6 and capture-format support, assess temporal generalization and adversarial robustness, measure RAG faithfulness and conduct controlled usability studies. Human approval should remain mandatory for firewall changes and other high-impact actions.

## References
[1] L. Breiman, “Random Forests,” *Machine Learning*, vol. 45, pp. 5–32, 2001, doi: 10.1023/A:1010933404324.

[2] I. Sharafaldin, A. H. Lashkari, and A. A. Ghorbani, “Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization,” in *Proc. 4th Int. Conf. Information Systems Security and Privacy*, 2018, pp. 108–116, doi: 10.5220/0006639801080116.

[3] M. Tavallaee, E. Bagheri, W. Lu, and A. A. Ghorbani, “A Detailed Analysis of the KDD CUP 99 Data Set,” in *Proc. IEEE Symp. Computational Intelligence for Security and Defense Applications*, 2009, pp. 1–6, doi: 10.1109/CISDA.2009.5356528.

[4] S. M. Lundberg and S.-I. Lee, “A Unified Approach to Interpreting Model Predictions,” in *Advances in Neural Information Processing Systems*, vol. 30, 2017.

[5] P. Lewis et al., “Retrieval-Augmented Generation for Knowledge-Intensive NLP Tasks,” in *Advances in Neural Information Processing Systems*, vol. 33, 2020.

[6] S. Yao et al., “ReAct: Synergizing Reasoning and Acting in Language Models,” arXiv:2210.03629, 2022.

[7] A. M. Raikar, “NetGuard AI: Network Anomaly Detection and Autonomous SOC Platform,” source-code repository, GitHub, 2026. [Online]. Available: https://github.com/adityaraikar5555-collab/NetGuard-AI. Accessed: Nov. 23, 2026.

---
*Submission note: This project-based draft was prepared from the repository's documented implementation. Verify every metric against the exact evaluation artifacts, add a second author if applicable, confirm institutional formatting requirements and run the official similarity checker. No similarity percentage is guaranteed.*
