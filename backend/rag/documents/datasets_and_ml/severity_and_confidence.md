# Severity Interpretation, Prediction Confidence & Model Triage Guide

> **Scope note (how to read this document):** This file explains two related things: (1) **general SOC/IDS concepts** — how severity is typically assessed and how ML confidence/probability scores are typically interpreted in intrusion detection — and (2) **NetGuard AI–specific facts** about its documented severity matrix and confidence-tier interpretation. Where a table describes recommended response actions (e.g., "firewall block rule generation," "IP ban via Fail2ban"), these are presented as **general SOC playbook guidance associated with a severity level**, not as claims that NetGuard AI itself automatically performs blocking, isolation, or firewall changes. NetGuard AI's documented capability is producing a classification (benign vs. specific attack category) with an associated confidence/probability score, surfaced via its FastAPI backend, Streamlit dashboard, and RAG chat assistant — it does not claim automated enforcement actions unless a project file explicitly documents that capability.

---

## Overview

In a modern Security Operations Center (SOC), machine learning classifications must be translated into actionable triage priorities. An anomaly flag by itself is insufficient; analysts require contextual **severity ratings**, **probabilistic confidence indicators**, and a clear distinction between **confirmed facts** and **model inferences**. This matters especially for ML-based Network Intrusion Detection Systems (NIDS), where a raw model output (a class label and a probability) needs to be translated into something an analyst can act on within a limited amount of time.

This document covers:
- How severity levels are typically defined and used in SOC triage (general knowledge), plus NetGuard AI's own severity classification matrix.
- How ML prediction confidence/probability scores should be interpreted (general ML + SOC knowledge), plus NetGuard AI's specific confidence tiers.
- False positives vs. false negatives and why the distinction matters operationally.
- How RAG-based explanation can help ground severity/confidence output in documented reasoning rather than free-form LLM guesswork.

---

## Definition

**Severity** (in a SOC context) is a rating assigned to a security alert or detected event that reflects the potential impact and urgency of the underlying activity — how much harm it could cause and how quickly it needs a response — independent of whether that activity has been fully confirmed as malicious.

**Confidence** (in an ML classification context) is a numeric estimate — typically a probability between 0 and 1 (or 0% and 100%) — representing how strongly the model's output supports its chosen classification. It is **not** the same as certainty that the classification is correct in the real world; it reflects how closely the input's feature vector matches patterns the model associates with that class, based on its training data.

Synonyms and related terms:
- "Alert priority", "criticality rating", "risk score" (severity)
- "prediction probability", "class probability", "model certainty", "probability distribution", "decision score" (confidence)

---

## Key Concepts

### Why severity and confidence are two separate dimensions
It is a common mistake to conflate "how confident is the model?" with "how bad is this if true?" These are independent axes:

| | High Confidence | Low Confidence |
| :--- | :--- | :--- |
| **High Severity** (e.g., suspected active DDoS or infiltration) | Strong signal, high potential impact → escalate immediately | Weak signal but high potential impact → investigate promptly, don't ignore |
| **Low Severity** (e.g., suspected routine scan) | Strong signal, low potential impact → log and monitor per policy | Weak signal, low potential impact → lowest priority, background monitoring |

A model can be very confident about a low-severity classification (e.g., 98% confident this is benign HTTPS traffic), and it can also be uncertain about a high-severity classification (e.g., 55% confident this might be infiltration). Good SOC triage design accounts for both dimensions rather than collapsing them into a single number.

### The role of thresholds
ML classifiers typically produce a continuous probability score, and a **decision threshold** (often 0.5 by default) is applied to convert that score into a discrete label. In a security context, the threshold is frequently **tuned away from the naive default** to favor recall (catching more true attacks) at some cost to precision (accepting more false alarms), because the cost of missing a real intrusion (false negative) is usually considered higher than the cost of an analyst spending time reviewing a false alarm (false positive) — though this tradeoff depends on organizational risk tolerance and analyst capacity.

---

## Technical Details

### NetGuard AI Severity Classification Matrix

| Severity Level | Color Code | Criteria & Threat Profiles | Suggested Operational Response SLA (general SOC playbook guidance) |
| :--- | :--- | :--- | :--- |
| **Critical** | 🔴 Crimson (`#ef4444`) | Active High-Bandwidth DDoS Floods, Confirmed Infiltration, Root Privilege Escalation (U2R), Active C2 Beaconing with Exfiltration. | **Immediate (0–15 minutes):** analyst-driven isolation/rate-limiting decisions, Tier-3 escalation. |
| **High** | 🟠 Amber-Orange (`#fb923c`) | DoS Hulk/GoldenEye, Persistent SSH/FTP Brute Force, Web SQL Injection / RCE attempts, Heavy Port Sweep on core servers. | **Urgent (15–60 minutes):** firewall rule review, IP-ban consideration (e.g., via tools like Fail2ban), credential rotation. |
| **Medium** | 🟡 Yellow (`#fbbf24`) | Isolated Port Scanning (Probe), single failed-login bursts, suspicious HTTP headers, Slowloris partial probes. | **Standard (1–4 hours):** log monitoring, IDS rule tuning, anomaly trend analysis. |
| **Low / Safe** | 🟢 Emerald (`#10b981`) | Normal routine network traffic (Benign/Normal flows, valid HTTP/HTTPS/DNS sessions, expected backup replication). | **Informational:** baseline telemetry recording. |

> **Clarification:** The "Suggested Operational Response SLA" column describes **typical SOC playbook actions** associated with each severity tier — a general reference for what a human analyst or a separately configured enforcement tool might do. NetGuard AI's documented function is to classify traffic and surface severity/confidence information to support this triage process; it does not itself perform firewall changes, IP bans, or isolation actions unless a specific project component documents that capability.

### General severity-rating frameworks (for context)
Beyond NetGuard AI's own matrix, SOC teams commonly reference broader industry frameworks when scoring severity, such as:
- **CVSS (Common Vulnerability Scoring System):** Used primarily for vulnerability severity rather than live traffic events, but its concepts (impact, exploitability, scope) often inform how organizations think about incident severity more generally.
- **Asset-criticality weighting:** The same attack type (e.g., a port scan) may be scored higher in severity if it targets a critical production server versus a low-value test host.
- **Business-impact framing:** Availability-impacting attacks (DoS/DDoS) are frequently weighted differently from confidentiality-impacting attacks (data exfiltration) or integrity-impacting attacks (unauthorized modification), depending on organizational priorities.

---

## Machine Learning Confidence & Probability Interpretation

In NetGuard AI, the ML inference engine outputs a prediction alongside a probability distribution (via `predict_proba()`-style output or an equivalent decision function score for the classifier used).

### 1. High Confidence (Confidence ≥ 90%)
- **Interpretation:** The flow's feature vector strongly aligns with known attack signatures (e.g., thousands of small SYN packets with 0-byte payloads matching a learned DoS pattern).
- **SOC Action:** Lower likelihood of a false positive relative to lower-confidence predictions; still generally paired with rapid analyst confirmation before any containment action is applied, since even high-confidence ML outputs are not a substitute for verification in most SOC workflows.

### 2. Moderate Confidence (70% ≤ Confidence < 90%)
- **Interpretation:** The flow shows clear anomalous tendencies (e.g., elevated error rates or unusual packet ratios) but also exhibits some normal baseline characteristics.
- **SOC Action:** Analyst verification is recommended. Cross-reference the source IP with threat-intelligence feeds and application/authentication logs before deciding on any blocking or containment step.

### 3. Low Confidence / Borderline (50% ≤ Confidence < 70%)
- **Interpretation:** The feature vector lies near the model's decision boundary. Often triggered by bursty but legitimate user traffic (e.g., large file downloads, software updates, backup jobs).
- **SOC Action:** Flag for observation rather than immediate action. Avoid aggressive automated bans in this range, since acting on borderline predictions risks disrupting legitimate users or business processes (a self-inflicted denial-of-service via false positive).

### 4. Very Low Confidence (< 50%, near the decision boundary or below it)
- **Interpretation:** The model's output is essentially uncertain — the input does not clearly resemble either class strongly. This can occur with genuinely novel traffic patterns the model has not seen well-represented examples of during training, or with a poor-quality/incomplete feature vector.
- **SOC Action:** Treat as low-priority for automated triage but retain the record for later analysis; a pattern of many low-confidence predictions clustering around a specific host or time window can itself be a useful signal worth investigating manually, even if no single prediction is individually actionable.

### Reading a confidence score correctly (general ML knowledge)
A few important caveats when interpreting confidence/probability scores from any classifier, including NetGuard AI's:

- **Confidence is not accuracy.** A well-calibrated model's "90% confidence" should, roughly, mean that 90% of the time it says this, it should be correct — but many classifiers (including tree ensembles like Random Forest) are not perfectly calibrated out of the box, so a 90% score should be treated as "strong relative confidence" rather than a literal, guaranteed accuracy rate.
- **Confidence reflects similarity to training data, not ground truth.** A model can be confidently wrong if the current traffic resembles a training pattern that happens to be mislabeled, or if the traffic is a novel technique not represented during training.
- **Class imbalance affects confidence distributions.** For rare classes (e.g., a dataset's least-represented attack type), a model may systematically produce lower-confidence scores simply because it saw fewer training examples of that class, not necessarily because the underlying signal is weaker.

---

## Detection

Combining severity and confidence into a single triage signal is itself a design decision. Common general approaches (not all necessarily implemented identically in every system):

- **Severity-first triage:** Route Critical/High severity alerts to analysts regardless of confidence level, since the potential cost of missing them is high even at moderate confidence.
- **Confidence-first filtering:** Suppress or batch very-low-confidence alerts regardless of severity category, to reduce alert fatigue, while still logging them for later pattern analysis.
- **Combined scoring:** Some systems compute a blended "priority score" from both severity and confidence (e.g., severity weight × confidence) to produce a single ranked queue for analysts — this is a common general design pattern, not a specific claim about NetGuard AI's internal scoring formula unless documented elsewhere.

---

## Network Indicators

While severity and confidence are largely an ML/triage-layer concept rather than a raw network indicator, the underlying network evidence that typically drives both dimensions includes:
- Volumetric anomalies (packet/byte rate spikes) → often drives DoS/DDoS severity classification.
- Authentication-related signals (failed logins, successful logins after failures) → often drives R2L/brute-force severity classification.
- Privilege/session-level indicators (root shell activity, unusual file operations) → often drives U2R/infiltration severity classification.
- Beaconing/timing regularity → often drives Botnet/C2 severity classification.

See the dataset-specific guides (CICIDS-2017 and NSL-KDD) for the exact flow/connection features that feed into these categories.

---

## Machine Learning Perspective

### False Positives vs. False Negatives in SOC Operations
- **False Positive (Type I Error):** Benign traffic misclassified as an attack. Causes unnecessary alerting, wastes analyst time, and risks disrupting legitimate users if acted upon aggressively (e.g., blocking a real customer's IP).
- **False Negative (Type II Error):** Malicious intrusion misclassified as normal. Poses a severe security risk of an undetected breach continuing unchecked.
- **SOC Best Practice (general knowledge):** Classification models used for intrusion detection are commonly tuned with decision-threshold calibration to balance recall (catching the maximum number of true threats) against precision decay (avoiding an overwhelming volume of false alarms), since both extremes carry real operational costs.

### Precision/Recall tradeoff in a security context
- **Optimizing purely for precision** (minimizing false positives) risks missing real attacks (lower recall) — dangerous for high-severity attack types.
- **Optimizing purely for recall** (minimizing false negatives) risks flooding analysts with false alarms (lower precision) — leads to alert fatigue, where analysts may start ignoring or rubber-stamping alerts, ironically making the SOC less effective overall.
- **F1-score** and related balanced metrics are often used to find a reasonable middle ground, though the "right" balance is ultimately a risk-tolerance decision made by the organization, not a purely mathematical one.

### Why probability/confidence output matters more than a bare label
A bare `BENIGN`/`ATTACK` label with no confidence score forces analysts to trust the model completely or ignore it completely. Providing a probability score lets analysts (and downstream systems) apply their own risk tolerance — for example, treating anything below 70% confidence as "needs human review" regardless of severity, while allowing very high-confidence, high-severity predictions to move faster through triage. This is why **NetGuard AI surfaces both a predicted class and a confidence/probability score together**, rather than a classification alone.

### Confidence and RAG-based explanation
When NetGuard AI's RAG chat assistant explains a specific prediction to a user, it can reference both the model's predicted class and its confidence score, and ground its explanation in the documented severity/confidence interpretation described in this file (e.g., "a 92% confidence DDoS classification falls in the High-Confidence tier, which typically means strong feature-vector alignment with known DDoS patterns") — rather than inventing a new, unsupported interpretation on the fly. This reduces the risk of the assistant overstating certainty (e.g., claiming a prediction is "100% confirmed") when the underlying model only produced a probabilistic estimate.

---

## SOC Perspective

For a SOC analyst working with NetGuard AI-style output, the practical workflow typically looks like:

1. **Receive the classification + severity + confidence** from the dashboard/API.
2. **Cross-reference severity against asset criticality** — a "Medium" severity port scan against a critical production database server may warrant faster attention than the default SLA suggests.
3. **Weigh confidence into urgency** — a Critical-severity but low-confidence prediction should still be investigated promptly (because the potential impact is high), just with an expectation that manual verification may reveal it to be a false positive.
4. **Corroborate with other data sources** — authentication logs, firewall logs, threat-intelligence feeds, and endpoint telemetry — before taking any containment action, since a single ML prediction is one input among several an analyst should consider.
5. **Document the decision** — record whether the alert was confirmed as a true positive, dismissed as a false positive, or escalated, both for incident records and to build institutional knowledge about the model's real-world reliability over time.

### Alert fatigue and tuning
A well-known SOC challenge (general knowledge) is **alert fatigue** — when a system generates so many alerts (often driven by too many false positives, or over-aggressive severity/confidence thresholds) that analysts become desensitized and start missing genuinely important alerts. Regularly reviewing the ratio of confirmed true positives to false positives per severity/confidence tier is a common practice for tuning thresholds over time to keep alert volume manageable without sacrificing detection of real threats.

---

## Examples

**Example 1 — Critical severity, high confidence:**
A flow classified as `DDoS` with 96% confidence, showing extremely high packet rate and near-zero backward traffic. This combination (Critical severity + High confidence) typically warrants the fastest available triage path in an organization's SOC playbook.

**Example 2 — High severity, low confidence:**
A flow classified as `Web Attack – SQL Injection` with 58% confidence. Even though confidence is only in the "borderline" range, the severity tier (High) means this should not be deprioritized purely because of the lower confidence — it should be reviewed by an analyst rather than auto-dismissed.

**Example 3 — Low severity, high confidence:**
A flow classified as `BENIGN` with 99% confidence, corresponding to routine HTTPS browsing traffic. This combination requires no analyst action beyond normal baseline logging.

**Example 4 — Ambiguous mid-range case:**
A flow classified as `PortScan` (Medium severity in the matrix above) with 72% confidence (Moderate-confidence tier). This is a reasonable candidate for standard-priority queued review rather than immediate escalation, consistent with both its severity tier and its confidence tier.

---

## Mitigation

As with other files in this knowledge base, mitigation actions described here are **general SOC practice**, not claims about automated NetGuard AI behavior unless explicitly documented:

- **For Critical/High severity alerts:** Analyst-led investigation, coordination with network/firewall teams for potential blocking or rate-limiting decisions, and possible escalation to incident response procedures (see the incident response guide for full detail).
- **For Medium severity alerts:** Continued monitoring, correlation with other log sources, and periodic review to catch any escalation in pattern (e.g., an isolated port scan turning into a sustained brute-force attempt).
- **For Low/Safe classifications:** Routine logging and baseline maintenance; useful for building a normal-traffic profile that can help the model (and analysts) better recognize genuine deviations over time.
- **Threshold and severity-matrix tuning:** Periodically reviewing false-positive/false-negative rates by severity tier and adjusting either the ML decision threshold or the severity-matrix criteria as the organization's traffic patterns and risk tolerance evolve.

---

## Limitations

- **Static severity matrix:** A fixed severity-to-attack-type mapping (as shown above) does not automatically account for context like asset criticality, business hours, or ongoing incidents — it is a useful starting default rather than a complete risk model.
- **Confidence is not ground truth:** As noted above, a high confidence score reflects the model's internal certainty relative to its training data, not a guarantee of real-world correctness.
- **No claimed production accuracy figures:** This document does not assert any specific production-measured false-positive rate, false-negative rate, or model accuracy for NetGuard AI, since those would depend on the specific trained model version, dataset split, and deployment environment, none of which are asserted here as fixed facts.
- **No automated enforcement claimed:** This document does not claim NetGuard AI automatically blocks, isolates, or bans traffic based on severity or confidence output — the documented capability is classification, severity/confidence reporting, and RAG-based explanation, not automated network enforcement.
- **Calibration caveats:** Many practical classifiers (including common Random Forest implementations) are not perfectly probability-calibrated by default; without additional calibration steps (e.g., Platt scaling, isotonic regression), a "90% confidence" score should be read as "high relative confidence" rather than a literal statistical guarantee.

---

## Common Questions

**Q: What is a false positive?**
A: A false positive occurs when benign, legitimate traffic is incorrectly classified as an attack. It causes unnecessary alerting and, if acted upon aggressively, can disrupt legitimate users or systems.

**Q: What is a false negative, and why is it dangerous?**
A: A false negative occurs when actual malicious traffic is incorrectly classified as benign, meaning a real intrusion goes undetected. This is generally considered more dangerous than a false positive because it can allow an attack to proceed unchecked.

**Q: What does a "confidence score" of 85% actually mean?**
A: It means the model's internal probability estimate for its predicted class is 85%, based on how closely the input's features match patterns the model associates with that class from its training data. It is a relative confidence indicator, not a guaranteed accuracy percentage, and should generally be corroborated with other evidence before high-impact action is taken.

**Q: How does NetGuard AI define its severity levels?**
A: NetGuard AI defines four severity tiers — Critical, High, Medium, and Low/Safe — each associated with specific threat profiles (e.g., Critical covers active DDoS floods, confirmed infiltration, and root privilege escalation) and a suggested SOC response timeframe.

**Q: Does a high-confidence prediction mean the traffic is definitely malicious?**
A: No. A high confidence score means the model's output strongly aligns with learned attack patterns, which lowers the likelihood of a false positive relative to a lower-confidence prediction, but it does not eliminate the possibility of one. Analyst verification is still recommended, especially before any containment action.

**Q: Why shouldn't low-confidence, high-severity alerts be ignored?**
A: Because severity reflects potential impact, not certainty. A low-confidence prediction for a high-severity category (like infiltration) could still represent a real, serious threat that the model is simply less certain about — often because the traffic pattern doesn't perfectly match previously seen examples. Ignoring it purely based on confidence risks missing a genuine incident.

**Q: What should a SOC analyst do with a Medium-severity, low-confidence alert?**
A: Generally, log it for monitoring and trend analysis rather than escalating immediately, while watching for whether similar activity recurs or intensifies — since neither the severity nor the confidence level individually indicates urgent action is required.

**Q: Does NetGuard AI automatically block attackers based on severity or confidence?**
A: No — that capability is not documented as part of the project. NetGuard AI's documented function is to classify network traffic, assign a severity interpretation and confidence/probability score, and surface this information through its FastAPI backend, Streamlit dashboard, and RAG chat assistant to support human-led SOC triage and decision-making.

**Q: Why does class imbalance affect confidence scores?**
A: If a model saw very few training examples of a particular attack class, it may systematically be less confident when classifying real instances of that class — not necessarily because the signal is weak, but because it has less data to build strong statistical certainty from.

**Q: How does RAG help explain a NetGuard AI prediction's severity and confidence?**
A: The RAG chat assistant retrieves relevant, previously written and verified documentation — such as this file's severity matrix and confidence-tier definitions — and grounds its explanation in that retrieved text, rather than generating a potentially inaccurate or overconfident explanation purely from the underlying LLM's general knowledge.

---

## Summary

Severity and confidence are two distinct but complementary dimensions for triaging ML-based network intrusion detection output: severity reflects potential impact and urgency, while confidence reflects how strongly the model's output aligns with previously learned patterns. NetGuard AI documents a four-tier severity matrix (Critical, High, Medium, Low/Safe) mapped to specific threat profiles, and a confidence-tier interpretation ranging from very-low to high confidence, both surfaced alongside its ML classification output via the FastAPI backend and Streamlit dashboard. Correctly interpreting these signals — understanding that high confidence does not guarantee correctness, that low confidence does not mean "ignore," and that false positives and false negatives carry different operational costs — is essential for effective SOC triage. NetGuard AI's documented role is producing and explaining these classifications and their associated severity/confidence information; it does not claim automated enforcement actions such as blocking or isolating traffic.
