# Severity Interpretation, Prediction Confidence & Model Triage Guide

## Overview
In a modern Security Operations Center (SOC), machine learning classifications must be translated into actionable triage priorities. An anomaly flag by itself is insufficient; analysts require contextual severity ratings, probabilistic confidence indicators, and clear distinction between confirmed facts and model inferences.

---

## NetGuard AI Severity Classification Matrix

| Severity Level | Color Code | Criteria & Threat Profiles | Operational Response SLA |
| :--- | :--- | :--- | :--- |
| **Critical** | 🔴 Crimson (`#ef4444`) | Active High-Bandwidth DDoS Floods, Confirmed Infiltration, Root Privilege Escalation (U2R), Active C2 Beaconing with Exfiltration. | **Immediate (0 - 15 minutes)**: Automated isolation, perimeter rate-limiting, Tier-3 escalation. |
| **High** | 🟠 Amber-Orange (`#fb923c`) | DoS Hulk/GoldenEye, Persistent SSH/FTP Brute Force, Web SQL Injection / RCE attempts, Heavy Port Sweep on core servers. | **Urgent (15 - 60 minutes)**: Firewall block rule generation, IP ban via Fail2ban, credential rotation. |
| **Medium** | 🟡 Yellow (`#fbbf24`) | Isolated Port Scanning (Probe), Single failed login bursts, Suspicious HTTP headers, Slowloris partial probes. | **Standard (1 - 4 hours)**: Log monitoring, IDS rule tuning, anomaly trend analysis. |
| **Low / Safe** | 🟢 Emerald (`#10b981`) | Normal routine network traffic (Benign / Normal flows, valid HTTP/HTTPS/DNS sessions, expected backup replication). | **Informational**: Baseline telemetry recording. |

---

## Machine Learning Confidence & Probability Interpretation

In NetGuard AI, the ML inference engine outputs a prediction alongside a probability distribution (via `predict_proba()` or decision function scores).

### 1. High Confidence (Confidence >= 90%)
- **Interpretation:** The flow's feature vector strongly aligns with known attack signatures (e.g., thousands of small SYN packets with 0 byte payloads).
- **SOC Action:** Low likelihood of false positive. Immediate containment actions can be automated or approved rapidly.

### 2. Moderate Confidence (70% <= Confidence < 90%)
- **Interpretation:** The flow shows clear anomalous tendencies (e.g., elevated error rates or unusual packet ratios), but exhibits some normal baseline characteristics.
- **SOC Action:** Analyst verification required. Cross-reference source IP with threat intelligence feeds and application logs before applying permanent blocks.

### 3. Low Confidence / Borderline (50% <= Confidence < 70%)
- **Interpretation:** The feature vector lies near the model's decision boundary. Often triggered by bursty legitimate user traffic (e.g., file downloads, software updates).
- **SOC Action:** Flagged for observation. Avoid aggressive automated bans to prevent false-positive denial of service for legitimate users.

---

## False Positives vs False Negatives in SOC Operations
- **False Positive (Type I Error):** Benign traffic misclassified as an attack. Causes unnecessary alerting and risk of blocking legitimate customers.
- **False Negative (Type II Error):** Malicious intrusion misclassified as normal. Poses severe security risk of undetected breach.
- **SOC Best Practice:** NetGuard AI models are tuned with decision threshold calibration to balance recall (catching maximum threats) while minimizing precision decay.
