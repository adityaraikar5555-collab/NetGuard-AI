# CICIDS-2017 Benchmark Dataset & Network Flow Features Guide

> **Scope note (how to read this document):** This file covers CICIDS-2017 as a general cybersecurity/ML benchmark dataset. Facts about the dataset itself (its creation, features, attack days, statistics) are **general, publicly documented cybersecurity/ML knowledge**. Statements that describe how **NetGuard AI** specifically uses this dataset (e.g., "NetGuard AI trains a Random Forest classifier on these features") are called out explicitly and are limited to what the project actually implements: dataset-driven ML classification, Random Forest models, a FastAPI backend, a Streamlit dashboard, and a RAG-grounded chat assistant. No production deployment metrics, automatic blocking behavior, or unverified capabilities are claimed here.

---

## Overview

**CICIDS-2017** (Canadian Institute for Cybersecurity Intrusion Detection System 2017) is one of the most widely cited benchmark datasets used in academic and applied research for **Network Intrusion Detection Systems (NIDS)** and **machine-learning-based anomaly detection**. It was produced by the Canadian Institute for Cybersecurity (CIC) at the University of New Brunswick (UNB) to address a long-standing problem in the intrusion-detection research community: most older datasets (such as the original 1999 KDD Cup dataset) were outdated, unrealistic, anonymized beyond usefulness, or lacked modern attack types.

CICIDS-2017 provides labeled **bidirectional network flow data** covering both **benign (normal) traffic** and **14 distinct modern attack scenarios**, captured over a five-day period in an emulated small-enterprise network. It is commonly used as training/evaluation data for supervised machine learning models that classify network traffic as either normal or malicious, and — in multiclass settings — identify the specific attack category.

In **NetGuard AI**, CICIDS-2017 is one of the datasets used to train the project's Random Forest-based classification model, and its terminology (attack names, flow feature names) is reused throughout the platform's outputs and its RAG knowledge base so that predictions can be explained in consistent, well-documented language.

---

## Definition

**CICIDS-2017** is a **labeled network traffic dataset** consisting of:
- Full packet captures (`.pcap` files) of real network traffic, and
- Derived, per-flow statistical feature sets (`.csv` files) generated from those captures using the **CICFlowMeter** tool.

Each row (flow record) in the dataset represents a single bidirectional network flow (identified by source IP, destination IP, source port, destination port, and protocol) summarized into roughly **78–80 numerical/statistical features**, plus a **Label** column identifying it as `BENIGN` or one of the attack categories.

Synonyms and related terms you may see used interchangeably:
- "CIC-IDS2017", "CICIDS2017", "CIC IDS 2017"
- "network flow dataset", "flow-based IDS dataset"
- "labeled intrusion detection dataset"
- "CICFlowMeter features" / "flow-level features"

---

## Key Concepts

### Why CICIDS-2017 was created
Earlier benchmark datasets used for IDS research (most notably **KDD Cup 1999** and its cleaned successor **NSL-KDD**) were criticized for:
- Being generated from traffic patterns of the 1990s, which do not reflect modern protocols, application-layer attacks, or encrypted traffic behavior.
- Containing significant redundancy and synthetic artifacts that made models trained on them perform unrealistically well ("dataset artifacts" rather than genuine attack signals).
- Lacking modern attack types such as web application attacks, botnets, and infiltration/lateral movement.

CICIDS-2017 was designed specifically to fix these issues by:
1. Capturing traffic from an emulated but realistic network topology (routers, firewalls, switches, and multiple operating systems).
2. Using a **B-Profile system** to generate realistic "human-like" background/benign traffic (web browsing, email, FTP, SSH, HTTP/HTTPS) based on abstracted behavior profiles of 25 real users.
3. Injecting well-known, contemporary attack tools and techniques on top of that realistic background traffic.
4. Providing full packet captures **and** extracted flow features, so researchers can either work at the packet level or the statistical flow level.

### The 5-day capture structure
The dataset spans **five working days** (Monday through Friday) of an emulated enterprise network:

| Day | Traffic Type |
| :--- | :--- |
| Monday | Entirely benign ("normal") traffic — establishes a baseline. |
| Tuesday | Benign traffic + Brute Force attacks (FTP-Patator, SSH-Patator). |
| Wednesday | Benign traffic + multiple DoS/DDoS attack tools + Heartbleed. |
| Thursday | Benign traffic + Web Attacks (Brute Force, XSS, SQL Injection) and Infiltration. |
| Friday | Benign traffic + Botnet (Ares), PortScan, and DDoS (LOIC). |

This day-by-day structure is useful conceptually (e.g., for time-based train/test splits) but most ML pipelines, including typical CICIDS-2017 workflows, combine the days into a single dataset and then split by row rather than strictly by day.

---

## 14 Attack Classes in CICIDS-2017

1. **DDoS:** Distributed Denial of Service (high-volume TCP/UDP flooding from multiple sources).
2. **DoS Slowloris:** Low-and-slow HTTP header exhaustion attack — keeps many connections open with partial headers.
3. **DoS Slowhttptest:** Slow HTTP body/read starvation attack — a general tool capable of Slowloris-style and R-U-Dead-Yet-style attacks.
4. **DoS Hulk:** Heavy HTTP request volumetric flood ("HTTP Unbearable Load King") using randomized headers to defeat caching.
5. **DoS GoldenEye:** HTTP Keep-Alive & Cache-Control starvation, another HTTP-layer volumetric DoS tool.
6. **Heartbleed:** OpenSSL TLS Heartbeat memory disclosure exploit (**CVE-2014-0160**) — an information-disclosure vulnerability, not a flood.
7. **FTP-Patator:** Automated brute-force credential guessing over FTP (port 21) using the Patator tool.
8. **SSH-Patator:** Automated brute-force credential guessing over SSH (port 22) using the Patator tool.
9. **PortScan:** Reconnaissance port sweep across diverse TCP/UDP ports, typically performed with Nmap.
10. **Bot:** Ares botnet command-and-control (C2) communication and malicious activity (data exfiltration, keylogging simulation).
11. **Web Attack – Brute Force:** HTTP form authentication credential stuffing/guessing against a web login page.
12. **Web Attack – XSS:** Cross-Site Scripting injection attempts against a web application.
13. **Web Attack – SQL Injection:** Database extraction and authentication bypass payloads submitted through web input fields.
14. **Infiltration:** Internal network compromise, post-exploitation pivoting, and simulated exfiltration (e.g., via Dropbox-hosted malware).

These 14 categories are commonly grouped into broader "family" labels for coarser analysis or to address class imbalance:

| Family | Included Sub-Attacks |
| :--- | :--- |
| DoS/DDoS | DDoS, DoS Hulk, DoS GoldenEye, DoS Slowloris, DoS Slowhttptest |
| Brute Force | FTP-Patator, SSH-Patator |
| Web Attack | Web Attack – Brute Force, Web Attack – XSS, Web Attack – SQL Injection |
| Reconnaissance | PortScan |
| Botnet | Bot |
| Infiltration | Infiltration |
| Exploit | Heartbleed |
| Benign | Normal traffic |

---

## Dataset File Structure

The public CICIDS-2017 release is typically distributed as eight CSV files (one or more per capture day, since some heavy attack days are split across a morning/afternoon file), alongside the original `.pcap` packet captures:

| File (typical name) | Day | Contents |
| :--- | :--- | :--- |
| `Monday-WorkingHours.pcap_ISCX.csv` | Monday | Benign traffic only (baseline). |
| `Tuesday-WorkingHours.pcap_ISCX.csv` | Tuesday | Benign + FTP-Patator + SSH-Patator (brute force). |
| `Wednesday-workingHours.pcap_ISCX.csv` | Wednesday | Benign + DoS Slowloris, Slowhttptest, Hulk, GoldenEye + Heartbleed. |
| `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` | Thursday AM | Benign + Web Attack – Brute Force, XSS, SQL Injection. |
| `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv` | Thursday PM | Benign + Infiltration. |
| `Friday-WorkingHours-Morning.pcap_ISCX.csv` | Friday AM | Benign + Bot (Ares botnet). |
| `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` | Friday PM | Benign + PortScan. |
| `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` | Friday PM | Benign + DDoS (LOIC). |

Most ML pipelines concatenate all eight CSVs into a single DataFrame before cleaning, encoding, and splitting into train/test sets, since per-day boundaries are not usually meaningful for row-level classification tasks.

---

## Extended Feature Reference (CICFlowMeter Columns)

Beyond the headline features already covered above, the following additional CICFlowMeter columns commonly appear in the CICIDS-2017 CSVs and are useful for grounding detailed technical questions:

| Feature Name | Description |
| :--- | :--- |
| `Destination Port` | The destination TCP/UDP port of the flow; often strongly correlated with service type (e.g., 80/443 for web, 22 for SSH). |
| `Protocol` | Transport-layer protocol number (e.g., 6 = TCP, 17 = UDP). |
| `Bwd Packet Length Max/Min/Mean/Std` | Statistical packet-size metrics in the backward (response) direction. |
| `Fwd IAT Total/Mean/Std/Max/Min` | Inter-arrival time statistics computed only over forward-direction packets. |
| `Bwd IAT Total/Mean/Std/Max/Min` | Inter-arrival time statistics computed only over backward-direction packets. |
| `Fwd PSH Flags` / `Bwd PSH Flags` | Count of PSH (push) flags seen in each direction, indicating the sender is requesting immediate delivery to the application layer. |
| `Fwd URG Flags` / `Bwd URG Flags` | Count of URG (urgent) flags seen in each direction. |
| `Fwd Header Length` / `Bwd Header Length` | Total bytes used by packet headers in each direction (protocol overhead, distinct from payload). |
| `Fwd Packets/s` / `Bwd Packets/s` | Packet rate computed separately for each direction. |
| `Min Packet Length` / `Max Packet Length` / `Packet Length Mean/Std/Variance` | Aggregate statistics across all packets in the flow, regardless of direction. |
| `FIN/SYN/RST/PSH/ACK/URG/CWE/ECE Flag Count` | Cumulative counts of each individual TCP control flag observed across the whole flow. |
| `Down/Up Ratio` | Ratio of backward to forward packet counts. |
| `Average Packet Size` | Mean size across all packets, combining both directions. |
| `Avg Fwd Segment Size` / `Avg Bwd Segment Size` | Average TCP segment size in each direction. |
| `Fwd Avg Bytes/Bulk`, `Fwd Avg Packets/Bulk`, `Fwd Avg Bulk Rate` | Bulk-transfer statistics for the forward direction (large contiguous data transfers). |
| `Bwd Avg Bytes/Bulk`, `Bwd Avg Packets/Bulk`, `Bwd Avg Bulk Rate` | Bulk-transfer statistics for the backward direction. |
| `Subflow Fwd Packets` / `Subflow Fwd Bytes` / `Subflow Bwd Packets` / `Subflow Bwd Bytes` | Statistics computed on sub-segments of a long flow, useful for spotting bursts hidden inside an otherwise "normal-looking" long connection. |
| `Init_Win_bytes_forward` / `Init_Win_bytes_backward` | Initial TCP window size advertised by each endpoint at connection setup. |
| `act_data_pkt_fwd` | Count of forward packets that actually carried at least 1 byte of payload (excludes pure ACKs). |
| `min_seg_size_forward` | Minimum observed forward-direction TCP segment size. |
| `Active Mean/Std/Max/Min` | How long, on average, the flow was actively transmitting data before going idle. |
| `Idle Mean/Std/Max/Min` | How long, on average, the flow sat idle before resuming activity. |
| `Label` | Ground-truth class: `BENIGN` or one of the 14 attack categories. |

This is the general set of columns researchers reference; **NetGuard AI's own model configuration may not necessarily use every single column above during training** — feature selection (e.g., dropping near-duplicate or zero-variance columns) is a normal part of any ML pipeline built on this dataset, and this document does not assert an exact final feature list used in any specific NetGuard AI training run.

---

## Technical Details

### CICFlowMeter and flow generation
CICIDS-2017's flow-level CSVs are produced by **CICFlowMeter**, a flow generator/analyzer that groups raw packets into **bidirectional flows** and computes statistical summaries. A flow is uniquely identified by a 5-tuple:

```
(Source IP, Destination IP, Source Port, Destination Port, Protocol)
```

A flow terminates on:
- A TCP `FIN` or `RST` flag (natural connection close), or
- An idle timeout (commonly 120 seconds of inactivity — configurable).

Each finished flow is written out as one row with ~78–80 numeric features plus the label.

### Full feature groups (conceptual categories)
The ~78 CICFlowMeter features fall into several conceptual groups. Rather than listing every column name, it is more RAG-useful to understand the *groups*, since questions are usually about a concept ("packet size features", "timing features") rather than one exact column:

| Feature Group | What it captures | Example Columns |
| :--- | :--- | :--- |
| **Duration** | How long the flow lasted | `Flow Duration` |
| **Packet counts** | Number of packets in each direction | `Total Fwd Packets`, `Total Backward Packets` |
| **Byte/length statistics** | Payload size distribution | `Total Length of Fwd Packets`, `Fwd Packet Length Max/Min/Mean/Std` |
| **Flow rate** | Volume per unit time | `Flow Bytes/s`, `Flow Packets/s` |
| **Inter-Arrival Time (IAT)** | Timing gaps between packets | `Flow IAT Mean/Std/Max/Min`, `Fwd IAT Total`, `Bwd IAT Total` |
| **TCP flag counts** | Control-bit usage | `FIN Flag Count`, `SYN Flag Count`, `RST Flag Count`, `PSH Flag Count`, `ACK Flag Count`, `URG Flag Count` |
| **Header/segment size** | Protocol overhead | `Fwd Header Length`, `Bwd Header Length` |
| **Window size** | TCP flow-control state | `Init_Win_bytes_forward`, `Init_Win_bytes_backward` |
| **Activity/idle timing** | Bursting behavior | `Active Mean/Std/Max/Min`, `Idle Mean/Std/Max/Min` |
| **Subflows** | Segmenting long flows into smaller windows | `Subflow Fwd Bytes`, `Subflow Bwd Bytes` |
| **Ratios** | Directional asymmetry | `Down/Up Ratio`, `Average Packet Size` |

### Detailed Key Feature Reference

| Feature Name | Description | Attack Interpretation |
| :--- | :--- | :--- |
| `Flow Duration` | Total duration of the bidirectional flow (microseconds). | DoS floods often have near-0 duration (rapid connect/reset); Slowloris deliberately has extremely long duration. |
| `Total Fwd Packets` / `Total Backward Packets` | Count of packets sent forward (source → dest) and backward. | Floods exhibit high forward packet counts with minimal backward packets (one-directional). |
| `Total Length of Fwd Packets` | Sum of forward payload byte lengths. | High in exfiltration and large-payload web attacks. |
| `Fwd Packet Length Max/Mean/Std` | Statistical packet-size metrics in the forward direction. | Consistent small packet lengths indicate brute force or port scans. |
| `Flow Bytes/s` & `Flow Packets/s` | Flow transmission rate. | Spikes sharply during volumetric DDoS floods. |
| `Flow IAT Mean/Std/Max/Min` | Inter-arrival time between consecutive packets. | Very low-variance, periodic IAT suggests automated/scripted or botnet beaconing traffic rather than human browsing. |
| `FIN / SYN / RST / PSH / ACK Flag Count` | Cumulative TCP flag counts within the flow. | Spikes in `SYN` suggest SYN floods or SYN-based port scanning. Spikes in `RST` suggest rejected/closed scan attempts. |
| `Down/Up Ratio` | Ratio of download to upload packet quantity. | Near 0 indicates one-way scanning or blind flooding (no meaningful response traffic). |
| `Average Packet Size` | Mean size of all packets in the flow. | Infiltration and exfiltration flows can show unusually large average packet sizes. |
| `Subflow Fwd/Bwd Bytes` | Feature count per subflow partition. | Used to detect fragmented or bursty attack patterns hidden inside a longer flow. |
| `Init_Win_bytes_forward/backward` | Initial TCP receive window size advertised by each side. | Useful for distinguishing OS/stack fingerprints and some scanning tool signatures. |
| `Active Mean` / `Idle Mean` | Average duration a flow is "active" (sending data) vs "idle" (no data) before the next burst. | Slowloris and Slow HTTP attacks show long idle periods punctuated by minimal keep-alive activity. |

---

## Detection

From a detection-engineering standpoint, CICIDS-2017-derived features are used in two broad ways:

1. **Statistical / rule-based detection** — simple thresholds on individual features (e.g., "flag if `SYN Flag Count` > N within a short flow duration"). This is fast and interpretable, but brittle: thresholds must be retuned per environment and attacker can adapt.
2. **Machine-learning-based detection** — a classifier (e.g., Random Forest, Gradient Boosting, or a neural network) is trained on the full 78-feature vector to recognize combinations of features that correlate with each attack class, rather than relying on any single threshold. This generalizes better across variations of the same attack family but is less directly "explainable" without additional tooling.

**NetGuard AI specifically** trains a Random Forest classifier over these flow features to output both a predicted class (benign or a specific attack category) and a prediction probability/confidence score, which is then surfaced through the FastAPI backend to the Streamlit dashboard and referenced by the RAG chat assistant when explaining a given prediction.

### Practical detection signals by attack family (general knowledge)

| Attack Family | Strongest CICIDS-2017 Signal(s) |
| :--- | :--- |
| DDoS / Volumetric DoS | Extremely high `Flow Packets/s` and `Flow Bytes/s`, very short `Flow Duration`, near-zero backward packets. |
| Slowloris / Slowhttptest | Very long `Flow Duration`, low `Flow Bytes/s`, high `Idle` time, minimal forward payload length. |
| Brute Force (FTP/SSH-Patator) | Many short, repetitive flows to the same destination port, consistent small packet sizes, regular IAT. |
| PortScan | Many flows to different destination ports from the same source, very short duration, high `RST Flag Count`. |
| Web Attacks (XSS/SQLi/Brute Force) | Elevated `Fwd Packet Length`, unusual HTTP-layer payload sizes, repeated requests to the same URI path (visible at the packet/log level more than the flow level). |
| Bot (C2) | Regular, low-variance beaconing intervals (`Flow IAT` with low standard deviation), small consistent payload sizes over time. |
| Infiltration | Larger-than-normal payloads over sustained internal-to-internal or internal-to-external flows, atypical destination ports. |
| Heartbleed | Anomalous TLS record/packet size patterns; this is more visible at the packet-payload level than in flow statistics alone. |

---

## Network Indicators

Analysts and detection systems commonly look for these network-level indicators when investigating CICIDS-2017-style attack traffic in a live environment:

- **Volumetric spikes:** Sudden, sustained increase in packets-per-second or bytes-per-second to/from a single host or subnet.
- **Skewed flag distributions:** A destination host receiving abnormal ratios of `SYN` to `SYN-ACK`/`ACK`, indicating incomplete handshakes.
- **Port fan-out:** A single source IP contacting many distinct destination ports on one or a few hosts in a short window (classic scanning signature).
- **Destination fan-in:** Many distinct source IPs contacting a single destination IP/port simultaneously (classic DDoS signature).
- **Regular timing intervals:** Beacon-like, highly regular time gaps between connections to the same external IP (botnet C2 indicator).
- **Long-lived low-throughput connections:** Many concurrent connections that stay open but transmit very little data (Slowloris-family indicator).
- **Repeated authentication attempts:** Bursts of short flows to authentication ports (21/FTP, 22/SSH, or HTTP login endpoints) from the same source.

---

## Machine Learning Perspective

### Supervised classification on CICIDS-2017
CICIDS-2017 is most often used as a **supervised learning** dataset: each flow already has a ground-truth `Label`, so models are trained to map the 78-feature vector to a class (either binary: `BENIGN` vs `ATTACK`, or multiclass: one of the 14 specific attack categories plus `BENIGN`).

Common algorithms applied to this dataset in research and in projects like NetGuard AI include:
- **Random Forest** — an ensemble of decision trees; each tree votes and the majority (or averaged probability) becomes the prediction. Well suited to tabular, mixed-scale features like CICIDS-2017's, resistant to overfitting relative to a single decision tree, and it naturally provides **feature importance** rankings.
- **Decision Trees** — the individual building block of a Random Forest; more interpretable alone but more prone to overfitting.
- Other approaches seen in the broader literature (general knowledge, not necessarily used by NetGuard AI): Gradient Boosting (XGBoost/LightGBM), Support Vector Machines, and various deep learning architectures (CNNs/LSTMs applied to flow sequences).

**NetGuard AI** uses a Random Forest model trained on CICIDS-2017 (alongside NSL-KDD) and reports a prediction along with a **probability/confidence score** for each classified flow.

### Feature importance
Random Forest models can rank which features contributed most to splitting decisions across the ensemble. On CICIDS-2017, features related to **flow duration, packet/byte rates, and flag counts** are typically among the most discriminative, because these directly capture the volumetric or timing signature that separates attack traffic from benign traffic.

### Class imbalance
CICIDS-2017 is **heavily imbalanced**: benign traffic vastly outnumbers most attack classes, and some rare classes (e.g., Heartbleed, Infiltration) may have only a few hundred samples compared to hundreds of thousands of benign or DDoS flows. This has real ML consequences:
- A naive model can achieve high **accuracy** simply by predicting "benign" most of the time, while still missing rare attacks entirely.
- **Precision, recall, and F1-score per class** are more informative than overall accuracy.
- Mitigation techniques (general knowledge) include: class weighting, oversampling rare classes (e.g., SMOTE), undersampling the majority class, or using ensemble methods that are naturally more robust to imbalance (like Random Forest with balanced class weights).

### Preprocessing considerations
- **Infinite/NaN values:** `Flow Bytes/s` and `Flow Packets/s` can become infinite when `Flow Duration` is 0 (division by zero); these must be cleaned or capped before training.
- **Feature scaling:** Because features span vastly different numeric ranges (durations in microseconds vs. small flag counts), standardization or min-max normalization is typically applied, especially for distance-based or gradient-based models (less critical for tree-based models like Random Forest, which are scale-invariant).
- **Categorical encoding:** CICIDS-2017 is mostly numeric already (unlike NSL-KDD), which simplifies preprocessing, though the `Label` column itself must be encoded for multiclass training.
- **Redundant/highly correlated features:** Some of the 78 features are near-duplicates of others (e.g., different statistical summaries of the same underlying quantity) and may be pruned during feature selection.

### Overfitting, underfitting, and validation
- **Overfitting:** A model memorizes noise or dataset-specific quirks (e.g., "Heartbleed" always coming from one specific IP in this capture) rather than learning generalizable attack signatures. It performs very well on CICIDS-2017's test split but poorly on new/unseen traffic.
- **Underfitting:** A model is too simple to capture the relationship between the 78 features and the labels, resulting in poor performance even on the training data.
- **Train/test split & validation:** Common practice is to hold out a percentage of flows (e.g., 20-30%) as a test set, and optionally use k-fold cross-validation on the training portion to tune hyperparameters (e.g., number of trees, tree depth) before final evaluation.

### Evaluation metrics (general ML knowledge)
| Metric | Meaning | Why it matters for IDS |
| :--- | :--- | :--- |
| **Accuracy** | Fraction of all predictions that are correct. | Misleading under class imbalance — can look high while missing rare attacks. |
| **Precision** | Of all flows predicted as "attack", how many were truly attacks. | High precision = fewer false alarms for analysts to chase. |
| **Recall** | Of all true attacks, how many were correctly detected. | High recall = fewer missed intrusions (false negatives). |
| **F1-score** | Harmonic mean of precision and recall. | Balances the two when there is no single "more important" metric. |
| **Confusion Matrix** | Table of predicted vs. actual classes. | Shows exactly which classes are confused with which (e.g., DoS Hulk vs. DoS GoldenEye). |
| **ROC-AUC** | Area under the Receiver Operating Characteristic curve; measures separability of classes across thresholds. | Useful for tuning the decision threshold rather than relying on a fixed 0.5 cutoff. |

### Concept drift and adversarial evasion (general knowledge)
- **Concept drift** refers to the fact that real-world network traffic patterns change over time (new applications, new protocols, new attacker tooling), so a model trained purely on a 2017 dataset may become less accurate on today's traffic without periodic retraining.
- **Adversarial evasion** refers to attackers deliberately shaping their traffic (e.g., padding packets, randomizing timing) to avoid matching the statistical signatures a model was trained on. This is a known limitation of any static, dataset-trained IDS model, including flow-feature-based classifiers.

### Comparison with NSL-KDD (context)
CICIDS-2017 is often discussed alongside **NSL-KDD** (covered in a separate knowledge-base file) because both are common IDS benchmark datasets, but they differ substantially:

| Aspect | CICIDS-2017 | NSL-KDD |
| :--- | :--- | :--- |
| Era of traffic | 2017 (modern protocols) | Derived from 1999 KDD Cup (dated protocols) |
| Feature count | ~78 flow-level statistical features | 41 features (mix of basic, content, and traffic features) |
| Attack categories | 14 specific attack types | 4 broad categories (DoS, Probe, R2L, U2R) plus Normal |
| Feature style | Purely flow/timing/byte statistics via CICFlowMeter | Mix of connection-level, content-based, and traffic-based features |
| Realism of benign traffic | Generated via behavior-profiled simulated users | Derived from older simulated military network traffic |

NetGuard AI uses **both** datasets as complementary training sources: CICIDS-2017 contributes modern, fine-grained flow statistics and specific attack sub-types, while NSL-KDD contributes a well-established, cleaned benchmark with broader attack-family labels. See the NSL-KDD guide for full detail on that dataset.

---

## Retrieval-Augmented Generation (RAG) Notes for This Topic

When NetGuard AI's chat assistant answers a question about CICIDS-2017, it retrieves relevant chunks of this document (e.g., the feature reference table, the attack class list, or the FAQ) and grounds its answer in that retrieved text rather than relying purely on the underlying LLM's general training knowledge. This reduces hallucination risk on dataset-specific numeric details (e.g., exact feature counts, exact attack class names) because the answer is anchored to text that was explicitly written and verified for this knowledge base, rather than generated freely. Where a user's question goes beyond what is documented here (e.g., asking about a completely different dataset not covered in this knowledge base), the assistant should fall back to general knowledge and be transparent that the answer is not sourced from the project-specific documentation.

---

## SOC Perspective

For a Security Operations Center (SOC) analyst, CICIDS-2017-style flow features map directly onto real triage questions:

- **"Is this a flood or a scan?"** → Compare `Flow Duration`, packet direction ratio, and destination port diversity.
- **"Is this automated or human?"** → Look at `Flow IAT` variance; low variance = scripted/automated behavior.
- **"Is this exfiltration?"** → Look for unusually large `Total Length of Fwd/Bwd Packets` on connections to unfamiliar external destinations.
- **"How confident should I be before escalating?"** → Combine the model's predicted class with its confidence/probability score, and cross-reference with other logs (firewall, proxy, authentication) before deciding on containment steps.

A well-designed NIDS trained on datasets like CICIDS-2017 does not replace analyst judgment — it triages and prioritizes traffic so analysts can focus attention on the flows most likely to represent genuine threats, and it provides feature-level evidence (e.g., "this flow had 40,000 packets in 2 seconds, all SYN, no response") that supports faster investigation.

---

## Examples

**Example 1 — DDoS flow signature:**
A single destination IP receives thousands of flows within seconds, each with `Total Fwd Packets` high, `Total Backward Packets` near 0, `Flow Duration` under 1 second, and `SYN Flag Count` elevated. This pattern is consistent with a volumetric SYN-flood-style DDoS.

**Example 2 — Slowloris signature:**
A web server sees many connections with `Flow Duration` measured in minutes, extremely low `Flow Bytes/s`, and long `Idle Mean` values — consistent with attackers holding connections open using partial HTTP headers to exhaust the server's connection pool.

**Example 3 — PortScan signature:**
One source IP generates hundreds of very short flows (under a few hundred milliseconds each) to sequential or random destination ports on the same target host, each ending quickly with a `RST` flag — consistent with an Nmap-style TCP scan.

**Example 4 — SSH-Patator (brute force) signature:**
Many short flows to destination port 22 from the same source IP, each with small, similar packet sizes and short duration, occurring in rapid succession — consistent with automated credential-guessing.

---

## Mitigation

General network defense measures relevant to the attack families represented in CICIDS-2017 (general cybersecurity knowledge; NetGuard AI itself is a detection/classification and knowledge-assistant platform and does not claim to perform these mitigations automatically unless explicitly documented elsewhere in the project):

- **DoS/DDoS:** Rate limiting, SYN cookies, upstream scrubbing/traffic-shaping, and CDN-based absorption for volumetric floods; connection-timeout tuning and reverse-proxy request limits for Slowloris-style attacks.
- **Brute Force:** Account lockout policies, multi-factor authentication, fail2ban-style IP banning after repeated failures, and disabling password auth in favor of key-based auth for SSH.
- **PortScan/Reconnaissance:** Network segmentation, minimizing exposed services, and alerting on scan-like fan-out behavior.
- **Web Attacks (XSS/SQLi/Brute Force):** Input validation/sanitization, parameterized queries, a Web Application Firewall (WAF), and rate-limiting login endpoints.
- **Bot/C2:** Egress filtering, DNS monitoring for known C2 domains, and endpoint detection for known bot behavior.
- **Infiltration:** Network segmentation/least privilege, monitoring for unusual internal lateral movement, and data-loss-prevention (DLP) controls on outbound traffic.
- **Heartbleed-class vulnerabilities:** Timely patch management and TLS library version monitoring.

An intrusion detection system trained on data like CICIDS-2017 supports these mitigations by **surfacing the relevant alerts and evidence early**, which shortens the time between attack onset and human/automated response — but the actual blocking, patching, or containment action is a separate operational step from the classification itself.

---

## Limitations

It is important to represent these limitations accurately (general, well-documented critiques of the dataset in the research community):

- **Age of the dataset:** Captured in 2017; some traffic patterns, application versions, and attacker tooling are dated relative to current threats.
- **Emulated environment:** Traffic was generated in a controlled testbed with a fixed topology and a limited number of simulated users (25 user profiles), which may not capture the full diversity of a real enterprise network.
- **Class imbalance:** As noted above, several attack classes are severely underrepresented, which can bias models toward the majority classes if not addressed.
- **Some labeling inconsistencies:** Independent research has identified minor labeling errors and duplicate/near-duplicate flows in portions of the public CSV release, which downstream users should be aware of during preprocessing.
- **Feature leakage risk:** A few features (e.g., certain flag counts or flow durations) can become "too easy" a shortcut for the model in this specific capture, which may not generalize to differently configured networks.
- **Static snapshot:** Like any static dataset, a model trained solely on CICIDS-2017 will not automatically account for concept drift (new applications, new attack tools) without retraining on newer data.
- **No production performance claims:** This document does not state any specific accuracy, false-positive rate, or latency figure for CICIDS-2017-trained models in a live NetGuard AI deployment, since those numbers depend on training run configuration and are not asserted here as fixed facts.

---

## Common Questions

**Q: What is CICIDS-2017?**
A: It is a labeled network traffic benchmark dataset created by the Canadian Institute for Cybersecurity, containing benign traffic and 14 categories of modern network attacks, captured over five days and summarized into ~78 statistical flow features per record.

**Q: What does Flow Duration mean?**
A: It is the total time (in microseconds) that a bidirectional network flow lasted, from its first packet to its last. Extremely short durations often indicate rapid connect/reset behavior (e.g., scans or floods), while extremely long durations can indicate slow, resource-exhaustion attacks like Slowloris.

**Q: How many attack classes does CICIDS-2017 have?**
A: 14 distinct attack classes, plus the `BENIGN` label, spanning DoS/DDoS, brute force, port scanning, botnet, web attacks, infiltration, and the Heartbleed exploit.

**Q: What tool generates the flow features in CICIDS-2017?**
A: CICFlowMeter, which converts raw packet captures into bidirectional flow records with statistical summaries (duration, packet/byte counts, IAT, flag counts, and more).

**Q: Why is class imbalance a problem in CICIDS-2017?**
A: Because benign traffic and some attacks like DDoS have far more samples than rare classes like Heartbleed or Infiltration, a model can achieve high overall accuracy while still failing to detect the rare, often more severe, attacks. Per-class precision/recall/F1 give a clearer picture than accuracy alone.

**Q: How does NetGuard AI use CICIDS-2017?**
A: NetGuard AI uses CICIDS-2017 (alongside NSL-KDD) as training data for a Random Forest classification model that predicts whether a flow is benign or a specific attack category, along with a confidence/probability score, exposed through its FastAPI backend and Streamlit dashboard.

**Q: Is CICIDS-2017 realistic enough for production intrusion detection?**
A: It is considered a strong academic benchmark and is widely used in research, but it has known limitations (dataset age, emulated topology, class imbalance) that mean models trained on it should be validated against current, real-world traffic before being trusted for production use.

**Q: What's the difference between a SYN flood signature and a PortScan signature in this dataset?**
A: Both can show elevated `SYN Flag Count`, but a SYN flood typically targets one destination with a high `Flow Packets/s` rate and near-zero backward packets, while a PortScan shows one source contacting many different destination ports/hosts with very short, quickly-reset flows.

**Q: Why does Flow Bytes/s sometimes appear as infinite or NaN?**
A: When `Flow Duration` is 0 (an extremely short-lived flow), dividing bytes by duration produces an undefined/infinite result. This must be handled during preprocessing (capping, replacing, or filtering such rows) before model training.

**Q: Does CICIDS-2017 include encrypted traffic content?**
A: The flow-level features are derived from packet metadata and timing/size statistics rather than decrypted payload content, so the dataset is usable even for traffic that is encrypted (e.g., HTTPS), since it does not require reading the actual message contents — only the statistical shape of the communication.

**Q: How is CICIDS-2017 organized into files?**
A: It is typically distributed as eight CSV files corresponding to the five capture days (with Thursday and Friday split into morning/afternoon segments), plus the original packet captures. Most pipelines merge all eight CSVs before training.

**Q: What is CICFlowMeter?**
A: It is the tool used to convert raw packet captures into bidirectional network flow records, computing the ~78 statistical features (duration, packet/byte counts, inter-arrival times, flag counts, and more) that make up each row of the CICIDS-2017 dataset.

**Q: Can a model trained on CICIDS-2017 detect brand-new, never-before-seen attacks?**
A: Not reliably. Supervised models trained on this dataset learn to recognize patterns similar to the 14 labeled attack types they were trained on. Detecting genuinely novel (zero-day) attack behavior generally requires unsupervised or semi-supervised anomaly detection approaches, ongoing retraining, or complementary detection layers, since a purely supervised classifier is fundamentally limited to the classes it has seen labeled examples of.

**Q: What is the difference between DoS Hulk and DoS GoldenEye in this dataset?**
A: Both are HTTP-layer volumetric denial-of-service tools included in CICIDS-2017's Wednesday capture. DoS Hulk generates a high volume of randomized HTTP requests to defeat caching and overwhelm the web server, while DoS GoldenEye focuses on exhausting server resources via HTTP Keep-Alive and Cache-Control header manipulation. At the flow-feature level both typically show short durations and high request rates, though their exact packet/byte statistics can differ.

---

## Summary

CICIDS-2017 is a modern, realistic, and widely used benchmark dataset for network intrusion detection research, offering both raw packet captures and ~78-feature bidirectional flow statistics across benign traffic and 14 attack categories captured over five days. Its flow-level features — duration, packet/byte counts, inter-arrival timing, and TCP flag distributions — provide strong, interpretable signals for distinguishing attack families such as DoS/DDoS, brute force, port scanning, botnets, web attacks, and infiltration. It is a core training dataset for NetGuard AI's Random Forest-based classification model, complementing NSL-KDD, and its terminology underpins how the platform explains its predictions. Its known limitations — dataset age, class imbalance, and emulated-network scope — mean it should be understood as a strong research benchmark rather than a guarantee of real-world production accuracy.
