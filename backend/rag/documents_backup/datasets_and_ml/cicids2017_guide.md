# CICIDS-2017 Benchmark Dataset & Network Flow Features Guide

## Dataset Background
The **CICIDS-2017** dataset (Canadian Institute for Cybersecurity, University of New Brunswick) is one of the most widely used network intrusion detection benchmarks. It captures realistic benign traffic alongside 14 modern network attack profiles generated over a 5-day capture window in an emulated enterprise environment.

---

## 14 Attack Classes in CICIDS-2017
1. **DDoS:** Distributed Denial of Service (High-volume TCP/UDP flooding).
2. **DoS Slowloris:** Low-and-slow HTTP header exhaustion attack.
3. **DoS Slowhttptest:** Slow HTTP body/read starvation attack.
4. **DoS Hulk:** Heavy HTTP request volumetric flood.
5. **DoS GoldenEye:** HTTP Keep-Alive & Cache-Control starvation.
6. **Heartbleed:** OpenSSL TLS Heartbeat memory disclosure exploit (CVE-2014-0160).
7. **FTP-Patator:** Automated brute-force credential guessing over FTP (port 21).
8. **SSH-Patator:** Automated brute-force credential guessing over SSH (port 22).
9. **PortScan:** Reconnaissance port sweep across diverse TCP/UDP ports.
10. **Bot:** Ares botnet C2 communication and malicious activity.
11. **Web Attack - Brute Force:** HTTP form authentication credential stuffing.
12. **Web Attack - XSS:** Cross-Site Scripting injection attempts.
13. **Web Attack - SQL Injection:** Database extraction and authentication bypass payloads.
14. **Infiltration:** Internal network compromise, post-exploitation pivoting, and Dropbox exfiltration.

---

## Key Flow Features & Technical Meaning

The dataset extracts 78 statistical network flow features via CICFlowMeter:

| Feature Name | Description | Attack Interpretation |
| :--- | :--- | :--- |
| `Flow Duration` | Total duration of the bidirectional flow (microseconds). | DoS floods have near-0 duration; Slowloris has extremely long duration. |
| `Total Fwd Packets` / `Total Backward Packets` | Count of packets sent forward (source -> dest) and backward. | Floods exhibit high forward packets with minimal backward packets. |
| `Total Length of Fwd Packets` | Sum of forward payload byte lengths. | High in exfiltration and large payload web attacks. |
| `Fwd Packet Length Max/Mean/Std` | Statistical packet size metrics in forward direction. | Consistent small packet lengths indicate brute force or port scans. |
| `Flow Bytes/s` & `Flow Packets/s` | Flow transmission rate per microsecond. | Skyrockets during volumetric DDoS floods (> 100,000 pps). |
| `Flow IAT Mean/Std/Max/Min` | Inter-arrival time between consecutive packets. | Periodic low-variance IAT indicates automated botnet beaconing. |
| `FIN / SYN / RST / PSH / ACK Flag Count` | Cumulative TCP flag counts within the flow. | Spikes in `SYN` indicate SYN floods or SYN port scanning. Spikes in `RST` indicate rejected scans. |
| `Down/Up Ratio` | Ratio of download to upload packet quantity. | 0 indicates one-way scanning or blind flooding. |
| `Average Packet Size` | Mean size of all packets in the flow. | Infiltration and exfiltration exhibit high average packet sizes. |
| `Subflow Fwd/Bwd Bytes` | Feature count per subflow partition. | Used to detect fragmented attack patterns. |

---

## Model Strengths & Practical Considerations
- **High Realism:** Bidirectional full-packet flow statistics capture complex temporal and volumetric behavior.
- **Preprocessing:** Features require standard scaling / min-max normalization and handling of extreme outliers (`inf` values in Flow Bytes/s).
- **Multiclass vs Binary:** In NetGuard AI, models classify traffic as Benign vs Anomaly with granular attack sub-type identification and confidence scoring.
