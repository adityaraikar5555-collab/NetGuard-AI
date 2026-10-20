"""
Multi-Class Attack Classifier and Signature Heuristic Engine for NetGuard AI.

Categorizes detected network anomalies into granular cybersecurity attack families:
1. DoS / DDoS (SYN Flood, Slowloris, UDP Flood)
2. PortScan & Network Reconnaissance
3. Brute Force (SSH, FTP, RDP)
4. Botnet & Command/Control (C2)
5. Web Application Attack (SQLi, XSS, Path Traversal)
6. Infiltration & Data Exfiltration
"""

from typing import Any, Dict, List, Optional, Union
import numpy as np


class MultiClassClassifier:
    """
    Sub-classifies binary anomaly detections into precise cyber threat vectors.
    """

    def classify_flow(self, flow: Dict[str, Any], dataset: str = "CICIDS-2017") -> Dict[str, Any]:
        """
        Evaluates a flow dictionary against multi-class behavioral attack profiles.
        """
        scores: Dict[str, float] = {
            "DOS": 0.0,
            "PORTSCAN": 0.0,
            "BRUTE_FORCE": 0.0,
            "BOTNET": 0.0,
            "WEB_ATTACK": 0.0,
            "INFILTRATION": 0.0,
        }
        signatures: Dict[str, List[str]] = {k: [] for k in scores}

        # Normalize key lookup
        f = {str(k).strip().lower(): v for k, v in flow.items()}

        def _val(keys: List[str], default: float = 0.0) -> float:
            for k in keys:
                if k.lower() in f:
                    try:
                        return float(f[k.lower()])
                    except (ValueError, TypeError):
                        pass
            return default

        dst_port = int(_val(["destination port", "dst_port", "destination_port"], 0))
        syn_flags = _val(["syn flag count", "syn"], 0)
        rst_flags = _val(["rst flag count", "rst"], 0)
        flow_pkts_s = _val(["flow packets/s", "flow_packets_s"], 0)
        flow_bytes_s = _val(["flow bytes/s", "flow_bytes_s"], 0)
        fwd_bytes = _val(["total length of fwd packets", "src_bytes"], 0)
        bwd_bytes = _val(["total length of bwd packets", "dst_bytes"], 0)
        fwd_pkts = _val(["total fwd packets", "count"], 0)
        bwd_pkts = _val(["total backward packets", "srv_count"], 0)
        down_up = _val(["down/up ratio"], 1.0)
        failed_logins = _val(["num_failed_logins"], 0)
        logged_in = _val(["logged_in"], 1)
        serror_rate = _val(["serror_rate", "dst_host_serror_rate"], 0.0)
        diff_srv_rate = _val(["diff_srv_rate"], 0.0)

        # ----------------------------------------------------
        # 1. DoS / DDoS Evaluation
        # ----------------------------------------------------
        if flow_pkts_s > 500 or serror_rate > 0.5:
            scores["DOS"] += 0.4
            signatures["DOS"].append("Abnormally elevated packet rate / SYN error rate")
        if syn_flags > 0 and bwd_pkts == 0:
            scores["DOS"] += 0.35
            signatures["DOS"].append("Unanswered SYN packets without return ACK (SYN Flood pattern)")
        if fwd_pkts > 50 and bwd_pkts < 3:
            scores["DOS"] += 0.25
            signatures["DOS"].append("One-way traffic flooding with negligible response")

        # ----------------------------------------------------
        # 2. PortScan & Reconnaissance
        # ----------------------------------------------------
        if diff_srv_rate > 0.4 or (fwd_pkts < 4 and bwd_bytes == 0):
            scores["PORTSCAN"] += 0.35
            signatures["PORTSCAN"].append("Multi-service connection probe with zero response payload")
        if rst_flags > 0 or syn_flags > 0 and fwd_bytes < 100:
            scores["PORTSCAN"] += 0.3
            signatures["PORTSCAN"].append("Minimal probe payload terminated with RST/SYN (Stealth sweep)")
        if dst_port in (0, 135, 139, 445, 1433, 3306, 5432, 8080):
            scores["PORTSCAN"] += 0.2
            signatures["PORTSCAN"].append("Target port aligns with common vulnerability discovery scans")

        # ----------------------------------------------------
        # 3. Brute Force Evaluation
        # ----------------------------------------------------
        if dst_port in (21, 22, 23, 3389):
            scores["BRUTE_FORCE"] += 0.4
            signatures["BRUTE_FORCE"].append(f"Target port {dst_port} matches standard authentication gateway (SSH/FTP/RDP)")
        if failed_logins > 0 or (logged_in == 0 and fwd_pkts > 10):
            scores["BRUTE_FORCE"] += 0.5
            signatures["BRUTE_FORCE"].append("Repeated failed authentication attempts without valid session token")

        # ----------------------------------------------------
        # 4. Botnet C2 Evaluation
        # ----------------------------------------------------
        if dst_port in (6667, 4444, 5555, 1337, 8000, 9999):
            scores["BOTNET"] += 0.45
            signatures["BOTNET"].append(f"Target port {dst_port} matches known C2 / reverse-shell backdoor channels")
        if fwd_bytes > 0 and fwd_bytes < 150 and bwd_bytes < 150 and fwd_pkts > 5:
            scores["BOTNET"] += 0.3
            signatures["BOTNET"].append("Low-volume periodic telemetry consistent with C2 heartbeat beaconing")

        # ----------------------------------------------------
        # 5. Web Application Attack
        # ----------------------------------------------------
        if dst_port in (80, 443, 8080, 8443):
            scores["WEB_ATTACK"] += 0.25
            signatures["WEB_ATTACK"].append("Target is an exposed HTTP/HTTPS web application interface")
        if fwd_bytes > 1500 and (bwd_bytes < 500 or bwd_pkts < 2):
            scores["WEB_ATTACK"] += 0.35
            signatures["WEB_ATTACK"].append("Disproportionately large HTTP forward payload without downstream data")

        # ----------------------------------------------------
        # 6. Infiltration & Data Exfiltration
        # ----------------------------------------------------
        if fwd_bytes > 50000 and (down_up < 0.15 or bwd_bytes < 2000):
            scores["INFILTRATION"] += 0.5
            signatures["INFILTRATION"].append("Massive forward outbound byte egress with near-zero inbound response")

        # Select highest-scoring family
        best_cat = max(scores, key=scores.get)
        best_score = scores[best_cat]

        FAMILY_DISPLAY = {
            "DOS": "Denial of Service (DoS / DDoS)",
            "PORTSCAN": "Reconnaissance / Port Scan",
            "BRUTE_FORCE": "Credential Brute Force",
            "BOTNET": "Botnet Command & Control (C2)",
            "WEB_ATTACK": "Web Application Exploit",
            "INFILTRATION": "Data Infiltration / Exfiltration",
        }

        if best_score < 0.2:
            return {
                "category_code": "GENERIC_ANOMALY",
                "attack_family": "Uncategorized Anomaly",
                "confidence": 0.65,
                "signatures": ["Flow telemetry diverges from baseline operational limits"],
                "mitre_technique": "T1036 (Masquerading)",
            }

        return {
            "category_code": best_cat,
            "attack_family": FAMILY_DISPLAY.get(best_cat, "Cyber Attack"),
            "confidence": round(min(0.99, 0.60 + best_score * 0.4), 2),
            "signatures": signatures[best_cat] or ["Observed deviation in traffic profile"],
            "all_scores": {k: round(v, 2) for k, v in scores.items()},
        }


multiclass_classifier = MultiClassClassifier()
