"""
NetGuard AI — Proactive Threat Hunting & Concept Drift Agent (Step 3)

An autonomous MLOps and Cyber Threat Hunting Agent that:
1. Monitors traffic distributions using the Population Stability Index (PSI).
2. Uncovers "low-and-slow" stealth attack clusters that evade standard binary thresholds.
3. Correlates drifting features with the MITRE ATT&CK enterprise matrix.
4. Synthesizes proactive threat hunting hypotheses, hunting queries, and MLOps retraining guidance.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union

import numpy as np
import pandas as pd

from src.drift_monitor import drift_monitor
from src.soar_engine import soar_engine
from backend.rag.generator import call_llm


@dataclass
class ThreatHuntingReport:
    """Structured report produced by the Autonomous Threat Hunting Agent."""
    hunt_id: str
    drift_status: str  # STABLE, MODERATE_DRIFT, SEVERE_DRIFT
    global_psi: float
    dataset: str
    total_flows_evaluated: int
    drifting_features: Dict[str, float]
    stealth_clusters: List[Dict[str, Any]]
    hypotheses: List[Dict[str, Any]]
    mitre_correlations: List[Dict[str, Any]]
    retraining_recommended: bool
    recommended_playbook: str
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ThreatHuntingAgent:
    """
    Autonomous Proactive Threat Hunter & Distribution Drift Agent.
    """

    def __init__(self, monitor=None):
        self.monitor = monitor or drift_monitor

    def hunt(
        self,
        data: Union[pd.DataFrame, List[Dict[str, Any]], Dict[str, Any]],
        dataset: str = "CICIDS-2017",
    ) -> ThreatHuntingReport:
        """
        Conducts an autonomous threat hunting cycle over a batch of network flows.
        """
        hunt_id = f"HUNT-{int(time.time() * 1000) % 1000000:06d}"

        # 1. Normalize data into DataFrame
        if isinstance(data, pd.DataFrame):
            df = data.copy()
        elif isinstance(data, list):
            df = pd.DataFrame(data)
        elif isinstance(data, dict):
            if "features" in data and isinstance(data["features"], dict):
                df = pd.DataFrame([data["features"]])
            else:
                df = pd.DataFrame([data])
        else:
            df = pd.DataFrame()

        total_flows = len(df)

        # 2. Evaluate Data Drift via Population Stability Index (PSI)
        drift_eval = self.monitor.evaluate_batch_drift(df, dataset=dataset) if not df.empty else {
            "status": "STABLE",
            "overall_psi": 0.04,
            "feature_drift": {},
            "recommendation": "Feature distributions match established normal traffic baselines.",
        }

        global_psi = float(drift_eval.get("overall_psi", 0.04))
        drifting_feats = drift_eval.get("feature_drift", {})

        # Categorize drift status
        if global_psi >= 0.25 or any(v >= 0.25 for v in drifting_feats.values()):
            drift_status = "SEVERE_DRIFT"
            retraining_recommended = True
        elif global_psi >= 0.10 or any(v >= 0.10 for v in drifting_feats.values()):
            drift_status = "MODERATE_DRIFT"
            retraining_recommended = False
        else:
            drift_status = "STABLE"
            retraining_recommended = False

        # 3. Detect Sub-Threshold Stealth Attack Clusters
        stealth_clusters = self._detect_stealth_clusters(df, dataset)

        # 4. Map Drifting Features to MITRE ATT&CK Tactics
        mitre_correlations = self._correlate_mitre(drifting_feats, stealth_clusters)

        # 5. Formulate Autonomous Threat Hunting Hypotheses
        hypotheses = self._formulate_hypotheses(
            hunt_id=hunt_id,
            drift_status=drift_status,
            global_psi=global_psi,
            drifting_feats=drifting_feats,
            stealth_clusters=stealth_clusters,
            mitre_correlations=mitre_correlations,
        )

        # 6. Synthesize Recommended SOC Playbook
        if drift_status == "SEVERE_DRIFT" or len(stealth_clusters) > 0:
            recommended_playbook = (
                "Deploy proactive canary honeypots on target ports; isolate offending source IPs identified in "
                "stealth clusters; export Splunk/SIEM hunt queries to correlate external egress logs; "
                "schedule an MLOps model retraining checkpoint with current traffic distribution."
            )
        else:
            recommended_playbook = (
                "Traffic distribution is stable. Continue baseline telemetry polling; no immediate containment required."
            )

        return ThreatHuntingReport(
            hunt_id=hunt_id,
            drift_status=drift_status,
            global_psi=round(global_psi, 4),
            dataset=dataset,
            total_flows_evaluated=total_flows,
            drifting_features=drifting_feats,
            stealth_clusters=stealth_clusters,
            hypotheses=hypotheses,
            mitre_correlations=mitre_correlations,
            retraining_recommended=retraining_recommended,
            recommended_playbook=recommended_playbook,
        )

    def _detect_stealth_clusters(self, df: pd.DataFrame, dataset: str) -> List[Dict[str, Any]]:
        """
        Uncovers low-and-slow threats (flows with subtle anomaly markers that individually evade thresholds).
        """
        clusters: List[Dict[str, Any]] = []
        if df.empty:
            # Provide sample stealth pattern for demonstration when empty
            return [
                {
                    "cluster_type": "Low-and-Slow Port Sweep",
                    "suspect_ip": "198.51.100.42",
                    "target_ports": [22, 80, 443, 8080],
                    "flow_count": 14,
                    "avg_packet_rate": 0.8,
                    "evidence": "Distributed single-packet probes with 45s intervals to bypass rate limiters.",
                    "confidence": 0.88,
                }
            ]

        # Check for destination port sweeps
        port_cols = [c for c in df.columns if "port" in str(c).lower()]
        if port_cols:
            p_col = port_cols[0]
            val_counts = df[p_col].value_counts()
            unique_ports = len(val_counts)
            if unique_ports >= 4:
                clusters.append({
                    "cluster_type": "Multi-Port Probe Cluster",
                    "suspect_ip": "External Scanner Pool",
                    "target_ports": [int(p) for p in val_counts.index[:5] if pd.notnull(p)],
                    "flow_count": int(len(df)),
                    "evidence": f"Broad multi-port sweep across {unique_ports} unique ports.",
                    "confidence": 0.85,
                })

        # Check for SYN flag dominance without data
        syn_cols = [c for c in df.columns if "syn" in str(c).lower()]
        if syn_cols:
            syn_sum = df[syn_cols[0]].sum()
            if syn_sum > len(df) * 0.4:
                clusters.append({
                    "cluster_type": "Sub-Threshold SYN Infiltration",
                    "suspect_ip": "Distributed Ingress",
                    "target_ports": [80, 443],
                    "flow_count": int(syn_sum),
                    "evidence": "Abnormally high SYN-to-data ratio in ambient traffic.",
                    "confidence": 0.90,
                })

        return clusters

    def _correlate_mitre(
        self,
        drifting_feats: Dict[str, float],
        stealth_clusters: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Maps drifting telemetry dimensions to MITRE ATT&CK techniques."""
        correlations = []
        feat_names = [f.lower() for f in drifting_feats.keys()]

        # Exfiltration check
        if any("byte" in f or "length" in f for f in feat_names):
            correlations.append({
                "tactic": "Exfiltration (TA0010)",
                "technique_id": "T1048",
                "technique_name": "Exfiltration Over Alternative Protocol",
                "risk_driver": "Significant drift in payload byte volume distributions.",
            })

        # Discovery / Reconnaissance check
        if any("port" in f or "count" in f or "rate" in f for f in feat_names) or len(stealth_clusters) > 0:
            correlations.append({
                "tactic": "Discovery (TA0007)",
                "technique_id": "T1046",
                "technique_name": "Network Service Discovery",
                "risk_driver": "Anomalous multi-port connectivity patterns and connection frequency shift.",
            })

        # Credential Access check
        if any("login" in f or "fail" in f for f in feat_names):
            correlations.append({
                "tactic": "Credential Access (TA0006)",
                "technique_id": "T1110",
                "technique_name": "Brute Force",
                "risk_driver": "Elevated failed authentication attempts exceeding historical baseline.",
            })

        if not correlations:
            correlations.append({
                "tactic": "Defense Evasion (TA0005)",
                "technique_id": "T1036",
                "technique_name": "Masquerading",
                "risk_driver": "Sub-threshold statistical divergence in background traffic baseline.",
            })

        return correlations

    def _formulate_hypotheses(
        self,
        hunt_id: str,
        drift_status: str,
        global_psi: float,
        drifting_feats: Dict[str, float],
        stealth_clusters: List[Dict[str, Any]],
        mitre_correlations: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Formulates actionable threat hunting hypotheses."""
        hypotheses = []

        if stealth_clusters:
            for sc in stealth_clusters:
                hypotheses.append({
                    "hypothesis": f"Adversary is conducting an evasion-oriented {sc['cluster_type']} to map network attack surfaces.",
                    "evidence": sc["evidence"],
                    "confidence": sc["confidence"],
                    "hunt_query": f'sourcetype=netflow dst_port IN ({", ".join(map(str, sc.get("target_ports", [80])))}) | stats count by src_ip, dst_port | where count > 5',
                    "action": "Quarantine offending subnet on border firewall; inspect proxy logs for secondary C2 handshakes.",
                })

        if drift_status in ("MODERATE_DRIFT", "SEVERE_DRIFT"):
            top_drift = sorted(drifting_feats.items(), key=lambda x: x[1], reverse=True)[:2]
            drift_desc = ", ".join([f"{k} (PSI={v})" for k, v in top_drift]) or "Ambient statistical divergence"
            hypotheses.append({
                "hypothesis": f"Concept drift detected in network features ({drift_desc}), signaling either an evolving attack vector or legitimate infrastructure shift.",
                "evidence": f"Global PSI is {global_psi:.3f} (threshold: 0.10). Key drivers: {drift_desc}.",
                "confidence": 0.85,
                "hunt_query": f'sourcetype=zeek_conn | eval psi_alert="{drift_desc}" | timechart span=1h count',
                "action": "Review newly deployed services; trigger active learning retrain cycle if drift persists over 24h.",
            })

        if not hypotheses:
            hypotheses.append({
                "hypothesis": "Network traffic conforms to expected baseline behavior with no active stealth campaigns observed.",
                "evidence": f"Global PSI is {global_psi:.3f} with zero sub-threshold anomaly clusters.",
                "confidence": 0.95,
                "hunt_query": "sourcetype=netflow | stats count by protocol",
                "action": "Maintain normal passive monitoring.",
            })

        return hypotheses


# Global singleton instance
threat_hunting_agent = ThreatHuntingAgent()
