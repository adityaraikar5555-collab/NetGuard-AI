"""
Real-Time Intrusion Detection Engine for NetGuard AI.
Part of Phase 3: Real-Time Detection, Risk Scoring & WebSocket Streaming.

Responsibilities:
1. Feeds live 78-feature flows from LiveNetworkMonitor into NetworkPredictionEngine.
2. Calculates calibrated risk score (0-100) and severity ratings (CRITICAL, HIGH, MEDIUM, LOW, SAFE).
3. Classifies specific attack vectors (DDoS, PortScan, Brute Force, Botnet, Web Attack, Infiltration)
   using MultiClassClassifier and links to MITRE ATT&CK techniques.
4. Maintains an active event ring-buffer and notifies registered WebSocket subscribers.
"""

from collections import deque
from datetime import datetime, timezone
import json
import threading
import time
from typing import Any, Callable, Deque, Dict, List, Optional
import numpy as np
import pandas as pd

from live_monitor import live_monitor
from multiclass_engine import multiclass_classifier
from prediction_engine import NetworkPredictionEngine


# Mapping attack families to MITRE ATT&CK Matrix techniques
MITRE_ATTACK_MAPPING = {
    "DOS": {"technique_id": "T1498", "name": "Network Denial of Service", "tactic": "Impact"},
    "PORTSCAN": {"technique_id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
    "BRUTE_FORCE": {"technique_id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    "BOTNET": {"technique_id": "T1071", "name": "Application Layer Protocol (C2)", "tactic": "Command and Control"},
    "WEB_ATTACK": {"technique_id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "INFILTRATION": {"technique_id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
    "ANOMALY": {"technique_id": "T1205", "name": "Traffic Signaling / Anomaly", "tactic": "Defense Evasion"},
}


class RealTimeDetector:
    """
    Sub-second real-time detection pipeline consuming live network flows,
    running ML inference, computing risk/severity, and broadcasting alerts.
    """

    def __init__(self):
        self.engine = NetworkPredictionEngine()
        self.classifier = multiclass_classifier

        self._lock = threading.Lock()
        self._history: Deque[Dict[str, Any]] = deque(maxlen=1000)
        self._listeners: List[Callable[[Dict[str, Any]], None]] = []

        self._total_evaluated = 0
        self._total_attacks = 0
        self._is_active = False

    # --------------------------------------------------------------------------
    # SUBSCRIBER MANAGEMENT (FOR WEBSOCKETS)
    # --------------------------------------------------------------------------

    def register_listener(self, callback: Callable[[Dict[str, Any]], None]):
        """Registers a listener callback (e.g. WebSocket broadcaster)."""
        with self._lock:
            if callback not in self._listeners:
                self._listeners.append(callback)

    def unregister_listener(self, callback: Callable[[Dict[str, Any]], None]):
        """Removes a listener callback."""
        with self._lock:
            if callback in self._listeners:
                self._listeners.remove(callback)

    def _broadcast(self, detection_event: Dict[str, Any]):
        """Dispatches detection event to all active WebSocket listeners."""
        with self._lock:
            listeners_snapshot = list(self._listeners)

        for callback in listeners_snapshot:
            try:
                callback(detection_event)
            except Exception:
                pass

    # --------------------------------------------------------------------------
    # DETECTION & RISK SCORING PIPELINE
    # --------------------------------------------------------------------------

    def evaluate_flow(self, flow_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Runs ML inference on a reconstructed 5-tuple flow, calculates risk and severity,
        and assigns MITRE techniques if an attack is identified.
        """
        features_dict = flow_dict.get("features", {})
        if not features_dict:
            features_dict = {k: v for k, v in flow_dict.items() if isinstance(v, (int, float))}

        # Construct single-row DataFrame for NetworkPredictionEngine
        df = pd.DataFrame([features_dict])

        # Execute actual trained Random Forest model
        t0 = time.perf_counter()
        pred_res = self.engine.predict_cicids(df)
        latency_ms = round((time.perf_counter() - t0) * 1000, 2)

        pred_label = str(pred_res.get("prediction", "BENIGN")).upper()
        confidence = float(pred_res.get("confidence", 0.95))
        attack_prob = float(pred_res.get("attack_probability", 0.0))
        is_attack = bool(pred_res.get("is_attack", False) or pred_label == "ATTACK" or attack_prob >= 0.50)

        # Dynamic Risk Scoring (0 to 100 scale)
        if is_attack:
            risk_score = min(100, max(50, round(attack_prob * 100)))
        else:
            risk_score = min(49, max(0, round(attack_prob * 100)))

        # Dynamic Severity Calibration
        if is_attack:
            if risk_score >= 85:
                severity = "CRITICAL"
            elif risk_score >= 70:
                severity = "HIGH"
            else:
                severity = "MEDIUM"
        else:
            severity = "LOW" if risk_score >= 20 else "SAFE"

        # Multi-class attack vector classification
        attack_family = "BENIGN"
        mitre_info = {}
        if is_attack:
            try:
                mc_res = self.classifier.classify_flow(features_dict, dataset="CICIDS-2017")
                attack_family = mc_res.get("predicted_class", "ANOMALY")
            except Exception:
                attack_family = "DOS" if features_dict.get("Destination Port") in (80, 443) else "PORTSCAN"
            mitre_info = MITRE_ATTACK_MAPPING.get(attack_family, MITRE_ATTACK_MAPPING["ANOMALY"])

        # Format detection event
        event = {
            "type": "flow_detection",
            "event_id": f"det_{int(time.time() * 1000)}_{np.random.randint(100, 999)}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": flow_dict.get("source_ip", "Unknown"),
            "destination_ip": flow_dict.get("destination_ip", "Unknown"),
            "source_port": flow_dict.get("source_port", 0),
            "destination_port": flow_dict.get("destination_port", int(features_dict.get("Destination Port", 0))),
            "protocol": flow_dict.get("protocol", "TCP"),
            "prediction": "ATTACK" if is_attack else "BENIGN",
            "attack_family": attack_family,
            "is_attack": is_attack,
            "confidence": confidence,
            "attack_probability": attack_prob,
            "risk_score": risk_score,
            "severity": severity,
            "flow_duration_us": float(features_dict.get("Flow Duration", 0.0)),
            "total_packets": int(flow_dict.get("packets", features_dict.get("Total Fwd Packets", 1) + features_dict.get("Total Backward Packets", 0))),
            "flow_bytes_per_sec": float(features_dict.get("Flow Bytes/s", 0.0)),
            "inference_latency_ms": latency_ms,
            "mitre": mitre_info,
        }

        with self._lock:
            self._total_evaluated += 1
            if is_attack:
                self._total_attacks += 1
            self._history.append(event)

        # Notify WebSockets
        self._broadcast(event)
        return event

    # --------------------------------------------------------------------------
    # PIPELINE CONTROLLER
    # --------------------------------------------------------------------------

    def start_pipeline(self, interface: Optional[str] = None) -> Dict[str, Any]:
        """
        Starts live monitoring and hooks the real-time detector to emitted flows.
        """
        if self._is_active:
            return {"status": "already_running"}

        target_if = interface or live_monitor.get_status().get("authorized_interface")
        if not target_if:
            raise PermissionError("No network interface authorized. Please authorize an interface first.")

        # Start live monitor with callback pointing to evaluate_flow
        res = live_monitor.start_monitoring(target_if, on_flow_callback=self.evaluate_flow)
        self._is_active = True
        return {
            "status": "started",
            "authorized_interface": target_if,
            "monitor_status": res,
        }

    def stop_pipeline(self) -> Dict[str, Any]:
        """Stops live monitoring and detection pipeline."""
        self._is_active = False
        res = live_monitor.stop_monitoring()
        return {"status": "stopped", "monitor_status": res}

    def get_latest_detections(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Returns the most recent detection events from the ring-buffer."""
        with self._lock:
            recent = list(self._history)[-limit:]
        return recent[::-1]  # Return in reverse chronological order (newest first)

    def get_statistics(self) -> Dict[str, Any]:
        """Returns aggregate detection throughput and anomaly ratios."""
        with self._lock:
            rate = round((self._total_attacks / max(1, self._total_evaluated)) * 100, 2)
            return {
                "is_active": self._is_active,
                "total_evaluated": self._total_evaluated,
                "total_attacks": self._total_attacks,
                "attack_rate_pct": rate,
                "cached_events": len(self._history),
                "active_listeners": len(self._listeners),
            }


# Singleton engine instance
realtime_detector = RealTimeDetector()
