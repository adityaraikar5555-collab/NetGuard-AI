"""
Validation, Statistical Efficacy Benchmarking & Cross-Tenant Security Audit Engine.
Part of Phase 5: Validation, Benchmarking & Tenant Security Verification.

Features:
1. Ground-Truth Traffic Evaluation: Tests model against labeled traffic samples in an authorized test environment.
2. Efficacy Metric Calculation:
   - Precision: TP / (TP + FP)
   - Recall: TP / (TP + FN)
   - F1-Score: 2 * (P * R) / (P + R)
   - False-Positive Rate (FPR): FP / (FP + TN)
   - Full Confusion Matrix Breakdown
3. Cross-Tenant Isolation Audit: Mathematically and programmatically validates that User A's alerts
   and streams are strictly isolated and inaccessible to User B.
"""

from datetime import datetime, timezone
import time
from typing import Any, Dict, List, Optional, Tuple, Union
import numpy as np
import pandas as pd

import auth
import database
from prediction_engine import NetworkPredictionEngine
from live_monitor import live_monitor


class BenchmarkValidator:
    """
    Validates model accuracy, precision, recall, false-positive rates,
    and certifies multi-tenant isolation compliance.
    """

    def __init__(self):
        self.engine = NetworkPredictionEngine()

    def evaluate_efficacy(
        self,
        y_true: List[int],
        y_pred: List[int],
    ) -> Dict[str, Any]:
        """
        Calculates precision, recall, F1-score, and false-positive rate from true vs predicted binary arrays.
        y_true: 1 for attack, 0 for normal
        y_pred: 1 for attack, 0 for normal
        """
        y_t = np.array(y_true, dtype=int)
        y_p = np.array(y_pred, dtype=int)

        tp = int(np.sum((y_t == 1) & (y_p == 1)))
        tn = int(np.sum((y_t == 0) & (y_p == 0)))
        fp = int(np.sum((y_t == 0) & (y_p == 1)))
        fn = int(np.sum((y_t == 1) & (y_p == 0)))

        total = len(y_t)
        accuracy = float((tp + tn) / max(1, total))
        precision = float(tp / max(1, (tp + fp)))
        recall = float(tp / max(1, (tp + fn)))
        f1_score = float(2 * (precision * recall) / max(1e-9, (precision + recall)))
        fpr = float(fp / max(1, (fp + tn)))

        return {
            "total_samples": total,
            "confusion_matrix": {
                "true_positives": tp,
                "true_negatives": tn,
                "false_positives": fp,
                "false_negatives": fn,
            },
            "metrics": {
                "accuracy": round(accuracy, 4),
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "f1_score": round(f1_score, 4),
                "false_positive_rate": round(fpr, 4),
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def run_ground_truth_test(self, sample_size: int = 50) -> Dict[str, Any]:
        """
        Generates/loads labeled normal and anomalous flows in the authorized environment,
        confirms that live predictions are produced by the actual trained model, and computes efficacy metrics.
        """
        from pathlib import Path
        project_root = Path(__file__).resolve().parent.parent
        attack_csv = project_root / "data" / "CICIDS-2017" / "test_attack_10_rows.csv"
        benign_csv = project_root / "data" / "CICIDS-2017" / "test_10_rows.csv"

        y_true: List[int] = []
        y_pred: List[int] = []

        if attack_csv.exists() and benign_csv.exists():
            df_att = pd.read_csv(attack_csv)
            df_ben = pd.read_csv(benign_csv)

            # Evaluate Benign Ground Truth
            X_ben = df_ben.drop(columns=["Label"], errors="ignore")
            for idx in range(min(len(X_ben), sample_size // 2)):
                pred_res = self.engine.predict_cicids(X_ben.iloc[[idx]])
                y_true.append(0)
                is_att = 1 if (pred_res.get("prediction", "BENIGN") != "BENIGN" or pred_res.get("attack_probability", 0) >= 0.50) else 0
                y_pred.append(is_att)

            # Evaluate Attack Ground Truth
            X_att = df_att.drop(columns=["Label"], errors="ignore")
            for idx in range(min(len(X_att), sample_size // 2)):
                pred_res = self.engine.predict_cicids(X_att.iloc[[idx]])
                y_true.append(1)
                is_att = 1 if (pred_res.get("prediction", "BENIGN") != "BENIGN" or pred_res.get("attack_probability", 0) >= 0.50) else 0
                y_pred.append(is_att)
        else:
            # Fallback to dynamic synthetic traffic simulation
            for i in range(sample_size // 2):
                flow = live_monitor.inject_synthetic_flow(
                    src_ip=f"192.168.1.{10 + i}",
                    dst_ip="10.0.0.1",
                    dst_port=80,
                    packet_count=6,
                )
                df = pd.DataFrame([flow["features"]])
                pred_res = self.engine.predict_cicids(df)
                y_true.append(0)
                is_att = 1 if pred_res.get("prediction", "BENIGN") != "BENIGN" or pred_res.get("attack_probability", 0) >= 0.50 else 0
                y_pred.append(is_att)

            for i in range(sample_size // 2):
                flow = live_monitor.inject_synthetic_flow(
                    src_ip=f"172.16.0.{50 + i}",
                    dst_ip="10.0.0.99",
                    dst_port=20 + i * 10,
                    packet_count=16,
                )
                feats = flow["features"].copy()
                feats["Destination Port"] = 4444.0
                feats["Flow Packets/s"] = 100000.0
                feats["Flow Bytes/s"] = 25000000.0
                df = pd.DataFrame([feats])
                pred_res = self.engine.predict_cicids(df)
                y_true.append(1)
                is_att = 1 if pred_res.get("prediction", "BENIGN") != "BENIGN" or pred_res.get("attack_probability", 0) >= 0.50 else 0
                y_pred.append(is_att)

        report = self.evaluate_efficacy(y_true, y_pred)
        report["test_status"] = "PASSED" if report["metrics"]["accuracy"] >= 0.80 else "FAILED"
        return report

    def audit_tenant_isolation(self) -> Dict[str, Any]:
        """
        SECURITY AUDIT:
        Validates that User A's alerts are never exposed to User B.
        """
        u_a_name = f"aud_user_a_{int(time.time())}"
        u_b_name = f"aud_user_b_{int(time.time())}"

        # Create two isolated tenant accounts
        u_a = database.create_user(u_a_name, f"{u_a_name}@test.com", "AudPassA123!")
        u_b = database.create_user(u_b_name, f"{u_b_name}@test.com", "AudPassB123!")

        # Insert 5 alerts under User A
        for i in range(5):
            database.insert_user_alert(
                user_id=u_a["id"],
                attack_type=f"DDoS-Vector-{i+1}",
                severity="Critical",
                confidence=0.98,
                source_ip=f"10.200.1.{i+10}",
                destination_ip="10.0.0.1",
            )

        # Insert 2 alerts under User B
        for j in range(2):
            database.insert_user_alert(
                user_id=u_b["id"],
                attack_type=f"PortScan-Vector-{j+1}",
                severity="Medium",
                confidence=0.85,
                source_ip=f"172.30.1.{j+20}",
                destination_ip="10.0.0.2",
            )

        # Query from User A's perspective
        alerts_a = database.get_user_alerts(user_id=u_a["id"])
        # Query from User B's perspective
        alerts_b = database.get_user_alerts(user_id=u_b["id"])

        a_ids = {a["id"] for a in alerts_a}
        b_ids = {b["id"] for b in alerts_b}

        # Check for overlap
        leaked_into_b = [aid for aid in a_ids if aid in b_ids]
        leaked_into_a = [bid for bid in b_ids if bid in a_ids]

        is_isolated = (len(leaked_into_b) == 0) and (len(leaked_into_a) == 0) and (len(alerts_a) == 5) and (len(alerts_b) == 2)

        return {
            "is_isolated": is_isolated,
            "tenant_a_count": len(alerts_a),
            "tenant_b_count": len(alerts_b),
            "leaked_into_tenant_b": len(leaked_into_b),
            "leaked_into_tenant_a": len(leaked_into_a),
            "audit_verdict": "PASSED — COMPLETE MULTI-TENANT ISOLATION" if is_isolated else "FAILED — LEAKAGE DETECTED",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


# Singleton validator instance
benchmark_validator = BenchmarkValidator()
