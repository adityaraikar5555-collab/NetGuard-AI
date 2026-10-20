"""
Explainable AI (XAI) & Instant Root-Cause Analysis Engine for NetGuard AI.

Provides:
1. Feature attribution (impact scores, direction: increases/decreases risk)
2. Decision-path heuristics based on Random Forest feature importances & baseline deviations
3. Plain-English analyst rationale generation
4. Local feature contrast against normal traffic baselines
"""

from typing import Any, Dict, List, Optional, Union
import numpy as np
import pandas as pd


# Baseline statistics for CICIDS-2017 benign traffic (key features approximate means & stds)
CICIDS_BENIGN_BASELINES = {
    "Destination Port": {"mean": 80.0, "std": 1200.0, "desc": "Target destination network port"},
    "Flow Duration": {"mean": 150000.0, "std": 350000.0, "desc": "Total flow lifetime in microseconds"},
    "Total Fwd Packets": {"mean": 6.5, "std": 15.0, "desc": "Number of packets sent in forward direction"},
    "Total Backward Packets": {"mean": 7.2, "std": 18.0, "desc": "Number of packets received in backward direction"},
    "Total Length of Fwd Packets": {"mean": 550.0, "std": 1200.0, "desc": "Total payload bytes in forward direction"},
    "Total Length of Bwd Packets": {"mean": 1200.0, "std": 3500.0, "desc": "Total payload bytes in backward direction"},
    "Fwd Packet Length Max": {"mean": 250.0, "std": 450.0, "desc": "Maximum size of forward packets"},
    "Bwd Packet Length Max": {"mean": 450.0, "std": 800.0, "desc": "Maximum size of backward packets"},
    "Flow Bytes/s": {"mean": 25000.0, "std": 80000.0, "desc": "Data transmission rate in bytes per second"},
    "Flow Packets/s": {"mean": 120.0, "std": 400.0, "desc": "Packet rate per second"},
    "Flow IAT Mean": {"mean": 45000.0, "std": 110000.0, "desc": "Mean inter-arrival time between packets"},
    "SYN Flag Count": {"mean": 0.04, "std": 0.20, "desc": "Presence of TCP SYN synchronization flags"},
    "RST Flag Count": {"mean": 0.01, "std": 0.10, "desc": "Presence of TCP Reset flags"},
    "ACK Flag Count": {"mean": 0.35, "std": 0.48, "desc": "Presence of TCP Acknowledgement flags"},
    "PSH Flag Count": {"mean": 0.25, "std": 0.43, "desc": "Presence of TCP Push flags"},
    "Bwd Packets/s": {"mean": 60.0, "std": 200.0, "desc": "Backward packet throughput"},
    "Down/Up Ratio": {"mean": 1.1, "std": 0.6, "desc": "Ratio of download to upload packets"},
    "Average Packet Size": {"mean": 180.0, "std": 250.0, "desc": "Mean packet size across the session"},
}

# Baseline statistics for NSL-KDD normal traffic
NSL_KDD_BENIGN_BASELINES = {
    "duration": {"mean": 45.0, "std": 180.0, "desc": "Connection length in seconds"},
    "src_bytes": {"mean": 400.0, "std": 1500.0, "desc": "Bytes sent from source to destination"},
    "dst_bytes": {"mean": 1200.0, "std": 4000.0, "desc": "Bytes sent from destination to source"},
    "wrong_fragment": {"mean": 0.0, "std": 0.05, "desc": "Number of wrong fragments"},
    "urgent": {"mean": 0.0, "std": 0.02, "desc": "Number of urgent packets"},
    "hot": {"mean": 0.05, "std": 0.3, "desc": "Number of hot indicators"},
    "num_failed_logins": {"mean": 0.001, "std": 0.03, "desc": "Failed login attempts"},
    "logged_in": {"mean": 0.75, "std": 0.43, "desc": "Successful login status (1=yes)"},
    "count": {"mean": 8.0, "std": 15.0, "desc": "Connections to same destination in past 2s"},
    "srv_count": {"mean": 8.0, "std": 15.0, "desc": "Connections to same service in past 2s"},
    "serror_rate": {"mean": 0.02, "std": 0.14, "desc": "Percentage of connections with SYN errors"},
    "rerror_rate": {"mean": 0.03, "std": 0.17, "desc": "Percentage of connections with REJ errors"},
    "same_srv_rate": {"mean": 0.95, "std": 0.20, "desc": "Percentage of connections to same service"},
    "diff_srv_rate": {"mean": 0.04, "std": 0.15, "desc": "Percentage of connections to different services"},
    "dst_host_count": {"mean": 115.0, "std": 100.0, "desc": "Connections having same destination host"},
    "dst_host_srv_count": {"mean": 120.0, "std": 105.0, "desc": "Connections having same destination service"},
    "dst_host_serror_rate": {"mean": 0.02, "std": 0.12, "desc": "SYN errors on destination host"},
}


class XAIEngine:
    """
    Computes explainability insights and root-cause attribution for network flow anomalies.
    """

    def __init__(self, predictor=None):
        self.predictor = predictor

    def explain(
        self,
        features: Union[Dict[str, Any], pd.Series, List[Any]],
        dataset: str = "CICIDS-2017",
        top_k: int = 5,
    ) -> Dict[str, Any]:
        """
        Calculates local feature contributions and generates a human-readable analyst rationale.
        """
        # 1. Normalize input features into a key-value dictionary
        feat_dict = self._normalize_to_dict(features, dataset)
        
        # 2. Select dataset-specific baseline
        is_cicids = "CICIDS" in dataset.upper()
        baselines = CICIDS_BENIGN_BASELINES if is_cicids else NSL_KDD_BENIGN_BASELINES

        # 3. Obtain model feature importances if available
        model_importances = self._get_feature_importances(dataset)

        # 4. Compute attribution for each feature
        attributions = []
        for feat_name, val in feat_dict.items():
            clean_name = str(feat_name).strip()
            # Try exact or partial match with baselines
            base_info = baselines.get(clean_name)
            if base_info is None:
                # Case-insensitive / partial match
                for b_name, b_data in baselines.items():
                    if b_name.lower() == clean_name.lower():
                        base_info = b_data
                        clean_name = b_name
                        break

            # Check if value is numeric
            try:
                num_val = float(val)
                if np.isnan(num_val) or np.isinf(num_val):
                    continue
            except (ValueError, TypeError):
                continue

            # Global importance weight
            global_weight = model_importances.get(clean_name, 0.02)

            if base_info:
                b_mean = base_info["mean"]
                b_std = base_info["std"] if base_info["std"] > 1e-6 else 1.0
                desc = base_info["desc"]

                # Standardized deviation (Z-score capped to ±5)
                z_score = (num_val - b_mean) / b_std
                z_capped = float(np.clip(z_score, -5.0, 5.0))

                # Impact score combines deviation magnitude with global model feature importance
                impact_score = abs(z_capped) * (global_weight * 10.0 + 0.1)
                
                # Direction: Does abnormal value drive anomaly/risk up?
                # For network attacks, elevated error rates, SYN flags, packet bursts, or zero payload increase risk
                is_risk_increasing = False
                if any(k in clean_name.lower() for k in ["serror", "rerror", "syn", "rst", "wrong", "fail", "hot"]):
                    is_risk_increasing = num_val > b_mean
                elif any(k in clean_name.lower() for k in ["same_srv", "logged_in"]):
                    is_risk_increasing = num_val < b_mean
                elif abs(z_capped) > 1.2:
                    is_risk_increasing = True

                direction = "increases_risk" if is_risk_increasing else "normalizing"

                attributions.append({
                    "feature": clean_name,
                    "value": round(num_val, 4) if abs(num_val) < 1000 else round(num_val, 1),
                    "baseline_mean": round(b_mean, 2),
                    "deviation_sigma": round(z_capped, 2),
                    "impact_score": round(float(impact_score), 3),
                    "direction": direction,
                    "description": desc,
                })
            else:
                # No specific baseline: use global importance if high
                if global_weight > 0.03 and abs(num_val) > 0:
                    attributions.append({
                        "feature": clean_name,
                        "value": round(num_val, 4) if abs(num_val) < 1000 else round(num_val, 1),
                        "baseline_mean": "N/A",
                        "deviation_sigma": 1.0,
                        "impact_score": round(float(global_weight * 5.0), 3),
                        "direction": "increases_risk",
                        "description": "Network telemetry attribute",
                    })

        # 5. Sort by impact score descending
        attributions.sort(key=lambda x: x["impact_score"], reverse=True)
        top_features = attributions[:top_k]

        # 6. Normalize impact scores to percentage breakdown
        total_impact = sum(f["impact_score"] for f in top_features) or 1.0
        for f in top_features:
            f["percentage"] = round((f["impact_score"] / total_impact) * 100, 1)

        # 7. Generate Plain-English Analyst Rationale
        rationale = self._generate_rationale(top_features, dataset)

        return {
            "dataset": dataset,
            "top_features": top_features,
            "plain_english_rationale": rationale,
            "feature_count_evaluated": len(attributions),
        }

    def _get_feature_importances(self, dataset: str) -> Dict[str, float]:
        """Fetches normalized feature importances from the trained Random Forest model."""
        importances: Dict[str, float] = {}
        if not self.predictor:
            return importances

        try:
            is_cicids = "CICIDS" in dataset.upper()
            model = self.predictor.cicids_model if is_cicids else self.predictor.nsl_kdd_model
            if hasattr(model, "feature_importances_") and hasattr(model, "feature_names_in_"):
                for name, imp in zip(model.feature_names_in_, model.feature_importances_):
                    importances[str(name).strip()] = float(imp)
        except Exception:
            pass
        return importances

    def _normalize_to_dict(self, features: Any, dataset: str) -> Dict[str, Any]:
        """Converts raw list, dict, or series to named feature dict."""
        if isinstance(features, dict):
            return features
        if isinstance(features, pd.Series):
            return features.to_dict()

        # If list, map to expected model feature names
        if isinstance(features, (list, tuple, np.ndarray)):
            names = []
            if self.predictor:
                try:
                    is_cicids = "CICIDS" in dataset.upper()
                    model = self.predictor.cicids_model if is_cicids else self.predictor.nsl_kdd_model
                    if hasattr(model, "feature_names_in_"):
                        names = list(model.feature_names_in_)
                except Exception:
                    pass
            if len(names) == len(features):
                return dict(zip(names, features))
            return {f"feature_{i}": v for i, v in enumerate(features)}

        return {}

    def _generate_rationale(self, top_features: List[Dict[str, Any]], dataset: str) -> str:
        """Constructs an expert SOC analyst rationale explaining root cause."""
        if not top_features:
            return "Telemetry parameters conform within expected statistical distribution boundaries."

        risk_drivers = [f for f in top_features if f["direction"] == "increases_risk"]
        if not risk_drivers:
            return "Flow parameters exhibit mild variation but remain predominantly consistent with standard baseline operations."

        primary = risk_drivers[0]
        reasons = []
        for f in risk_drivers[:3]:
            sigma = f.get("deviation_sigma", 0)
            if sigma > 2.0:
                reasons.append(f"{f['feature']} is abnormally high (+{sigma}σ above normal)")
            elif sigma < -2.0:
                reasons.append(f"{f['feature']} is abnormally suppressed ({sigma}σ below baseline)")
            else:
                reasons.append(f"{f['feature']} ({f['value']}) significantly deviates from standard telemetry")

        reasons_str = "; ".join(reasons)
        return (
            f"Classified as elevated threat primarily driven by {primary['feature']} "
            f"accounting for {primary.get('percentage', 0)}% of the model attribution. "
            f"Key observations: {reasons_str}. "
            f"This behavior aligns with typical network anomaly signatures such as reconnaissance, flood degradation, or unusual connection bursts."
        )


# Global singleton instance
xai_engine = XAIEngine()
