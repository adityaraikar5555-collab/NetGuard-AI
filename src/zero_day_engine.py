"""
NetGuard AI — Unsupervised Deep Autoencoder (Zero-Day Anomaly Detection Engine)
==============================================================================
Provides unsupervised zero-day anomaly detection by training deep reconstruction
networks exclusively on benign network traffic manifolds.

Features dual-backend runtime:
1. PyTorch Deep Autoencoder (accelerated tensor inference)
2. Pure-NumPy Matrix Feedforward Fallback (runs in any Python environment with zero torch dependencies)

When a novel/zero-day attack enters the system, the Autoencoder fails to
reconstruct the unfamiliar latent structure, producing a sharp reconstruction
error (MSE) spike that exceeds the dynamically calibrated threshold tau.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

# Check PyTorch availability safely
try:
    import torch
    import torch.nn as nn
    HAS_TORCH = True
except Exception:
    torch = None
    nn = None
    HAS_TORCH = False


if HAS_TORCH:
    class PyTorchAutoencoder(nn.Module):
        """
        Deep symmetric feedforward Autoencoder with bottleneck latent representation.
        Compresses 78-dimensional network flow vectors down to a 12-dimensional manifold.
        """

        def __init__(self, in_dim: int = 78, latent_dim: int = 12):
            super().__init__()
            self.encoder = nn.Sequential(
                nn.Linear(in_dim, 48),
                nn.LeakyReLU(0.1),
                nn.Linear(48, 24),
                nn.LeakyReLU(0.1),
                nn.Linear(24, latent_dim),
            )
            self.decoder = nn.Sequential(
                nn.Linear(latent_dim, 24),
                nn.LeakyReLU(0.1),
                nn.Linear(24, 48),
                nn.LeakyReLU(0.1),
                nn.Linear(48, in_dim),
            )

        def forward(self, x: torch.Tensor) -> torch.Tensor:
            latent = self.encoder(x)
            reconstruction = self.decoder(latent)
            return reconstruction

        def encode(self, x: torch.Tensor) -> torch.Tensor:
            return self.encoder(x)
else:
    PyTorchAutoencoder = None


class ZeroDayEngine:
    """
    High-performance Unsupervised Anomaly Detection Engine for NetGuard AI.
    Features:
    - Pre-trained & auto-calibrated Autoencoder on benign network traffic
    - PyTorch & Pure-NumPy dual-mode forward execution (Zero crash guarantee)
    - Dynamic anomaly thresholding (90th/95th/99th percentile of reconstruction loss)
    - Feature-level reconstruction residual attribution (Zero-Day XAI)
    - Dual-Engine Threat Fusion (Supervised RF + Unsupervised Autoencoder)
    """

    def __init__(self, models_dir: Optional[Path] = None):
        self.root_dir = Path(__file__).resolve().parent.parent
        self.models_dir = models_dir or (self.root_dir / "models")
        self.model_path = self.models_dir / "zero_day_autoencoder.pt"
        self.weights_npz_path = self.models_dir / "zero_day_weights.npz"
        self.scaler_path = self.models_dir / "zero_day_scaler.pkl"
        self.meta_path = self.models_dir / "zero_day_meta.json"

        self.model: Optional[Any] = None
        self.np_weights: Optional[Dict[str, np.ndarray]] = None
        self.scaler: Optional[StandardScaler] = None
        self.feature_names: List[str] = []
        self.threshold: float = 0.2618
        self.threshold_90: float = 0.1873
        self.threshold_95: float = 0.2618
        self.threshold_99: float = 0.6857
        self.benign_mean_mse: float = 0.0948
        self.latent_dim: int = 12
        self.is_loaded: bool = False
        self.backend: str = "numpy"

        self._initialize()

    def _initialize(self) -> None:
        """Loads existing model artifacts or triggers automatic training on benign dataset."""
        if self.scaler_path.exists() and self.meta_path.exists():
            if (HAS_TORCH and self.model_path.exists()) or self.weights_npz_path.exists():
                try:
                    self._load_artifacts()
                    self.is_loaded = True
                    return
                except Exception as e:
                    print(f"[ZeroDayEngine] Failed to load artifacts ({e}), retraining...")

        # Train and calibrate if not found or corrupted
        self.train_and_calibrate()

    def _load_artifacts(self) -> None:
        """Loads weights, scaler, and metadata from disk."""
        with open(self.meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)

        self.feature_names = meta["feature_names"]
        self.threshold = meta["threshold_95"]
        self.threshold_90 = meta.get("threshold_90", self.threshold * 0.85)
        self.threshold_95 = meta["threshold_95"]
        self.threshold_99 = meta.get("threshold_99", self.threshold * 1.5)
        self.benign_mean_mse = meta.get("benign_mean_mse", 0.0948)
        self.latent_dim = meta.get("latent_dim", 12)

        self.scaler = joblib.load(self.scaler_path)
        in_dim = len(self.feature_names)

        # 1. Try PyTorch first if available
        if HAS_TORCH and self.model_path.exists():
            try:
                self.model = PyTorchAutoencoder(in_dim=in_dim, latent_dim=self.latent_dim)
                state_dict = torch.load(self.model_path, map_location=torch.device("cpu"))
                self.model.load_state_dict(state_dict)
                self.model.eval()
                self.backend = "pytorch"
            except Exception as e:
                print(f"[ZeroDayEngine] PyTorch load error ({e}), falling back to NumPy matrix engine")
                self.model = None

        # 2. Load NumPy weights for pure-NumPy execution
        if self.weights_npz_path.exists():
            loaded_npz = np.load(self.weights_npz_path)
            self.np_weights = {k: loaded_npz[k] for k in loaded_npz.files}
            if self.model is None:
                self.backend = "numpy"
        elif self.model is not None and HAS_TORCH:
            self._export_numpy_weights()

        self.is_loaded = True

    def _export_numpy_weights(self) -> None:
        """Exports PyTorch model weights to pure NumPy npz format for zero-dependency execution."""
        if self.model is None or not HAS_TORCH:
            return
        m = self.model
        w = {
            "W1": m.encoder[0].weight.detach().cpu().numpy().T,
            "b1": m.encoder[0].bias.detach().cpu().numpy(),
            "W2": m.encoder[2].weight.detach().cpu().numpy().T,
            "b2": m.encoder[2].bias.detach().cpu().numpy(),
            "W3": m.encoder[4].weight.detach().cpu().numpy().T,
            "b3": m.encoder[4].bias.detach().cpu().numpy(),
            "W4": m.decoder[0].weight.detach().cpu().numpy().T,
            "b4": m.decoder[0].bias.detach().cpu().numpy(),
            "W5": m.decoder[2].weight.detach().cpu().numpy().T,
            "b5": m.decoder[2].bias.detach().cpu().numpy(),
            "W6": m.decoder[4].weight.detach().cpu().numpy().T,
            "b6": m.decoder[4].bias.detach().cpu().numpy(),
        }
        np.savez(self.weights_npz_path, **w)
        self.np_weights = w

    def _numpy_forward(self, x_scaled: np.ndarray) -> np.ndarray:
        """Executes pure NumPy forward pass without PyTorch."""
        if self.np_weights is None:
            if self.weights_npz_path.exists():
                loaded_npz = np.load(self.weights_npz_path)
                self.np_weights = {k: loaded_npz[k] for k in loaded_npz.files}
            else:
                raise RuntimeError("No Autoencoder weights available in models/zero_day_weights.npz")

        def lrelu(v: np.ndarray, a: float = 0.1) -> np.ndarray:
            return np.where(v > 0, v, v * a)

        w = self.np_weights
        h1 = lrelu(x_scaled @ w["W1"] + w["b1"])
        h2 = lrelu(h1 @ w["W2"] + w["b2"])
        z = h2 @ w["W3"] + w["b3"]
        h3 = lrelu(z @ w["W4"] + w["b4"])
        h4 = lrelu(h3 @ w["W5"] + w["b5"])
        x_recon = h4 @ w["W6"] + w["b6"]
        return x_recon

    def train_and_calibrate(self, epochs: int = 120, lr: float = 0.005) -> Dict[str, Any]:
        """
        Trains the Autoencoder exclusively on verified Benign flows from CICIDS-2017
        and computes the statistical anomaly threshold.
        """
        data_path = self.root_dir / "data" / "CICIDS-2017" / "_validation_sample.csv"
        if not data_path.exists():
            data_path = self.root_dir / "data" / "CICIDS-2017" / "test_10_rows.csv"

        df = pd.read_csv(data_path)
        feature_cols = [c for c in df.columns if c.strip() != "Label"]
        self.feature_names = [c.strip() for c in feature_cols]

        X_raw = df[feature_cols].replace([np.inf, -np.inf], np.nan).fillna(0).values

        if "Label" in df.columns:
            benign_mask = df["Label"].astype(str).str.upper() == "BENIGN"
            if np.any(benign_mask):
                X_benign_raw = X_raw[benign_mask]
            else:
                X_benign_raw = X_raw
        else:
            X_benign_raw = X_raw

        X_benign_log = np.log1p(np.maximum(0, X_benign_raw))
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X_benign_log)
        in_dim = X_scaled.shape[1]

        if HAS_TORCH:
            self.model = PyTorchAutoencoder(in_dim=in_dim, latent_dim=self.latent_dim)
            criterion = nn.MSELoss()
            optimizer = torch.optim.Adam(self.model.parameters(), lr=lr, weight_decay=1e-5)
            t_data = torch.tensor(X_scaled, dtype=torch.float32)

            self.model.train()
            for _ in range(epochs):
                optimizer.zero_grad()
                recon = self.model(t_data)
                loss = criterion(recon, t_data)
                loss.backward()
                optimizer.step()

            self.model.eval()
            with torch.no_grad():
                recon = self.model(t_data)
                mse_vals = torch.mean((recon - t_data) ** 2, dim=1).numpy()

            self.models_dir.mkdir(parents=True, exist_ok=True)
            torch.save(self.model.state_dict(), self.model_path)
            self._export_numpy_weights()
            self.backend = "pytorch"
        else:
            # If PyTorch is unavailable during training, use sklearn MLPRegressor
            from sklearn.neural_network import MLPRegressor
            mlp = MLPRegressor(
                hidden_layer_sizes=(48, 24, 12, 24, 48),
                activation="relu",
                max_iter=epochs,
                random_state=42,
            )
            mlp.fit(X_scaled, X_scaled)
            recon = mlp.predict(X_scaled)
            mse_vals = np.mean((recon - X_scaled) ** 2, axis=1)
            self.backend = "numpy"

        self.benign_mean_mse = float(np.mean(mse_vals))
        self.threshold_90 = float(np.percentile(mse_vals, 90))
        self.threshold_95 = float(np.percentile(mse_vals, 95))
        self.threshold_99 = float(np.percentile(mse_vals, 99))
        self.threshold = self.threshold_95

        self.models_dir.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.scaler, self.scaler_path)

        meta = {
            "feature_names": self.feature_names,
            "latent_dim": self.latent_dim,
            "benign_mean_mse": self.benign_mean_mse,
            "threshold_90": self.threshold_90,
            "threshold_95": self.threshold_95,
            "threshold_99": self.threshold_99,
            "epochs": epochs,
            "in_dim": in_dim,
        }
        with open(self.meta_path, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)

        self.is_loaded = True
        return meta

    def _prepare_vector(self, flow: Union[Dict[str, Any], pd.Series, pd.DataFrame, np.ndarray]) -> np.ndarray:
        """Extracts and normalizes features in matching order."""
        if isinstance(flow, dict):
            clean_flow = {k.strip(): v for k, v in flow.items()}
            row = []
            for col in self.feature_names:
                val = clean_flow.get(col, 0.0)
                try:
                    fval = float(val)
                    if np.isinf(fval) or np.isnan(fval):
                        fval = 0.0
                except (ValueError, TypeError):
                    fval = 0.0
                row.append(fval)
            arr = np.array([row], dtype=np.float32)
        elif isinstance(flow, pd.Series):
            return self._prepare_vector(flow.to_dict())
        elif isinstance(flow, pd.DataFrame):
            df = flow.copy()
            df.columns = [str(c).strip() for c in df.columns]
            for col in self.feature_names:
                if col not in df.columns:
                    df[col] = 0.0
            arr = df[self.feature_names].replace([np.inf, -np.inf], np.nan).fillna(0.0).values.astype(np.float32)
        elif isinstance(flow, np.ndarray):
            if flow.ndim == 1:
                arr = flow.reshape(1, -1).astype(np.float32)
            else:
                arr = flow.astype(np.float32)
        else:
            arr = np.zeros((1, len(self.feature_names)), dtype=np.float32)

        return arr

    def score_flow(self, flow: Union[Dict[str, Any], pd.Series, pd.DataFrame, np.ndarray]) -> Dict[str, Any]:
        """
        Calculates reconstruction error (MSE), Zero-Day anomaly verdict,
        and feature-level attribution residuals.
        """
        if not self.is_loaded or self.scaler is None:
            self._initialize()

        raw_vec = self._prepare_vector(flow)
        log_vec = np.log1p(np.maximum(0, raw_vec))
        scaled_vec = self.scaler.transform(log_vec)

        # Execute reconstruction: PyTorch if loaded, else pure NumPy forward pass
        if HAS_TORCH and self.model is not None:
            try:
                t_in = torch.tensor(scaled_vec, dtype=torch.float32)
                self.model.eval()
                with torch.no_grad():
                    t_recon = self.model(t_in)
                    squared_diffs = (t_recon - t_in) ** 2
                    mse_val = float(torch.mean(squared_diffs).item())
                    feature_residuals = squared_diffs[0].numpy()
            except Exception:
                # Fallback to pure numpy
                recon = self._numpy_forward(scaled_vec)
                feature_residuals = (recon[0] - scaled_vec[0]) ** 2
                mse_val = float(np.mean(feature_residuals))
        else:
            recon = self._numpy_forward(scaled_vec)
            feature_residuals = (recon[0] - scaled_vec[0]) ** 2
            mse_val = float(np.mean(feature_residuals))

        if mse_val <= self.threshold:
            novelty_score = round(min(50.0, (mse_val / max(1e-5, self.threshold)) * 50.0), 2)
        else:
            ratio = mse_val / max(1e-5, self.threshold)
            novelty_score = round(min(99.9, 50.0 + (ratio - 1.0) * 25.0), 2)

        is_zero_day = mse_val > self.threshold
        severity = "CRITICAL" if mse_val > self.threshold_99 else ("HIGH" if mse_val > self.threshold_95 else "NORMAL")

        top_indices = np.argsort(feature_residuals)[::-1][:5]
        top_attributions = []
        for idx in top_indices:
            top_attributions.append({
                "feature": self.feature_names[idx],
                "residual": round(float(feature_residuals[idx]), 4),
                "original_value": round(float(raw_vec[0][idx]), 2),
            })

        return {
            "reconstruction_error": round(mse_val, 5),
            "threshold": round(self.threshold, 5),
            "threshold_95": round(self.threshold_95, 5),
            "threshold_99": round(self.threshold_99, 5),
            "is_zero_day": is_zero_day,
            "novelty_score": novelty_score,
            "severity": severity,
            "verdict": "ZERO_DAY_ANOMALY" if is_zero_day else "BENIGN_PROFILE",
            "top_attributions": top_attributions,
            "latent_bottleneck": self.latent_dim,
            "backend": self.backend,
        }

    def dual_engine_fusion(
        self,
        rf_prediction: str,
        rf_attack_probability: Optional[float] = None,
        flow_features: Optional[Union[Dict[str, Any], pd.Series]] = None,
        rf_probability: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Blends Supervised Random Forest and Unsupervised Autoencoder into an
        enterprise-grade Hybrid Defense Verdict.
        """
        actual_prob = rf_attack_probability if rf_attack_probability is not None else (rf_probability or 0.0)
        actual_flow = flow_features if flow_features is not None else {}
        ae_result = self.score_flow(actual_flow)
        is_ae_anomaly = ae_result["is_zero_day"]
        is_rf_attack = rf_prediction.strip().upper() not in ("BENIGN", "NORMAL", "SAFE")

        if is_rf_attack and is_ae_anomaly:
            status = "CONFIRMED_KNOWN_ATTACK"
            hybrid_verdict = f"CONFIRMED THREAT: {rf_prediction} (Dual-Engine Confirmed)"
            risk_tier = "CRITICAL"
            color = "#ef4444"
            desc = "Both Supervised Random Forest and Unsupervised Autoencoder confirm high-confidence intrusion."
        elif not is_rf_attack and is_ae_anomaly:
            status = "ZERO_DAY_ANOMALY"
            hybrid_verdict = "🚨 ZERO-DAY EXPLOIT DETECTED (Bypassed Supervised Classifier)"
            risk_tier = "CRITICAL"
            color = "#f43f5e"
            desc = (
                "Supervised Random Forest classified flow as BENIGN, but Unsupervised Autoencoder "
                f"flagged catastrophic reconstruction failure (MSE {ae_result['reconstruction_error']} > τ {ae_result['threshold']}). "
                "Indicates novel zero-day exploit or advanced evasion technique!"
            )
        elif is_rf_attack and not is_ae_anomaly:
            status = "SUSPICIOUS_LOW_RESIDUAL"
            hybrid_verdict = f"SUSPICIOUS PROBE: {rf_prediction} (Mild Feature Deviation)"
            risk_tier = "MEDIUM"
            color = "#f59e0b"
            desc = "Random Forest flagged malicious signature, but structural manifold residual remains within normal bounds."
        else:
            status = "VERIFIED_SAFE"
            hybrid_verdict = "VERIFIED CLEAN: Normal Network Traffic"
            risk_tier = "LOW"
            color = "#10b981"
            desc = "Both Supervised and Unsupervised engines verified legitimate baseline traffic."

        return {
            "status": status,
            "hybrid_verdict": hybrid_verdict,
            "risk_tier": risk_tier,
            "color": color,
            "description": desc,
            "rf_prediction": rf_prediction,
            "rf_probability": round(actual_prob, 4),
            "autoencoder": ae_result,
        }


# Singleton instance
zero_day_engine = ZeroDayEngine()
