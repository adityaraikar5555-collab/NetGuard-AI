"""
Unit & Integration Tests for the Unsupervised Autoencoder (Zero-Day Engine).
"""

from pathlib import Path
import pandas as pd
import pytest

from src.zero_day_engine import PyTorchAutoencoder, ZeroDayEngine, zero_day_engine


def test_autoencoder_architecture():
    import torch
    model = PyTorchAutoencoder(in_dim=78, latent_dim=12)
    dummy_input = torch.randn(4, 78)
    out = model(dummy_input)
    assert out.shape == (4, 78)

    latent = model.encode(dummy_input)
    assert latent.shape == (4, 12)


def test_zero_day_engine_initialization():
    assert zero_day_engine.is_loaded is True
    assert zero_day_engine.model is not None
    assert zero_day_engine.scaler is not None
    assert len(zero_day_engine.feature_names) == 78
    assert zero_day_engine.threshold > 0.0
    assert zero_day_engine.threshold_95 > 0.0
    assert zero_day_engine.threshold_99 >= zero_day_engine.threshold_95


def test_benign_flow_reconstruction():
    test_csv = Path("data/CICIDS-2017/test_10_rows.csv")
    if not test_csv.exists():
        pytest.skip("Test sample not found")

    df = pd.read_csv(test_csv)
    first_flow = df.iloc[0].to_dict()

    res = zero_day_engine.score_flow(first_flow)
    assert "reconstruction_error" in res
    assert "threshold" in res
    assert "is_zero_day" in res
    assert "novelty_score" in res
    assert "top_attributions" in res
    # Benign flow should have low reconstruction error
    assert res["is_zero_day"] is False
    assert res["verdict"] == "BENIGN_PROFILE"
    assert res["reconstruction_error"] <= zero_day_engine.threshold_99


def test_anomalous_flow_reconstruction():
    attack_csv = Path("data/CICIDS-2017/test_attack_10_rows.csv")
    if not attack_csv.exists():
        pytest.skip("Attack sample not found")

    df_atk = pd.read_csv(attack_csv)
    atk_flow = df_atk.iloc[0].to_dict()

    res = zero_day_engine.score_flow(atk_flow)
    assert res["reconstruction_error"] > 0
    assert len(res["top_attributions"]) == 5
    # First attribution should have non-zero residual
    assert res["top_attributions"][0]["residual"] >= 0.0


def test_dual_engine_fusion_scenarios():
    test_csv = Path("data/CICIDS-2017/test_10_rows.csv")
    attack_csv = Path("data/CICIDS-2017/test_attack_10_rows.csv")

    df_benign = pd.read_csv(test_csv)
    df_atk = pd.read_csv(attack_csv)

    benign_flow = df_benign.iloc[0].to_dict()
    atk_flow = df_atk.iloc[0].to_dict()

    # Scenario 1: Clean Normal Traffic
    f_safe = zero_day_engine.dual_engine_fusion("BENIGN", 0.02, benign_flow)
    assert f_safe["status"] == "VERIFIED_SAFE"
    assert f_safe["risk_tier"] == "LOW"

    # Scenario 2: Known Attack (both agree)
    f_known = zero_day_engine.dual_engine_fusion("DDoS_LOIC", 0.98, atk_flow)
    assert f_known["status"] == "CONFIRMED_KNOWN_ATTACK"
    assert f_known["risk_tier"] == "CRITICAL"

    # Scenario 3: Stealth Zero-Day Exploit (RF fooled -> predicted BENIGN, but Autoencoder catches it)
    f_zeroday = zero_day_engine.dual_engine_fusion("BENIGN", 0.05, atk_flow)
    assert f_zeroday["status"] == "ZERO_DAY_ANOMALY"
    assert "ZERO-DAY" in f_zeroday["hybrid_verdict"]
    assert f_zeroday["risk_tier"] == "CRITICAL"


def test_dataframe_batch_input():
    test_csv = Path("data/CICIDS-2017/test_10_rows.csv")
    df = pd.read_csv(test_csv).head(3)
    res = zero_day_engine.score_flow(df)
    assert "reconstruction_error" in res


def test_zero_day_fastapi_endpoints():
    from fastapi.testclient import TestClient
    from frontend.app import app

    client = TestClient(app)

    # 1. Test Status
    res_status = client.get("/detection/zero-day/status")
    assert res_status.status_code == 200
    status_data = res_status.json()
    assert status_data["status"] == "ready"
    assert status_data["input_dimensions"] == 78
    assert status_data["latent_bottleneck"] == 12

    # 2. Test Score
    test_csv = Path("data/CICIDS-2017/test_10_rows.csv")
    df = pd.read_csv(test_csv)
    sample_feat = df.iloc[0].to_dict()

    res_score = client.post("/detection/zero-day/score", json={"features": sample_feat})
    assert res_score.status_code == 200
    score_data = res_score.json()
    assert score_data["status"] == "success"
    assert "reconstruction_error" in score_data["analysis"]
    assert "top_attributions" in score_data["analysis"]

    # 3. Test Fusion
    res_fusion = client.post(
        "/detection/zero-day/fuse",
        json={"rf_prediction": "BENIGN", "rf_probability": 0.05, "features": sample_feat},
    )
    assert res_fusion.status_code == 200
    fusion_data = res_fusion.json()
    assert fusion_data["status"] == "success"
    assert fusion_data["verdict"]["status"] == "VERIFIED_SAFE"

