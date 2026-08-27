import requests


API_BASE_URL = "http://127.0.0.1:8000"


def get_health():
    response = requests.get(
        f"{API_BASE_URL}/health",
        timeout=10
    )
    response.raise_for_status()
    return response.json()


def get_model_info():
    response = requests.get(
        f"{API_BASE_URL}/model-info",
        timeout=10
    )
    response.raise_for_status()
    return response.json()


def predict_cicids(features):
    response = requests.post(
        f"{API_BASE_URL}/predict/cicids",
        json={"features": features},
        timeout=30
    )
    response.raise_for_status()
    return response.json()


def predict_nsl_kdd(features):
    response = requests.post(
        f"{API_BASE_URL}/predict/nsl-kdd",
        json={"features": features},
        timeout=30
    )
    response.raise_for_status()
    return response.json()