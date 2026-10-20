import requests


API_BASE_URL = "https://netguard-ai-nd5e.onrender.com"


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


def investigate_agent(context: dict, base_url: str = None):
    url = (base_url or API_BASE_URL).rstrip("/") + "/agent/investigate"
    response = requests.post(url, json=context, timeout=45)
    response.raise_for_status()
    return response.json()


def hunt_agent(context: dict, base_url: str = None):
    url = (base_url or API_BASE_URL).rstrip("/") + "/agent/hunt"
    response = requests.post(url, json=context, timeout=45)
    response.raise_for_status()
    return response.json()


def swarm_agent(context: dict, base_url: str = None):
    url = (base_url or API_BASE_URL).rstrip("/") + "/agent/swarm"
    response = requests.post(url, json=context, timeout=45)
    response.raise_for_status()
    return response.json()


