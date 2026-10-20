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


def analyze_pcap_file(file_bytes: bytes, filename: str = "capture.pcap", max_packets: int = 15000, base_url: str = None):
    url = (base_url or API_BASE_URL).rstrip("/") + "/analyze/pcap"
    files = {"file": (filename, file_bytes, "application/vnd.tcpdump.pcap")}
    params = {"max_packets": max_packets}
    response = requests.post(url, files=files, params=params, timeout=120)
    response.raise_for_status()
    return response.json()


def simulate_adversarial(flows: list = None, attack_type: str = "HEADER_PADDING", epsilon: float = 0.15, base_url: str = None):
    url = (base_url or API_BASE_URL).rstrip("/") + "/adversarial/simulate"
    payload = {
        "flows": flows or [],
        "attack_type": attack_type,
        "epsilon": epsilon,
    }
    response = requests.post(url, json=payload, timeout=60)
    response.raise_for_status()
    return response.json()


def export_forensic_package(incident_data: dict, flows: list = None, investigator: str = "NetGuard Autonomous SOC Tier-2", base_url: str = None):
    url = (base_url or API_BASE_URL).rstrip("/") + "/forensics/export-package"
    payload = {
        "incident_data": incident_data,
        "flows": flows,
        "investigator": investigator,
    }
    response = requests.post(url, json=payload, timeout=60)
    response.raise_for_status()
    return response.json()



