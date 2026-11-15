import os
import requests


API_BASE_URL = os.environ.get("NETGUARD_API_URL", "http://127.0.0.1:8000").rstrip("/")


def set_api_base_url(url: str):
    global API_BASE_URL
    API_BASE_URL = url.rstrip("/")


def get_api_base_url() -> str:
    return API_BASE_URL


def get_health(base_url: str = None):
    url = (base_url or API_BASE_URL).rstrip("/")
    response = requests.get(
        f"{url}/health",
        timeout=10
    )
    response.raise_for_status()
    return response.json()


def get_model_info(base_url: str = None):
    url = (base_url or API_BASE_URL).rstrip("/")
    response = requests.get(
        f"{url}/model-info",
        timeout=10
    )
    response.raise_for_status()
    return response.json()


def predict_cicids(features, base_url: str = None):
    url = (base_url or API_BASE_URL).rstrip("/")
    response = requests.post(
        f"{url}/predict/cicids",
        json={"features": features},
        timeout=30
    )
    response.raise_for_status()
    return response.json()


def predict_nsl_kdd(features, base_url: str = None):
    url = (base_url or API_BASE_URL).rstrip("/")
    response = requests.post(
        f"{url}/predict/nsl-kdd",
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



