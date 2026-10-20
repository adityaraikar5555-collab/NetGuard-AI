"""
Comprehensive Verification and Stress-Testing Suite for NetGuard AI's 7 New Features.

Executes:
1. Engine Unit Verifications
2. FastAPI Endpoint Call Validations via Starlette TestClient (Zero-mock real HTTP invocation)
3. Synthetic flow generation & full pipeline assertions
"""

import sys
from pathlib import Path
import json
import struct
import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(PROJECT_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "src"))

from starlette.testclient import TestClient
from frontend.app import app
from src.xai_engine import xai_engine
from src.soar_engine import soar_engine
from src.pcap_extractor import pcap_extractor
from src.multiclass_engine import multiclass_classifier
from src.threat_intel import threat_intel_engine
from src.alert_integrations import alert_integration_engine
from src.drift_monitor import drift_monitor

client = TestClient(app)


def verify_feature_1_xai():
    print("[1/7] Verifying Explainable AI (XAI) & Root Cause Analysis...")
    flow = {
        "Destination Port": 80,
        "Flow Duration": 95000000,
        "Total Fwd Packets": 12000,
        "Total Backward Packets": 5,
        "Flow Bytes/s": 3500000.0,
        "Flow Packets/s": 85000.0,
        "SYN Flag Count": 11500,
        "ACK Flag Count": 1,
    }
    # 1. Engine check
    engine_res = xai_engine.explain(flow, dataset="CICIDS-2017", top_k=5)
    assert len(engine_res["top_features"]) == 5
    assert engine_res["top_features"][0]["percentage"] > 0
    assert "Total Fwd Packets" in [f["feature"] for f in engine_res["top_features"]]

    # 2. FastAPI endpoint check
    resp = client.post("/explain", json={"features": flow, "dataset": "CICIDS-2017", "top_k": 5})
    assert resp.status_code == 200
    api_data = resp.json()
    assert len(api_data["top_features"]) == 5
    assert len(api_data["plain_english_rationale"]) > 20
    print("  ✓ Feature 1 (XAI): Engine & API /explain verified successfully!")


def verify_feature_2_soar():
    print("[2/7] Verifying Agentic SOAR & MITRE ATT&CK Mapping...")
    # 1. Engine check
    mitre = soar_engine.map_mitre("DOS_SYN_FLOOD")
    assert mitre["technique_id"] == "T1498"
    assert mitre["tactic"].startswith("Impact")

    remediation = soar_engine.generate_remediation(
        src_ip="203.0.113.55", dst_ip="10.0.0.1", dst_port=443, proto="tcp", severity="CRITICAL"
    )
    assert "sudo iptables" in remediation["firewall_rules"]["iptables"]
    assert "sudo ufw" in remediation["firewall_rules"]["ufw"]
    assert "New-NetFirewallRule" in remediation["firewall_rules"]["powershell"]
    assert "alert tcp" in remediation["ids_rules"]["snort"]
    assert "drop tcp" in remediation["ids_rules"]["suricata"]

    # 2. FastAPI endpoint check
    resp = client.post("/soar/remediation", json={
        "threat_category": "DOS_SYN_FLOOD",
        "src_ip": "203.0.113.55",
        "dst_ip": "10.0.0.1",
        "dst_port": 443,
        "protocol": "tcp",
        "severity": "CRITICAL"
    })
    assert resp.status_code == 200
    soar_data = resp.json()
    assert soar_data["success"] is True
    assert "INCIDENT TICKET" in soar_data["ticket"]["ticket_markdown"]
    assert soar_data["ticket"]["stix_bundle"]["type"] == "bundle"
    print("  ✓ Feature 2 (SOAR): Engine & API /soar/remediation verified successfully!")


def verify_feature_3_pcap():
    print("[3/7] Verifying PCAP / PCAPNG Ingestion & Flow Reconstructor...")
    # Build syntactically valid PCAP stream with 2 packets
    global_hdr = struct.pack("=IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 1, 0, 64, 6, 0, b"\xc0\xa8\x01\x1e", b"\n\x00\x00\x02")
    tcp = struct.pack("!HHIIBBHHH", 50222, 80, 100, 0, 0x50, 0x02, 8192, 0, 0)
    pkt_data = eth + ip + tcp
    pkt_hdr = struct.pack("=IIII", 1600000000, 0, len(pkt_data), len(pkt_data))
    pcap_bytes = global_hdr + pkt_hdr + pkt_data

    # 1. Engine check
    flows_df = pcap_extractor.parse_file(pcap_bytes)
    assert not flows_df.empty
    assert len(flows_df) == 1
    assert "Flow Duration" in flows_df.columns
    assert "Total Fwd Packets" in flows_df.columns

    # 2. FastAPI endpoint check
    resp = client.post(
        "/analyze/pcap",
        files={"file": ("capture.pcap", pcap_bytes, "application/vnd.tcpdump.pcap")}
    )
    assert resp.status_code == 200
    pcap_api_res = resp.json()
    assert pcap_api_res["success"] is True
    assert pcap_api_res["summary"]["total_flows"] == 1
    assert len(pcap_api_res["predictions"]) == 1
    print("  ✓ Feature 3 (PCAP): Engine & API /analyze/pcap verified successfully!")


def verify_feature_4_multiclass():
    print("[4/7] Verifying Multi-Class Attack Classification...")
    # Test DoS SYN flood
    syn_flood = {"Destination Port": 80, "Total Fwd Packets": 10000, "SYN Flag Count": 9500, "Flow Duration": 60000}
    res_dos = multiclass_classifier.classify_flow(syn_flood)
    assert res_dos["category_code"] == "DOS"

    # Test Port Scan
    port_scan = {"Destination Port": 445, "Total Fwd Packets": 2, "SYN Flag Count": 2, "Flow Duration": 50}
    res_scan = multiclass_classifier.classify_flow(port_scan)
    assert res_scan["category_code"] == "PORTSCAN"

    # Test SSH Brute Force
    ssh_brute = {"Destination Port": 22, "Total Fwd Packets": 60, "RST Flag Count": 20, "Flow Duration": 8000}
    res_ssh = multiclass_classifier.classify_flow(ssh_brute)
    assert res_ssh["category_code"] == "BRUTE_FORCE"
    print("  ✓ Feature 4 (MultiClass): DoS, PortScan, and Brute Force classified with distinct behavioral signatures!")


def verify_feature_5_threat_intel():
    print("[5/7] Verifying Threat Intelligence & Geo-IP Enrichment...")
    # 1. Engine check (private IP)
    priv_info = threat_intel_engine.lookup_ip("192.168.1.50")
    assert priv_info["country"] == "Internal Network"
    assert priv_info["asn"] == "RFC-1918 Private Intranet"

    # 2. Engine check (public IP)
    pub_info = threat_intel_engine.lookup_ip("142.250.190.46", is_flagged_threat=True)
    assert pub_info["country"] != "Internal Network"
    assert pub_info["reputation_score"] >= 0

    # 3. FastAPI endpoint check
    resp = client.post("/threat-intel/lookup", json={"ip": "142.250.190.46", "is_flagged_threat": True})
    assert resp.status_code == 200
    intel_data = resp.json()
    assert "country" in intel_data
    assert "city" in intel_data
    assert "reputation_score" in intel_data
    print("  ✓ Feature 5 (Threat Intel): Engine & API /threat-intel/lookup verified successfully!")


def verify_feature_6_alerting():
    print("[6/7] Verifying Real-Time Alert Dispatcher & SIEM Integration...")
    payload = {
        "Severity": "CRITICAL",
        "attack_family": "DDoS SYN Flood",
        "src_ip": "198.51.100.22",
        "dst_ip": "10.0.0.1",
        "dst_port": 80,
        "attack_probability": 0.985,
        "rationale": "High-rate asymmetric SYN packet burst matching volumetric attack profile.",
    }
    # 1. Engine check: CEF & Syslog
    cef = alert_integration_engine.format_cef(payload)
    assert "CEF:0|NetGuard AI" in cef
    assert "198.51.100.22" in cef

    syslog = alert_integration_engine.format_syslog_rfc5424(payload)
    assert "<131>1" in syslog or "<134>1" in syslog
    assert "netguard-ai" in syslog

    # 2. FastAPI endpoint check (Mock webhook URL test)
    resp = client.post("/alerts/webhook", json={
        "webhook_url": "invalid-url",
        "channel_type": "slack",
        "alert_payload": payload,
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is False
    assert "Invalid or missing" in data["error"]
    print("  ✓ Feature 6 (Alerting): CEF, Syslog RFC 5424, and /alerts/webhook validated successfully!")


def verify_feature_7_drift():
    print("[7/7] Verifying Continuous Learning & MLOps Drift Monitoring...")
    # 1. Engine PSI check
    sample_df = pd.DataFrame({
        "Flow Duration": np.random.uniform(100, 1000, 40),
        "Total Fwd Packets": np.random.uniform(5, 50, 40),
    })
    drift_res = drift_monitor.evaluate_batch_drift(sample_df)
    assert "overall_psi" in drift_res
    assert drift_res["status"] in ("STABLE", "MODERATE_DRIFT", "CRITICAL_DRIFT")

    # 2. Active learning persistence
    prev_cnt = drift_monitor.get_feedback_count()
    ok = drift_monitor.record_feedback("test-alert-999", "CONFIRMED_ATTACK", {"Flow Duration": 500}, "Verified by QA")
    assert ok is True
    assert drift_monitor.get_feedback_count() == prev_cnt + 1

    # 3. FastAPI endpoint check
    resp = client.post("/mlops/feedback", json={
        "alert_id": "test-alert-1000",
        "analyst_label": "FALSE_POSITIVE",
        "feature_vector": {"Flow Duration": 250},
        "analyst_notes": "Internal vulnerability scan",
    })
    assert resp.status_code == 200
    assert resp.json()["success"] is True
    print("  ✓ Feature 7 (Drift & MLOps): PSI drift scoring & /mlops/feedback active learning validated!")


def verify_api_status():
    print("[STATUS] Checking Overall FastAPI System Health & Capabilities...")
    resp = client.get("/api/status")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "online"
    assert data["version"] == "2.0.0"
    services = data["services"]
    for svc in [
        "ml_engine", "rag_knowledge_base", "xai_engine", "soar_engine",
        "pcap_extractor", "multiclass_classifier", "threat_intel_engine",
        "alert_integrations", "drift_monitor"
    ]:
        assert services.get(svc) is True, f"Service {svc} is not reported as active!"
    print(f"  ✓ System Status: 100% Online with {len(data['endpoints'])} registered endpoints!")


if __name__ == "__main__":
    print("=" * 70)
    print("NETGUARD AI — COMPLETE 7 FEATURES RE-VERIFICATION & ENDPOINT AUDIT")
    print("=" * 70)
    verify_feature_1_xai()
    verify_feature_2_soar()
    verify_feature_3_pcap()
    verify_feature_4_multiclass()
    verify_feature_5_threat_intel()
    verify_feature_6_alerting()
    verify_feature_7_drift()
    verify_api_status()
    print("=" * 70)
    print(">>> ALL 7 RECOMMENDED FEATURES FULLY RE-VERIFIED & OPERATIONAL! <<<")
    print("=" * 70)
