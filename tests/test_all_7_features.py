"""
Comprehensive End-to-End Verification Test Suite for All 7 Power Features in NetGuard AI.
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

from src.xai_engine import xai_engine
from src.soar_engine import soar_engine
from src.pcap_extractor import pcap_extractor
from src.multiclass_engine import multiclass_classifier
from src.threat_intel import threat_intel_engine
from src.alert_integrations import alert_integration_engine
from src.drift_monitor import drift_monitor
from frontend.app import app


def test_feature_1_xai():
    print("[1/7] Testing Explainable AI (XAI)...")
    sample_flow = {
        "Destination Port": 80,
        "Flow Duration": 120000000,
        "Total Fwd Packets": 15000,
        "Total Backward Packets": 10,
        "Flow Bytes/s": 4500000.0,
        "Flow Packets/s": 98000.0,
        "SYN Flag Count": 14000,
        "ACK Flag Count": 2,
    }
    explanation = xai_engine.explain(sample_flow, dataset="CICIDS-2017", top_k=5)
    assert "top_features" in explanation
    assert len(explanation["top_features"]) > 0
    assert "plain_english_rationale" in explanation
    assert len(explanation["plain_english_rationale"]) > 10
    print(f"  ✓ XAI Rationale: {explanation['plain_english_rationale'][:80]}...")


def test_feature_2_soar():
    print("[2/7] Testing Agentic SOAR & MITRE ATT&CK...")
    mitre = soar_engine.map_mitre("DOS_SYN_FLOOD")
    assert mitre["technique_id"] == "T1498"
    assert "Denial of Service" in mitre["technique_name"]

    remediation = soar_engine.generate_remediation("198.51.100.42", "10.0.0.1", 80, "tcp", "CRITICAL")
    assert "iptables" in remediation["firewall_rules"]
    assert "198.51.100.42" in remediation["firewall_rules"]["iptables"]
    assert "snort" in remediation["ids_rules"]

    ticket = soar_engine.create_incident_ticket({"Severity": "Critical"}, mitre, remediation)
    assert "INCIDENT TICKET" in ticket["ticket_markdown"]
    assert "stix_bundle" in ticket
    print(f"  ✓ MITRE: {mitre['technique_id']} | Rule: {remediation['firewall_rules']['iptables'][:45]}...")


def test_feature_3_pcap():
    print("[3/7] Testing PCAP Ingestion & Flow Reconstructor...")
    global_hdr = struct.pack("=IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 1, 0, 64, 6, 0, b"\xc0\xa8\x01\x05", b"\n\x00\x00\x01")
    tcp = struct.pack("!HHIIBBHHH", 44321, 80, 100, 0, 0x50, 0x02, 8192, 0, 0)
    pkt_data = eth + ip + tcp
    pkt_hdr = struct.pack("=IIII", 1600000000, 0, len(pkt_data), len(pkt_data))
    pcap_bytes = global_hdr + pkt_hdr + pkt_data

    flows_df = pcap_extractor.parse_file(pcap_bytes)
    assert not flows_df.empty
    assert "Flow Duration" in flows_df.columns
    assert "Destination Port" in flows_df.columns
    ports = [int(flows_df.iloc[0]["Source Port"]), int(flows_df.iloc[0]["Destination Port"])]
    assert 80 in ports
    print(f"  ✓ PCAP Flows Extracted: 1 flow, Port 80 matched.")


def test_feature_4_multiclass():
    print("[4/7] Testing Multi-Class Attack Classification...")
    sample_recon = {
        "Destination Port": 445,
        "Total Fwd Packets": 2,
        "SYN Flag Count": 2,
        "Flow Duration": 50,
    }
    mc = multiclass_classifier.classify_flow(sample_recon)
    assert mc["category_code"] == "PORTSCAN"
    assert "Port Scan" in mc["attack_family"] or "Reconnaissance" in mc["attack_family"]
    print(f"  ✓ Attack Family: {mc['attack_family']} (Confidence: {mc['confidence']*100:.0f}%)")


def test_feature_5_threat_intel():
    print("[5/7] Testing Threat Intelligence & Geo-IP...")
    intel = threat_intel_engine.lookup_ip("142.250.190.46", is_flagged_threat=True)
    assert intel["country"] != ""
    assert "reputation_score" in intel
    assert intel["reputation_score"] >= 0
    print(f"  ✓ Geo-IP: {intel['country']} ({intel['city']}), Reputation Score: {intel['reputation_score']}/100")


def test_feature_6_alerting():
    print("[6/7] Testing Real-Time Alert Formats & Integrations...")
    alert_payload = {
        "Severity": "CRITICAL",
        "attack_family": "DDoS SYN Flood",
        "src_ip": "198.51.100.5",
        "dst_ip": "10.0.0.1",
        "dst_port": 80,
        "rationale": "High-volume SYN flood overwhelming web server.",
    }
    cef = alert_integration_engine.format_cef(alert_payload)
    syslog = alert_integration_engine.format_syslog_rfc5424(alert_payload)
    assert cef.startswith("CEF:0|NetGuard AI")
    assert "<131>1" in syslog or "<134>1" in syslog
    print(f"  ✓ CEF: {cef[:60]}...")
    print(f"  ✓ Syslog: {syslog[:60]}...")


def test_feature_7_drift_and_active_learning():
    print("[7/7] Testing MLOps Data Drift & Active Learning...")
    df_batch = pd.DataFrame({"Flow Duration": np.random.uniform(50, 500, 30)})
    drift = drift_monitor.evaluate_batch_drift(df_batch)
    assert "status" in drift
    assert "overall_psi" in drift

    ok = drift_monitor.record_feedback("alert-test-01", "CONFIRMED_ATTACK", {"Flow Duration": 120}, "Test triage")
    assert ok is True
    assert drift_monitor.get_feedback_count() > 0
    print(f"  ✓ Drift Status: {drift['status']} (PSI: {drift['overall_psi']:.3f}), Logged Feedback Count: {drift_monitor.get_feedback_count()}")


def test_fastapi_routes():
    print("[API] Testing FastAPI Endpoint Registry...")
    route_paths = [r.path for r in app.routes]
    expected_new_routes = [
        "/explain",
        "/soar/remediation",
        "/analyze/pcap",
        "/threat-intel/lookup",
        "/alerts/webhook",
        "/mlops/feedback",
        "/api/status",
    ]
    for route in expected_new_routes:
        assert route in route_paths, f"Route {route} not registered in FastAPI!"
    print(f"  ✓ All {len(expected_new_routes)} new API endpoints successfully registered!")


if __name__ == "__main__":
    print("=" * 60)
    print("NETGUARD AI — 7 ADVANCED POWER FEATURES VERIFICATION SUITE")
    print("=" * 60)
    test_feature_1_xai()
    test_feature_2_soar()
    test_feature_3_pcap()
    test_feature_4_multiclass()
    test_feature_5_threat_intel()
    test_feature_6_alerting()
    test_feature_7_drift_and_active_learning()
    test_fastapi_routes()
    print("=" * 60)
    print(">>> ALL 7 FEATURES FULLY IMPLEMENTED AND VERIFIED PASSING! <<<")
    print("=" * 60)
