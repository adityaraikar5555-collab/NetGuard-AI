"""
Tests for NetGuard AI Red vs Blue Interactive Attack Simulator Engine.
Verifies offensive weapon synthesis, line-rate ML detection, XAI attribution, and SOAR containment.
"""

import pytest
from src.attack_simulator import AttackSimulatorEngine, attack_simulator


@pytest.fixture
def simulator():
    return AttackSimulatorEngine()


def test_arsenal_profiles(simulator):
    arsenal = simulator.get_arsenal_list()
    assert len(arsenal) >= 6

    keys = [item["id"] for item in arsenal]
    assert "SYN_FLOOD" in keys
    assert "PORT_SCAN" in keys
    assert "SLOWLORIS" in keys
    assert "BRUTE_FORCE" in keys
    assert "DNS_EXFILTRATION" in keys
    assert "ICMP_SMURF" in keys


def test_generate_flow_vector_syn_flood(simulator):
    flow = simulator.generate_flow_vector("SYN_FLOOD", intensity=1.5, target_port=80)
    assert isinstance(flow, dict)
    assert flow["Destination Port"] == 80
    assert flow["SYN Flag Count"] == 1
    assert flow["ACK Flag Count"] == 0
    assert flow["Flow Packets/s"] > 50000


def test_generate_flow_vector_port_scan(simulator):
    flow = simulator.generate_flow_vector("PORT_SCAN", target_port=443)
    assert flow["Destination Port"] == 443
    assert flow["Total Fwd Packets"] == 1
    assert flow["Init_Win_bytes_forward"] == 1024


def test_emit_network_probe(simulator):
    res = simulator.emit_network_probe(target_port=80, protocol="TCP", packet_count=2)
    assert isinstance(res, dict)
    assert "packets_emitted" in res
    assert res["protocol"] == "TCP"


def test_run_war_game_pipeline(simulator):
    report = simulator.run_war_game(
        attack_type="SYN_FLOOD",
        intensity=1.2,
        target_ip="192.168.1.50",
        target_port=80,
        emit_live_probe=False,
    )
    assert isinstance(report, dict)
    assert report["campaign_id"].startswith("WAR-")
    assert report["mitre_id"] == "T1498.001"
    assert report["severity"] in ("CRITICAL", "HIGH", "MEDIUM")
    assert report["risk_score"] >= 50
    assert report["confidence_pct"] > 70.0
    assert len(report["events_timeline"]) == 5
    assert len(report["xai_top_features"]) >= 1
    assert "iptables" in report["soar_mitigation"]
    assert "powershell" in report["soar_mitigation"]


def test_host_quarantine_lifecycle(simulator):
    ip = "198.51.100.99"
    q_entry = simulator.quarantine_host(ip, reason="SYN Flood DoS", mitre_id="T1498.001", risk_score=99)
    assert q_entry["ip"] == ip
    assert q_entry["status"] == "QUARANTINED"

    hosts = simulator.get_quarantined_hosts()
    assert any(h["ip"] == ip for h in hosts)

    unq_res = simulator.unquarantine_host(ip)
    assert unq_res is True

    hosts_after = simulator.get_quarantined_hosts()
    assert not any(h["ip"] == ip for h in hosts_after)
