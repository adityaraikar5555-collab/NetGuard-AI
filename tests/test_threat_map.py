"""
Unit tests for the 3D Global Threat Intelligence Map Engine.
"""

import pytest
from src.threat_map_engine import (
    DEFAULT_SOC_LOCATION,
    ThreatEvent,
    ThreatMapEngine,
    global_threat_map_engine,
)


def test_threat_map_engine_init_and_seed():
    engine = ThreatMapEngine(max_history=50)
    assert engine.max_history == 50
    assert engine.soc_location["city"] == DEFAULT_SOC_LOCATION["city"]
    # Seeded with initial baseline
    assert len(engine._history) == 35


def test_generate_synthetic_event():
    engine = ThreatMapEngine(max_history=20)
    event = engine.generate_synthetic_event(force_critical=True, fixed_country="Germany")
    assert isinstance(event, ThreatEvent)
    assert event.event_id.startswith("EVT-")
    assert event.severity == "Critical"
    assert event.src_country == "Germany"
    assert event.dst_city == engine.soc_location["city"]
    assert event.status in ("BLOCKED", "INTERCEPTED", "ANALYZING")
    assert event.bandwidth_mbps > 0


def test_ring_buffer_eviction():
    engine = ThreatMapEngine(max_history=10)
    for _ in range(25):
        ev = engine.generate_synthetic_event()
        engine.record_event(ev)
    assert len(engine._history) == 10


def test_pulse_attack():
    engine = ThreatMapEngine(max_history=50)
    initial_count = len(engine._history)
    new_events = engine.pulse_attack(count=5)
    assert len(new_events) == 5
    assert len(engine._history) == initial_count + 5


def test_get_recent_events_and_filtering():
    engine = ThreatMapEngine(max_history=50)
    # Inject specific events
    crit = engine.generate_synthetic_event(force_critical=True)
    engine.record_event(crit)

    recent = engine.get_recent_events(limit=10)
    assert len(recent) <= 10
    assert recent[0]["event_id"] == crit.event_id  # Most recent first

    crit_only = engine.get_recent_events(limit=50, severity_filter="Critical")
    assert all(e["severity"] == "Critical" for e in crit_only)
    assert any(e["event_id"] == crit.event_id for e in crit_only)


def test_get_top_origin_countries():
    engine = ThreatMapEngine(max_history=50)
    top_countries = engine.get_top_origin_countries(limit=4)
    assert isinstance(top_countries, list)
    assert len(top_countries) <= 4
    if top_countries:
        first = top_countries[0]
        assert "country" in first
        assert "code" in first
        assert "total_attacks" in first
        assert "critical_attacks" in first
        assert first["total_attacks"] >= 1


def test_get_threat_arc_data():
    engine = ThreatMapEngine(max_history=50)
    arcs = engine.get_threat_arc_data(limit=15)
    assert isinstance(arcs, list)
    assert len(arcs) <= 15
    if arcs:
        arc = arcs[0]
        assert "src_lat" in arc
        assert "src_lon" in arc
        assert "dst_lat" in arc
        assert "dst_lon" in arc
        assert arc["color"].startswith("#")
        assert "attack_type" in arc


def test_get_summary_metrics():
    engine = ThreatMapEngine(max_history=50)
    metrics = engine.get_summary_metrics()
    assert metrics["total_events"] > 0
    assert 0 <= metrics["mitigation_rate"] <= 100.0
    assert metrics["total_bandwidth_gbps"] >= 0
    assert metrics["unique_countries"] > 0
    assert metrics["soc_hq"] == DEFAULT_SOC_LOCATION["name"]


def test_singleton_instance():
    assert global_threat_map_engine is not None
    assert len(global_threat_map_engine._history) > 0


def test_threat_map_fastapi_endpoints():
    from fastapi.testclient import TestClient
    from frontend.app import app

    client = TestClient(app)

    # 1. Test Telemetry Endpoint
    res = client.get("/threat-map/telemetry?limit_arcs=10&limit_events=15")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert "summary" in data
    assert "top_countries" in data
    assert "arcs" in data
    assert "recent_events" in data
    assert len(data["arcs"]) <= 10
    assert len(data["recent_events"]) <= 15
    assert data["soc_hq"]["city"] == DEFAULT_SOC_LOCATION["city"]

    # 2. Test Pulse Endpoint
    pulse_res = client.post("/threat-map/pulse", json={"count": 3})
    assert pulse_res.status_code == 200
    pulse_data = pulse_res.json()
    assert pulse_data["status"] == "success"
    assert pulse_data["pulsed_count"] == 3
    assert len(pulse_data["events"]) == 3
    assert "summary" in pulse_data

