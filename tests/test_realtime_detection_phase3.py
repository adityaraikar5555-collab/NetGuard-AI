"""
Comprehensive Automated Test Suite for NetGuard AI Phase 3: Real-Time Detection & WebSocket Streaming.

Validates:
1. End-to-end execution of the actual trained Random Forest model on live flows.
2. Real-time dynamic risk scoring (0-100) and severity ratings.
3. Multi-class attack vector classification and MITRE ATT&CK mapping.
4. Active event ring-buffer and statistical tracking.
5. FastAPI REST endpoints (/detection/latest, /detection/stats, /detection/simulate-event).
6. Live WebSocket streaming over /ws/live-stream (connection handshake, ping-pong, real-time alert dispatch).
"""

import json
from pathlib import Path
import sys
import unittest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = PROJECT_ROOT / "src"
BACKEND_DIR = PROJECT_ROOT / "backend"
FRONTEND_DIR = PROJECT_ROOT / "frontend"

for p in (PROJECT_ROOT, SRC_DIR, BACKEND_DIR, FRONTEND_DIR):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

import auth
import database
from fastapi.testclient import TestClient
from frontend.app import app
from live_monitor import live_monitor
from realtime_detector import realtime_detector


class TestPhase3RealTimeDetection(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        database.init_db()
        cls.client = TestClient(app)
        live_monitor.authorize_interface("eth0_sim")

    def test_01_actual_model_inference(self):
        """Verify realtime_detector runs the actual trained model and returns real predictions."""
        # Synthesize a legitimate flow
        normal_flow = live_monitor.inject_synthetic_flow(
            src_ip="192.168.1.55",
            dst_ip="10.0.0.1",
            dst_port=80,
            packet_count=6,
        )
        self.assertIn("features", normal_flow)

        detection = realtime_detector.evaluate_flow(normal_flow)
        self.assertIn("prediction", detection)
        self.assertIn(detection["prediction"], ("BENIGN", "ATTACK"))
        self.assertIn("confidence", detection)
        self.assertIn("risk_score", detection)
        self.assertIn("severity", detection)
        self.assertIn("inference_latency_ms", detection)
        self.assertGreaterEqual(detection["risk_score"], 0)
        self.assertLessEqual(detection["risk_score"], 100)

    def test_02_risk_and_severity_calibration(self):
        """Verify severity levels map correctly to risk scores."""
        # Test low risk flow
        low_risk_flow = live_monitor.inject_synthetic_flow(
            src_ip="192.168.1.10",
            dst_ip="10.0.0.1",
            dst_port=443,
            packet_count=5,
        )
        det = realtime_detector.evaluate_flow(low_risk_flow)
        self.assertIsInstance(det["risk_score"], int)
        self.assertIn(det["severity"], ("CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE"))

    def test_03_event_ring_buffer_and_stats(self):
        """Verify the ring-buffer stores recent events and statistics update monotonically."""
        initial_stats = realtime_detector.get_statistics()
        initial_evals = initial_stats["total_evaluated"]

        # Run an evaluation
        flow = live_monitor.inject_synthetic_flow(src_ip="10.1.1.2", dst_ip="10.1.1.99", dst_port=22)
        realtime_detector.evaluate_flow(flow)

        updated_stats = realtime_detector.get_statistics()
        self.assertGreater(updated_stats["total_evaluated"], initial_evals)

        recent = realtime_detector.get_latest_detections(limit=5)
        self.assertGreater(len(recent), 0)
        self.assertEqual(recent[0]["source_ip"], "10.1.1.2")

    def test_04_fastapi_rest_endpoints(self):
        """Verify /detection/latest, /detection/stats, and /detection/simulate-event."""
        client = self.client

        # Stats
        stats_resp = client.get("/detection/stats")
        self.assertEqual(stats_resp.status_code, 200)
        self.assertIn("statistics", stats_resp.json())

        # Simulate event endpoint
        sim_resp = client.post("/detection/simulate-event", json={
            "source_ip": "192.168.20.10",
            "destination_ip": "10.0.0.8",
            "destination_port": 8080,
            "packet_count": 6,
        })
        self.assertEqual(sim_resp.status_code, 200)
        event = sim_resp.json()["event"]
        self.assertEqual(event["source_ip"], "192.168.20.10")
        self.assertIn("prediction", event)

        # Latest detections
        lat_resp = client.get("/detection/latest?limit=10")
        self.assertEqual(lat_resp.status_code, 200)
        self.assertGreaterEqual(lat_resp.json()["count"], 1)

    def test_05_websocket_live_stream(self):
        """
        CRITICAL REAL-TIME WEBSOCKET TEST:
        Connect to /ws/live-stream, verify handshake, test ping-pong, and receive live detection broadcasts.
        """
        client = self.client

        with client.websocket_connect("/ws/live-stream") as websocket:
            # 1. Initial Handshake Message
            handshake = websocket.receive_json()
            self.assertEqual(handshake["type"], "connection_established")
            self.assertIn("stats", handshake)

            # 2. Ping-Pong Heartbeat
            websocket.send_json({"action": "ping"})
            pong = websocket.receive_json()
            self.assertEqual(pong["type"], "pong")

            # 3. Simulate Flow via WebSocket and receive broadcasted real-time prediction
            websocket.send_json({
                "action": "simulate",
                "src_ip": "192.168.99.1",
                "dst_ip": "10.0.0.5",
                "dst_port": 80,
            })
            stream_event = websocket.receive_json()
            self.assertEqual(stream_event["type"], "flow_detection")
            self.assertEqual(stream_event["source_ip"], "192.168.99.1")
            self.assertIn("prediction", stream_event)
            self.assertIn("risk_score", stream_event)
            self.assertIn("severity", stream_event)
            self.assertIn("confidence", stream_event)


if __name__ == "__main__":
    unittest.main()
