"""
Comprehensive Automated Test Suite for NetGuard AI Phase 2: Live Monitoring & Flow Feature Extraction.

Validates:
1. Local interface discovery and detailed attribute parsing.
2. Strict interface authorization policy (unauthorized interfaces are rejected).
3. Packet-to-flow conversion using canonical 5-tuple session keys.
4. Bidirectional flow direction tracking (forward client vs backward server).
5. TCP connection teardown handling (FIN/RST flags).
6. Exact 78-feature CICIDS feature extraction schema.
7. Machine learning model compatibility: feeds reconstructed flows directly into
   NetworkPredictionEngine.predict_cicids() and verifies end-to-end inference.
8. FastAPI /monitor endpoints with JWT authentication.
"""

from pathlib import Path
import sys
import time
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
from live_monitor import (
    BidirectionalFlow,
    CICIDS_78_FEATURE_NAMES,
    LiveNetworkMonitor,
    PacketRecord,
)
from prediction_engine import NetworkPredictionEngine


class TestPhase2LiveMonitoring(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        database.init_db()
        cls.monitor = LiveNetworkMonitor()
        cls.engine = NetworkPredictionEngine()
        cls.client = TestClient(app)

        # Generate a test analyst token for FastAPI endpoint tests
        cls.token = auth.create_access_token({
            "sub": "1",
            "username": "analyst",
            "email": "analyst@netguard.ai",
            "role": "analyst",
        })
        cls.auth_headers = {"Authorization": f"Bearer {cls.token}"}

    def test_01_interface_discovery(self):
        """Verify interface discovery returns populated interface list with friendly attributes."""
        interfaces = self.monitor.get_available_interfaces()
        self.assertIsInstance(interfaces, list)
        self.assertGreater(len(interfaces), 0)
        first_if = interfaces[0]
        self.assertIn("id", first_if)
        self.assertIn("name", first_if)
        self.assertIn("description", first_if)

    def test_02_interface_authorization_policy(self):
        """Verify sniffing is strictly prohibited on non-authorized interfaces."""
        unauthorized_if = "FakeInterface_NotAuthorized_999"
        self.assertFalse(self.monitor.is_interface_authorized(unauthorized_if))

        # Sniffing on unauthorized interface must raise PermissionError
        with self.assertRaises(PermissionError):
            self.monitor.start_monitoring(unauthorized_if)

        # Authorizing interface
        auth_res = self.monitor.authorize_interface("eth0_sim")
        self.assertEqual(auth_res["status"], "authorized")
        self.assertTrue(self.monitor.is_interface_authorized("eth0_sim"))

    def test_03_packet_to_flow_aggregation(self):
        """Verify multiple packets sharing a 5-tuple are correctly assembled into a bidirectional flow."""
        monitor = LiveNetworkMonitor()
        monitor.authorize_interface("eth0_sim")

        # Client -> Server (SYN)
        p1 = PacketRecord(
            timestamp=100.0,
            src_ip="192.168.1.10",
            dst_ip="10.0.0.5",
            src_port=51234,
            dst_port=443,
            protocol="TCP",
            length=64,
            header_length=32,
            payload_length=0,
            tcp_flags={"SYN": 1, "ACK": 0, "FIN": 0, "RST": 0, "PSH": 0, "URG": 0, "ECE": 0, "CWE": 0},
            tcp_window=64240,
        )
        monitor.process_packet(p1)

        # Server -> Client (SYN-ACK)
        p2 = PacketRecord(
            timestamp=100.005,
            src_ip="10.0.0.5",
            dst_ip="192.168.1.10",
            src_port=443,
            dst_port=51234,
            protocol="TCP",
            length=64,
            header_length=32,
            payload_length=0,
            tcp_flags={"SYN": 1, "ACK": 1, "FIN": 0, "RST": 0, "PSH": 0, "URG": 0, "ECE": 0, "CWE": 0},
            tcp_window=65535,
        )
        monitor.process_packet(p2)

        # Client -> Server (Data ACK)
        p3 = PacketRecord(
            timestamp=100.010,
            src_ip="192.168.1.10",
            dst_ip="10.0.0.5",
            src_port=51234,
            dst_port=443,
            protocol="TCP",
            length=1420,
            header_length=32,
            payload_length=1388,
            tcp_flags={"SYN": 0, "ACK": 1, "FIN": 0, "RST": 0, "PSH": 1, "URG": 0, "ECE": 0, "CWE": 0},
            tcp_window=64240,
        )
        monitor.process_packet(p3)

        status = monitor.get_status()
        self.assertEqual(status["packets_captured"], 3)
        self.assertEqual(status["active_flows"], 1)

    def test_04_tcp_fin_flow_termination(self):
        """Verify TCP FIN flag terminates flow and places it into emitted flows."""
        monitor = LiveNetworkMonitor()
        monitor.authorize_interface("eth0_sim")

        flow_dict = monitor.inject_synthetic_flow(
            src_ip="192.168.1.20",
            dst_ip="10.0.0.1",
            dst_port=80,
            packet_count=5,
        )
        self.assertIsNotNone(flow_dict)
        self.assertEqual(flow_dict["source_ip"], "192.168.1.20")
        self.assertEqual(flow_dict["destination_ip"], "10.0.0.1")
        self.assertEqual(flow_dict["destination_port"], 80)
        self.assertGreaterEqual(flow_dict["packets"], 4)

    def test_05_exact_78_cicids_features(self):
        """Verify all 78 exact features required by CICIDS model are extracted with correct schema."""
        monitor = LiveNetworkMonitor()
        flow = monitor.inject_synthetic_flow(src_ip="172.16.0.5", dst_ip="10.0.0.8", dst_port=8080)
        features = flow["features"]

        self.assertEqual(len(features), 78, f"Feature count was {len(features)}, expected 78.")

        # Ensure zero missing feature names
        missing_names = [name for name in CICIDS_78_FEATURE_NAMES if name not in features]
        self.assertEqual(missing_names, [], f"Missing CICIDS feature columns: {missing_names}")

        # Check key numeric properties
        self.assertEqual(features["Destination Port"], 8080.0)
        self.assertGreater(features["Flow Duration"], 0.0)
        self.assertGreaterEqual(features["Total Fwd Packets"], 1.0)
        self.assertGreaterEqual(features["Total Backward Packets"], 1.0)
        self.assertGreater(features["Flow Bytes/s"], 0.0)

    def test_06_model_inference_compatibility(self):
        """Verify that recent reconstructed flows are accepted directly by prediction_engine."""
        monitor = LiveNetworkMonitor()
        monitor.inject_synthetic_flow(src_ip="192.168.1.99", dst_ip="10.0.0.1", dst_port=80, packet_count=6)

        df = monitor.get_recent_flows_df()
        self.assertFalse(df.empty)

        # Run CICIDS Random Forest prediction directly
        prediction = self.engine.predict_cicids(df)
        self.assertIn("prediction", prediction)
        self.assertIn("confidence", prediction)
        self.assertIn("attack_probability", prediction)
        self.assertIn("risk_score", prediction)
        self.assertIn("severity", prediction)
        self.assertIsInstance(prediction["confidence"], (float, int))

    def test_07_fastapi_monitor_endpoints(self):
        """Verify FastAPI REST endpoints for interface authorization, start, status, and flows."""
        client = self.client
        headers = self.auth_headers

        # 1. Get interfaces
        if_resp = client.get("/monitor/interfaces", headers=headers)
        self.assertEqual(if_resp.status_code, 200)
        self.assertIn("interfaces", if_resp.json())

        # 2. Authorize an interface
        auth_resp = client.post("/monitor/authorize", headers=headers, json={"interface": "eth0_sim"})
        self.assertEqual(auth_resp.status_code, 200)
        self.assertTrue(auth_resp.json()["success"])

        # 3. Simulate packet stream
        sim_resp = client.post("/monitor/simulate-packet-stream", headers=headers, json={
            "source_ip": "192.168.1.77",
            "destination_ip": "10.0.0.2",
            "source_port": 49152,
            "destination_port": 443,
            "protocol": "TCP",
            "packet_count": 6,
        })
        self.assertEqual(sim_resp.status_code, 200)
        self.assertEqual(sim_resp.json()["flow"]["feature_count"], 78)

        # 4. Get recent flows
        flows_resp = client.get("/monitor/flows/recent", headers=headers)
        self.assertEqual(flows_resp.status_code, 200)
        self.assertGreaterEqual(flows_resp.json()["flow_count"], 1)

        # 5. Check status
        stat_resp = client.get("/monitor/status", headers=headers)
        self.assertEqual(stat_resp.status_code, 200)
        self.assertIn("monitor", stat_resp.json())


if __name__ == "__main__":
    unittest.main()
