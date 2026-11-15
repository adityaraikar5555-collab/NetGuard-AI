"""
Comprehensive Automated Test Suite for NetGuard AI Phase 4: Notifications, Deduplication & Delivery.

Validates:
1. Sliding-Window Deduplication: Suppresses notification storms/bursts within configurable TTL window.
2. Canonical Key Generation: Evaluates deterministic hashing of (src_ip, attack_family, dst_port).
3. Occurrence Aggregation: Increments burst counts on duplicate threats.
4. Multi-Tenant Alert History Persistence: Binds delivered notifications to tenant storage.
5. In-Browser / Dashboard Toast Payload Generation.
6. Cyber HTML Alert Email Formatting & Fallback Delivery.
7. FastAPI Endpoints (/notifications/dispatch, /notifications/suppression-stats, /notifications/test-email).
"""

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
from notification_engine import NotificationEngine, notification_engine


class TestPhase4Notifications(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        database.init_db()
        cls.client = TestClient(app)
        # Login admin user to obtain Bearer JWT
        login_res = cls.client.post("/auth/login", json={
            "username": "admin",
            "password": "NetGuard@Admin2026!",
        })
        assert login_res.status_code == 200, f"Auth login failed: {login_res.text}"
        cls.admin_token = login_res.json()["access_token"]
        cls.auth_headers = {"Authorization": f"Bearer {cls.admin_token}"}

    def setUp(self):
        # Reset engine window for deterministic test states
        notification_engine.reset_window()

    def test_01_canonical_key_generation(self):
        """Verifies deterministic deduplication key generation."""
        engine = NotificationEngine(suppression_window_seconds=10.0)

        p1 = {"source_ip": "192.168.1.100", "attack_family": "DDoS", "destination_port": 80}
        p2 = {"source_ip": "192.168.1.100", "attack_family": "ddos", "destination_port": "80"}
        p3 = {"source_ip": "192.168.1.101", "attack_family": "DDoS", "destination_port": 80}

        k1 = engine.compute_alert_key(p1)
        k2 = engine.compute_alert_key(p2)
        k3 = engine.compute_alert_key(p3)

        self.assertEqual(k1, k2, "Keys should match regardless of case or string/int port type.")
        self.assertNotEqual(k1, k3, "Different IP must yield a distinct deduplication key.")

    def test_02_first_occurrence_dispatches_alert(self):
        """Verifies first alert in window is dispatched, returns browser notification, and saves to DB."""
        payload = {
            "attack_family": "PortScan",
            "severity": "High",
            "confidence": 0.94,
            "source_ip": "10.0.0.99",
            "destination_ip": "10.0.0.1",
            "destination_port": 443,
            "protocol": "TCP",
        }

        res = notification_engine.process_incoming_alert(payload, user_id=1)
        self.assertEqual(res["status"], "dispatched")
        self.assertEqual(res["event_count"], 1)
        self.assertIn("alert_key", res)
        self.assertIn("alert_id", res)
        self.assertIn("browser_notification", res)
        self.assertIn("🚨 NetGuard Alert", res["browser_notification"]["title"])

    def test_03_sliding_window_suppresses_repeated_bursts(self):
        """Verifies duplicate events within 180s TTL window are suppressed."""
        payload = {
            "attack_family": "DDoS-LOIC-HTTP",
            "severity": "Critical",
            "confidence": 0.99,
            "source_ip": "192.168.1.50",
            "destination_ip": "10.0.0.1",
            "destination_port": 80,
            "protocol": "TCP",
        }

        # First alert: dispatched
        r1 = notification_engine.process_incoming_alert(payload, user_id=1)
        self.assertEqual(r1["status"], "dispatched")

        # Second alert: duplicate -> suppressed
        r2 = notification_engine.process_incoming_alert(payload, user_id=1)
        self.assertEqual(r2["status"], "suppressed")
        self.assertEqual(r2["event_count"], 2)
        self.assertIn("Duplicate event suppressed", r2["reason"])

        # Third alert: duplicate -> suppressed
        r3 = notification_engine.process_incoming_alert(payload, user_id=1)
        self.assertEqual(r3["status"], "suppressed")
        self.assertEqual(r3["event_count"], 3)

    def test_04_suppression_statistics_telemetry(self):
        """Verifies accurate calculation of suppression metrics and storm prevention rate."""
        payload_a = {"source_ip": "1.1.1.1", "attack_family": "Infiltration", "destination_port": 22}
        payload_b = {"source_ip": "2.2.2.2", "attack_family": "Botnet", "destination_port": 8080}

        notification_engine.process_incoming_alert(payload_a, user_id=1)  # dispatched
        notification_engine.process_incoming_alert(payload_a, user_id=1)  # suppressed
        notification_engine.process_incoming_alert(payload_a, user_id=1)  # suppressed
        notification_engine.process_incoming_alert(payload_b, user_id=1)  # dispatched

        stats = notification_engine.get_suppression_statistics()
        self.assertEqual(stats["total_received"], 4)
        self.assertEqual(stats["total_dispatched"], 2)
        self.assertEqual(stats["total_suppressed"], 2)
        self.assertEqual(stats["suppression_rate_percent"], 50.0)
        self.assertEqual(stats["active_window_entries"], 2)

    def test_05_email_html_formatting_and_safe_dispatch(self):
        """Verifies HTML alert email builder and safe simulation when offline."""
        payload = {
            "attack_family": "DDoS-SYN-Flood",
            "severity": "CRITICAL",
            "confidence": 0.98,
            "source_ip": "172.16.0.44",
            "destination_ip": "10.0.0.1",
            "destination_port": 80,
        }

        res = notification_engine.send_email_alert(
            recipient="analyst@netguard.ai",
            alert_payload=payload,
        )
        self.assertTrue(res.get("success") or res.get("simulated"))
        self.assertEqual(res.get("recipient"), "analyst@netguard.ai")

    def test_06_fastapi_dispatch_endpoint(self):
        """Verifies POST /notifications/dispatch endpoint with authenticated user token."""
        client = self.client

        # Ingest first event
        resp1 = client.post(
            "/notifications/dispatch",
            headers=self.auth_headers,
            json={
                "attack_family": "SSH-Bruteforce",
                "severity": "High",
                "confidence": 0.92,
                "source_ip": "10.20.30.40",
                "destination_ip": "10.0.0.5",
                "destination_port": 22,
                "protocol": "TCP",
            },
        )
        self.assertEqual(resp1.status_code, 200)
        res1 = resp1.json()["result"]
        self.assertEqual(res1["status"], "dispatched")

        # Ingest identical event (should be suppressed by sliding window)
        resp2 = client.post(
            "/notifications/dispatch",
            headers=self.auth_headers,
            json={
                "attack_family": "SSH-Bruteforce",
                "severity": "High",
                "confidence": 0.92,
                "source_ip": "10.20.30.40",
                "destination_ip": "10.0.0.5",
                "destination_port": 22,
                "protocol": "TCP",
            },
        )
        self.assertEqual(resp2.status_code, 200)
        res2 = resp2.json()["result"]
        self.assertEqual(res2["status"], "suppressed")
        self.assertEqual(res2["event_count"], 2)

    def test_07_fastapi_suppression_stats_and_test_email(self):
        """Verifies GET /notifications/suppression-stats and POST /notifications/test-email."""
        client = self.client

        stats_resp = client.get("/notifications/suppression-stats", headers=self.auth_headers)
        self.assertEqual(stats_resp.status_code, 200)
        self.assertIn("statistics", stats_resp.json())

        mail_resp = client.post(
            "/notifications/test-email",
            headers=self.auth_headers,
            json={
                "recipient": "security_ops@netguard.ai",
                "attack_family": "Infiltration-Drop",
                "severity": "Critical",
            },
        )
        self.assertEqual(mail_resp.status_code, 200)
        self.assertTrue(mail_resp.json().get("result", {}).get("success") or mail_resp.json().get("result", {}).get("simulated"))


if __name__ == "__main__":
    unittest.main()
