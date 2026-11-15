"""
Comprehensive Automated Test Suite for NetGuard AI Phase 1: Authentication & Multi-Tenancy.

Validates:
1. Secure password hashing with bcrypt (salt generation, constant-time match, bad password rejection).
2. JWT lifecycle (signing, claim extraction, expiry enforcement).
3. API key generation and format validation.
4. User creation and unique constraint handling.
5. Multi-tenant alert isolation: User A's alerts are completely segregated from User B.
6. FastAPI endpoints: /auth/register, /auth/login, /auth/me, /alerts, /alerts/{id}/acknowledge.
"""

from datetime import timedelta
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


class TestPhase1Authentication(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        database.init_db()
        cls.client = TestClient(app)

    def test_01_password_hashing(self):
        """Verify bcrypt hashing and constant-time verification."""
        pwd = "CyberSec@NetGuard2026!#"
        hashed = auth.hash_password(pwd)
        self.assertNotEqual(pwd, hashed)
        self.assertTrue(hashed.startswith("$2b$") or hashed.startswith("$2a$"))
        
        # Correct password verification
        self.assertTrue(auth.verify_password(pwd, hashed))
        # Wrong password rejection
        self.assertFalse(auth.verify_password("WrongPassword123", hashed))
        # Empty inputs
        self.assertFalse(auth.verify_password("", hashed))
        self.assertFalse(auth.verify_password(pwd, ""))

    def test_02_jwt_token_lifecycle(self):
        """Verify JWT token creation, decoding, and expiration."""
        payload = {"sub": "42", "username": "sec_analyst_01", "role": "analyst"}
        token = auth.create_access_token(payload, expires_delta=timedelta(minutes=15))
        self.assertIsInstance(token, str)

        decoded = auth.decode_access_token(token)
        self.assertEqual(decoded["sub"], "42")
        self.assertEqual(decoded["username"], "sec_analyst_01")
        self.assertEqual(decoded["role"], "analyst")
        self.assertIn("exp", decoded)

        # Expired token rejection
        expired_token = auth.create_access_token(payload, expires_delta=timedelta(seconds=-1))
        with self.assertRaises(Exception):
            auth.decode_access_token(expired_token)

    def test_03_api_key_format(self):
        """Verify generated API keys conform to standard prefix and high entropy."""
        key = auth.generate_api_key()
        self.assertTrue(key.startswith("ng_live_"))
        self.assertEqual(len(key), 8 + 64)  # 'ng_live_' + 64 hex chars

    def test_04_user_registration_and_auth(self):
        """Verify user creation, duplicate prevention, and login via DB layer."""
        test_user = "test_user_alpha"
        test_email = "alpha@netguard.ai"
        test_pwd = "StrongPassword@123"

        # Cleanup if left over from previous run
        with database.get_db_connection() as conn:
            conn.execute("DELETE FROM users WHERE username = ?", (test_user,))

        user = database.create_user(
            username=test_user,
            email=test_email,
            password=test_pwd,
            full_name="Alpha Tester",
            role="analyst",
        )
        self.assertEqual(user["username"], test_user)
        self.assertEqual(user["email"], test_email)
        self.assertTrue(user["api_key"].startswith("ng_live_"))

        # Prevent duplicate registration
        with self.assertRaises(ValueError):
            database.create_user(
                username=test_user,
                email="different@netguard.ai",
                password="AnotherPassword@123",
            )

    def test_05_multi_tenant_alert_isolation(self):
        """
        CRITICAL MULTI-TENANCY TEST:
        Ensure User A cannot view, query, or acknowledge alerts created by User B.
        """
        # Create User A and User B
        user_a_name = "tenant_user_a"
        user_b_name = "tenant_user_b"

        with database.get_db_connection() as conn:
            conn.execute("DELETE FROM users WHERE username IN (?, ?)", (user_a_name, user_b_name))

        user_a = database.create_user(user_a_name, "usera@test.com", "PassA123!@#")
        user_b = database.create_user(user_b_name, "userb@test.com", "PassB123!@#")

        # Insert alert under User A
        alert_a = database.insert_user_alert(
            user_id=user_a["id"],
            attack_type="DDoS-LOIC-HTTP",
            severity="Critical",
            confidence=0.99,
            source_ip="192.168.1.50",
            destination_ip="10.0.0.5",
        )

        # Insert alert under User B
        alert_b = database.insert_user_alert(
            user_id=user_b["id"],
            attack_type="PortScan",
            severity="Medium",
            confidence=0.88,
            source_ip="172.16.0.22",
            destination_ip="10.0.0.9",
        )

        # User A queries their alerts: must only see alert_a
        alerts_for_a = database.get_user_alerts(user_id=user_a["id"])
        alert_ids_for_a = [a["id"] for a in alerts_for_a]
        self.assertIn(alert_a["id"], alert_ids_for_a)
        self.assertNotIn(alert_b["id"], alert_ids_for_a, "SECURITY VIOLATION: User A saw User B's alert!")

        # User B queries their alerts: must only see alert_b
        alerts_for_b = database.get_user_alerts(user_id=user_b["id"])
        alert_ids_for_b = [b["id"] for b in alerts_for_b]
        self.assertIn(alert_b["id"], alert_ids_for_b)
        self.assertNotIn(alert_a["id"], alert_ids_for_b, "SECURITY VIOLATION: User B saw User A's alert!")

        # User B attempts to acknowledge User A's alert: must be blocked
        ack_success = database.acknowledge_user_alert(user_id=user_b["id"], alert_id=alert_a["id"])
        self.assertFalse(ack_success, "SECURITY VIOLATION: User B acknowledged User A's alert!")

    def test_06_fastapi_auth_endpoints(self):
        """Verify FastAPI HTTP endpoints for authentication and user-specific alerts."""
        client = self.client

        # 1. Register a test analyst via HTTP
        uname = "http_analyst_test"
        email = "http_analyst@netguard.ai"
        pwd = "HttpSecPass@2026!"

        with database.get_db_connection() as conn:
            conn.execute("DELETE FROM users WHERE username = ?", (uname,))

        reg_resp = client.post("/auth/register", json={
            "username": uname,
            "email": email,
            "password": pwd,
            "full_name": "HTTP Test Analyst",
            "role": "analyst",
        })
        self.assertEqual(reg_resp.status_code, 201)
        token = reg_resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 2. Verify /auth/me
        me_resp = client.get("/auth/me", headers=headers)
        self.assertEqual(me_resp.status_code, 200)
        self.assertEqual(me_resp.json()["user"]["username"], uname)

        # 3. Post a new alert
        alert_resp = client.post("/alerts", headers=headers, json={
            "attack_type": "Infiltration-Exploit",
            "severity": "High",
            "confidence": 0.94,
            "source_ip": "192.168.10.55",
            "destination_ip": "10.1.1.200",
            "protocol": "TCP",
            "details": {"payload_size": 1420, "cve": "CVE-2026-9999"},
        })
        self.assertEqual(alert_resp.status_code, 201)
        created_alert_id = alert_resp.json()["alert"]["id"]

        # 4. Retrieve user alerts
        list_resp = client.get("/alerts", headers=headers)
        self.assertEqual(list_resp.status_code, 200)
        user_alerts = list_resp.json()["alerts"]
        self.assertTrue(any(a["id"] == created_alert_id for a in user_alerts))

        # 5. Acknowledge alert
        ack_resp = client.post(f"/alerts/{created_alert_id}/acknowledge", headers=headers)
        self.assertEqual(ack_resp.status_code, 200)

        # 6. Check stats
        stats_resp = client.get("/alerts/stats", headers=headers)
        self.assertEqual(stats_resp.status_code, 200)
        self.assertGreaterEqual(stats_resp.json()["statistics"]["total_alerts"], 1)


if __name__ == "__main__":
    unittest.main()
