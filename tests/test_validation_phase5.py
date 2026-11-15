"""
Comprehensive Automated Test Suite for NetGuard AI Phase 5: Validation, Benchmarking & Multi-Tenant Security Isolation.

Validates:
1. Mathematical accuracy of efficacy metrics (Precision, Recall, F1-Score, False-Positive Rate).
2. Live ground-truth evaluation on labeled CICIDS-2017 dataset traffic.
3. Confirmation that actual traffic produces real machine learning predictions.
4. Programmatic audit of cross-tenant data isolation certifying zero alert leakage between accounts.
5. Strict enforcement that tenant users cannot acknowledge or inspect another tenant's alerts.
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
from benchmark_validator import BenchmarkValidator, benchmark_validator


class TestPhase5Validation(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        database.init_db()
        cls.client = TestClient(app)
        cls.validator = BenchmarkValidator()

    def test_01_mathematical_metric_calculation(self):
        """Verifies formulas for Precision, Recall, F1, and FPR against known confusion matrices."""
        validator = self.validator

        # Synthetic scenario:
        # TP = 40, FP = 10, FN = 5, TN = 45 -> Total = 100
        # Accuracy: (40 + 45) / 100 = 0.85
        # Precision: 40 / (40 + 10) = 0.80
        # Recall: 40 / (40 + 5) = 40 / 45 = 0.8889
        # F1: 2 * (0.80 * 0.8889) / (0.80 + 0.8889) = 0.8421
        # FPR: 10 / (10 + 45) = 10 / 55 = 0.1818

        y_true = [1]*40 + [0]*10 + [1]*5 + [0]*45
        y_pred = [1]*40 + [1]*10 + [0]*5 + [0]*45

        report = validator.evaluate_efficacy(y_true, y_pred)
        metrics = report["metrics"]
        cm = report["confusion_matrix"]

        self.assertEqual(cm["true_positives"], 40)
        self.assertEqual(cm["false_positives"], 10)
        self.assertEqual(cm["false_negatives"], 5)
        self.assertEqual(cm["true_negatives"], 45)

        self.assertAlmostEqual(metrics["accuracy"], 0.85, places=2)
        self.assertAlmostEqual(metrics["precision"], 0.80, places=2)
        self.assertAlmostEqual(metrics["recall"], 0.8889, places=2)
        self.assertAlmostEqual(metrics["f1_score"], 0.8421, places=2)
        self.assertAlmostEqual(metrics["false_positive_rate"], 0.1818, places=2)

    def test_02_zero_division_resilience(self):
        """Verifies evaluate_efficacy gracefully handles arrays with no positive predictions."""
        validator = self.validator
        y_true = [0, 0, 0, 0]
        y_pred = [0, 0, 0, 0]

        report = validator.evaluate_efficacy(y_true, y_pred)
        self.assertEqual(report["metrics"]["precision"], 0.0)
        self.assertEqual(report["metrics"]["false_positive_rate"], 0.0)
        self.assertEqual(report["metrics"]["accuracy"], 1.0)

    def test_03_ground_truth_traffic_benchmark(self):
        """
        Runs actual trained model on ground-truth labeled flows.
        Confirms actual traffic produces predictions and benchmarks efficacy.
        """
        report = benchmark_validator.run_ground_truth_test(sample_size=20)

        self.assertIn("metrics", report)
        metrics = report["metrics"]
        self.assertGreaterEqual(metrics["accuracy"], 0.80, "Model accuracy on ground truth must be >= 80%")
        self.assertGreaterEqual(metrics["precision"], 0.80, "Precision on ground truth must be >= 80%")
        self.assertGreaterEqual(metrics["recall"], 0.80, "Recall on ground truth must be >= 80%")
        self.assertLessEqual(metrics["false_positive_rate"], 0.15, "False positive rate must remain low")
        self.assertEqual(report["test_status"], "PASSED")

    def test_04_cross_tenant_security_isolation_audit(self):
        """
        Verifies that Tenant A's alerts and streams are strictly inaccessible to Tenant B.
        Zero cross-tenant leakage allowed.
        """
        audit = benchmark_validator.audit_tenant_isolation()

        self.assertTrue(audit["is_isolated"], "Audit failed: Cross-tenant alert leakage detected!")
        self.assertEqual(audit["leaked_into_tenant_b"], 0)
        self.assertEqual(audit["leaked_into_tenant_a"], 0)
        self.assertIn("PASSED", audit["audit_verdict"])

    def test_05_cross_tenant_api_access_boundary(self):
        """
        Tests API endpoint authorization: User A cannot acknowledge or access User B's alert.
        """
        # Create User A and User B
        import time
        ts = int(time.time() * 1000)
        u_a = database.create_user(f"sec_a_{ts}", f"sec_a_{ts}@test.com", "Password@A123!")
        u_b = database.create_user(f"sec_b_{ts}", f"sec_b_{ts}@test.com", "Password@B123!")

        # Insert alert under User A
        alert_a = database.insert_user_alert(
            user_id=u_a["id"],
            attack_type="DDoS-LOIC-HTTP",
            severity="Critical",
            confidence=0.99,
            source_ip="192.168.1.50",
            destination_ip="10.0.0.1",
        )

        # Login as User B to obtain User B's token
        login_b = self.client.post("/auth/login", json={
            "username": u_b["username"],
            "password": "Password@B123!",
        })
        token_b = login_b.json()["access_token"]
        headers_b = {"Authorization": f"Bearer {token_b}"}

        # User B queries alerts: User A's alert must NOT be present
        b_alerts_resp = self.client.get("/alerts", headers=headers_b)
        b_alerts = b_alerts_resp.json()["alerts"]
        b_alert_ids = [a["id"] for a in b_alerts]
        self.assertNotIn(alert_a["id"], b_alert_ids, "User A's alert leaked into User B's alerts list!")

        # User B attempts to acknowledge User A's alert: must return 404 Not Found (isolated)
        ack_resp = self.client.post(f"/alerts/{alert_a['id']}/acknowledge", headers=headers_b)
        self.assertEqual(ack_resp.status_code, 404, "User B should not be able to acknowledge User A's alert!")


if __name__ == "__main__":
    unittest.main()
