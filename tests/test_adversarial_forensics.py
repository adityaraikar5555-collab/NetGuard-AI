"""
Unit and Integration Tests for Option B Features:
- Feature 3: Adversarial Robustness & Red-Team Evasion Tester
- Feature 4: 1-Click Cryptographic Incident Package & Forensic Case Export
"""

import unittest
import base64
import zipfile
import io
import hashlib
from pathlib import Path
from fastapi.testclient import TestClient

from src.adversarial_tester import adversarial_tester, AdversarialRobustnessTester
from src.forensic_packager import forensic_packager, ForensicIncidentPackager
from backend.main import app as backend_app
from frontend.app import app as frontend_app


class TestAdversarialAndForensics(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.backend_client = TestClient(backend_app)
        cls.frontend_client = TestClient(frontend_app)
        cls.sample_flow = {
            "Flow Duration": 120000000,
            "Total Fwd Packets": 15000,
            "Total Backward Packets": 10,
            "Total Length of Fwd Packets": 1050000,
            "Flow Bytes/s": 4500000.0,
            "Flow Packets/s": 98000.0,
            "SYN Flag Count": 14000,
            "ACK Flag Count": 2,
            "Init_Win_bytes_forward": 8192,
            "attack_probability": 0.98,
            "is_attack": True,
            "prediction": "Attack",
        }

    # ========================================================================
    # FEATURE 3: ADVERSARIAL ROBUSTNESS TESTS
    # ========================================================================

    def test_01_adversarial_perturbation_vectors(self):
        """Test all 4 adversarial evasion strategies mutate target features."""
        # 1. Header Padding
        p_pad = adversarial_tester.perturb_flow(self.sample_flow, attack_type="HEADER_PADDING", epsilon=0.2)
        self.assertGreater(p_pad["Total Length of Fwd Packets"], self.sample_flow["Total Length of Fwd Packets"])

        # 2. Low and Slow
        p_slow = adversarial_tester.perturb_flow(self.sample_flow, attack_type="LOW_AND_SLOW", epsilon=0.2)
        self.assertLess(p_slow["Flow Packets/s"], self.sample_flow["Flow Packets/s"])
        self.assertGreater(p_slow["Flow Duration"], self.sample_flow["Flow Duration"])

        # 3. TCP Chameleon
        p_cham = adversarial_tester.perturb_flow(self.sample_flow, attack_type="TCP_CHAMELEON", epsilon=0.2)
        self.assertLess(p_cham["SYN Flag Count"], self.sample_flow["SYN Flag Count"])

        # 4. Feature Noise
        p_noise = adversarial_tester.perturb_flow(self.sample_flow, attack_type="FEATURE_NOISE", epsilon=0.1)
        self.assertNotEqual(p_noise["Flow Bytes/s"], self.sample_flow["Flow Bytes/s"])

    def test_02_adversarial_evaluation_metrics(self):
        """Verify robustness index, evasion rate, and hardening recommendations."""
        def dummy_predict(f):
            # If flow has packet rate diluted under 5000, simulate successful evasion
            rate = float(f.get("Flow Packets/s", 98000.0))
            is_att = rate > 50000.0
            return {
                "prediction": "Attack" if is_att else "BENIGN",
                "attack_probability": 0.95 if is_att else 0.25,
                "is_attack": is_att,
            }

        res = adversarial_tester.evaluate_robustness(
            flows=[self.sample_flow],
            predict_fn=dummy_predict,
            attack_type="LOW_AND_SLOW",
            epsilon=0.3,
        )
        self.assertTrue(res["success"])
        self.assertIn("robustness_index", res)
        self.assertIn("evasion_success_rate", res)
        self.assertIn("hardening_recommendations", res)
        self.assertGreater(len(res["hardening_recommendations"]), 0)

    def test_03_backend_adversarial_endpoint(self):
        """Test backend POST /adversarial/simulate endpoint."""
        response = self.backend_client.post(
            "/adversarial/simulate",
            json={
                "flows": [self.sample_flow],
                "attack_type": "HEADER_PADDING",
                "epsilon": 0.15,
            },
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data.get("success"))
        self.assertIn("robustness_index", data)
        self.assertIn("hardening_recommendations", data)

    # ========================================================================
    # FEATURE 4: FORENSIC CASE PACKAGER TESTS
    # ========================================================================

    def test_04_forensic_bundle_generation_and_signatures(self):
        """Verify zip creation, SHA-256 seal, and artifact file integrity."""
        incident_data = {
            "case_id": "IR-20261021-TEST01",
            "src_ip": "198.51.100.5",
            "dst_ip": "10.0.0.1",
            "dst_port": 80,
            "protocol": "TCP",
            "severity": "CRITICAL",
            "attack_family": "DDoS SYN Flood",
            "mitre_id": "T1498",
            "mitre_technique": "Network Denial of Service",
            "risk_score": 98.0,
        }

        bundle = forensic_packager.generate_incident_bundle(
            incident_data=incident_data,
            flows=[self.sample_flow],
            investigator="Test SOC Investigator",
        )

        self.assertTrue(bundle["success"])
        self.assertEqual(bundle["case_id"], "IR-20261021-TEST01")
        self.assertTrue(bundle["filename"].endswith(".zip"))
        self.assertIn("zip_sha256", bundle)

        # Unpack the in-memory zip bytes to verify all 7 artifacts
        zip_buf = io.BytesIO(bundle["zip_bytes"])
        with zipfile.ZipFile(zip_buf, "r") as zf:
            file_list = zf.namelist()
            expected_files = [
                "incident_dossier.html",
                "contain_threat.sh",
                "contain_threat.ps1",
                "snort_ids_rules.rules",
                "stix_incident_bundle.json",
                "network_evidence_dump.csv",
                "evidence_manifest.txt",
            ]
            for exp in expected_files:
                self.assertIn(exp, file_list, f"Forensic artifact {exp} missing from zip archive")

            # Check evidence manifest content
            manifest_content = zf.read("evidence_manifest.txt").decode("utf-8")
            self.assertIn("CRYPTOGRAPHIC EVIDENCE MANIFEST", manifest_content)
            self.assertIn("SEAL-SHA256:", manifest_content)

            # Check that dossier is valid HTML
            dossier_html = zf.read("incident_dossier.html").decode("utf-8")
            self.assertIn("<!DOCTYPE html>", dossier_html)
            self.assertIn("198.51.100.5", dossier_html)

            # Check containment script
            sh_script = zf.read("contain_threat.sh").decode("utf-8")
            self.assertIn("iptables", sh_script)
            self.assertIn("198.51.100.5", sh_script)

    def test_05_backend_forensics_export_endpoint(self):
        """Test backend POST /forensics/export-package endpoint."""
        response = self.backend_client.post(
            "/forensics/export-package",
            json={
                "incident_data": {
                    "case_id": "CASE-API-TEST",
                    "src_ip": "203.0.113.19",
                    "dst_ip": "10.0.0.5",
                    "dst_port": 443,
                    "protocol": "TCP",
                    "severity": "HIGH",
                    "attack_family": "Port Scan",
                },
                "investigator": "Automated Unit Test",
            },
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data.get("success"))
        self.assertEqual(data.get("case_id"), "CASE-API-TEST")
        self.assertIn("zip_base64", data)
        self.assertIn("zip_sha256", data)

        # Decode base64 and verify valid zip
        zip_bytes = base64.b64decode(data["zip_base64"])
        calculated_sha = hashlib.sha256(zip_bytes).hexdigest()
        self.assertEqual(calculated_sha, data["zip_sha256"])

    def test_06_frontend_api_status_registration(self):
        """Verify new Option B services are registered in /api/status."""
        response = self.frontend_client.get("/api/status")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["services"].get("adversarial_tester"))
        self.assertTrue(data["services"].get("forensic_packager"))
        self.assertIn("adversarial_simulate", data["endpoints"])
        self.assertIn("forensics_export", data["endpoints"])


if __name__ == "__main__":
    unittest.main()
