"""
Unit and Integration Tests for Option A:
1. PCAP / Wireshark File Ingestion & Deep Packet Inspection (DPI)
2. Interactive MITRE ATT&CK Enterprise Matrix Knowledge Base & Route Verification
"""

import unittest
from pathlib import Path
from fastapi.testclient import TestClient

from src.pcap_extractor import pcap_extractor
from src.mitre_database import MITRE_TACTICS_DB, get_mitre_tactics_count, get_mitre_techniques_count, find_technique
from backend.main import app as backend_app
from frontend.app import app as frontend_app


class TestOptionACybersecurity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pcap_file = Path("data/test/sample_capture.pcap")
        cls.assertTrue(cls, cls.pcap_file.exists(), "Sample PCAP fixture must exist at data/test/sample_capture.pcap")

    def test_01_pcap_binary_parsing_and_flow_features(self):
        """Verify pure-Python PCAP binary parsing extracts statistical flow features."""
        pcap_bytes = self.pcap_file.read_bytes()
        df = pcap_extractor.parse_file(pcap_bytes, max_packets=5000)

        self.assertFalse(df.empty, "Extracted flows dataframe should not be empty")
        self.assertGreaterEqual(len(df), 1, "Should have extracted at least 1 flow")

        required_features = [
            "Source IP",
            "Destination IP",
            "Source Port",
            "Destination Port",
            "Protocol",
            "Flow Duration",
            "Total Fwd Packets",
            "Total Backward Packets",
            "Total Length of Fwd Packets",
            "Total Length of Bwd Packets",
            "SYN Flag Count",
            "FIN Flag Count",
            "RST Flag Count",
            "ACK Flag Count",
            "Flow Bytes/s",
            "Flow Packets/s",
        ]
        for feat in required_features:
            self.assertIn(feat, df.columns, f"Flow feature '{feat}' must be present in parsed PCAP")

    def test_02_backend_pcap_endpoint(self):
        """Verify backend /analyze/pcap ingestion, classification, and enriched metadata."""
        client = TestClient(backend_app)
        pcap_bytes = self.pcap_file.read_bytes()

        response = client.post(
            "/analyze/pcap",
            files={"file": ("sample_capture.pcap", pcap_bytes, "application/vnd.tcpdump.pcap")},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()

        self.assertTrue(data.get("success"))
        self.assertIn(data.get("dataset"), ["PCAP-Reconstructed", "PCAP-Live-DPI"])
        self.assertIn("summary", data)
        self.assertIn("predictions", data)
        self.assertGreaterEqual(len(data["predictions"]), 1)

        first_pred = data["predictions"][0]
        self.assertIn("prediction", first_pred)
        self.assertIn("attack_probability", first_pred)
        self.assertIn("Severity", first_pred)

    def test_03_frontend_pcap_endpoint(self):
        """Verify frontend /analyze/pcap endpoint functions in tandem."""
        client = TestClient(frontend_app)
        pcap_bytes = self.pcap_file.read_bytes()

        response = client.post(
            "/analyze/pcap",
            files={"file": ("sample_capture.pcap", pcap_bytes, "application/vnd.tcpdump.pcap")},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data.get("success"))
        self.assertIn("summary", data)
        self.assertIn("predictions", data)

    def test_04_mitre_tactics_database_integrity(self):
        """Verify MITRE ATT&CK Enterprise Matrix database completeness across all 14 tactics."""
        tactics_count = get_mitre_tactics_count()
        self.assertEqual(tactics_count, 14, f"Should contain all 14 official MITRE tactics, got {tactics_count}")

        all_tactics = [t["tactic_id"] for t in MITRE_TACTICS_DB]
        expected_tactics = [
            "TA0043", "TA0042", "TA0001", "TA0002", "TA0003",
            "TA0004", "TA0005", "TA0006", "TA0007", "TA0008",
            "TA0009", "TA0011", "TA0010", "TA0040",
        ]
        for tac in expected_tactics:
            self.assertIn(tac, all_tactics, f"Tactic {tac} must be present in MITRE_TACTICS_DB")

        total_techniques = get_mitre_techniques_count()
        self.assertGreaterEqual(total_techniques, 15, "Should have at least 15 mapped techniques")

        # Verify technique structure
        for tactic in MITRE_TACTICS_DB:
            for tech in tactic["techniques"]:
                self.assertTrue(tech["id"].startswith("T"), f"Technique ID {tech['id']} must start with T")
                self.assertIn("name", tech)
                self.assertIn("description", tech)
                self.assertIn("iptables", tech)
                self.assertIn("snort", tech)
                self.assertIn("actors", tech)

    def test_05_mitre_technique_lookup(self):
        """Verify MITRE ATT&CK technique lookup utility."""
        tech, tac = find_technique("T1498")
        self.assertIsNotNone(tech)
        self.assertEqual(tech["id"], "T1498")
        self.assertIn("Denial of Service", tech["name"])
        self.assertEqual(tac["tactic_id"], "TA0040")

        # Non-existent
        tech_bad, _ = find_technique("T99999")
        self.assertIsNone(tech_bad)

    def test_06_dashboard_page_registration(self):
        """Verify dashboard.py registers MITRE ATT&CK Matrix in navigation and PAGES router."""
        dashboard_text = Path("frontend/dashboard.py").read_text(encoding="utf-8")
        self.assertIn('"MITRE ATT&CK Matrix": render_mitre_matrix', dashboard_text)
        self.assertIn('("🛡️", "MITRE ATT&CK Matrix")', dashboard_text)
        self.assertIn('tab_alerts, tab_matrix = st.tabs(["🚨 Alert Workstation & Triage", "🛡️ MITRE ATT&CK® Matrix Heatmap"])', dashboard_text)


if __name__ == "__main__":
    unittest.main()
