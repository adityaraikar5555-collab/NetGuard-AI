"""
Unit tests for NetGuard AI's Native ReAct SOC Agent.
"""

from pathlib import Path
import sys
import unittest

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))
if str(ROOT_DIR / "src") not in sys.path:
    sys.path.insert(0, str(ROOT_DIR / "src"))

from src.agents import (
    native_soc_agent,
    default_tool_registry,
    AgentStep,
    IncidentDossier,
)


class TestNativeReActSOCAgent(unittest.TestCase):
    """Verifies Native ReAct SOC Agent tool registry, reasoning loop, and dossier synthesis."""

    def setUp(self):
        self.sample_context = {
            "dataset": "CICIDS-2017",
            "src_ip": "185.220.101.5",
            "dst_ip": "192.168.1.100",
            "dst_port": "80",
            "attack_probability": 0.98,
            "features": {
                "Destination Port": 80,
                "Flow Duration": 120000,
                "Total Fwd Packets": 100,
                "Total Backward Packets": 0,
                "SYN Flag Count": 1,
                "Flow Packets/s": 850.0,
            },
        }

    def test_tool_registry_contains_required_tools(self):
        """Ensure all 6 core security tools are properly registered."""
        required = [
            "threat_intel_lookup",
            "xai_explain_flow",
            "multiclass_classify",
            "soar_mitre_mapping",
            "soar_generate_containment",
            "rag_search_knowledge",
        ]
        for tool_name in required:
            tool = default_tool_registry.get(tool_name)
            self.assertIsNotNone(tool, f"Tool '{tool_name}' should be registered.")
            self.assertTrue(len(tool.description) > 10)

    def test_tool_threat_intel_execution(self):
        """Test threat intel lookup tool execution."""
        tool = default_tool_registry.get("threat_intel_lookup")
        res = tool.execute(ip="185.220.101.5", is_flagged_threat=True)
        self.assertEqual(res["ip"], "185.220.101.5")
        self.assertIn("country", res)
        self.assertIn("reputation_score", res)

    def test_tool_xai_execution(self):
        """Test XAI explanation tool execution."""
        tool = default_tool_registry.get("xai_explain_flow")
        res = tool.execute(features=self.sample_context["features"], dataset="CICIDS-2017")
        self.assertIn("top_features", res)
        self.assertIn("rationale", res)

    def test_tool_multiclass_execution(self):
        """Test attack multi-class classifier tool execution."""
        tool = default_tool_registry.get("multiclass_classify")
        res = tool.execute(flow=self.sample_context["features"], dataset="CICIDS-2017")
        self.assertIn("category_code", res)
        self.assertIn("attack_family", res)
        # Should classify as DOS due to high packets/s and SYN flags with zero backward packets
        self.assertEqual(res["category_code"], "DOS")

    def test_tool_containment_generation(self):
        """Test SOAR containment rule generation."""
        tool = default_tool_registry.get("soar_generate_containment")
        res = tool.execute(src_ip="185.220.101.5", dst_port="80", proto="tcp", severity="HIGH")
        self.assertIn("firewall_rules", res)
        self.assertIn("iptables", res["firewall_rules"])
        self.assertIn("powershell", res["firewall_rules"])
        self.assertIn("snort", res["ids_rules"])

    def test_agent_investigate_synchronous(self):
        """Test synchronous end-to-end autonomous investigation."""
        dossier = native_soc_agent.investigate(self.sample_context)
        self.assertIsInstance(dossier, IncidentDossier)
        self.assertEqual(dossier.verdict, "CONFIRMED_ATTACK")
        self.assertEqual(dossier.source_ip, "185.220.101.5")
        self.assertIn("80", dossier.target_ip)
        self.assertGreaterEqual(len(dossier.steps), 1)
        self.assertTrue(len(dossier.executive_summary) > 20)
        self.assertTrue(len(dossier.recommended_actions) >= 1)
        self.assertIn("firewall_rules", dossier.containment_plan)

    def test_agent_investigate_streaming(self):
        """Test generator-based streaming of investigation steps."""
        steps_received = 0
        final_dossier = None

        for item in native_soc_agent.investigate_stream(self.sample_context):
            if isinstance(item, AgentStep):
                steps_received += 1
                self.assertIsNotNone(item.thought)
                self.assertIsNotNone(item.action)
            elif isinstance(item, IncidentDossier):
                final_dossier = item

        self.assertGreaterEqual(steps_received, 1)
        self.assertIsNotNone(final_dossier)
        self.assertEqual(final_dossier.verdict, "CONFIRMED_ATTACK")

    def test_threat_hunting_agent_drift_and_stealth(self):
        """Test Step 3: ThreatHuntingAgent concept drift and stealth anomaly detection."""
        from src.agents import threat_hunting_agent, ThreatHuntingReport
        report = threat_hunting_agent.hunt(self.sample_context["features"], dataset="CICIDS-2017")
        self.assertIsInstance(report, ThreatHuntingReport)
        self.assertIn(report.drift_status, ["STABLE", "MODERATE_DRIFT", "SEVERE_DRIFT"])
        self.assertIsInstance(report.global_psi, float)
        self.assertTrue(len(report.hypotheses) >= 1)
        self.assertTrue(len(report.mitre_correlations) >= 1)
        self.assertTrue(len(report.recommended_playbook) > 10)

    def test_multi_agent_swarm_coordination(self):
        """Test Step 4: Hierarchical Multi-Agent Swarm (Supervisor + Specialists)."""
        from src.agents import soc_swarm_supervisor, SwarmIncidentBrief
        brief = soc_swarm_supervisor.coordinate_investigation(self.sample_context)
        self.assertIsInstance(brief, SwarmIncidentBrief)
        self.assertEqual(brief.commander_verdict, "CONFIRMED_ATTACK")
        self.assertEqual(brief.attacker_ip, "185.220.101.5")
        self.assertTrue(len(brief.specialist_contributions) == 3)
        self.assertTrue(brief.blast_radius_safe)
        self.assertIn("firewall_rules", brief.containment_finding)
        self.assertIn("country", brief.threat_intel_finding)
        self.assertIn("attack_family", brief.forensics_finding)


if __name__ == "__main__":
    unittest.main()

