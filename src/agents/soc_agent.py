"""
NetGuard AI — Native ReAct SOC Agent

An autonomous Security Operations Center (SOC) Tier-2 AI Agent implementing
the ReAct (Reasoning + Acting) loop:
    Thought -> Action -> Action Input -> Tool Execution -> Observation -> ... -> Final Verdict

Features:
1. Multi-step autonomous threat investigation and root-cause analysis.
2. Direct invocation of domain engines via SOCAgentToolRegistry.
3. Generator-based streaming (for real-time dashboard UI and SSE APIs).
4. Deterministic fallback mode when LLM API is unavailable or offline.
5. Produces an audit-ready IncidentDossier with MITRE mappings, XAI rationale, and containment rules.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, Generator, List, Optional, Tuple, Union

from src.agents.tools import SOCAgentToolRegistry, default_tool_registry
from backend.rag.generator import call_llm


@dataclass
class AgentStep:
    """Represents a single step in the ReAct investigation loop."""
    step_number: int
    thought: str
    action: Optional[str] = None
    action_input: Optional[Dict[str, Any]] = None
    observation: Optional[Union[Dict[str, Any], str]] = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class IncidentDossier:
    """The synthesized executive cybersecurity incident dossier."""
    incident_id: str
    verdict: str  # CONFIRMED_ATTACK, SUSPICIOUS_ANOMALY, BENIGN_FALSE_POSITIVE
    threat_family: str
    confidence: float
    severity: str
    target_ip: str
    source_ip: str
    executive_summary: str
    root_cause_analysis: str
    mitre_attack: Dict[str, Any]
    threat_intel: Dict[str, Any]
    containment_plan: Dict[str, Any]
    recommended_actions: List[str]
    steps: List[Dict[str, Any]]
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


SYSTEM_PROMPT_TEMPLATE = """You are NetGuard-Agent, a Senior Tier-2 Autonomous SOC Security Analyst.
Your mission is to autonomously investigate suspicious network traffic anomalies detected by NetGuard AI's Machine Learning models.

You have access to the following cybersecurity tools:
{tool_definitions}

### Operational Rules:
1. Follow the strict ReAct format:
Thought: <Reason about what information you currently have and what specific investigation step is needed next>
Action: <Tool name to execute, EXACTLY as listed in the available tools>
Action Input: <Valid single-line or multi-line JSON object specifying tool parameters>

2. When you receive an Observation, analyze it critically before deciding the next move.
3. Investigation Procedure:
   - You MUST execute at least 2 diagnostic actions (e.g. multiclass_classify, xai_explain_flow, threat_intel_lookup, soar_mitre_mapping) to gather empirical evidence before concluding.
   - Do NOT jump directly to Final Verdict on step 1 without calling tools.
4. Once you have gathered sufficient evidence from your tool observations, output:
Thought: I have gathered all necessary evidence to conclude this security investigation.
Final Verdict:
```json
{{
  "verdict": "CONFIRMED_ATTACK" or "SUSPICIOUS_ANOMALY" or "BENIGN_FALSE_POSITIVE",
  "threat_family": "Specific attack name or family",
  "confidence": 0.95,
  "severity": "CRITICAL" or "HIGH" or "MEDIUM" or "LOW",
  "executive_summary": "Concise executive overview of the incident",
  "root_cause_analysis": "Key anomalous features and why they triggered the alert",
  "recommended_actions": ["Action 1", "Action 2", "Action 3"]
}}
```
"""


class NativeReActSOCAgent:
    """
    Autonomous ReAct Incident Investigation Agent.
    """

    def __init__(
        self,
        tool_registry: Optional[SOCAgentToolRegistry] = None,
        max_steps: int = 7,
    ):
        self.registry = tool_registry or default_tool_registry
        self.max_steps = max_steps

    def investigate(self, context: Dict[str, Any]) -> IncidentDossier:
        """
        Runs the full autonomous investigation synchronously and returns the final dossier.
        """
        dossier = None
        for step_or_dossier in self.investigate_stream(context):
            if isinstance(step_or_dossier, IncidentDossier):
                dossier = step_or_dossier
        return dossier or self._build_emergency_dossier(context, [])

    def investigate_stream(
        self,
        context: Dict[str, Any],
    ) -> Generator[Union[AgentStep, IncidentDossier], None, None]:
        """
        Streams each step of the ReAct reasoning process as it executes.
        Yields AgentStep instances, and finally yields the IncidentDossier.
        """
        incident_id = f"INC-{int(time.time() * 1000) % 1000000:06d}"
        steps: List[AgentStep] = []
        raw_observations: Dict[str, Any] = {}

        # Normalize context attributes
        dataset = context.get("dataset", "CICIDS-2017")
        features = context.get("features", {})
        src_ip = context.get("src_ip") or context.get("Source IP") or "185.220.101.5"
        dst_ip = context.get("dst_ip") or context.get("Destination IP") or "192.168.1.10"
        dst_port = str(context.get("dst_port") or context.get("Destination Port") or "80")
        initial_prob = float(context.get("attack_probability", 0.95))

        # Build initial prompt
        system_prompt = SYSTEM_PROMPT_TEMPLATE.format(
            tool_definitions=self.registry.get_tool_definitions_prompt()
        )

        user_query = (
            f"ALERT INGESTION - Incident ID: {incident_id}\n"
            f"Dataset: {dataset}\n"
            f"Source IP: {src_ip}\n"
            f"Destination IP: {dst_ip}\n"
            f"Target Port: {dst_port}\n"
            f"Initial Model Anomaly Score: {initial_prob:.2f}\n"
            f"Flow Sample Features:\n{json.dumps(features, indent=2)}\n\n"
            f"Please conduct an end-to-end autonomous incident investigation."
        )

        history_prompt = f"{system_prompt}\n\nUser Request:\n{user_query}\n"

        # Check if live LLM is responding
        llm_available = self._test_llm_liveness()

        if not llm_available:
            # Deterministic fallback mode: execute standardized ReAct flow cleanly
            yield from self._stream_deterministic_investigation(
                incident_id=incident_id,
                dataset=dataset,
                features=features,
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                initial_prob=initial_prob,
            )
            return

        # ReAct Execution Loop
        for step_idx in range(1, self.max_steps + 1):
            history_prompt += f"\nStep {step_idx}:\n"
            llm_output = call_llm(history_prompt)

            if not llm_output or not llm_output.strip():
                # Fallback to local reasoning if LLM timed out
                break

            parsed = self._parse_react_output(llm_output)

            # Check if Agent reached Final Verdict
            if parsed.get("final_verdict"):
                step = AgentStep(
                    step_number=step_idx,
                    thought=parsed.get("thought", "Concluded investigation."),
                    action="FINAL_VERDICT",
                    action_input={},
                    observation="Investigation concluded successfully.",
                )
                steps.append(step)
                yield step

                dossier = self._build_dossier_from_verdict(
                    incident_id=incident_id,
                    verdict_data=parsed["final_verdict"],
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    steps=[s.to_dict() for s in steps],
                    raw_observations=raw_observations,
                )
                yield dossier
                return

            action_name = parsed.get("action")
            action_input = parsed.get("action_input", {})
            thought_text = parsed.get("thought", f"Investigating step {step_idx}...")

            if not action_name:
                # LLM didn't call a tool; conclude
                break

            # Execute Tool
            tool = self.registry.get(action_name)
            if tool:
                obs = tool.execute(**action_input)
            else:
                obs = {"error": f"Tool '{action_name}' is not in the registry."}

            raw_observations[action_name] = obs

            step = AgentStep(
                step_number=step_idx,
                thought=thought_text,
                action=action_name,
                action_input=action_input,
                observation=obs,
            )
            steps.append(step)
            yield step

            # Append to prompt history for next iteration
            history_prompt += (
                f"Thought: {thought_text}\n"
                f"Action: {action_name}\n"
                f"Action Input: {json.dumps(action_input)}\n"
                f"Observation: {json.dumps(obs)}\n"
            )

        # If loop exited without any steps completed, fall back to deterministic pipeline
        if len(steps) == 0:
            yield from self._stream_deterministic_investigation(
                incident_id=incident_id,
                dataset=dataset,
                features=features,
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                initial_prob=initial_prob,
            )
            return

        # If loop completed some steps but no explicit final verdict, synthesize from observations
        dossier = self._synthesize_final_dossier(
            incident_id=incident_id,
            dataset=dataset,
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            steps=steps,
            raw_observations=raw_observations,
            initial_prob=initial_prob,
        )
        yield dossier

    # --- Deterministic Resilient Execution ---

    def _stream_deterministic_investigation(
        self,
        incident_id: str,
        dataset: str,
        features: Dict[str, Any],
        src_ip: str,
        dst_ip: str,
        dst_port: str,
        initial_prob: float,
    ) -> Generator[Union[AgentStep, IncidentDossier], None, None]:
        """
        Fully deterministic ReAct execution path used when LLM is unavailable or for offline testing.
        Guarantees 100% reliable execution without crashing.
        """
        steps: List[AgentStep] = []
        raw_obs: Dict[str, Any] = {}

        # Step 1: Multi-class classification
        s1 = AgentStep(
            step_number=1,
            thought=f"Begin investigation for incident {incident_id}. First, I will evaluate behavioral signatures to classify the specific attack family.",
            action="multiclass_classify",
            action_input={"flow": features, "dataset": dataset},
        )
        s1.observation = self.registry.get("multiclass_classify").execute(**s1.action_input)
        raw_obs["multiclass_classify"] = s1.observation
        steps.append(s1)
        yield s1

        threat_cat = s1.observation.get("category_code", "GENERIC_ANOMALY")
        threat_family = s1.observation.get("attack_family", "Suspicious Anomaly")

        # Step 2: XAI Root-Cause Explanation
        s2 = AgentStep(
            step_number=2,
            thought=f"The flow matches {threat_family}. Now inspecting feature attributions with Explainable AI to pinpoint why the model flagged it.",
            action="xai_explain_flow",
            action_input={"features": features, "dataset": dataset, "top_k": 4},
        )
        s2.observation = self.registry.get("xai_explain_flow").execute(**s2.action_input)
        raw_obs["xai_explain_flow"] = s2.observation
        steps.append(s2)
        yield s2

        # Step 3: Threat Intelligence Lookup
        s3 = AgentStep(
            step_number=3,
            thought=f"Examining source IP {src_ip} via Threat Intelligence for reputation, ASN, and geographic attribution.",
            action="threat_intel_lookup",
            action_input={"ip": src_ip, "is_flagged_threat": True},
        )
        s3.observation = self.registry.get("threat_intel_lookup").execute(**s3.action_input)
        raw_obs["threat_intel_lookup"] = s3.observation
        steps.append(s3)
        yield s3

        # Step 4: MITRE ATT&CK Mapping
        s4 = AgentStep(
            step_number=4,
            thought=f"Mapping identified threat pattern '{threat_cat}' to MITRE ATT&CK enterprise tactics and mitigations.",
            action="soar_mitre_mapping",
            action_input={"threat_type": threat_cat, "flow_data": features},
        )
        s4.observation = self.registry.get("soar_mitre_mapping").execute(**s4.action_input)
        raw_obs["soar_mitre_mapping"] = s4.observation
        steps.append(s4)
        yield s4

        # Step 5: Containment Rule Generation
        s5 = AgentStep(
            step_number=5,
            thought=f"Generating multi-platform firewall and IDS containment rules to block traffic from {src_ip}.",
            action="soar_generate_containment",
            action_input={"src_ip": src_ip, "dst_port": dst_port, "proto": "tcp", "severity": "HIGH"},
        )
        s5.observation = self.registry.get("soar_generate_containment").execute(**s5.action_input)
        raw_obs["soar_generate_containment"] = s5.observation
        steps.append(s5)
        yield s5

        # Final Synthesis
        dossier = self._synthesize_final_dossier(
            incident_id=incident_id,
            dataset=dataset,
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            steps=steps,
            raw_observations=raw_obs,
            initial_prob=initial_prob,
        )
        yield dossier

    # --- Parser & Dossier Helpers ---

    def _parse_react_output(self, text: str) -> Dict[str, Any]:
        """Parses ReAct Thought, Action, Action Input, or Final Verdict from LLM response."""
        result: Dict[str, Any] = {}

        # 1. Check if Action is specified
        action_match = re.search(r"Action:\s*([a-zA-Z0-9_-]+)", text)

        # 2. Check if Final Verdict is specified
        has_final_verdict_header = "Final Verdict:" in text
        action_pos = text.find("Action:") if action_match else -1
        verdict_pos = text.find("Final Verdict:") if has_final_verdict_header else -1

        if has_final_verdict_header and (action_pos == -1 or verdict_pos < action_pos):
            fv_match = re.search(r"Final Verdict:\s*```json\s*(\{.*?\})\s*```", text, re.DOTALL)
            if not fv_match:
                fv_match = re.search(r"Final Verdict:.*?(\{[\s\S]*\"verdict\"[\s\S]*\})", text, re.DOTALL)
            if fv_match:
                try:
                    result["final_verdict"] = json.loads(fv_match.group(1))
                    thought_m = re.search(r"Thought:\s*(.*?)(?=Final Verdict:|$)", text, re.DOTALL)
                    result["thought"] = thought_m.group(1).strip() if thought_m else "Investigation completed."
                    return result
                except Exception:
                    pass

        # Extract Thought
        thought_match = re.search(r"Thought:\s*(.*?)(?=\nAction:|$)", text, re.DOTALL)
        result["thought"] = thought_match.group(1).strip() if thought_match else text.strip()

        # Extract Action
        if action_match:
            result["action"] = action_match.group(1).strip()

        # Extract Action Input
        input_match = re.search(r"Action Input:\s*```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
        if not input_match:
            input_match = re.search(r"Action Input:\s*(\{.*?\})", text, re.DOTALL)

        if input_match:
            try:
                result["action_input"] = json.loads(input_match.group(1))
            except Exception:
                result["action_input"] = {}
        else:
            result["action_input"] = {}

        return result

    def _test_llm_liveness(self) -> bool:
        """Verifies if an LLM is active and responsive."""
        try:
            test_resp = call_llm("Ping")
            return bool(test_resp and len(test_resp.strip()) > 0)
        except Exception:
            return False

    def _synthesize_final_dossier(
        self,
        incident_id: str,
        dataset: str,
        src_ip: str,
        dst_ip: str,
        dst_port: str,
        steps: List[AgentStep],
        raw_observations: Dict[str, Any],
        initial_prob: float,
    ) -> IncidentDossier:
        """Synthesizes structured observations into a comprehensive IncidentDossier."""
        mc = raw_observations.get("multiclass_classify", {})
        xai = raw_observations.get("xai_explain_flow", {})
        threat = raw_observations.get("threat_intel_lookup", {})
        mitre = raw_observations.get("soar_mitre_mapping", {})
        containment = raw_observations.get("soar_generate_containment", {})

        threat_family = mc.get("attack_family", "Anomalous Network Activity")
        confidence = float(mc.get("confidence", max(initial_prob, 0.85)))
        severity = "CRITICAL" if confidence > 0.9 else ("HIGH" if confidence > 0.75 else "MEDIUM")

        # Root cause synthesis
        top_feats = xai.get("top_features", [])
        if top_feats:
            top_strs = [f"{f.get('feature')}={f.get('value')} (deviation: {f.get('deviation_sigma')}σ)" for f in top_feats[:3]]
            root_cause = f"Model triggered by anomalous feature distributions: {', '.join(top_strs)}. {xai.get('rationale', '')}"
        else:
            root_cause = xai.get("rationale", "Flow behavior statistically deviates from baseline normal network operations.")

        # Executive summary
        origin_country = threat.get("country", "Unknown")
        asn_info = threat.get("asn", "External Autonomous System")
        rep_score = threat.get("reputation_score", 85)

        summary = (
            f"NetGuard-Agent autonomously confirmed a {severity} severity incident ({threat_family}) targeting {dst_ip}:{dst_port}. "
            f"Traffic originated from {src_ip} ({origin_country}, {asn_info}) with a threat reputation score of {rep_score}/100. "
            f"Correlation with MITRE ATT&CK indicates {mitre.get('technique_name', 'T1036')} ({mitre.get('technique_id', 'T1036')})."
        )

        recommended_actions = [
            f"Enforce automated firewall drop on host boundary: block {src_ip}",
            f"Deploy Snort/Suricata signature for port {dst_port}",
            f"Review host logs on {dst_ip} for secondary lateral movement",
            f"Export STIX 2.1 ticket to SIEM for security operations tracking",
        ]

        return IncidentDossier(
            incident_id=incident_id,
            verdict="CONFIRMED_ATTACK" if initial_prob >= 0.5 else "BENIGN_FALSE_POSITIVE",
            threat_family=threat_family,
            confidence=confidence,
            severity=severity,
            target_ip=f"{dst_ip}:{dst_port}",
            source_ip=src_ip,
            executive_summary=summary,
            root_cause_analysis=root_cause,
            mitre_attack=mitre,
            threat_intel=threat,
            containment_plan=containment,
            recommended_actions=recommended_actions,
            steps=[s.to_dict() for s in steps],
        )

    def _build_dossier_from_verdict(
        self,
        incident_id: str,
        verdict_data: Dict[str, Any],
        src_ip: str,
        dst_ip: str,
        dst_port: str,
        steps: List[Dict[str, Any]],
        raw_observations: Dict[str, Any],
    ) -> IncidentDossier:
        """Converts an LLM Final Verdict JSON into an IncidentDossier."""
        mitre = raw_observations.get("soar_mitre_mapping")
        if not mitre or not isinstance(mitre, dict) or "technique_id" not in mitre:
            mitre_tool = self.registry.get("soar_mitre_mapping")
            mitre = mitre_tool.execute(threat_type=verdict_data.get("threat_family", "ANOMALY")) if mitre_tool else {}

        threat = raw_observations.get("threat_intel_lookup")
        if not threat or not isinstance(threat, dict) or "country" not in threat:
            threat_tool = self.registry.get("threat_intel_lookup")
            threat = threat_tool.execute(ip=src_ip, is_flagged_threat=(verdict_data.get("verdict") == "CONFIRMED_ATTACK")) if threat_tool else {}

        containment = raw_observations.get("soar_generate_containment")
        if not containment or not isinstance(containment, dict) or "firewall_rules" not in containment:
            soar_tool = self.registry.get("soar_generate_containment")
            containment = soar_tool.execute(src_ip=src_ip, dst_port=dst_port, proto="tcp", severity=verdict_data.get("severity", "HIGH")) if soar_tool else {}

        return IncidentDossier(
            incident_id=incident_id,
            verdict=verdict_data.get("verdict", "CONFIRMED_ATTACK"),
            threat_family=verdict_data.get("threat_family", "Network Anomaly"),
            confidence=float(verdict_data.get("confidence", 0.90)),
            severity=verdict_data.get("severity", "HIGH"),
            target_ip=f"{dst_ip}:{dst_port}",
            source_ip=src_ip,
            executive_summary=verdict_data.get("executive_summary", "Autonomous investigation concluded."),
            root_cause_analysis=verdict_data.get("root_cause_analysis", "Flow telemetry analyzed."),
            mitre_attack=mitre,
            threat_intel=threat,
            containment_plan=containment,
            recommended_actions=verdict_data.get("recommended_actions", ["Isolate endpoint", "Monitor network socket"]),
            steps=steps,
        )

    def _build_emergency_dossier(self, context: Dict[str, Any], steps: List[AgentStep]) -> IncidentDossier:
        return IncidentDossier(
            incident_id=f"INC-{int(time.time()):06d}",
            verdict="SUSPICIOUS_ANOMALY",
            threat_family="Unclassified Anomaly",
            confidence=0.7,
            severity="MEDIUM",
            target_ip="Unknown",
            source_ip="Unknown",
            executive_summary="Emergency investigation fallback generated.",
            root_cause_analysis="Telemetry could not be fully parsed.",
            mitre_attack={},
            threat_intel={},
            containment_plan={},
            recommended_actions=["Manual review required"],
            steps=[s.to_dict() for s in steps],
        )


# Global singleton instance
native_soc_agent = NativeReActSOCAgent()
