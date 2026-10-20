"""
NetGuard AI — Agentic AI Package

Provides autonomous, multi-step SOC Tier-2 investigation and remediation agents:
- NativeReActSOCAgent: ReAct reasoning & acting loop with streaming support (Step 1).
- SOCAgentToolRegistry: Domain security engine tool registry.
- IncidentDossier: Structured investigation report with MITRE, XAI, and containment rules.
- AgentStep: Granular step tracking for transparent audit trails.
- ThreatHuntingAgent: Autonomous Concept Drift & Sub-Threshold Threat Hunter (Step 3).
- ThreatHuntingReport: MLOps drift status, stealth clusters, and hunting hypotheses.
- SupervisorAgent: Commander orchestrating Forensics, Threat Intel, and Remediation swarm (Step 4).
- SwarmIncidentBrief: Consolidated multi-agent incident briefing.
"""

from src.agents.tools import (
    AgentTool,
    SOCAgentToolRegistry,
    default_tool_registry,
)
from src.agents.soc_agent import (
    NativeReActSOCAgent,
    AgentStep,
    IncidentDossier,
    native_soc_agent,
)
from src.agents.drift_hunter_agent import (
    ThreatHuntingAgent,
    ThreatHuntingReport,
    threat_hunting_agent,
)
from src.agents.multi_agent_swarm import (
    SupervisorAgent,
    ForensicsAgent,
    ThreatIntelAgent,
    RemediationAgent,
    SwarmIncidentBrief,
    soc_swarm_supervisor,
)

__all__ = [
    "AgentTool",
    "SOCAgentToolRegistry",
    "default_tool_registry",
    "NativeReActSOCAgent",
    "AgentStep",
    "IncidentDossier",
    "native_soc_agent",
    "ThreatHuntingAgent",
    "ThreatHuntingReport",
    "threat_hunting_agent",
    "SupervisorAgent",
    "ForensicsAgent",
    "ThreatIntelAgent",
    "RemediationAgent",
    "SwarmIncidentBrief",
    "soc_swarm_supervisor",
]
