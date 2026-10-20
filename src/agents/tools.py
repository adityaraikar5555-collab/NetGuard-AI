"""
NetGuard AI — SOC Agent Tools Registry

Exposes domain security engines as standardized tools for the Native ReAct SOC Agent:
1. threat_intel_lookup - Geolocation, ASN, threat reputation, and abuse scoring.
2. xai_explain_flow - Feature attributions, standard deviations, and root-cause rationale.
3. multiclass_classify - Behavioral classification into DoS, PortScan, BruteForce, C2, etc.
4. soar_mitre_mapping - MITRE ATT&CK tactic, technique, and mitigation identification.
5. soar_generate_containment - Ready-to-execute iptables, UFW, Windows Firewall, and Snort/Suricata rules.
6. rag_search_knowledge - Grounded semantic retrieval from local cybersecurity documentation.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Union

# Import NetGuard core engines
from src.threat_intel import threat_intel_engine
from src.soar_engine import soar_engine
from src.multiclass_engine import multiclass_classifier
from src.xai_engine import xai_engine

try:
    from backend.rag import RAGRetriever, default_config
    _rag_retriever = RAGRetriever(config=default_config)
except Exception:
    _rag_retriever = None


@dataclass
class AgentTool:
    """Represents an executable tool available to the SOC Agent."""
    name: str
    description: str
    parameters: Dict[str, Any]
    func: Callable[..., Any]

    def execute(self, **kwargs) -> Dict[str, Any]:
        """Safely executes the tool with defensive error handling."""
        try:
            return self.func(**kwargs)
        except Exception as err:
            return {
                "error": True,
                "tool": self.name,
                "message": f"Execution failed: {str(err)}",
            }


class SOCAgentToolRegistry:
    """Registry managing all tools callable by the ReAct SOC Agent."""

    def __init__(self):
        self._tools: Dict[str, AgentTool] = {}
        self._register_default_tools()

    def register(self, tool: AgentTool) -> None:
        self._tools[tool.name] = tool

    def get(self, name: str) -> Optional[AgentTool]:
        return self._tools.get(name)

    def list_tools(self) -> List[AgentTool]:
        return list(self._tools.values())

    def get_tool_definitions_prompt(self) -> str:
        """Formats the registered tools for inclusion in LLM ReAct prompts."""
        lines = []
        for tool in self._tools.values():
            lines.append(f"- **{tool.name}**: {tool.description}")
            params_str = json.dumps(tool.parameters, indent=2)
            lines.append(f"  *Parameters JSON Schema*:\n```json\n{params_str}\n```")
        return "\n".join(lines)

    def _register_default_tools(self) -> None:
        # Tool 1: Threat Intel Lookup
        self.register(AgentTool(
            name="threat_intel_lookup",
            description=(
                "Enriches an IP address with OSINT threat intelligence, "
                "geolocation (country, city, coordinates), ASN, ISP, and threat reputation score (0-100)."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "ip": {
                        "type": "string",
                        "description": "IPv4 address to inspect (e.g. '185.220.101.5' or '192.168.1.100')."
                    },
                    "is_flagged_threat": {
                        "type": "boolean",
                        "description": "True if the flow was marked as an anomaly by the ML model.",
                        "default": True
                    }
                },
                "required": ["ip"]
            },
            func=self._tool_threat_intel,
        ))

        # Tool 2: XAI Flow Explainer
        self.register(AgentTool(
            name="xai_explain_flow",
            description=(
                "Explains why a network flow is anomalous using explainable AI. "
                "Calculates top contributing features, baseline deviations (sigma z-scores), "
                "and generates an analyst rationale."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "features": {
                        "type": "object",
                        "description": "Dictionary of network flow features (e.g. {'Destination Port': 80, 'SYN Flag Count': 1})."
                    },
                    "dataset": {
                        "type": "string",
                        "description": "Benchmark dataset name: 'CICIDS-2017' or 'NSL-KDD'.",
                        "default": "CICIDS-2017"
                    },
                    "top_k": {
                        "type": "integer",
                        "description": "Number of top contributing features to return (default 5).",
                        "default": 5
                    }
                },
                "required": ["features"]
            },
            func=self._tool_xai_explain,
        ))

        # Tool 3: Multi-Class Attack Classifier
        self.register(AgentTool(
            name="multiclass_classify",
            description=(
                "Performs granular heuristic and signature classification to identify the exact cyber attack family: "
                "DoS / DDoS, PortScan, Brute Force, Botnet C2, Web Attack, or Data Infiltration."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "flow": {
                        "type": "object",
                        "description": "Dictionary of network flow features and port metadata."
                    },
                    "dataset": {
                        "type": "string",
                        "description": "Dataset format ('CICIDS-2017' or 'NSL-KDD').",
                        "default": "CICIDS-2017"
                    }
                },
                "required": ["flow"]
            },
            func=self._tool_multiclass_classify,
        ))

        # Tool 4: MITRE ATT&CK Mapping
        self.register(AgentTool(
            name="soar_mitre_mapping",
            description=(
                "Maps a suspected attack family or anomaly type to the MITRE ATT&CK Enterprise Matrix, "
                "returning Tactic ID, Technique ID, subtechnique, and recommended MITRE mitigation."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "threat_type": {
                        "type": "string",
                        "description": "Threat type or family (e.g. 'DOS_SYN_FLOOD', 'RECONNAISSANCE', 'BRUTE_FORCE', 'BOTNET_C2')."
                    },
                    "flow_data": {
                        "type": "object",
                        "description": "Optional dictionary containing destination port or protocol features.",
                        "default": {}
                    }
                },
                "required": ["threat_type"]
            },
            func=self._tool_soar_mitre,
        ))

        # Tool 5: SOAR Containment Rule Generator
        self.register(AgentTool(
            name="soar_generate_containment",
            description=(
                "Synthesizes actionable containment rules across Linux iptables, Linux UFW, "
                "Windows PowerShell Firewall, and Snort/Suricata IDS definitions to isolate or block malicious traffic."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "src_ip": {
                        "type": "string",
                        "description": "Malicious source IP to block."
                    },
                    "dst_port": {
                        "type": "string",
                        "description": "Target destination port (or 'any').",
                        "default": "any"
                    },
                    "proto": {
                        "type": "string",
                        "description": "Network protocol ('tcp', 'udp', 'icmp').",
                        "default": "tcp"
                    },
                    "severity": {
                        "type": "string",
                        "description": "Incident severity ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL').",
                        "default": "HIGH"
                    }
                },
                "required": ["src_ip"]
            },
            func=self._tool_soar_remediation,
        ))

        # Tool 6: RAG Cybersecurity Knowledge Base Search
        self.register(AgentTool(
            name="rag_search_knowledge",
            description=(
                "Queries NetGuard AI's local knowledge base for verified documentation on intrusion detection, "
                "incident response playbooks, CVEs, dataset nuances, and mitigation procedures."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Security question or search terms (e.g. 'SYN flood mitigation playbook' or 'CICIDS-2017 features')."
                    }
                },
                "required": ["query"]
            },
            func=self._tool_rag_search,
        ))

    # --- Tool Implementation Callables ---

    def _tool_threat_intel(self, ip: str, is_flagged_threat: bool = True) -> Dict[str, Any]:
        return threat_intel_engine.lookup_ip(ip_str=ip, is_flagged_threat=is_flagged_threat)

    def _tool_xai_explain(self, features: Dict[str, Any], dataset: str = "CICIDS-2017", top_k: int = 5) -> Dict[str, Any]:
        res = xai_engine.explain(features=features, dataset=dataset, top_k=top_k)
        if "plain_english_rationale" in res and "rationale" not in res:
            res["rationale"] = res["plain_english_rationale"]
        return res

    def _tool_multiclass_classify(self, flow: Dict[str, Any], dataset: str = "CICIDS-2017") -> Dict[str, Any]:
        return multiclass_classifier.classify_flow(flow=flow, dataset=dataset)

    def _tool_soar_mitre(self, threat_type: str, flow_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return soar_engine.map_mitre(threat_type=threat_type, flow_data=flow_data)

    def _tool_soar_remediation(
        self,
        src_ip: str,
        dst_port: str = "any",
        proto: str = "tcp",
        severity: str = "HIGH"
    ) -> Dict[str, Any]:
        return soar_engine.generate_remediation(
            src_ip=src_ip,
            dst_port=dst_port,
            proto=proto,
            severity=severity,
        )

    def _tool_rag_search(self, query: str) -> Dict[str, Any]:
        if _rag_retriever is None:
            return {
                "has_evidence": False,
                "context_text": "RAG retriever not initialized.",
                "sources": [],
            }
        res = _rag_retriever.retrieve(query=query)
        return {
            "has_evidence": res.get("has_evidence", False),
            "sources": [s.get("document_name") for s in res.get("sources", []) if s.get("document_name")],
            "context_snippet": (res.get("context_text") or "")[:1000],
        }


# Global tool registry singleton
default_tool_registry = SOCAgentToolRegistry()
