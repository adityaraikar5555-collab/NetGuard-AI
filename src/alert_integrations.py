"""
Real-Time Alert Dispatcher & SIEM Integration Engine for NetGuard AI.

Supports:
1. Webhooks: Slack, Discord, Microsoft Teams, Generic HTTP JSON
2. SIEM Export: ArcSight/Splunk CEF (Common Event Format)
3. Syslog RFC 5424 format generation
"""

from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional
import requests


class AlertIntegrationEngine:
    """
    Dispatches alerts to external communication channels and SIEM systems.
    """

    def send_webhook(
        self,
        webhook_url: str,
        channel_type: str,
        alert_payload: Dict[str, Any],
        timeout: int = 5,
    ) -> Dict[str, Any]:
        """
        Formats and delivers an alert payload to Slack, Discord, Teams, or a custom Webhook.
        """
        if not webhook_url or not webhook_url.startswith("http"):
            return {"success": False, "error": "Invalid or missing Webhook URL"}

        channel = channel_type.lower().strip()
        sev = alert_payload.get("Severity", "HIGH").upper()
        title = f"🚨 NetGuard AI Alert: {alert_payload.get('attack_family', 'Network Anomaly Detected')}"
        ip = alert_payload.get("src_ip") or alert_payload.get("Source IP") or "192.168.1.100"
        dst_ip = alert_payload.get("dst_ip") or alert_payload.get("Destination IP") or "10.0.0.1"
        port = alert_payload.get("dst_port") or alert_payload.get("Destination Port") or "80"
        prob = alert_payload.get("attack_probability", 0.95)
        rationale = alert_payload.get("rationale") or "Anomalous traffic characteristics detected by ML model."

        try:
            if channel == "slack":
                payload = {
                    "text": title,
                    "blocks": [
                        {
                            "type": "header",
                            "text": {"type": "plain_text", "text": title, "emoji": True},
                        },
                        {
                            "type": "section",
                            "fields": [
                                {"type": "mrkdwn", "text": f"*Severity:*\n`{sev}`"},
                                {"type": "mrkdwn", "text": f"*Confidence:*\n{float(prob)*100:.1f}%"},
                                {"type": "mrkdwn", "text": f"*Source IP:*\n`{ip}`"},
                                {"type": "mrkdwn", "text": f"*Target Port:*\n`{dst_ip}:{port}`"},
                            ],
                        },
                        {
                            "type": "section",
                            "text": {"type": "mrkdwn", "text": f"*Root Cause Analysis:*\n_{rationale}_"},
                        },
                    ],
                }
            elif channel == "discord":
                color_code = 0xEF4444 if sev in ("CRITICAL", "HIGH") else 0xF59E0B
                payload = {
                    "username": "NetGuard AI SOC",
                    "embeds": [
                        {
                            "title": title,
                            "description": rationale,
                            "color": color_code,
                            "fields": [
                                {"name": "Severity", "value": sev, "inline": True},
                                {"name": "Probability", "value": f"{float(prob)*100:.1f}%", "inline": True},
                                {"name": "Attacker IP", "value": str(ip), "inline": True},
                                {"name": "Target Destination", "value": f"{dst_ip}:{port}", "inline": True},
                            ],
                            "footer": {"text": "NetGuard AI Autonomous SOC"},
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        }
                    ],
                }
            elif channel in ("teams", "msteams"):
                payload = {
                    "@type": "MessageCard",
                    "@context": "http://schema.org/extensions",
                    "themeColor": "EF4444" if sev in ("CRITICAL", "HIGH") else "F59E0B",
                    "summary": title,
                    "sections": [
                        {
                            "activityTitle": title,
                            "activitySubtitle": f"Severity: {sev} | Target: {dst_ip}:{port}",
                            "text": rationale,
                            "facts": [
                                {"name": "Source IP", "value": str(ip)},
                                {"name": "Probability", "value": f"{float(prob)*100:.1f}%"},
                            ],
                        }
                    ],
                }
            else:
                # Generic JSON webhook
                payload = {
                    "source": "NetGuard-AI",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "alert": alert_payload,
                }

            response = requests.post(webhook_url, json=payload, timeout=timeout)
            return {
                "success": response.status_code in (200, 201, 204),
                "status_code": response.status_code,
                "response": response.text[:200],
            }

        except Exception as exc:
            return {"success": False, "error": str(exc)}

    def format_cef(self, alert_payload: Dict[str, Any]) -> str:
        """
        Formats alert into Common Event Format (CEF) standard string for SIEM.
        """
        sev = alert_payload.get("Severity", "High").capitalize()
        sev_int = {"Critical": 10, "High": 8, "Medium": 5, "Low": 3}.get(sev, 5)
        threat_type = alert_payload.get("attack_family", "Network Anomaly")
        src_ip = alert_payload.get("src_ip") or alert_payload.get("Source IP") or "192.168.1.100"
        dst_ip = alert_payload.get("dst_ip") or alert_payload.get("Destination IP") or "10.0.0.1"
        dst_port = alert_payload.get("dst_port") or alert_payload.get("Destination Port") or "80"
        proto = alert_payload.get("Protocol", "TCP")
        rationale = alert_payload.get("rationale", "Anomaly flagged by ML")

        cef = (
            f"CEF:0|NetGuard AI|Network IDS|2.0|{threat_type}|{threat_type}|{sev_int}|"
            f"src={src_ip} dst={dst_ip} dpt={dst_port} proto={proto} cs1={rationale[:100]}"
        )
        return cef

    def format_syslog_rfc5424(self, alert_payload: Dict[str, Any]) -> str:
        """
        Formats alert into standard RFC 5424 Syslog message.
        """
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        sev = alert_payload.get("Severity", "HIGH").upper()
        pri = 131 if sev == "CRITICAL" else 134  # Local0.Alert or Local0.Notice
        src_ip = alert_payload.get("src_ip") or alert_payload.get("Source IP") or "192.168.1.100"
        dst_ip = alert_payload.get("dst_ip") or alert_payload.get("Destination IP") or "10.0.0.1"
        port = alert_payload.get("dst_port") or alert_payload.get("Destination Port") or "80"
        attack = alert_payload.get("attack_family", "Network_Anomaly")

        return f"<{pri}>1 {now} netguard-ai nids - - - [incident@41804 sev=\"{sev}\" src=\"{src_ip}\" dst=\"{dst_ip}:{port}\" type=\"{attack}\"] {alert_payload.get('rationale', 'Threat detected')}"


alert_integration_engine = AlertIntegrationEngine()
