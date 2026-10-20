"""
SOAR (Security Orchestration, Automation, and Response) Engine for NetGuard AI.

Capabilities:
1. MITRE ATT&CK Framework Mapping (Tactics, Techniques, Mitigation IDs)
2. Automated Containment / Firewall Rule Generation:
   - Linux iptables
   - Linux UFW
   - Windows Firewall (PowerShell)
   - Snort IDS rule
   - Suricata IDS rule
3. Incident Ticket / STIX 2.1 JSON generator for SIEM/SOAR dispatch
"""

from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional, Union


MITRE_MATRIX_MAPPING = {
    "DOS_SYN_FLOOD": {
        "tactic": "Impact (TA0040)",
        "technique_id": "T1498",
        "technique_name": "Network Denial of Service",
        "subtechnique": "T1498.001 - Direct Network Flood",
        "mitigation_id": "M1037",
        "mitigation_name": "Filter Network Traffic",
        "url": "https://attack.mitre.org/techniques/T1498/001/",
        "description": "Adversary conducts volumetric network flood attacks to degrade availability of target services.",
    },
    "RECONNAISSANCE": {
        "tactic": "Discovery (TA0007)",
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "subtechnique": "Port Scanning / Sweep",
        "mitigation_id": "M1030",
        "mitigation_name": "Network Segmentation",
        "url": "https://attack.mitre.org/techniques/T1046/",
        "description": "Adversary attempts to enumerate active listening services and open network ports to identify vulnerabilities.",
    },
    "BRUTE_FORCE": {
        "tactic": "Credential Access (TA0006)",
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "subtechnique": "T1110.001 - Password Guessing",
        "mitigation_id": "M1036",
        "mitigation_name": "Account Use Policies",
        "url": "https://attack.mitre.org/techniques/T1110/",
        "description": "Adversary attempts to authenticate repeatedly against network services (SSH/FTP/RDP) using credential dictionaries.",
    },
    "BOTNET_C2": {
        "tactic": "Command and Control (TA0011)",
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "subtechnique": "T1071.001 - Web Protocols (HTTP/HTTPS)",
        "mitigation_id": "M1031",
        "mitigation_name": "Network Intrusion Prevention",
        "url": "https://attack.mitre.org/techniques/T1071/",
        "description": "Adversary establishes periodic command-and-control beaconing channels disguised within typical network traffic.",
    },
    "WEB_ATTACK": {
        "tactic": "Initial Access (TA0001)",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "subtechnique": "SQLi / XSS / Infiltration",
        "mitigation_id": "M1050",
        "mitigation_name": "Exploit Protection",
        "url": "https://attack.mitre.org/techniques/T1190/",
        "description": "Adversary sends malformed payloads to exploit vulnerabilities in Internet-facing applications.",
    },
    "EXFILTRATION": {
        "tactic": "Exfiltration (TA0010)",
        "technique_id": "T1048",
        "technique_name": "Exfiltration Over Alternative Protocol",
        "subtechnique": "T1048.003 - Exfiltration Over Unencrypted Non-C2 Protocol",
        "mitigation_id": "M1031",
        "mitigation_name": "Network Intrusion Prevention",
        "url": "https://attack.mitre.org/techniques/T1048/",
        "description": "Adversary steals sensitive organization data by transmitting high outbound volumes across unauthorized sockets.",
    },
    "ANOMALY": {
        "tactic": "Defense Evasion (TA0005)",
        "technique_id": "T1036",
        "technique_name": "Masquerading",
        "subtechnique": "T1036.005 - Device / Flow Masquerading",
        "mitigation_id": "M1037",
        "mitigation_name": "Filter Network Traffic",
        "url": "https://attack.mitre.org/techniques/T1036/",
        "description": "Traffic statistical parameters strongly deviate from baseline normal network behavior.",
    },
}


class SOAREngine:
    """
    Automated Remediation, MITRE ATT&CK Mapping, and Incident Response Engine.
    """

    def __init__(self):
        self.mappings = MITRE_MATRIX_MAPPING

    def map_mitre(
        self,
        threat_type: str,
        flow_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Maps an identified threat type or flow profile to its MITRE ATT&CK tactic, technique, and mitigation.
        """
        normalized = threat_type.upper().replace(" ", "_").replace("-", "_")

        # Heuristic lookup
        for key, val in self.mappings.items():
            if key in normalized or normalized in key:
                return val.copy()

        # Check port heuristic if flow_data provided
        if flow_data:
            port = flow_data.get("Destination Port") or flow_data.get("dst_port") or 0
            try:
                port = int(port)
                if port in (21, 22, 23, 3389):
                    return self.mappings["BRUTE_FORCE"].copy()
                if port in (80, 443, 8080):
                    return self.mappings["WEB_ATTACK"].copy()
            except (ValueError, TypeError):
                pass

        return self.mappings["ANOMALY"].copy()

    def generate_remediation(
        self,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        dst_port: Optional[Union[int, str]] = None,
        proto: str = "tcp",
        severity: str = "HIGH",
    ) -> Dict[str, Any]:
        """
        Generates automated containment rules across Linux iptables, UFW, Windows Firewall, and Snort/Suricata IDS.
        """
        ip = src_ip if src_ip and src_ip != "N/A" else "198.51.100.1"
        port = str(dst_port) if dst_port and dst_port != "N/A" else "any"
        proto = proto.lower() if proto in ("tcp", "udp", "icmp") else "tcp"

        rule_tag = f"NetGuard_AutoBlock_{ip.replace('.', '_')}"

        # 1. Linux iptables
        if port != "any":
            iptables_rule = f"sudo iptables -I INPUT -p {proto} -s {ip} --dport {port} -j DROP -m comment --comment \"{rule_tag}\""
        else:
            iptables_rule = f"sudo iptables -I INPUT -s {ip} -j DROP -m comment --comment \"{rule_tag}\""

        # 2. Linux UFW (Uncomplicated Firewall)
        if port != "any":
            ufw_rule = f"sudo ufw insert 1 deny from {ip} to any port {port} proto {proto} comment '{rule_tag}'"
        else:
            ufw_rule = f"sudo ufw insert 1 deny from {ip} comment '{rule_tag}'"

        # 3. Windows PowerShell (New-NetFirewallRule)
        if port != "any":
            powershell_rule = (
                f'New-NetFirewallRule -DisplayName "{rule_tag}" -Direction Inbound '
                f'-RemoteAddress "{ip}" -LocalPort {port} -Protocol {proto.upper()} -Action Block'
            )
        else:
            powershell_rule = (
                f'New-NetFirewallRule -DisplayName "{rule_tag}" -Direction Inbound '
                f'-RemoteAddress "{ip}" -Action Block'
            )

        # 4. Snort IDS Rule
        sid = 1000000 + abs(hash(rule_tag)) % 900000
        snort_port = port if port != "any" else "any"
        snort_rule = (
            f'alert {proto} {ip} any -> any {snort_port} '
            f'(msg:\"[NetGuard-AI] {severity} Threat Blocked from {ip}\"; '
            f'threshold:type limit,track by_src,count 1,seconds 60; sid:{sid}; rev:1;)'
        )

        # 5. Suricata IDS Rule
        suricata_rule = (
            f'drop {proto} {ip} any -> any {snort_port} '
            f'(msg:\"[NetGuard-AI] Automated Drop for {severity} Anomaly\"; '
            f'flow:established; sid:{sid + 1}; rev:1;)'
        )

        return {
            "target_ip": ip,
            "port": port,
            "protocol": proto,
            "firewall_rules": {
                "iptables": iptables_rule,
                "ufw": ufw_rule,
                "powershell": powershell_rule,
            },
            "ids_rules": {
                "snort": snort_rule,
                "suricata": suricata_rule,
            },
        }

    def create_incident_ticket(
        self,
        alert_row: Dict[str, Any],
        mitre_info: Dict[str, Any],
        remediation: Dict[str, Any],
        analyst_notes: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Creates ready-to-dispatch Markdown ticket and STIX 2.1 Threat Intel JSON.
        """
        now = datetime.now(timezone.utc).isoformat()
        sev = alert_row.get("Severity", "HIGH")
        pred = alert_row.get("prediction", "ATTACK")
        ip = remediation.get("target_ip", alert_row.get("src_ip", "198.51.100.1"))
        port = remediation.get("port", alert_row.get("dst_port", 80))

        # Markdown Ticket for Jira / ServiceNow
        ticket_md = f"""# [INCIDENT TICKET] NetGuard AI SOC - Threat Detection #{abs(hash(str(alert_row))) % 100000:05d}

**Status:** TRIAGED / REMEDIATION READY  
**Severity:** {sev}  
**Detected At:** {now}  
**Target Actor IP:** `{ip}`  
**Target Port:** `{port}`  
**Classification:** `{pred}`  

---

### 1. MITRE ATT&CK Classification
- **Tactic:** {mitre_info.get('tactic', 'N/A')}
- **Technique:** [{mitre_info.get('technique_id', 'T1036')} - {mitre_info.get('technique_name', 'Masquerading')}]({mitre_info.get('url', 'https://attack.mitre.org')})
- **Sub-technique:** {mitre_info.get('subtechnique', 'N/A')}
- **Recommended Mitigation:** {mitre_info.get('mitigation_id', 'M1037')} ({mitre_info.get('mitigation_name', 'Filter Network Traffic')})

### 2. Threat Summary
{mitre_info.get('description', 'Anomalous traffic profile detected exceeding risk baseline.')}

### 3. Automated Containment Playbook
Run the containment command appropriate for the host perimeter:

```bash
# Linux iptables
{remediation.get('firewall_rules', {}).get('iptables', 'iptables -A INPUT -j DROP')}

# Linux UFW
{remediation.get('firewall_rules', {}).get('ufw', 'ufw deny')}

# Windows PowerShell
{remediation.get('firewall_rules', {}).get('powershell', 'New-NetFirewallRule')}
```

### 4. Analyst Notes
{analyst_notes if analyst_notes else "Automated incident report generated by NetGuard AI Autonomous SOAR."}
"""

        # OASIS STIX 2.1 Threat Intelligence Bundle
        stix_indicator_id = f"indicator--{abs(hash(ip + str(port))) % 1000000000:09d}-41804"
        stix_bundle = {
            "type": "bundle",
            "id": f"bundle--{abs(hash(now)) % 1000000000:09d}",
            "objects": [
                {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": stix_indicator_id,
                    "created": now,
                    "modified": now,
                    "name": f"Malicious Network Traffic from {ip}",
                    "description": mitre_info.get("description", "Network anomaly detected by NetGuard AI"),
                    "pattern": f"[ipv4-addr:value = '{ip}']",
                    "pattern_type": "stix",
                    "valid_from": now,
                    "labels": ["malicious-activity", "network-anomaly", sev.lower()],
                }
            ],
        }

        return {
            "ticket_markdown": ticket_md,
            "stix_bundle": stix_bundle,
        }


soar_engine = SOAREngine()
