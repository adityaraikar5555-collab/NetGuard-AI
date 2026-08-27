# SOC Incident Response Procedures (NIST SP 800-61 Rev 2 Framework)

## Overview
The Security Operations Center (SOC) follows a standardized incident handling lifecycle based on NIST Special Publication 800-61 Rev. 2. When NetGuard AI detects network anomalies, analysts execute procedural playbooks to contain threats, preserve forensic evidence, and restore operational integrity.

---

## 4-Stage Incident Handling Lifecycle

```
┌─────────────────┐       ┌────────────────────────┐
│  1. Preparation  │ ----> │ 2. Detection & Analysis│
└─────────────────┘       └───────────┬────────────┘
                                      │
┌─────────────────────────┐           ▼
│ 4. Post-Incident Review │ <── ┌────────────────────────┐
└─────────────────────────┘     │3. Containment,         │
                                │   Eradication & Recovery│
                                └────────────────────────┘
```

---

## Phase 1: Preparation
- Maintain updated network architecture maps and baseline traffic profiles.
- Configure NetGuard AI detection thresholds, logging agents, and API integrations.
- Pre-authorize containment workflows (e.g., standard firewall change templates).

---

## Phase 2: Detection & Analysis (Triage)
1. **Alert Ingestion:** Receive anomalous flow alerts from NetGuard AI dashboard.
2. **Context Enrichment:** Inspect flow attributes:
   - Source IP / Destination IP & GeoIP origin.
   - Flow Duration, Bytes/sec, Packets/sec.
   - TCP Flags (`SYN`, `RST`, `FIN`).
   - ML model confidence and severity classification.
3. **Scope Assessment:** Determine if the anomaly represents a single host probe or a coordinated enterprise-wide campaign.
4. **Distinguish True vs False Positive:** Cross-reference scheduled network backups, pentesting windows, or internal batch jobs.

---

## Phase 3: Containment, Eradication & Recovery

### Short-Term Containment (Immediate Isolation)
- **Perimeter Firewall Rule:** Block attacking source IP or entire malicious ASN:
  ```bash
  iptables -I INPUT -s <MALICIOUS_IP>/32 -j DROP
  ```
- **Network Segmentation:** Place compromised internal host into an isolated quarantine VLAN.
- **Null-Route / BGP Blackholing:** Drop volumetric DDoS traffic at the edge router.

### Eradication (Eliminate the Root Cause)
- Terminate malicious processes, C2 beaconing tasks, and rogue cronjobs/scheduled tasks.
- Close unused vulnerable ports and services.
- Revoke and rotate compromised credentials and Kerberos tickets (KRBTGT).
- Apply security patches for exploited vulnerabilities (e.g., CVE patches).

### Recovery (Restoring Safe Operations)
- Re-enable services under enhanced telemetry monitoring.
- Verify normal baseline flow rates through NetGuard AI Live Traffic monitor.
- Confirm integrity of restored database backups and configuration files.

---

## Phase 4: Post-Incident Activity & Continuous Improvement
- **Incident Documentation:** Record timestamped incident timeline, attack vectors, impacted assets, and time to detect/resolve (MTTD / MTTR).
- **Lessons Learned Meeting:** Identify detection gaps or configuration delays.
- **Model / Rule Tuning:** Retrain anomaly detection models with newly observed threat samples or update Suricata / Snort IDS rules.
