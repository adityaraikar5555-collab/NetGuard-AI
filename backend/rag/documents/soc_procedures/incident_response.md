# SOC Incident Response Procedures (NIST SP 800-61 Rev 2 Framework)

## Overview
The Security Operations Center (SOC) follows a standardized incident handling lifecycle based on NIST Special Publication 800-61 Rev. 2. When NetGuard AI detects network anomalies, analysts execute procedural playbooks to contain threats, preserve forensic evidence, and restore operational integrity.

Incident Response (IR) is not a single action but a repeatable, documented process — the goal is to move from initial detection to full recovery in a way that is fast, consistent, and produces evidence that can be reviewed and learned from afterward.

---

## Definition

- **Incident:** A violation or imminent threat of violation of computer security policies, acceptable use policies, or standard security practices (per NIST SP 800-61).
- **Incident Response (IR):** The organized approach to addressing and managing the aftermath of a security incident, aiming to limit damage and reduce recovery time and cost.
- **Playbook / Runbook:** A predefined, step-by-step procedure for responding to a specific type of incident (e.g., a DDoS playbook, a ransomware playbook).
- **Alert Triage:** The process of reviewing incoming security alerts to determine validity, severity, and priority for further investigation.
- **MTTD / MTTR:** Mean Time to Detect and Mean Time to Respond/Resolve — key metrics used to measure SOC efficiency.

**Alternative / related terminology:** incident handling, security incident management, IR lifecycle, breach response, cyber incident response plan (CIRP).

---

## Key Concepts

### Why a Structured Lifecycle Matters
Without a consistent process, incident response can become chaotic — evidence gets lost, containment steps get skipped or duplicated, and organizations fail to learn from past incidents. Frameworks such as NIST SP 800-61 Rev. 2 exist so that regardless of which analyst is on shift, the same disciplined sequence of steps is followed.

### Relationship Between Detection Tooling and IR Process
NetGuard AI, as a network anomaly detection platform, sits primarily at the **Detection & Analysis** phase of the lifecycle: it surfaces ML-classified anomalous flows with severity and confidence information (see `severity_and_confidence.md`) that analysts use as the starting point for investigation. The subsequent containment, eradication, and recovery actions are analyst-driven decisions informed by, but not automatically executed by, the detection layer, unless explicitly documented otherwise for a given deployment.

### Severity-Driven Prioritization
Not every alert warrants the same urgency. Incidents are typically prioritized using a combination of:
- **Confirmed vs. suspected** activity.
- **Asset criticality** (a compromised domain controller is more urgent than a compromised test VM).
- **Model confidence/severity classification**, where available, to help rank which alerts need immediate human attention versus routine monitoring.

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

The lifecycle is often drawn as a loop rather than a straight line: lessons learned in Phase 4 feed back into improved Preparation for the next incident, and analysis during a single incident can reveal new indicators worth continuously monitoring.

---

## Phase 1: Preparation
- Maintain updated network architecture maps and baseline traffic profiles.
- Configure NetGuard AI detection thresholds, logging agents, and API integrations.
- Pre-authorize containment workflows (e.g., standard firewall change templates).
- Maintain an up-to-date contact list and escalation matrix (who to notify for which severity of incident, and by what channel).
- Ensure forensic tooling (packet capture, disk/memory imaging tools) is available and tested before it is needed under pressure.
- Conduct periodic tabletop exercises so analysts have practiced the IR process before a real incident occurs.

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
5. **Severity Assignment:** Map the finding to a severity tier (Critical / High / Medium / Low) using consistent criteria so that downstream response time expectations (SLAs) are clear (see `severity_and_confidence.md` for NetGuard AI's severity matrix).
6. **Initial Documentation:** Open an incident ticket or case record capturing the alert time, source data, and initial analyst assessment, even before the investigation is complete — this creates the backbone of the eventual incident timeline.

### Alert Triage Decision Points
- **Is this consistent with a known benign pattern?** (e.g., scheduled vulnerability scans, load-testing traffic, backup replication windows.)
- **Does the source or destination appear on any threat intelligence list?**
- **Is the affected asset business-critical?**
- **Does the confidence/severity score suggest immediate action, or does it fall in a borderline range warranting further verification before escalation?**

---

## Phase 3: Containment, Eradication & Recovery

### Short-Term Containment (Immediate Isolation)
- **Perimeter Firewall Rule:** Block attacking source IP or entire malicious ASN:
  ```bash
  iptables -I INPUT -s <MALICIOUS_IP>/32 -j DROP
  ```
- **Network Segmentation:** Place compromised internal host into an isolated quarantine VLAN.
- **Null-Route / BGP Blackholing:** Drop volumetric DDoS traffic at the edge router.
- **Preserve Volatile Evidence First:** Before powering off or aggressively remediating a host, capture volatile evidence (running processes, network connections, memory) where feasible, since containment actions can destroy evidence needed for later analysis.

### Long-Term Containment
- Apply temporary compensating controls (additional monitoring, restricted network access) to affected systems that cannot be immediately taken offline due to business impact, while a permanent fix is prepared.

### Eradication (Eliminate the Root Cause)
- Terminate malicious processes, C2 beaconing tasks, and rogue cronjobs/scheduled tasks.
- Close unused vulnerable ports and services.
- Revoke and rotate compromised credentials and Kerberos tickets (KRBTGT).
- Apply security patches for exploited vulnerabilities (e.g., CVE patches).
- Remove any persistence mechanisms discovered during investigation (unauthorized scheduled tasks, registry run keys, unfamiliar services).

### Recovery (Restoring Safe Operations)
- Re-enable services under enhanced telemetry monitoring.
- Verify normal baseline flow rates through NetGuard AI Live Traffic monitor.
- Confirm integrity of restored database backups and configuration files.
- Gradually restore access in phases rather than all at once, watching for recurrence of the original indicators before declaring the incident fully resolved.

---

## Evidence Handling & Documentation

Proper evidence handling ensures that findings from an investigation are reliable and, where relevant, usable in a legal or regulatory context.

- **Chain of Custody:** Record who collected each piece of evidence, when, and how it was stored/transferred, to preserve its integrity and credibility.
- **Timestamping:** Ensure all systems involved in the incident have synchronized clocks (e.g., via NTP) so that timeline reconstruction across multiple logs/sources is accurate.
- **Preserve, Don't Alter:** Work from copies of logs, disk images, or memory captures wherever possible rather than the original evidence, to avoid accidental modification.
- **Incident Timeline:** Build a chronological record correlating detection time, analyst actions, and system events — this timeline underpins both the technical understanding of the incident and any post-incident reporting.

---

## Escalation Matrix (Conceptual / General Practice)

| Severity | Typical Escalation Path |
| :--- | :--- |
| Critical | Immediate escalation to senior/Tier-3 analyst and incident commander; may require executive or legal notification depending on organizational policy. |
| High | Escalation to a senior analyst for validation and containment approval within the defined SLA window. |
| Medium | Handled by on-shift analyst; escalated only if investigation reveals broader scope. |
| Low | Logged and monitored; escalated only if a pattern emerges over time. |

*(This table reflects general SOC practice; specific SLA timings and severity criteria used by NetGuard AI are documented in `severity_and_confidence.md`.)*

---

## Phase 4: Post-Incident Activity & Continuous Improvement
- **Incident Documentation:** Record timestamped incident timeline, attack vectors, impacted assets, and time to detect/resolve (MTTD / MTTR).
- **Lessons Learned Meeting:** Identify detection gaps or configuration delays.
- **Model / Rule Tuning:** Retrain anomaly detection models with newly observed threat samples or update Suricata / Snort IDS rules.
- **Metric Review:** Compare this incident's MTTD/MTTR against historical baselines to identify whether process changes are improving response speed over time.
- **Update Playbooks:** Revise or create playbooks based on gaps discovered during the incident (e.g., a new attack variant not covered by existing procedures).
- **Report to Stakeholders:** Summarize the incident, impact, and remediation for management or affected business units, in language appropriate to a non-technical audience where needed.

---

## SOC Perspective: The Analyst Workflow in Practice

A typical analyst workflow when NetGuard AI surfaces a new anomalous flow:
1. Open the alert and review the ML classification, confidence score, and severity tier.
2. Pull up related flow metadata (source/destination, ports, protocol, duration, byte/packet counts).
3. Ask the RAG-backed assistant contextual questions about the detected pattern (e.g., "what does a high SYN flag ratio combined with low bytes per flow typically indicate?") to accelerate understanding without needing to consult external documentation.
4. Decide whether the finding requires escalation, further monitoring, or can be closed as a false positive with documented justification.
5. If escalated, follow the appropriate containment/eradication/recovery playbook for the matched attack category.
6. Document every action taken directly on the incident ticket to preserve the timeline for Phase 4 review.

---

## Role of RAG-Based Assistance in Incident Response

A Retrieval-Augmented Generation (RAG) knowledge base, such as the one powering NetGuard AI's chatbot, supports the IR process by giving analysts fast, contextual access to reference material during triage — for example, explaining what a given attack category or dataset feature typically means — without requiring them to leave their workflow to search external documentation. This supports faster, more consistent triage decisions, though the final containment/eradication/recovery decisions remain analyst-driven judgment calls informed by the retrieved context.

---

## Examples

- **DDoS Incident Walkthrough:** Alert triggers on a sustained SYN flood pattern → analyst confirms via flow attributes (high SYN flag count, low completed handshakes) → short-term containment via rate-limiting/BGP blackholing → eradication involves verifying no secondary payload was delivered → recovery restores normal service and monitors for recurrence → post-incident review updates the DDoS playbook with any new observed variant.
- **Suspected Brute Force Incident:** Repeated failed SSH logins detected → triage confirms no successful login occurred → containment bans the source IP → eradication includes verifying no other accounts were targeted → recovery involves optional password rotation as a precaution → lessons learned may recommend enabling MFA if not already enforced.

---

## Limitations

- **Human judgment remains essential:** Automated detection surfaces candidate incidents, but determining true scope, intent, and appropriate response still requires analyst expertise and business context that tooling alone cannot supply.
- **Evidence volatility:** Some evidence (in-memory artifacts, active network connections) is lost quickly if not captured promptly, creating time pressure that can conflict with careful, methodical containment.
- **Playbook coverage gaps:** Predefined playbooks cannot cover every possible incident variant; novel attacks may require improvisation informed by general IR principles rather than a matching runbook.
- **Metric interpretation:** MTTD/MTTR figures can be misleading in isolation (e.g., a fast MTTR achieved by insufficiently thorough eradication may lead to reinfection), so metrics should be reviewed alongside qualitative post-incident findings.

---

## Common Questions

**Q: What are the four phases of the NIST SP 800-61 incident response lifecycle?**
A: Preparation; Detection & Analysis; Containment, Eradication & Recovery; and Post-Incident Activity.

**Q: What is alert triage?**
A: Alert triage is the process of reviewing an incoming security alert to determine whether it is a true or false positive, assess its severity, and decide on the appropriate next steps and priority.

**Q: What is the difference between containment and eradication?**
A: Containment focuses on immediately limiting the spread or impact of an incident (e.g., isolating a host or blocking an IP), while eradication focuses on removing the root cause (e.g., malware, backdoors, vulnerable configurations) so the threat cannot recur.

**Q: What do MTTD and MTTR mean?**
A: MTTD (Mean Time to Detect) measures how long it takes to identify that an incident has occurred; MTTR (Mean Time to Respond/Resolve) measures how long it takes to contain and resolve the incident once detected. Both are used to evaluate and improve SOC performance over time.

**Q: Why is evidence chain of custody important?**
A: Chain of custody documents who handled evidence and when, which preserves its integrity and credibility — important both for accurate technical analysis and for any potential legal or regulatory follow-up.

**Q: How does NetGuard AI fit into the incident response lifecycle?**
A: NetGuard AI primarily supports the Detection & Analysis phase by surfacing ML-classified anomalous network flows along with confidence and severity information, which analysts then use to drive the subsequent containment, eradication, and recovery steps.

**Q: What happens in the post-incident review phase?**
A: The team documents the full incident timeline, reviews what worked and what did not (lessons learned), updates playbooks and detection rules/models as needed, and reports outcomes to relevant stakeholders.

**Q: Why should volatile evidence be preserved before containment?**
A: Certain evidence, such as running processes or active network connections in memory, can be lost the moment a system is powered off or aggressively remediated, so capturing it beforehand (where feasible) preserves valuable forensic detail for later investigation.

---

## Summary
Incident response follows a structured, repeatable lifecycle — Preparation, Detection & Analysis, Containment/Eradication/Recovery, and Post-Incident Activity — that ensures security incidents are handled consistently rather than ad hoc. NetGuard AI supports the Detection & Analysis phase by surfacing ML-classified anomalies with confidence and severity context, which analysts use to triage, decide on containment strategy, and drive eradication and recovery actions. Careful evidence handling (chain of custody, timestamp synchronization, preserving volatile data) and honest post-incident review (tracking MTTD/MTTR, updating playbooks) are what allow a SOC to continuously improve its response capability over time, while final judgment on scope, severity, and remediation remains an analyst-driven process informed — not replaced — by automated detection.
