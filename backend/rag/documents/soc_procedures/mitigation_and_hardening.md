# Network Hardening, Defensive Configuration & Mitigation Playbooks

## Overview
Proactive network hardening reduces the attack surface and enforces Zero Trust security principles across all layers of the OSI model. When threats are identified by NetGuard AI, these mitigation playbooks provide verified technical countermeasures.

Hardening and mitigation are complementary: **hardening** is the ongoing, proactive work of reducing weaknesses before an attack occurs, while **mitigation playbooks** are the reactive, attack-specific response actions taken once a threat is identified.

---

## Definition

- **Hardening:** The process of reducing a system's or network's attack surface by disabling unnecessary services, enforcing secure configurations, and applying the principle of least privilege.
- **Mitigation:** An action taken to reduce the impact or likelihood of a specific identified threat, either proactively (hardening) or reactively (in response to a detected attack).
- **Attack Surface:** The complete set of points where an unauthorized user could attempt to enter or extract data from a system.
- **Defense-in-Depth:** A security strategy that layers multiple independent controls so that if one layer fails, others still provide protection.
- **Zero Trust:** A security model that assumes no implicit trust is granted to any user or device based solely on network location, requiring continuous verification.

**Alternative / related terminology:** attack surface reduction, security baseline configuration, network defense posture, defensive configuration, countermeasure playbook.

---

## Key Concepts

### Hardening vs. Playbook-Driven Response
| Aspect | Hardening | Attack-Specific Playbook |
| :--- | :--- | :--- |
| Timing | Continuous, proactive | Triggered by a specific detected event |
| Goal | Reduce likelihood/impact of *any* future attack | Respond effectively to *this* attack, now |
| Example | Disabling SMBv1 across the domain | Isolating a host actively beaconing to a C2 server |

### Defense-in-Depth Across the OSI Model
Effective hardening applies controls at multiple layers rather than relying on a single control:
- **Network Layer:** Firewalls, segmentation, VLANs, ACLs.
- **Transport Layer:** TLS enforcement, rate limiting, SYN cookie protections.
- **Application Layer:** WAFs, input validation, secure coding practices.
- **Identity Layer:** MFA, least-privilege access, credential hygiene.
- **Endpoint Layer:** EDR, patch management, host-based firewalls.

No single layer is assumed sufficient; the goal is that a failure or bypass at one layer is caught by another.

### The Role of Baselines
Hardening decisions and anomaly detection both depend on having a clear baseline of "normal" — normal open ports, normal traffic volumes, normal login times and locations. Without an accurate baseline, both proactive hardening priorities and reactive detection thresholds are harder to set correctly.

---

## Technical Details

## Defensive Playbooks by Attack Type

### 1. DDoS & Volumetric Flood Playbook
- **Immediate Action:**
  - Activate cloud DDoS protection (Cloudflare / AWS Shield / Akamai).
  - Deploy upstream BGP Flowspec rules to filter attack vectors at the carrier level.
  - Enable SYN flood defense on Linux hosts:
    ```bash
    sysctl -w net.ipv4.tcp_syncookies=1
    sysctl -w net.ipv4.tcp_max_syn_backlog=8192
    ```
- **Firewall Rule (NFTables):**
  ```nft
  table ip filter {
      chain input {
          type filter hook input priority 0; policy accept;
          tcp flags syn tcp dport { 80, 443 } meter synmeter { ip saddr limit rate over 25/second } drop
      }
  }
  ```
- **Proactive Hardening:** Pre-provision sufficient bandwidth headroom and connection-table capacity, and pre-negotiate DDoS scrubbing/mitigation contracts with an upstream provider before an attack occurs, rather than during one.

### 2. Port Scanning & Reconnaissance Playbook
- **Immediate Action:**
  - Temporarily block aggressive scanning source IPs for 24 hours.
  - Disable ICMP Timestamp / Address Mask replies to prevent network mapping.
  - Implement dynamic scanning blocking with iptables `recent` module:
    ```bash
    iptables -A INPUT -m recent --name portscan --rcheck --seconds 86400 -j DROP
    iptables -A INPUT -m recent --name portscan --remove
    iptables -A INPUT -p tcp -m tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix "Portscan detected: "
    iptables -A INPUT -p tcp -m tcp --dport 139 -m recent --name portscan --set -j DROP
    ```
- **Proactive Hardening:** Close and disable unused services and ports as a standing practice (rather than only reacting when scanned), minimizing what a reconnaissance scan can even discover.

### 3. Brute Force Playbook (SSH / RDP / FTP)
- **Immediate Action:**
  - Ban offending IP address immediately via Fail2ban / firewall.
  - Rotate passwords for targeted accounts and verify no successful unauthorized logins occurred.
  - Change default management listening ports (e.g., move SSH from 22 to non-standard port or require VPN).
  - Enforce mandatory MFA (TOTP / FIDO2) and public key authentication.
- **Proactive Hardening:** Enforce account lockout policies and strong password requirements organization-wide, and require VPN or bastion-host access for all administrative protocols rather than exposing them directly to the internet.

### 4. Botnet C2 Beaconing Playbook
- **Immediate Action:**
  - Identify infected internal host from destination IP / MAC address.
  - Isolate endpoint from network via EDR (Endpoint Detection and Response) or switch port shutdown.
  - Add C2 domain to internal DNS sinkhole (`0.0.0.0` or loopback).
  - Perform memory and disk forensic capture before re-imaging the host.
- **Proactive Hardening:** Enforce default-deny egress filtering so that even a successfully infected host cannot freely reach arbitrary external C2 infrastructure.

### 5. Web Application Attack Playbook (SQLi / XSS)
- **Immediate Action:**
  - Block malicious IP and user-agent string at the Web Application Firewall (WAF).
  - Review application audit logs to confirm if any SQL payload returned valid data or database errors.
  - Patch vulnerable endpoint with parameterized SQL queries and input validation.
- **Proactive Hardening:** Conduct regular code review and dependency scanning to catch injection-prone patterns before deployment, rather than relying solely on the WAF as a compensating control.

### 6. Infiltration / Lateral Movement Playbook
- **Immediate Action:**
  - Disable or reset credentials for any account observed authenticating to unusual internal hosts.
  - Segment or isolate the affected VLAN/subnet to prevent further pivoting while investigation continues.
  - Review internal authentication logs for the scope of accounts and hosts touched.
- **Proactive Hardening:** Apply Tiered Administration and network micro-segmentation (see `web_and_infiltration.md`) before an incident occurs, so that lateral movement paths are limited by design.

---

## Detection Considerations for Hardening Effectiveness

Hardening measures also influence what "normal" traffic looks like, which in turn affects anomaly detection tuning:
- Disabling unused services reduces the number of legitimate reasons for certain ports to show any traffic at all, making activity on those ports a stronger anomaly signal.
- Enforcing egress filtering means any traffic that does slip past should be rarer and more suspicious by default, improving the effective signal-to-noise ratio for C2/botnet detection.
- Consistent baseline configurations across similar hosts make behavioral deviations easier to spot, since fewer "normal" variations exist to obscure genuine anomalies.

---

## Machine Learning Perspective

*(General knowledge — how hardening interacts with ML-based detection.)*

- **Cleaner baselines improve model quality:** A well-hardened network typically produces more consistent "normal" traffic patterns, which can make it easier for anomaly-detection models to separate benign from malicious flows, since there is less natural variance in legitimate traffic to account for.
- **Reduced attack surface reduces alert volume:** Fewer open ports and services generally mean fewer avenues for attacks, which can reduce the volume of alerts a Random Forest or other classifier needs to triage, allowing SOC analysts to focus attention on genuinely suspicious activity.
- **Hardening does not replace detection:** Even a well-hardened network can be targeted by novel or zero-day techniques, so proactive hardening and ongoing ML-based monitoring are complementary rather than substitutes for one another.

---

## SOC Perspective

- Mitigation playbooks give analysts a consistent, pre-approved set of response actions for common attack categories, reducing decision time during a live incident.
- Analysts should verify that the chosen playbook actually matches the observed attack pattern before applying it — using the wrong playbook (e.g., treating a legitimate load spike as a DDoS) can cause unnecessary business disruption.
- Hardening recommendations arising from an incident (e.g., "disable SMBv1 domain-wide") should be tracked as follow-up action items during the post-incident review phase of the incident response lifecycle (see `incident_response.md`).

---

## Examples

- **DDoS Response:** Sustained SYN flood detected → immediate SYN cookie enablement and NFTables rate limiting applied → longer-term hardening ticket opened to negotiate a scrubbing contract with an upstream provider.
- **Recon Response:** Aggressive port sweep detected from a single external IP → temporary 24-hour block applied via iptables `recent` module → hardening review confirms several unused services were exposed and schedules their removal.
- **Brute Force Response:** Repeated failed SSH logins trigger a Fail2ban block → post-incident hardening enforces public-key-only SSH authentication organization-wide to prevent recurrence.

---

## Zero Trust Architecture Principles
1. **Never Trust, Always Verify:** Every access request is fully authenticated, authorized, and encrypted before granting access.
2. **Least Privilege Access:** Restrict user and service account privileges with Just-In-Time (JIT) and Just-Enough-Access (JEA) models.
3. **Assume Breach:** Design networks assuming attackers are already present inside the perimeter; enforce micro-segmentation and comprehensive flow telemetry monitoring via NetGuard AI.

### Additional Zero Trust Practices (General Knowledge)
4. **Micro-Segmentation by Default:** Treat every network segment, and ideally every workload, as its own perimeter requiring explicit authorization to communicate with any other segment.
5. **Continuous Verification:** Re-validate trust continuously (e.g., re-authenticating sessions, monitoring for behavioral drift) rather than granting indefinite trust after a single successful login.
6. **Comprehensive Logging & Telemetry:** Zero Trust depends on rich visibility into who is accessing what, from where, and how — without telemetry, "assume breach" cannot be operationalized into actual detection.

---

## Limitations

- **Hardening cannot eliminate all risk:** Even a well-hardened environment remains vulnerable to zero-day exploits, insider threats, and sophisticated social engineering that bypasses technical controls entirely.
- **Operational trade-offs:** Some hardening measures (strict firewall rules, mandatory MFA, service restrictions) can introduce friction for legitimate users or break dependent business processes if not carefully planned and communicated.
- **Playbooks are necessarily generic:** A predefined playbook captures common response patterns for a category of attack but may need adaptation for attacks that combine multiple techniques or that target unusual assets.
- **Zero Trust is a journey, not a single configuration change:** Implementing Zero Trust principles fully is a multi-year organizational effort involving identity, network, and application changes — it is rarely achieved through a single technical deployment.
- **Egress filtering and segmentation require accurate application mapping:** Overly aggressive default-deny policies can break legitimate business applications if the required destinations and ports were not correctly identified beforehand.

---

## Common Questions

**Q: What is the difference between hardening and mitigation?**
A: Hardening is the proactive, ongoing process of reducing a system's attack surface before any attack occurs (e.g., disabling unused services), while mitigation typically refers to the reactive actions taken to reduce the impact of a specific identified threat once it is detected.

**Q: What is defense-in-depth?**
A: Defense-in-depth is a security strategy that layers multiple independent controls (network, application, identity, endpoint) so that if an attacker bypasses one layer, other layers still provide protection.

**Q: What are the three Zero Trust principles listed for NetGuard AI's context?**
A: Never Trust, Always Verify; Least Privilege Access; and Assume Breach.

**Q: How does hardening help machine learning-based anomaly detection?**
A: A well-hardened network typically has more consistent, predictable "normal" traffic patterns, which can make it easier for anomaly-detection models to distinguish genuinely malicious flows from benign variance, and it reduces the overall attack surface generating alerts in the first place.

**Q: What is a mitigation playbook?**
A: A mitigation playbook is a predefined, step-by-step set of response actions tailored to a specific type of attack (such as DDoS, port scanning, or brute force), designed to speed up and standardize the SOC's reaction when that attack type is detected.

**Q: Why is egress filtering considered important for botnet/C2 defense?**
A: Default-deny egress filtering restricts what external destinations an internal host is allowed to reach, so that even if a host becomes infected, it is less able to freely communicate with arbitrary command-and-control infrastructure.

**Q: Does hardening remove the need for ongoing detection and monitoring?**
A: No. Hardening reduces attack surface and risk but does not eliminate it; novel or zero-day techniques can still succeed against a hardened environment, so ongoing detection and monitoring remain necessary alongside proactive hardening.

---

## Summary
Network hardening and attack-specific mitigation playbooks are complementary halves of a defensive strategy: hardening proactively shrinks the attack surface (disabling unused services, enforcing least privilege, applying Zero Trust principles) while playbooks provide fast, pre-approved reactive responses for specific attack categories such as DDoS, port scanning, brute force, botnet C2 beaconing, and web application attacks. Defense-in-depth across network, transport, application, identity, and endpoint layers ensures no single control failure results in full compromise. A well-hardened network also tends to produce cleaner, more consistent baseline traffic, which can improve the effectiveness of machine-learning-based anomaly detection by making genuine deviations easier to identify — but hardening and detection remain complementary, not substitutable, since even hardened environments can be targeted by novel techniques.
