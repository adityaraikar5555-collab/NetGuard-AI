# Network Hardening, Defensive Configuration & Mitigation Playbooks

## Overview
Proactive network hardening reduces the attack surface and enforces Zero Trust security principles across all layers of the OSI model. When threats are identified by NetGuard AI, these mitigation playbooks provide verified technical countermeasures.

---

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

### 3. Brute Force Playbook (SSH / RDP / FTP)
- **Immediate Action:**
  - Ban offending IP address immediately via Fail2ban / firewall.
  - Rotate passwords for targeted accounts and verify no successful unauthorized logins occurred.
  - Change default management listening ports (e.g., move SSH from 22 to non-standard port or require VPN).
  - Enforce mandatory MFA (TOTP / FIDO2) and public key authentication.

### 4. Botnet C2 Beaconing Playbook
- **Immediate Action:**
  - Identify infected internal host from destination IP / MAC address.
  - Isolate endpoint from network via EDR (Endpoint Detection and Response) or switch port shutdown.
  - Add C2 domain to internal DNS sinkhole (`0.0.0.0` or loopback).
  - Perform memory and disk forensic capture before re-imaging the host.

### 5. Web Application Attack Playbook (SQLi / XSS)
- **Immediate Action:**
  - Block malicious IP and user-agent string at the Web Application Firewall (WAF).
  - Review application audit logs to confirm if any SQL payload returned valid data or database errors.
  - Patch vulnerable endpoint with parameterized SQL queries and input validation.

---

## Zero Trust Architecture Principles
1. **Never Trust, Always Verify:** Every access request is fully authenticated, authorized, and encrypted before granting access.
2. **Least Privilege Access:** Restrict user and service account privileges with Just-In-Time (JIT) and Just-Enough-Access (JEA) models.
3. **Assume Breach:** Design networks assuming attackers are already present inside the perimeter; enforce micro-segmentation and comprehensive flow telemetry monitoring via NetGuard AI.
