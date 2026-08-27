# Brute Force & Credential Access Attacks

## Overview
Brute Force attacks (MITRE ATT&CK T1110) involve automated, systematic attempts to guess usernames and passwords to gain unauthorized access to accounts, services, or APIs.

Common targets include administrative interfaces (SSH port 22, RDP port 3389, FTP port 21, Telnet port 23, SMB port 445) and web authentication portals.

---

## Attack Varieties & Methodologies

### 1. Dictionary & Exhaustive Brute Force
- **Mechanism:** Iterating through extensive wordlists (e.g., `rockyou.txt`, `SecLists`) trying thousands of passwords against a specific known username (e.g., `root`, `administrator`, `admin`).
- **Tooling:** Hydra, Medusa, Ncrack, Patator.

### 2. Password Spraying (Low & Slow)
- **Mechanism:** Trying a single common password (e.g., `Spring2026!`, `Company@123`) against hundreds of distinct enterprise accounts before trying a second password.
- **Advantage to Attacker:** Evades account lockout thresholds and security alerts triggered by rapid consecutive failed attempts on a single account.

### 3. Credential Stuffing
- **Mechanism:** Replaying massive databases of leaked username/password combinations obtained from previous third-party breaches across diverse online services, exploiting widespread password reuse.

---

## Network Flow Signatures

### CICIDS-2017 & NSL-KDD Indicators
- **High Repetition on Single Port:** Hundreds of short TCP flows from a single source IP to port 22 (SSH), 21 (FTP), or 3389 (RDP).
- **Uniform Packet Sizes:** High concentration of small bidirectional packet exchanges with near-identical byte lengths corresponding to failed authentication responses (`Bwd Packet Length Mean` consistent).
- **Short Flow Inter-Arrival Time (IAT):** Very small `Flow IAT Mean` (< 50ms) during rapid brute force attacks.
- **NSL-KDD Features:** `srv_count` high, `same_srv_rate` high (1.0), `dst_host_srv_count` elevated.

---

## Defensive Mitigation & Hardening

### 1. Authentication Hardening
- **Multi-Factor Authentication (MFA):** Enforce FIDO2 / WebAuthn / TOTP across all external-facing services.
- **Disable Password Authentication:** Enforce public key authentication (ED25519) for SSH:
  ```sshd_config
  PasswordAuthentication no
  PubkeyAuthentication yes
  PermitRootLogin no
  ```

### 2. Automated Intrusion Prevention (Fail2ban / CrowdSec)
```ini
# /etc/fail2ban/jail.local
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 4
findtime = 600
bantime = 86400
```

### 3. Account Lockout Policies & CAPTCHA
- Enforce exponential backoff delays on authentication endpoints after consecutive failures.
- Implement progressive rate limiting and proof-of-work/CAPTCHA challenges on web login portals.
