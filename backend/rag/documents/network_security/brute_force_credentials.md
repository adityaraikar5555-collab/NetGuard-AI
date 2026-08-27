# Brute Force & Credential Access Attacks

> **Scope note (how to read this document):** This file covers brute-force and credential-access attacks as **general network security knowledge** — attack mechanics, network indicators, and defensive practices widely documented in the cybersecurity field, including specific tool names and configuration examples. Where this document references NetGuard AI specifically (e.g., dataset labels used in training), those statements are limited to what is actually documented in the project's dataset guides (CICIDS-2017 and NSL-KDD). NetGuard AI's documented capability is classifying flows/connections as benign or brute-force/credential-access activity with a confidence score — it does not claim to automatically ban IPs, enforce MFA, or configure authentication systems unless explicitly documented elsewhere.

---

## Overview

**Brute Force attacks** (MITRE ATT&CK **T1110 – Brute Force**) involve automated, systematic attempts to guess usernames and passwords in order to gain unauthorized access to accounts, services, or APIs. Unlike attacks that exploit a software vulnerability, brute-force attacks exploit **weak, reused, or guessable credentials** — the "vulnerability" is fundamentally a human/policy weakness rather than a code defect.

Common targets include administrative interfaces (SSH port 22, RDP port 3389, FTP port 21, Telnet port 23, SMB port 445) and web authentication portals (login forms, API authentication endpoints, VPN gateways, email/webmail logins).

Common synonyms and related terms:
- "Brute force attack", "credential guessing", "password guessing"
- "credential access" (the broader MITRE ATT&CK tactic category T1110 falls under)
- "password spraying", "credential stuffing" (specific sub-techniques, detailed below)
- "authentication attack"

---

## Definition

A **brute-force attack** is any method of gaining unauthorized access by systematically trying many possible credential combinations (usernames, passwords, or both) until a valid combination is found, rather than exploiting a specific software flaw. It relies on the target failing to sufficiently limit, delay, detect, or lock out repeated failed authentication attempts.

Brute-force techniques differ mainly in **how the guessing is distributed** — across passwords, across accounts, or across both — which materially changes their detection signature, as described below.

---

## Key Concepts

### Why brute force remains effective despite being "unsophisticated"
Brute-force attacks require no software vulnerability and no advanced exploit development — only patience, automation, and (often) leaked credential data. They remain highly effective because:
- Many users reuse the same password across multiple services, making credentials leaked from one breach useful against entirely unrelated systems (credential stuffing).
- Many organizations lack consistent account lockout, rate limiting, or MFA enforcement on every external-facing authentication endpoint.
- Automation tooling for brute forcing is mature, freely available, and easy to configure at scale.

### MITRE ATT&CK sub-techniques (context)
T1110 (Brute Force) is commonly broken into sub-techniques reflecting the varieties described below:
- **T1110.001 – Password Guessing:** Manually or automatically trying passwords one at a time against a known account.
- **T1110.002 – Password Cracking:** Attempting to recover plaintext passwords from a captured password hash offline (distinct from an online guessing attack against a live service, but often discussed alongside brute force).
- **T1110.003 – Password Spraying:** Trying one (or a few) common password(s) across many accounts before moving to the next password.
- **T1110.004 – Credential Stuffing:** Replaying previously leaked username/password pairs against a new target service.

### Online vs. offline brute force
- **Online brute force:** The attacker interacts directly with the live authentication service (e.g., an SSH daemon, a web login form), guessing credentials one attempt at a time. This is what generates network flow evidence and is the primary focus of this document.
- **Offline brute force / password cracking:** The attacker has already obtained a password hash (e.g., from a stolen database) and attempts to recover the plaintext password using computational guessing (dictionary attacks, rainbow tables, GPU-accelerated brute forcing) without ever contacting the target service — this produces no network traffic at all and is therefore invisible to a network-based IDS like NetGuard AI; it is a host/data-security concern rather than a network detection concern.

---

## Attack Varieties & Methodologies

### 1. Dictionary & Exhaustive Brute Force
- **Mechanism:** Iterating through extensive wordlists (e.g., `rockyou.txt`, `SecLists`) trying thousands of passwords against a specific, known (or guessed) username (e.g., `root`, `administrator`, `admin`).
- **Exhaustive variant:** Rather than a curated wordlist, systematically trying every possible character combination up to a given length — far slower but guaranteed to eventually succeed against a password of that length if no rate limiting is in place; generally impractical against long, high-entropy passwords without offline hash access.
- **Tooling:** Hydra, Medusa, Ncrack, Patator (the tool referenced in CICIDS-2017's `FTP-Patator` and `SSH-Patator` attack labels).
- **Detection profile:** Highly repetitive connections to a single account/service from one source, in rapid succession — the most "obvious" and easily detected brute-force variant.

### 2. Password Spraying (Low & Slow)
- **Mechanism:** Trying a single common password (e.g., a seasonal password like `Spring2026!` or a company-themed password like `Company@123`) against hundreds or thousands of distinct enterprise accounts, before trying a second password against the same broad set of accounts.
- **Advantage to Attacker:** Evades account lockout thresholds and security alerts that are triggered by rapid, consecutive failed attempts **on a single account**, since each individual account only receives one (or a few) attempt(s) per password round — the attack volume is spread across many accounts rather than concentrated on one.
- **Detection profile:** Requires looking across many accounts/destinations for a shared pattern (same password attempted broadly) rather than looking at any single account's failure count in isolation — often invisible to naive per-account lockout policies.

### 3. Credential Stuffing
- **Mechanism:** Replaying massive databases of leaked username/password combinations — obtained from previous, unrelated third-party data breaches — across diverse online services, exploiting widespread password reuse across accounts.
- **Detection profile:** Often characterized by a high volume of login attempts using already-plausible (previously real, breached) username/password pairs rather than randomly generated guesses, and frequently distributed across many source IPs (sometimes via botnets or proxy/VPN rotation) to evade simple IP-based rate limiting.
- **Relationship to data breaches:** Credential stuffing is fundamentally downstream of prior data breaches elsewhere on the Internet — it highlights why password reuse across services is a significant systemic risk even for organizations that have never themselves been breached.

### 4. Comparison of brute-force sub-techniques

| Technique | Password Space | Account Space | Detection Difficulty | Typical Defeat |
| :--- | :--- | :--- | :--- | :--- |
| Dictionary/Exhaustive | Many passwords | One account | Low (obvious repetition) | Account lockout, rate limiting |
| Password Spraying | Few passwords | Many accounts | Medium–High (spread thin) | Cross-account correlation, MFA |
| Credential Stuffing | Many known-real pairs | Many accounts | Medium (distributed sources) | MFA, breach-credential monitoring |

---

## Detection

Detection of brute-force activity generally relies on identifying repetitive, automated authentication patterns that a normal human user would not produce:

- **Threshold-based detection (general knowledge):** Alerting when a single source (or a single account) exceeds a defined number of failed login attempts within a time window — simple and effective against classic dictionary attacks but easily evaded by low-and-slow password spraying.
- **Cross-account correlation:** Looking for the same password (or a small set of passwords) being attempted across many different accounts in a short window — necessary to catch password spraying, since no single account's failure count looks unusual in isolation.
- **Credential-plausibility signals:** Recognizing that credential stuffing attempts often use real (previously breached), plausible-looking username/password pairs rather than randomly generated guesses — while this isn't directly visible at the network-flow level, correlating with known-breach credential-monitoring services is a common complementary defense.
- **Statistical/ML-based detection:** Training a classifier on flow features (e.g., Random Forest on CICIDS-2017's `FTP-Patator`, `SSH-Patator`, and `Web Attack – Brute Force` labels, or NSL-KDD's R2L family attacks like `guess_passwd`) to recognize the combined statistical signature of automated credential guessing — short, repetitive, uniform-sized connections to authentication ports/services — rather than relying on a single hard-coded failure-count threshold. **NetGuard AI** applies this approach using both datasets' brute-force-labeled data.

---

## Network Flow Signatures

### CICIDS-2017 & NSL-KDD Indicators
- **High Repetition on Single Port:** Hundreds of short TCP flows from a single source IP to port 22 (SSH), 21 (FTP), or 3389 (RDP).
- **Uniform Packet Sizes:** A high concentration of small, bidirectional packet exchanges with near-identical byte lengths, corresponding to repeated failed-authentication response patterns (`Bwd Packet Length Mean` remaining consistent across many flows).
- **Short Flow Inter-Arrival Time (IAT):** Very small `Flow IAT Mean` (often under 50ms) during rapid, automated brute-force attempts, reflecting scripted/tool-driven timing rather than human typing speed.
- **NSL-KDD Features:** `srv_count` high (many connections to the same service in the 2-second window), `same_srv_rate` high (close to 1.0, indicating focused targeting of one service rather than a broad scan), `dst_host_srv_count` elevated (sustained targeting of the same host/service over the longer 100-connection window). The content feature `num_failed_logins` is also directly relevant when session-level detail is available, since it explicitly counts failed authentication attempts within a connection.

### Distinguishing brute force from port scanning
Brute-force traffic and port-scanning traffic can look superficially similar (many short flows from one source), but differ in an important way: brute-force traffic is **highly focused on a single service/port** (`same_srv_rate` near 1.0) with repeated, similar-sized authentication exchanges, whereas scanning traffic spreads across **many different ports/services** (`diff_srv_rate` high) with minimal or no actual protocol-level exchange beyond the initial handshake.

---

## Machine Learning Perspective

### Dataset representation
- **CICIDS-2017:** Brute-force activity is represented by `FTP-Patator` and `SSH-Patator` (automated credential guessing over FTP and SSH respectively, using the Patator tool, captured on Tuesday), as well as `Web Attack – Brute Force` (HTTP form authentication guessing, captured Thursday morning).
- **NSL-KDD:** Brute-force/credential-guessing activity falls primarily under the **R2L (Remote to Local)** family, with `guess_passwd` as the most directly relevant specific attack, alongside other R2L attacks that involve unauthorized remote access attempts more broadly (e.g., `ftp_write`, `multihop`, `warezmaster`).

### Feature importance for brute-force detection
Because brute-force attacks are characterized by **repetition against a single, consistent target (service/port)** with **uniform, small packet exchanges**, the most discriminative features tend to include: same-service concentration (`same_srv_rate`, `srv_count`), short and consistent flow inter-arrival timing, and small/uniform packet-length statistics — reflecting the mechanical regularity of automated tooling versus the more variable behavior of a real human logging in.

### Class imbalance considerations
Brute-force attacks (particularly `FTP-Patator`/`SSH-Patator` in CICIDS-2017) generate a substantial number of short flow records relative to rarer classes, making them reasonably well represented for training. However, R2L attacks as a broader family in NSL-KDD (including `guess_passwd`) are comparatively underrepresented relative to DoS/Probe, which is a documented class-imbalance concern for NSL-KDD-trained R2L detection generally (see the NSL-KDD guide for detail).

### Confidence interpretation
Fast, high-repetition dictionary-style brute-force attacks tend to produce **high-confidence classifications**, given their very distinctive, mechanically regular statistical signature (uniform packet sizes, tight timing, single-service focus). **Password-spraying attacks** are more likely to produce lower-confidence or harder-to-detect predictions at the individual-flow level, since each single flow (one password attempt against one account) may not look statistically unusual in isolation — the anomalous pattern only becomes clear when correlating across many accounts, which is a detection design challenge more than a single-flow classification challenge. See the severity and confidence guide for the general confidence-tier interpretation framework NetGuard AI applies.

---

## SOC Perspective

### Investigation priorities
- **Confirm success vs. failure:** The single most important question for a brute-force alert is whether any attempt actually succeeded. A sustained brute-force attempt with **zero successful logins** is concerning but lower urgency than one where **`logged_in` transitions to a successful state** at some point — the latter represents an active, confirmed compromise requiring immediate incident-response action (see the incident response guide).
- **Check for lateral use of compromised credentials:** If a brute-force attempt succeeds, investigate immediately whether the compromised account was used to access additional systems, escalate privileges, or move laterally, since credential compromise is frequently just the first step of a larger intrusion.
- **Distinguish targeted vs. opportunistic attacks:** Brute-force attempts against generic/default accounts (`admin`, `root`, `administrator`) from many different source IPs are common, low-sophistication, largely automated background noise across the Internet; a sustained, adaptive attack against a specific, non-obvious account name may indicate more deliberate, targeted reconnaissance of the organization beforehand.
- **Correlate with prior reconnaissance:** Brute-force attempts frequently follow port-scanning/reconnaissance activity that first identified an open, exposed authentication service — reviewing recent scan activity from the same source can help establish the broader attack timeline (see the reconnaissance guide for detail).

### Severity considerations
Per NetGuard AI's documented severity matrix (see the severity and confidence guide), persistent SSH/FTP brute-force activity is generally categorized at the **High** severity tier, while an isolated, single failed-login burst is generally categorized at the **Medium** tier — reflecting the difference between a sustained, likely-intentional attack and a single anomalous event that could plausibly be a legitimate user mistyping a password.

---

## Examples

**Example 1 — Classic SSH dictionary attack:**
A single source IP generates hundreds of short flows to port 22 on a target host within a few minutes, each flow showing near-identical packet sizes and rapid, consistent timing (`Flow IAT Mean` very low), consistent with an automated tool like Hydra or Patator cycling through a password wordlist against a fixed username. This matches the `SSH-Patator` label in CICIDS-2017.

**Example 2 — Password spraying against enterprise accounts:**
Over the course of several hours, a single source IP (or a small rotating set of IPs) attempts the same password against hundreds of distinct usernames on an organization's web-based authentication portal, with only one or two attempts per account — evading any lockout policy that triggers only after several failures on the same account.

**Example 3 — Credential stuffing following a third-party breach:**
Shortly after a large, unrelated online service discloses a data breach, an organization observes a spike in login attempts using username/password combinations that match previously breached credentials from that unrelated service — reflecting attackers testing whether users reused the same password on this organization's systems.

**Example 4 — Legitimate user lockout (a false-positive-risk case):**
A real employee mistypes their password several times in a row while trying to log in, generating a small burst of failed-login flow records that could superficially resemble the very early stage of a brute-force attempt. Distinguishing this from a genuine attack typically depends on volume, timing regularity, and whether the failures are followed by a normal successful login from the same, consistent client shortly afterward.

---

## Mitigation

### 1. Authentication Hardening
- **Multi-Factor Authentication (MFA):** Enforcing FIDO2/WebAuthn/TOTP-based multi-factor authentication across external-facing services significantly reduces the practical impact of brute force, since knowing (or guessing) the password alone is no longer sufficient to gain access.
- **Disable Password Authentication where possible:** For services like SSH, enforcing public-key authentication (e.g., Ed25519 keys) instead of passwords eliminates the brute-forceable password entirely:
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
This example configuration bans a source IP for 86,400 seconds (24 hours) after 4 failed SSH login attempts within a 600-second (10-minute) window — a widely used, general-purpose brute-force mitigation pattern (Fail2ban and similar tools like CrowdSec implement this kind of automated, host-level banning independently of any specific project referenced in this knowledge base).

### 3. Account Lockout Policies & CAPTCHA
- Enforce exponential backoff delays on authentication endpoints after consecutive failures, increasing the time cost of each subsequent guess.
- Implement progressive rate limiting and proof-of-work/CAPTCHA challenges on web login portals to slow down or block automated tooling while minimizing friction for genuine users.

### 4. Credential hygiene and monitoring
- Enforce strong, unique password policies and discourage password reuse (general best practice, though enforcement mechanisms vary by organization).
- Monitor for organizational credentials appearing in known public breach-data repositories, allowing proactive password resets before attackers can exploit reused credentials via credential stuffing.

These are general, widely documented mitigation practices; **NetGuard AI's own documented role is classifying flows/connections as benign or brute-force/credential-access activity with a confidence score**, not automated MFA enforcement, IP banning, or authentication configuration changes, unless a specific project component documents that capability.

---

## Limitations

- **Offline password cracking is invisible to network detection:** Once an attacker has obtained a password hash through some other means (e.g., a database breach), offline cracking generates no network traffic at all and cannot be detected by a network-flow-based system like NetGuard AI.
- **Password spraying is harder to detect at the single-flow level:** Because each individual attempt against each individual account may look unremarkable, effective detection typically requires correlating attempts across many accounts/destinations over time — a capability that depends on broader log aggregation and analytics, not solely on classifying one flow at a time.
- **Legitimate failed logins create false-positive risk:** Ordinary user error (mistyped passwords, expired credentials, forgotten passwords) generates flow patterns that can resemble the very early stages of a brute-force attempt, particularly in isolation without broader context (volume, timing regularity, success/failure pattern).
- **Credential stuffing detection benefits from external threat intelligence:** Recognizing that a set of attempted credentials matches a known public breach generally requires external breach-data monitoring rather than network flow analysis alone.
- **No production performance figures are asserted here** — this document does not claim any specific detection accuracy, false-positive rate, or response latency for NetGuard AI's brute-force classification in a live deployment.

---

## Common Questions

**Q: What is a brute-force attack?**
A: It is an automated, systematic attempt to guess valid usernames and passwords in order to gain unauthorized access to an account, service, or API — corresponding to MITRE ATT&CK technique T1110.

**Q: What is the difference between a dictionary attack and password spraying?**
A: A dictionary attack tries many passwords against one (or a small number of) known account(s), which produces an obvious, easily detected repetitive pattern. Password spraying instead tries one common password across many different accounts before trying the next password, which spreads the attempt volume thin enough to often evade single-account lockout policies and simple failure-count alerting.

**Q: What is credential stuffing?**
A: It is the practice of replaying username/password combinations leaked from a previous, unrelated data breach against a new target service, exploiting the fact that many users reuse the same password across multiple online accounts.

**Q: How can network flow features distinguish brute force from a port scan?**
A: Brute-force traffic is tightly focused on a single service/port (high `same_srv_rate`, close to 1.0) with repeated, similarly sized authentication exchanges, while port-scanning traffic spreads across many different ports/services (`diff_srv_rate` high) and typically involves minimal or no actual protocol exchange beyond an initial handshake.

**Q: Which CICIDS-2017 labels represent brute-force attacks?**
A: `FTP-Patator`, `SSH-Patator`, and `Web Attack – Brute Force` are the CICIDS-2017 labels directly representing brute-force/credential-guessing activity.

**Q: Which NSL-KDD attack category do brute-force attacks fall under?**
A: They fall primarily under the **R2L (Remote to Local)** family, with `guess_passwd` being the most directly relevant specific attack.

**Q: Why is offline password cracking invisible to network-based intrusion detection?**
A: Because offline cracking is performed entirely on hardware the attacker already controls, using a stolen password hash, without ever sending guess attempts across the network to the target service — meaning there is no network flow evidence for a system like NetGuard AI to observe or classify.

**Q: Why does confirming whether a brute-force attempt succeeded matter so much for SOC response?**
A: Because a sustained brute-force attempt with zero successful logins, while concerning, represents an unsuccessful attack attempt, whereas a successful login following repeated failures indicates an actual account compromise, requiring immediate incident-response actions such as credential reset, session termination, and investigation of any subsequent activity by the compromised account.

**Q: Can multi-factor authentication (MFA) fully stop brute-force attacks?**
A: MFA significantly reduces the practical risk of brute force, since guessing (or even correctly guessing) the password alone is no longer sufficient to gain access — an attacker would additionally need to compromise or bypass the second authentication factor. However, MFA does not prevent brute-force attempts from occurring or being logged; it primarily prevents them from succeeding.

**Q: Does NetGuard AI automatically ban IPs after detecting brute-force activity?**
A: No — that capability is not documented as part of the project. NetGuard AI's documented function is classifying flows/connections as benign or brute-force/credential-access activity with a confidence score, surfaced through its dashboard and RAG assistant; automated IP banning (e.g., via tools like Fail2ban) is a separate, general-purpose defensive technique that organizations may configure independently.

---

## Summary

Brute-force and credential-access attacks systematically guess usernames and passwords to gain unauthorized access, exploiting weak or reused credentials rather than a software vulnerability. Key varieties — dictionary/exhaustive guessing, password spraying, and credential stuffing — differ mainly in how guessing effort is distributed across passwords versus accounts, which materially changes both their real-world effectiveness against lockout policies and their network detection signature. These attacks are represented in CICIDS-2017 (`FTP-Patator`, `SSH-Patator`, `Web Attack – Brute Force`) and NSL-KDD's R2L family (`guess_passwd` and related attacks), giving NetGuard AI's Random Forest classifier labeled examples of the characteristic repetitive, single-service-focused, uniformly timed flow pattern these attacks produce. Because password spraying and credential stuffing are harder to detect at the level of any single flow, effective SOC handling generally depends on cross-account correlation and confirming whether any attempt actually succeeded, in addition to whatever automated classification a network-flow-based detection system provides.
