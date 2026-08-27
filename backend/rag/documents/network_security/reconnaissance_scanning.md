# Port Scanning & Network Reconnaissance

## Overview
Reconnaissance is the initial phase of cyber attacks (MITRE ATT&CK T1595 / T1046). Adversaries probe targeted networks to discover live hosts, open ports, running network services, operating system versions, and potential vulnerabilities before launching targeted exploits.

Reconnaissance is often described as the "casing the building" phase of an attack: it does not itself compromise a system, but it produces the map an attacker needs to choose where and how to attack next.

---

## Definition

- **Reconnaissance:** The information-gathering phase in which an adversary discovers details about a target network — live hosts, open ports, running services, and software versions — without necessarily exploiting anything yet.
- **Port Scanning:** A specific reconnaissance technique that systematically probes a range of ports on one or more hosts to determine which are open, closed, or filtered.
- **Host Discovery:** The process of determining which IP addresses within a target range correspond to live, reachable hosts.
- **OS/Service Fingerprinting:** Techniques used to infer the operating system or specific software version running on a target based on subtle differences in how it responds to crafted probes.
- **Footprinting:** A broader term encompassing reconnaissance activities beyond just network scanning, including passive information gathering (WHOIS records, DNS records, public documents, social media).

**Alternative / related terminology:** network probing, network mapping, service enumeration, vulnerability scanning (when reconnaissance extends to identifying known vulnerabilities), pre-attack surveillance.

---

## Key Concepts

### Passive vs. Active Reconnaissance
- **Passive Reconnaissance:** Gathering information without directly interacting with the target's systems — e.g., WHOIS lookups, DNS record enumeration, reviewing public job postings or social media for technology hints. Passive recon generates no direct traffic to the target and is far harder to detect.
- **Active Reconnaissance:** Directly interacting with target systems — e.g., port scanning, banner grabbing, OS fingerprinting. Active recon generates network traffic that defenders can potentially observe and flag.

### Why Reconnaissance Matters to Defenders
Because reconnaissance precedes exploitation, detecting it early gives defenders a valuable opportunity to respond *before* damage occurs — blocking a scanning source, hardening exposed services, or increasing monitoring on a specific segment before an actual attack attempt arrives.

### Scan Scope and Intent
Reconnaissance can range from a single host being probed for open ports to internet-wide "mass scanning" campaigns (using tools capable of scanning millions of hosts) that are typically opportunistic rather than targeted at a specific organization. Distinguishing an opportunistic, broad internet scan from a targeted reconnaissance campaign against a specific organization is an important part of triage.

---

## Technical Details

## Port Scanning Techniques

### 1. TCP SYN (Stealth / Half-Open) Scan
- **Flag Pattern:** `SYN` -> `SYN-ACK` (Port Open) or `RST` (Port Closed).
- **Mechanism:** The scanner sends a `SYN` packet. If the target replies with `SYN-ACK`, the scanner immediately sends a `RST` (reset) packet instead of completing the 3-way handshake (`ACK`).
- **Characteristics:**
  - Fast and avoids full socket connection creation.
  - Generates high volume of uncompleted connection states.

### 2. TCP Connect() Scan
- **Flag Pattern:** `SYN` -> `SYN-ACK` -> `ACK` -> `RST` / `FIN`.
- **Mechanism:** Completes the standard 3-way handshake via the operating system's `connect()` API call.
- **Characteristics:**
  - Easy to detect in application logs (web servers, SSH daemons).
  - Used when the scanner lacks raw socket privileges (non-root users).

### 3. Stealth Flag Manipulation Scans
- **FIN Scan:** Sends packets with only the `FIN` flag set. RFC 793 states closed ports must return `RST`, while open ports drop the packet.
- **NULL Scan:** Sends packets with no flags set (`0x00`).
- **Xmas Scan:** Sends packets with `FIN`, `PSH`, and `URG` flags illuminated ("lit like a Christmas tree").
- **ACK Scan:** Sends `ACK` packets to map firewall rulesets and stateful filtering behavior rather than finding open ports.

### 4. UDP Port Scanning
- **Mechanism:** Sends empty UDP packets to destination ports. If an ICMP Type 3 Code 3 (*Destination Unreachable - Port Unreachable*) error is returned, the port is closed. If no reply is received, the port is inferred to be open or filtered.
- **Characteristics:** Very slow due to OS ICMP rate limiting (RFC 1812).

### 5. Host Discovery Techniques
- **ICMP Echo (Ping) Sweep:** Sending ICMP Echo Requests across a range of IPs to identify which hosts respond, though many networks now block ICMP at the perimeter, limiting this technique's reliability.
- **ARP Scanning:** On a local network segment, sending ARP requests for every possible host address is a highly reliable discovery method since ARP is required for local communication and is rarely filtered.
- **TCP/UDP Ping Sweeps:** Sending TCP SYN or ACK packets, or UDP packets, to commonly open ports (e.g., 80, 443) as an alternative to ICMP when ICMP is blocked.

### 6. Service & OS Fingerprinting
- **Banner Grabbing:** Connecting to an open port and reading the service's initial response banner (e.g., an SSH server announcing its version string), which can directly reveal software and version information.
- **TCP/IP Stack Fingerprinting:** Inferring the operating system by analyzing subtle differences in how a host's TCP/IP stack responds to unusual or malformed packets (e.g., initial TTL values, TCP window sizes, and specific flag-handling quirks that vary between operating systems).
- **Vulnerability Correlation:** Once a service and version are identified, an attacker (or defender running the same tools proactively) can cross-reference known vulnerability databases (e.g., CVE listings) for that specific version.

### Common Scanning Tools (General Knowledge)
Nmap is the most widely referenced general-purpose network scanning tool, supporting SYN scans, Connect scans, UDP scans, OS fingerprinting (`-O`), and service/version detection (`-sV`). Masscan is designed for very high-speed, internet-scale port scanning. These tools are dual-use: the same techniques are used defensively (asset discovery, vulnerability assessment) and offensively (attacker reconnaissance).

---

## Detection

- **Volume and breadth of destination ports:** A single source contacting an unusually large number of distinct ports on one or more hosts in a short time window is the clearest recon signature.
- **Incomplete handshake ratios:** A high ratio of SYN packets to completed connections (ACK) suggests SYN/stealth scanning rather than normal application traffic.
- **Sequential or patterned targeting:** Scans often proceed through IP ranges or port numbers in a sequential or otherwise systematic order, unlike the more random access patterns of typical user traffic.
- **Low interaction duration:** Because scanning tools do not exchange application-layer data (beyond the minimum needed to determine port state), scan-related flows tend to be extremely short in duration and small in size.
- **Timing consistency across many destinations:** Automated scanning tools often probe multiple destinations with very similar per-probe timing, unlike organic human-driven access patterns.

---

## Network Flow Indicators (CICIDS & NSL-KDD)
- **High Destination Port Variance:** Single source IP contacting hundreds of distinct destination ports (`Dst Port`).
- **Low Bytes Per Flow:** Flows consist of only 1 or 2 small packets (`Total Fwd Packets <= 2`, `Fwd Packet Length Mean < 60 bytes`).
- **High RST and SYN Flag Ratios:** Abnormal ratios of `RST Flag Count` and `SYN Flag Count` relative to `ACK Flag Count`.
- **NSL-KDD Flags:** Dominated by `REJ` (rejected connection) or `RSTO` / `RSTR` (connection reset by originator/responder).
- **Short Flow Duration:** `Flow Duration` values clustered near the minimum observable value, since scan probes rarely maintain an open connection.
- **High `count` / `srv_count` (NSL-KDD):** Elevated counts of connections to the same host and to the same service within a short time window are classic Probe-category indicators in NSL-KDD.

---

## Machine Learning Perspective

*(General knowledge — how ML systems can approach recon/scan detection conceptually.)*

- **Strong feature separability:** Reconnaissance and scanning traffic tends to be one of the more separable attack categories for flow-based ML models, because features like destination port variance, flag ratios, and flow duration differ sharply from typical benign traffic.
- **NSL-KDD "Probe" category:** NSL-KDD explicitly labels reconnaissance-style traffic under the Probe attack category, making it a natural class for supervised classification alongside DoS, R2L, and U2R.
- **Random Forest suitability:** Because scan detection often reduces to threshold-like decision boundaries on a handful of strongly discriminative features (destination port count, flag ratios, packet size), tree-based models such as Random Forest tend to perform well and offer interpretable feature importance for these categories.
- **False positive sources:** Legitimate vulnerability scanning (authorized penetration testing, internal asset discovery tools) can closely resemble malicious reconnaissance at the flow level, so models and analysts benefit from knowing about scheduled/authorized scanning windows to avoid false alarms.
- **Confidence interpretation:** Because recon traffic is often strongly separable, high-confidence classifications are common for clear scan patterns, while borderline confidence scores may indicate a low-and-slow scan deliberately designed to blend in with normal traffic volume.

---

## SOC Perspective

1. **Confirm scan scope:** Determine whether the source is targeting a single host, a subnet, or scanning broadly and opportunistically (potentially indiscriminate internet-wide scanning unrelated to a targeted campaign).
2. **Check for authorized activity:** Cross-reference with any scheduled penetration testing, red team exercises, or internal vulnerability management scans before treating the activity as hostile.
3. **Assess exposed findings:** If the scan appears successful (i.e., it likely identified open ports/services), prioritize hardening or verifying the exposed services rather than only blocking the source, since the same information could be rediscovered by another scanner.
4. **Watch for escalation:** Reconnaissance is frequently followed by a targeted exploitation attempt against a service identified during scanning; sustained monitoring of the previously-scanned host after the scan itself is good practice.
5. **Threat intelligence correlation:** Check whether the scanning source IP is a known, previously observed scanning infrastructure (e.g., associated with mass internet scanning services) versus a novel or suspicious origin.

---

## Examples

- **Fast SYN Scan:** A single external IP sends SYN packets to 500 different ports on one internal host within 10 seconds, receiving mostly RST responses with a handful of SYN-ACKs — consistent with an automated SYN scan enumerating open services.
- **Slow, Distributed Scan ("Low and Slow"):** Multiple source IPs each probe a small number of ports on a target over several hours, deliberately staying below common per-source alerting thresholds — a technique intended to evade simple rate-based detection.
- **UDP Service Enumeration:** A source sends single UDP packets to ports 53, 123, 161, and 500 sequentially, consistent with probing for DNS, NTP, SNMP, and IKE/VPN services respectively.
- **Authorized Internal Scan:** A vulnerability management platform performs a full port sweep of internal subnets on a documented weekly schedule — flagged by NetGuard AI as anomalous by pattern, but resolved as a false positive once cross-referenced against the scheduled maintenance window.

---

## Defensive Mitigation & SOC Countermeasures

### 1. Firewall & Port Knocking Defenses
- Block unused inbound ports at perimeter firewalls.
- Implement Port Knocking (e.g., `knockd`) or Single Packet Authorization (SPA / `fwknop`) for administrative interfaces (SSH, RDP).

### 2. Rate-Limiting Connection Attempts
```bash
# Drop IPs attempting more than 20 new TCP connections in 10 seconds
iptables -I INPUT -p tcp --dport 22 -m state --state NEW -m recent --set
iptables -I INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 10 --hitcount 20 -j DROP
```

### 3. IDS/IPS Detection Signatures (Snort / Suricata)
```suricata
# Detect Rapid Port Sweep
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"SCAN Potential Port Sweep Detected"; flags:S; threshold:type both, track by_src, count 25, seconds 5; classtype:attempted-recon; sid:1000001; rev:1;)
```

### 4. Deception & Honeypots
- Deploy low-interaction honeypots (Cowrie, OpenCanary) to detect scanners early and automatically ban source IPs.

### 5. Reducing Fingerprinting Surface
- Suppress or standardize service banners so that banner grabbing yields minimal version information to an external scanner.
- Disable or restrict ICMP Timestamp and Address Mask replies to limit OS/network fingerprinting opportunities.

---

## Limitations

- **Low-and-slow evasion:** Distributing scan probes over long time periods or across many source IPs can evade simple rate- or threshold-based detection rules.
- **Ambiguity with legitimate scanning:** Authorized vulnerability scans, uptime monitoring, and research/academic internet-wide scanning projects can closely resemble malicious reconnaissance at the network-flow level, requiring contextual whitelisting rather than blanket blocking.
- **Encrypted/obfuscated scan traffic:** Some advanced scanning techniques attempt to blend in with legitimate application traffic patterns, reducing the reliability of simple flag-ratio or port-variance heuristics.
- **Detecting recon does not prevent the underlying vulnerability:** Blocking a scanning source addresses the immediate probe but does not remediate whatever vulnerable or exposed service the scan might have found — hardening the discovered exposure is still necessary.
- **Dataset scope:** Benchmark datasets like CICIDS-2017 and NSL-KDD capture the scanning tool behaviors present at the time of collection and may not reflect newer scanning techniques or evasion strategies.

---

## Common Questions

**Q: What is network reconnaissance?**
A: Network reconnaissance is the information-gathering phase of an attack, in which an adversary discovers live hosts, open ports, running services, and software versions on a target network, typically before attempting exploitation.

**Q: What is the difference between passive and active reconnaissance?**
A: Passive reconnaissance gathers information without directly interacting with the target (e.g., WHOIS or DNS lookups), while active reconnaissance involves direct interaction such as port scanning, which generates observable network traffic.

**Q: What is a SYN scan and why is it called a "stealth" scan?**
A: A SYN scan sends a SYN packet and, upon receiving a SYN-ACK, immediately sends a RST instead of completing the handshake — it is called "stealth" because it avoids creating a full logged connection at the application layer, unlike a full TCP Connect() scan.

**Q: What network flow features most strongly indicate port scanning?**
A: High variance in destination ports contacted by a single source, very low bytes and packets per flow, short flow durations, and abnormal ratios of SYN/RST flags relative to completed ACK handshakes.

**Q: What is the NSL-KDD "Probe" attack category?**
A: Probe is one of the four NSL-KDD attack categories (alongside DoS, R2L, and U2R), representing reconnaissance and scanning activity such as port scans and network mapping.

**Q: Why can reconnaissance detection be difficult in practice?**
A: Because legitimate activities such as authorized vulnerability scans, uptime monitors, and even some research internet-scanning projects can produce network flow patterns very similar to malicious reconnaissance, requiring analysts to check for authorized scanning windows before concluding an alert is malicious.

**Q: Why is Random Forest often effective for detecting scanning traffic?**
A: Scanning traffic tends to differ sharply from normal traffic on a small set of strongly discriminative features (destination port variance, flag ratios, flow duration), which tree-based models like Random Forest can separate effectively using simple, interpretable decision thresholds.

**Q: What is a "low and slow" scan?**
A: A low-and-slow scan spreads probing activity over a long time period or across multiple source IPs, deliberately staying below common rate-based detection thresholds to evade simple volumetric alerting.

---

## Summary
Reconnaissance and port scanning represent the information-gathering phase that typically precedes exploitation, ranging from passive footprinting to active techniques like SYN, Connect(), stealth flag-manipulation, and UDP scans, along with host discovery and OS/service fingerprinting. These activities tend to produce strongly distinctive network flow signatures — high destination-port variance, low bytes-per-flow, short flow durations, and abnormal SYN/RST-to-ACK ratios — that map well onto NSL-KDD's Probe category and make scanning one of the more reliably separable classes for machine-learning models such as Random Forest. Effective defense combines perimeter firewall discipline, rate-limiting, IDS/IPS signatures, honeypots, and reduced fingerprinting surface, while SOC analysts must carefully distinguish malicious reconnaissance from authorized vulnerability scanning or benign internet-wide research scans before escalating a response.
