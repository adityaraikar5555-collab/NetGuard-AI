# Port Scanning & Network Reconnaissance

## Overview
Reconnaissance is the initial phase of cyber attacks (MITRE ATT&CK T1595 / T1046). Adversaries probe targeted networks to discover live hosts, open ports, running network services, operating system versions, and potential vulnerabilities before launching targeted exploits.

---

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

---

## Network Flow Indicators (CICIDS & NSL-KDD)
- **High Destination Port Variance:** Single source IP contacting hundreds of distinct destination ports (`Dst Port`).
- **Low Bytes Per Flow:** Flows consist of only 1 or 2 small packets (`Total Fwd Packets <= 2`, `Fwd Packet Length Mean < 60 bytes`).
- **High RST and SYN Flag Ratios:** Abnormal ratios of `RST Flag Count` and `SYN Flag Count` relative to `ACK Flag Count`.
- **NSL-KDD Flags:** Dominated by `REJ` (rejected connection) or `RSTO` / `RSTR` (connection reset by originator/responder).

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
