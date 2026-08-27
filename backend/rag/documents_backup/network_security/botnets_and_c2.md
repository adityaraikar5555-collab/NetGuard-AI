# Botnets, Malware Traffic & Command and Control (C2)

## Overview
A Botnet is a network of compromised internet-connected devices (IoT cameras, servers, routers, endpoints) infected with malware and controlled collectively by a threat actor (Botmaster).

Command and Control (C2 / C&C) infrastructure (MITRE ATT&CK T1071) provides the communication channel through which the attacker issues operational directives (e.g., launching DDoS floods, downloading secondary ransomware payloads, exfiltrating stolen data).

---

## C2 Architecture & Communication Patterns

### 1. Centralized C2 (IRC / HTTP / HTTPS)
- **Mechanism:** Compromised bots periodically connect to a centralized domain or IP address using standard protocols.
- **Beaconing:** Periodic "heartbeat" requests sent at regular or jittered intervals (e.g., every 30 seconds ± 10% jitter) to poll for new instructions.
- **Example Malware:** Mirai, Zeus, Emotet, TrickBot, Cobalt Strike.

### 2. Peer-to-Peer (P2P) Botnets
- **Mechanism:** Bots communicate directly with each other without a single point of failure. Nodes maintain neighbor routing tables (e.g., Kademlia DHT algorithms).
- **Example Malware:** Storm, Sality, Necurs, Joanap.

### 3. Covert Channels & Tunneling
- **DNS Tunneling (T1071.004):** Encoding commands or exfiltrated data into DNS queries/responses (e.g., base64 subdomains: `data123.c2domain.com` requesting `TXT` records).
- **ICMP Tunneling:** Embedding payload bytes inside ICMP Echo request/reply data fields.
- **Domain Generation Algorithms (DGA):** Generating hundreds of pseudo-random domain names daily based on seed dates to evade static IP/domain blocklists.

---

## Network Flow Signatures & Indicators

### Behavioral Indicators (CICIDS & NSL-KDD)
- **Periodic Beaconing Rhythms:** Low variance in `Flow IAT Mean` and `Flow IAT Std` across multiple distinct connections to external IP addresses.
- **Anomalous Outbound Data Ratios:** High `Fwd Packet Length` relative to `Bwd Packet Length` during data exfiltration phases.
- **DNS Query Anomalies:** High volume of NXDOMAIN responses (from DGA lookups) and unusually long DNS query strings (> 60 characters).
- **Unusual Ports / Protocols:** TLS traffic on non-standard ports (e.g., 4444, 8443) or plaintext IRC on ports 6667.

---

## Defensive Mitigation Strategies

### 1. DNS Security & Sinkholing
- Route all enterprise DNS queries through protective DNS resolvers (e.g., Quad9, Cloudflare 1.1.1.2) with automatic DGA and threat intelligence blocklists.
- Deploy RPZ (Response Policy Zones) to sinkhole known malicious C2 domains to internal analysis servers (`127.0.0.1` or honeynet).

### 2. TLS/SSL Inspection & JA3/JA3S Fingerprinting
- Inspect TLS Client Hello packets using JA3 cryptographic fingerprinting to identify known malicious framework signatures (e.g., standard Cobalt Strike malleable C2 profiles).

### 3. Network Segmentation & Micro-Perimeters
- Isolate IoT devices on dedicated VLANs with strict outbound egress filtering (blocking non-essential internet connectivity).
- Block direct outbound connection attempts to RFC 1918 internal subnets from DMZ hosts.
