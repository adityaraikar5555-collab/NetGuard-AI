# Denial of Service (DoS) & Distributed Denial of Service (DDoS) Attacks

## Overview
Denial of Service (DoS) and Distributed Denial of Service (DDoS) attacks aim to disrupt the normal operation of a targeted server, service, or network by overwhelming the target or its surrounding infrastructure with a flood of Internet traffic.

While DoS attacks originate from a single source host, DDoS attacks leverage a distributed botnet comprising thousands to millions of compromised hosts (zombies or bots) controlled via a Command and Control (C2) server.

---

## Common Attack Vectors & Mechanics

### 1. SYN Flood (Layer 4 - Transport)
- **Protocol:** TCP
- **Mechanism:** Exploits the TCP three-way handshake (`SYN` -> `SYN-ACK` -> `ACK`). The attacker sends a rapid succession of `SYN` packets from spoofed source IP addresses to open ports on the target without sending the concluding `ACK` packet.
- **Impact:** The victim server allocates memory/buffers in its transmission control block (TCB) table for each half-open connection until the connection state table is completely exhausted, preventing legitimate clients from establishing connections.
- **Network Flow Indicators:**
  - High ratio of SYN packets to ACK packets.
  - Abnormally short Flow Duration with 0 backward payload bytes (`Bwd Packet Length Mean ≈ 0`).
  - Elevated `SYN Flag Count` and high `Flow Packets/s`.

### 2. UDP Flood & Amplification (Layer 4 & Layer 7)
- **Protocol:** UDP
- **Mechanism:** Attackers flood random or specific UDP ports on the remote host with large UDP packets. In reflection/amplification attacks (e.g., DNS, NTP monlist, Memcached, SSDP, SNMP), the attacker sends small requests with a spoofed source IP (the victim's IP) to misconfigured open reflectors, causing them to send massive response payloads to the victim.
- **Amplification Factors:**
  - DNS: 28x to 54x amplification.
  - NTP (monlist): Up to 556x amplification.
  - Memcached: Up to 51,000x amplification.
- **Network Flow Indicators:**
  - Sudden surge in UDP traffic volume (`Flow Bytes/s` > 100 MB/s).
  - High packet rate to specific port numbers (e.g., 53, 123, 1900, 11211).
  - High `Total Fwd Packets` and asymmetrical bidirectional flow volume.

### 3. HTTP Flood & Slowloris (Layer 7 - Application)
- **Protocol:** HTTP / HTTPS
- **Mechanism:**
  - **HTTP GET/POST Flood:** Floods the web server with seemingly legitimate GET or POST requests that require expensive database queries or CPU-heavy rendering.
  - **Slowloris:** Opens multiple HTTP connections and sends partial HTTP headers very slowly at periodic intervals, keeping sockets open and consuming thread worker pools until Apache/Nginx connection limits (`MaxRequestWorkers`) are reached.
- **Network Flow Indicators:**
  - High session duration with minimal data rate (`Flow IAT Mean` high, `Flow Bytes/s` low for Slowloris).
  - High concentration of HTTP requests per source IP.

### 4. Smurf & Teardrop Attacks (Legacy / Network Layer)
- **Smurf Attack:** Broadcasts ICMP Echo requests with victim's spoofed source IP to intermediate router broadcast addresses, causing all subnet nodes to reply to the victim.
- **Teardrop Attack:** Sends overlapping, fragmented IP packets (`Fragment Offset` manipulation) causing OS kernel crash during packet reassembly.

---

## Defensive Mitigation Strategies

### Infrastructure & Perimeter Defense
1. **SYN Cookies:** Enable kernel SYN cookies (`sysctl -w net.ipv4.tcp_syncookies=1`) to eliminate the half-open connection state table requirement in memory.
2. **Rate Limiting & Connection Throttling:**
   - Configure firewall rate limiting per source subnet (e.g., `iptables -A INPUT -p tcp --syn -m limit --limit 20/s --limit-burst 50 -j ACCEPT`).
   - Implement Nginx / HAProxy connection limits (`limit_conn_zone $binary_remote_addr zone=addr:10m; limit_conn addr 20;`).
3. **Upstream DDoS Scrubbing & BGP Anycast:**
   - Divert volumetric floods through global cloud scrubbing centers (Cloudflare, AWS Shield, Akamai Prolexic) using BGP Anycast routing.
   - Employ BGP Flowspec (RFC 5575) to distribute filtering rules across ISP edge routers.

### Host & Kernel Hardening
```bash
# Hardening Linux TCP/IP Stack against DoS
sysctl -w net.ipv4.tcp_max_syn_backlog=4096
sysctl -w net.ipv4.tcp_synack_retries=2
sysctl -w net.ipv4.tcp_abort_on_overflow=1
sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
```

### SOC Triage & Response Workflow
1. **Assess Flow Volume:** Determine whether the attack is volumetric (L3/L4 Gbps) or application-state based (L7).
2. **Filter Suspicious Subnets:** Apply temporary geoblocking or CIDR drops on perimeter firewalls.
3. **Engage ISP/CDN:** Request upstream BGP blackholing (Null0 routing) for non-critical overwhelmed single target IPs or activate anti-DDoS proxy shielding.
