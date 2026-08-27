# Denial of Service (DoS) & Distributed Denial of Service (DDoS) Attacks

> **Scope note (how to read this document):** This file covers DoS/DDoS attacks as **general network security knowledge** — attack mechanics, network indicators, and defensive practices that are widely documented in the cybersecurity field. Where this document references NetGuard AI specifically (e.g., which attack labels appear in its training datasets), those statements are limited to what is actually documented in the project's dataset guides (CICIDS-2017 and NSL-KDD). NetGuard AI's documented capability is classifying flows/connections as benign or a specific DoS/DDoS sub-type with a confidence score — it does not claim to automatically block, scrub, or reroute traffic unless explicitly documented elsewhere.

---

## Overview

**Denial of Service (DoS)** and **Distributed Denial of Service (DDoS)** attacks aim to disrupt the normal operation of a targeted server, service, or network by overwhelming the target or its surrounding infrastructure with a flood of traffic or by exhausting a limited resource (connection slots, CPU, memory, bandwidth) until legitimate users can no longer be served.

While **DoS** attacks originate from a single source host, **DDoS** attacks leverage a distributed **botnet** comprising many (sometimes thousands to millions of) compromised hosts ("zombies" or "bots") controlled via a **Command and Control (C2)** infrastructure, making the attack traffic harder to block by simply denying a single IP address.

Common synonyms and related terms used interchangeably across the security literature and in this knowledge base:
- "Denial of Service (DoS)", "Distributed Denial of Service (DDoS)"
- "flood attack", "volumetric attack", "resource exhaustion attack"
- "availability attack" (as opposed to confidentiality/integrity attacks)
- "L3/L4 attack" (network/transport-layer flood) vs. "L7 attack" (application-layer flood)

---

## Definition

A **Denial of Service (DoS)** attack is any deliberate action intended to make a computer resource (a service, host, or network) unavailable to its intended legitimate users, typically by consuming a finite resource faster than it can be replenished or freed.

A **Distributed Denial of Service (DDoS)** attack is a DoS attack carried out from multiple distributed sources simultaneously — usually a botnet — which both amplifies the total attack volume and makes source-based blocking far less effective, since traffic originates from many different, often geographically distributed, IP addresses.

The finite resource being exhausted can be at different layers:
- **Bandwidth** (network-layer capacity)
- **Connection state / memory** (transport-layer, e.g., TCP connection tables)
- **CPU / application logic** (application-layer, e.g., expensive database queries)
- **Session/worker threads** (application-layer, e.g., a fixed-size web server worker pool)

---

## Key Concepts

### Attack layer classification
DoS/DDoS attacks are commonly classified by the OSI layer they primarily target:

| Layer | Attack Style | Examples |
| :--- | :--- | :--- |
| L3 (Network) | Volumetric flooding of raw packets | ICMP flood, Smurf |
| L4 (Transport) | Exhausting connection state or transport resources | SYN flood, UDP flood |
| L7 (Application) | Exhausting application logic/worker capacity with seemingly valid requests | HTTP GET/POST flood, Slowloris, Slowhttptest |

L3/L4 attacks are typically measured in **bits per second (bps)** or **packets per second (pps)** and rely on raw volume. L7 attacks are typically measured in **requests per second (rps)** and rely on the disproportionate cost of processing each request relative to the cost of sending it, meaning even relatively low request volumes can exhaust a server if each request is expensive to handle.

### Volumetric vs. protocol vs. application attacks
Another common three-way classification (general knowledge):
- **Volumetric attacks:** Aim to saturate available bandwidth (e.g., UDP floods, amplification attacks).
- **Protocol attacks:** Aim to exhaust server or intermediate-device resources by abusing protocol state machines (e.g., SYN floods exhausting TCP connection tables, or attacks targeting firewall/load-balancer state tables).
- **Application-layer attacks:** Aim to exhaust the application itself, often with a low volume of expensive requests (e.g., Slowloris, HTTP floods against expensive endpoints like search or login).

### DoS vs. DDoS: why distribution matters
A single-source DoS attack can often be mitigated relatively easily by blocking or rate-limiting the offending IP address. A DDoS attack defeats this simple defense because:
- Traffic arrives from many distinct source IPs, so IP-based blocking has to block a very large and constantly shifting list.
- Some sources may be legitimate hosts that were compromised (reflectors/amplifiers or bots), meaning blocking them can have unintended secondary effects.
- The attacker's C2 infrastructure can dynamically recruit new bots faster than defenders can identify and block them.

---

## Common Attack Vectors & Mechanics

### 1. SYN Flood (Layer 4 – Transport)
- **Protocol:** TCP
- **Mechanism:** Exploits the TCP three-way handshake (`SYN` → `SYN-ACK` → `ACK`). The attacker sends a rapid succession of `SYN` packets, often from spoofed source IP addresses, to open ports on the target without sending the concluding `ACK` packet.
- **Impact:** The victim server allocates memory/buffers in its transmission control block (TCB) table for each half-open connection until the connection state table is completely exhausted, preventing legitimate clients from establishing new connections.
- **Network Flow Indicators:**
  - High ratio of `SYN` packets to `ACK` packets.
  - Abnormally short Flow Duration with 0 backward payload bytes (`Bwd Packet Length Mean ≈ 0`).
  - Elevated `SYN Flag Count` and high `Flow Packets/s`.
- **Dataset mapping:** Represented as `neptune` in NSL-KDD's DoS family, and as part of the `DDoS` label in CICIDS-2017 when carried out at volume from multiple sources.

### 2. UDP Flood & Amplification (Layer 4 & Layer 7)
- **Protocol:** UDP
- **Mechanism:** Attackers flood random or specific UDP ports on the remote host with large UDP packets. In **reflection/amplification attacks** (e.g., DNS, NTP `monlist`, Memcached, SSDP, SNMP), the attacker sends small requests with a spoofed source IP (the victim's IP) to misconfigured open reflectors, causing them to send massive response payloads to the victim — the reflector does the "flooding" on the attacker's behalf.
- **Amplification Factors (approximate, general knowledge):**
  - DNS: roughly 28x to 54x amplification.
  - NTP (`monlist` command): up to roughly 556x amplification.
  - Memcached: up to roughly 51,000x amplification (one of the highest known amplification factors).
  - CLDAP, SSDP, and SNMP have also been used as amplification vectors with substantial (though generally lower) multipliers.
- **Network Flow Indicators:**
  - Sudden surge in UDP traffic volume (e.g., `Flow Bytes/s` far above baseline).
  - High packet rate to specific well-known reflector ports (e.g., 53/DNS, 123/NTP, 1900/SSDP, 11211/Memcached).
  - High `Total Fwd Packets` and asymmetrical bidirectional flow volume (heavy inbound response traffic relative to the tiny spoofed request).
- **Dataset mapping:** Represented as `udpstorm` in NSL-KDD's DoS family, and captured within the general `DDoS`/`DoS` labels of CICIDS-2017.

### 3. ICMP Flood (Ping Flood) (Layer 3 – Network)
- **Protocol:** ICMP
- **Mechanism:** The attacker overwhelms the target with a high rate of ICMP Echo Request ("ping") packets, forcing the target to spend CPU/bandwidth generating Echo Reply responses.
- **Variants:**
  - **Smurf Attack:** Broadcasts ICMP Echo requests with the victim's spoofed source IP to intermediate router broadcast addresses, causing all subnet nodes to reply to the victim simultaneously (an amplification technique at the network layer).
  - **Ping of Death (`pod`):** Sends malformed or oversized ICMP packets that exceed the maximum allowed IP packet size, historically able to crash or destabilize systems with buggy TCP/IP stack implementations.
- **Network Flow Indicators:**
  - Sustained spike in ICMP packet volume, often from spoofed or broadcast-amplified sources.
  - Unusually large or malformed ICMP packet sizes (Ping of Death variant).
- **Dataset mapping:** Represented as `smurf` and `pod` in NSL-KDD's DoS family.

### 4. HTTP Flood & Slowloris (Layer 7 – Application)
- **Protocol:** HTTP / HTTPS
- **Mechanism:**
  - **HTTP GET/POST Flood:** Floods the web server with seemingly legitimate GET or POST requests that require expensive database queries, search operations, or CPU-heavy rendering, exhausting server compute resources rather than raw bandwidth.
  - **Slowloris:** Opens multiple HTTP connections and sends partial HTTP headers very slowly at periodic intervals, keeping sockets open and consuming thread/worker pools until the web server's connection limits (e.g., Apache's `MaxRequestWorkers`) are reached, without ever completing a request.
  - **Slowhttptest / R-U-Dead-Yet:** A related family of slow-attack tools capable of Slowloris-style header starvation as well as slow HTTP POST body attacks, where the request body is trickled in extremely slowly to keep the connection occupied.
- **Network Flow Indicators:**
  - High session duration with minimal data rate (`Flow IAT Mean` high, `Flow Bytes/s` low for Slowloris/Slowhttptest).
  - High concentration of HTTP requests per source IP (HTTP flood variant).
  - Long `Idle` periods punctuated by minimal keep-alive activity.
- **Dataset mapping:** Directly represented in CICIDS-2017 as `DoS Slowloris`, `DoS Slowhttptest`, `DoS Hulk`, and `DoS GoldenEye` — four distinct HTTP-layer DoS tool signatures captured on the Wednesday capture day. NSL-KDD's `apache2` and `back` labels also represent Apache-targeted HTTP-layer DoS behavior from the earlier KDD Cup era.

### 5. Smurf & Teardrop Attacks (Legacy / Network Layer)
- **Smurf Attack:** As described above — ICMP broadcast amplification using a spoofed victim source address.
- **Teardrop Attack:** Sends overlapping, fragmented IP packets (manipulating the `Fragment Offset` field) causing vulnerable operating system kernels to fail during packet reassembly, historically leading to crashes or instability on unpatched systems. Both `smurf` and `teardrop` are explicitly represented as named attacks in NSL-KDD's DoS family, reflecting their historical significance in the dataset's original (1998–1999) capture era; modern operating systems and network stacks are generally patched against the specific Teardrop vulnerability, though the general fragmentation-abuse technique remains a documented attack class.

### 6. Land Attack
- **Mechanism:** Sends a spoofed packet where the source IP address and port are identical to the destination IP address and port, which can confuse certain vulnerable systems into an infinite reply loop with themselves, consuming resources.
- **Dataset mapping:** Directly represented as `land` in NSL-KDD, and reflected in CICIDS-2017's dataset schema via the `land` feature column (a binary indicator for this exact source=destination pattern).

---

## Technical Details

### Why volumetric attacks are measured differently from application-layer attacks
Because volumetric (L3/L4) attacks primarily consume network capacity, they are typically reported in **Gbps (gigabits per second)** or **Mpps (million packets per second)**. Application-layer (L7) attacks primarily consume compute/connection resources rather than bandwidth, so they are typically reported in **requests per second (rps)** — a Slowloris attack, for instance, might use very little bandwidth while still fully exhausting a web server's worker pool.

### Amplification/reflection mathematics (general knowledge)
An amplification attack's effectiveness is often summarized by its **Bandwidth Amplification Factor (BAF)**:

```
BAF = (size of response traffic to the victim) / (size of request traffic sent by the attacker)
```

A higher BAF means the attacker needs to send proportionally less of their own bandwidth to generate a given amount of attack traffic at the victim, which is why protocols with very high BAFs (like Memcached, historically) have been especially attractive to attackers.

### Spoofing and its role in DoS/DDoS
Many classic DoS techniques (SYN flood, Smurf, most reflection/amplification attacks) rely on **IP address spoofing** — forging the source IP address in outgoing packets — either to hide the true attacker or, in reflection attacks, to redirect the reflector's response toward the victim instead of the attacker. Network-level defenses like **BCP38 / ingress filtering** (verifying that outbound traffic from a network actually originates from that network's assigned address space) are a widely recommended general mitigation against spoofing-based amplification, though adoption varies across ISPs globally.

### Botnets and DDoS (cross-reference)
Modern large-scale DDoS attacks are typically carried out using **botnets** — networks of compromised devices (traditional PCs, servers, or increasingly IoT devices) controlled via C2 infrastructure. See the dedicated botnets and C2 knowledge-base file for full detail on botnet architecture, C2 communication patterns, and detection of C2 beaconing traffic.

---

## Detection

Detection of DoS/DDoS activity generally combines volumetric monitoring with flow/connection-level statistical analysis:

- **Threshold-based detection (general knowledge):** Monitoring aggregate metrics (packets/sec, bits/sec, connections/sec) against a baseline and alerting when they exceed a defined threshold. Simple and fast but requires per-environment tuning and can miss low-and-slow application-layer attacks that don't produce high volume.
- **Statistical/flow-based detection:** Analyzing per-flow features (as described in the CICIDS-2017 and NSL-KDD guides) such as `Flow Packets/s`, `SYN Flag Count`, `Flow Duration`, and directional packet ratios to distinguish attack flows from normal traffic, even when raw volume alone might not obviously exceed a fixed threshold.
- **Machine-learning-based detection:** Training a classifier (e.g., Random Forest) on labeled flow features to recognize the statistical signatures associated with specific DoS/DDoS sub-types (SYN flood vs. UDP flood vs. Slowloris, etc.) rather than relying on a single hand-tuned threshold. **NetGuard AI** applies this approach, training on CICIDS-2017's DoS/DDoS-labeled flows (`DDoS`, `DoS Hulk`, `DoS GoldenEye`, `DoS Slowloris`, `DoS Slowhttptest`) and NSL-KDD's DoS family (`neptune`, `smurf`, `pod`, `teardrop`, `land`, `back`, `apache2`, `udpstorm`) to output a predicted attack sub-type with a confidence score.

### Distinguishing attack sub-types from flow features (summary table)

| Sub-Type | Flow Duration | Packet Rate | Direction Symmetry | Distinctive Signal |
| :--- | :--- | :--- | :--- | :--- |
| SYN flood | Very short | Very high | One-directional (few/no backward packets) | High `SYN Flag Count`, low `ACK` completion |
| UDP flood/amplification | Short | Very high | Asymmetric (large inbound response vs. small spoofed request) | High volume to specific reflector ports |
| ICMP/Smurf flood | Short | High | Broadcast-amplified inbound | High ICMP volume, often spoofed source |
| HTTP flood | Variable | Moderate–high (request rate) | Roughly symmetric (real HTTP responses) | High request concentration per source, expensive endpoint targeting |
| Slowloris/Slowhttptest | Very long | Low | Minimal backward payload | Long `Idle` time, low `Flow Bytes/s` |

---

## Network Indicators

General network-level indicators associated with DoS/DDoS activity:

- **Bandwidth/packet-rate spikes** far above established baseline for a given host, subnet, or time-of-day pattern.
- **Skewed TCP flag ratios**, especially a high proportion of `SYN` packets relative to completed `SYN-ACK`/`ACK` handshakes.
- **Destination fan-in**: many distinct source IPs (or a large volume of spoofed-looking sources) converging on a single destination IP/port.
- **Reflector traffic to unusual ports**: traffic concentrated on known amplification-vector ports (53, 123, 1900, 11211, etc.) at volumes inconsistent with normal usage of those services.
- **Long-lived, low-throughput connections**: many concurrent connections that remain open but transmit minimal data (Slowloris-family indicator).
- **Sudden drop in legitimate traffic/service responsiveness**: an indirect but important indicator — actual users experiencing timeouts or failures alongside anomalous traffic patterns.
- **Geographic/ASN anomalies**: a sudden surge of traffic from ranges or regions not typically seen in an organization's normal traffic profile (context-dependent, not a standalone indicator).

---

## Machine Learning Perspective

### Feature relevance for DoS/DDoS classification
Across both CICIDS-2017 and NSL-KDD, the features most predictive of DoS/DDoS activity tend to be those capturing **volume, rate, and directional asymmetry**: `Flow Packets/s`, `Flow Bytes/s`, `SYN Flag Count`, `count`/`srv_count` (NSL-KDD's 2-second window features), and `serror_rate`/`dst_host_serror_rate`. This makes intuitive sense — DoS/DDoS attacks are fundamentally about overwhelming volume or exploiting handshake/state-machine behavior, both of which show up strongly in rate- and flag-based features rather than in content-level features (which matter more for R2L/U2R-style attacks).

### Class imbalance considerations
DoS/DDoS classes are typically **among the best-represented attack classes** in both CICIDS-2017 and NSL-KDD (unlike rarer classes such as Heartbleed, Infiltration, R2L, or U2R), since flood-style attacks naturally generate large numbers of flow/connection records. This generally makes DoS/DDoS one of the **easier attack families for a classifier to learn**, though distinguishing between similar DoS sub-types (e.g., `DoS Hulk` vs. `DoS GoldenEye`, both HTTP-layer floods) can still be a source of misclassification in a confusion matrix, since their flow-level statistical signatures can be similar.

### Confidence interpretation for DoS/DDoS predictions
Because DoS/DDoS attacks tend to produce strong, distinctive statistical signatures (extreme values in packet rate, flag counts, or duration), classifiers trained on this data often produce **high-confidence predictions** for clear volumetric floods. Borderline or low-confidence DoS predictions are more likely to occur for:
- Low-and-slow application-layer attacks (Slowloris-style), which deliberately mimic legitimate long-lived connections.
- Legitimate but bursty traffic (e.g., a flash crowd of real users, a software update rollout, or a backup job), which can share some statistical similarity with flood-style traffic (high packet/byte rate in a short window).

See the severity and confidence guide for the full interpretation framework NetGuard AI applies to these confidence levels.

---

## SOC Perspective

### SOC Triage & Response Workflow (general practice)
1. **Assess flow volume and layer:** Determine whether the attack is volumetric (L3/L4, measured in Gbps/pps) or application-state based (L7, measured in rps or connection-count).
2. **Identify the specific sub-type:** Use flow features (or a classifier's predicted label) to distinguish SYN flood vs. UDP amplification vs. HTTP flood vs. Slowloris, since each has different effective mitigations.
3. **Filter suspicious subnets:** Apply temporary geoblocking or CIDR-based filtering at perimeter firewalls if the attack sources cluster in identifiable ranges.
4. **Engage ISP/CDN partners:** For large volumetric attacks exceeding local mitigation capacity, request upstream BGP blackholing (Null0 routing) for non-critical overwhelmed single-target IPs, or activate anti-DDoS proxy/scrubbing services.
5. **Monitor for secondary attacks:** DoS/DDoS activity is sometimes used as a distraction ("smokescreen") to draw analyst attention away from a simultaneous, quieter intrusion attempt elsewhere in the environment — SOC teams should maintain visibility into other alert categories during a DDoS event rather than focusing exclusively on the flood.
6. **Document and review:** Record attack duration, peak volume, sub-type, and mitigation actions taken for post-incident review and future threshold tuning.

### Severity considerations
Per NetGuard AI's documented severity matrix (see the severity and confidence guide), active high-bandwidth DDoS floods are classified as **Critical** severity, while isolated or low-volume DoS-style probing (e.g., a single Slowloris partial probe) may be classified at a lower tier depending on scale and persistence.

---

## Examples

**Example 1 — Volumetric SYN flood:**
A target web server receives an extreme spike in inbound TCP `SYN` packets from many distinct (often spoofed) source addresses, with almost no corresponding `SYN-ACK`/`ACK` completions and near-zero backward payload. This matches the flow signature of `neptune` (NSL-KDD) or the `DDoS`/general DoS label (CICIDS-2017).

**Example 2 — Slowloris application-layer starvation:**
A web application experiences hundreds of long-lived, low-throughput HTTP connections, each sending only partial headers at slow intervals, gradually exhausting the server's available worker threads until new legitimate connections are refused. This matches the `DoS Slowloris` label in CICIDS-2017.

**Example 3 — DNS amplification:**
A victim's IP address receives a flood of large DNS response packets from many different DNS resolvers, none of which the victim actually queried — consistent with an attacker spoofing the victim's IP in small DNS queries sent to open resolvers, redirecting the large responses toward the victim.

**Example 4 — Legitimate flash-crowd traffic (a false-positive risk case):**
A news website suddenly receives a large, genuine surge in HTTP requests following a viral article, showing elevated request rate and packet volume similar in some respects to an HTTP flood, but with normal, complete request/response cycles and diverse, plausible user-agent/browser fingerprints. This illustrates why request-completion behavior and traffic diversity should be considered alongside raw volume before concluding an attack is underway.

---

## Mitigation

### Infrastructure & Perimeter Defense (general practice)
1. **SYN Cookies:** Enable kernel SYN cookies (`sysctl -w net.ipv4.tcp_syncookies=1`) to eliminate the half-open connection state table requirement in memory, allowing the server to validate a connection without pre-allocating full state until the handshake completes.
2. **Rate Limiting & Connection Throttling:**
   - Configure firewall rate limiting per source subnet, e.g.: `iptables -A INPUT -p tcp --syn -m limit --limit 20/s --limit-burst 50 -j ACCEPT`
   - Implement reverse-proxy connection limits, e.g. (Nginx): `limit_conn_zone $binary_remote_addr zone=addr:10m; limit_conn addr 20;`
3. **Upstream DDoS Scrubbing & BGP Anycast:**
   - Divert volumetric floods through cloud scrubbing centers (commercial providers such as Cloudflare, AWS Shield, or Akamai Prolexic) using BGP Anycast routing to distribute and absorb the flood across many points of presence.
   - Employ **BGP Flowspec (RFC 5575)** to distribute granular filtering rules across ISP edge routers, enabling faster, more surgical mitigation than blunt null-routing.
4. **Ingress filtering (BCP38):** Network operators filtering outbound traffic to ensure source IPs match their assigned address space, reducing the viability of spoofing-based amplification attacks originating from their network.

### Host & Kernel Hardening
```bash
# Hardening Linux TCP/IP Stack against DoS
sysctl -w net.ipv4.tcp_max_syn_backlog=4096
sysctl -w net.ipv4.tcp_synack_retries=2
sysctl -w net.ipv4.tcp_abort_on_overflow=1
sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
```

### Application-layer mitigations
- Tune web-server worker/connection limits and timeouts (e.g., Apache `MaxRequestWorkers`, `RequestReadTimeout`) to reduce Slowloris-style exposure.
- Use a Web Application Firewall (WAF) or reverse proxy capable of buffering/validating requests before they reach the application server, mitigating some HTTP-flood and slow-attack patterns.
- Apply CAPTCHA or proof-of-work challenges selectively for suspicious high-volume request patterns on expensive endpoints (e.g., search, login).

These are general, widely documented mitigation practices; **NetGuard AI's own documented role is detection and classification of DoS/DDoS flow patterns with a confidence score, not automated execution of firewall rules, BGP announcements, or scrubbing-service activation**, unless a specific project component documents that capability.

---

## Limitations

- **Spoofed traffic obscures true source attribution**, making pure IP-blocking an incomplete defense against volumetric and reflection-based attacks.
- **Low-and-slow application-layer attacks** (Slowloris-family) can evade purely volume-based detection thresholds, since they deliberately avoid high packet/byte rates.
- **Legitimate bursty traffic (flash crowds, backups, software rollouts)** can superficially resemble flood traffic in raw volume, creating false-positive risk if detection relies solely on rate-based thresholds without considering completion behavior or traffic diversity.
- **Dataset-trained classifiers reflect the attack tools and traffic patterns present in their training data** (e.g., specific tools like Hulk, GoldenEye, or the Ares botnet in CICIDS-2017's Bot samples); genuinely novel DoS tooling not resembling these patterns may not be reliably classified without retraining or complementary detection methods.
- **No production performance figures are asserted here** — this document does not claim any specific detection accuracy, false-positive rate, or mitigation latency for NetGuard AI's DoS/DDoS classification in a live deployment.

---

## Common Questions

**Q: What is the difference between DoS and DDoS?**
A: DoS (Denial of Service) originates from a single source attacking a target, while DDoS (Distributed Denial of Service) uses many distributed sources — typically a botnet of compromised hosts — to attack a target simultaneously, making it both more powerful and harder to mitigate through simple source-IP blocking.

**Q: What is a SYN flood?**
A: A SYN flood is a Layer 4 DoS technique that exploits the TCP three-way handshake by sending many `SYN` packets (often with spoofed source IPs) without completing the handshake, exhausting the target's connection-state table so legitimate connections can no longer be established.

**Q: What is DNS/NTP/Memcached amplification?**
A: These are reflection/amplification DDoS techniques where an attacker sends a small, spoofed request (using the victim's IP as the source) to an open, misconfigured server (a "reflector"), which then sends a much larger response to the victim — multiplying the effective attack bandwidth well beyond what the attacker could generate directly.

**Q: What makes Slowloris different from a typical flood attack?**
A: Slowloris uses very low bandwidth and request volume, instead exhausting a web server's connection/worker pool by opening many connections and sending partial HTTP headers extremely slowly, keeping each connection occupied without ever completing a normal request — making it a "low-and-slow" attack rather than a volumetric one.

**Q: How can flow features distinguish a SYN flood from a UDP flood?**
A: A SYN flood shows an elevated `SYN Flag Count` with very few completed handshakes and near-zero backward packets on TCP flows, while a UDP flood/amplification attack shows a surge in UDP traffic to specific reflector-associated ports with typically asymmetric (often much larger) inbound response volume relative to any outbound request.

**Q: Which CICIDS-2017 labels correspond to DoS/DDoS attacks?**
A: `DDoS`, `DoS Hulk`, `DoS GoldenEye`, `DoS Slowloris`, and `DoS Slowhttptest` are the CICIDS-2017 labels directly representing DoS/DDoS attack traffic.

**Q: Which NSL-KDD labels correspond to DoS attacks?**
A: `neptune`, `smurf`, `pod`, `teardrop`, `land`, `back`, `apache2`, and `udpstorm` are the specific attacks that make up NSL-KDD's DoS family.

**Q: Why is class imbalance less of a concern for DoS/DDoS detection compared to R2L/U2R?**
A: Flood-style attacks naturally generate a large volume of flow/connection records in a short time, so DoS/DDoS classes tend to be well represented in benchmark datasets like CICIDS-2017 and NSL-KDD, giving classifiers ample training examples — unlike rarer attack types such as R2L or U2R, which produce far fewer records.

**Q: Can legitimate traffic be mistaken for a DoS/DDoS attack?**
A: Yes. Genuine traffic surges (flash crowds, marketing campaigns, software update rollouts, backup jobs) can produce high packet/byte rates similar to flood traffic. Distinguishing them typically requires looking at additional signals beyond raw volume, such as handshake completion rates, traffic diversity, and whether requests resemble normal application usage.

**Q: Does NetGuard AI automatically stop a DDoS attack once detected?**
A: No — that capability is not documented as part of the project. NetGuard AI's documented function is classifying network flows as benign or a specific DoS/DDoS sub-type with a confidence score, surfaced through its dashboard and RAG assistant to support SOC decision-making; actual mitigation (rate-limiting, scrubbing, blackholing) is a separate operational step typically carried out by network/firewall teams or upstream providers.

**Q: What is BGP blackholing?**
A: It is a mitigation technique where an overwhelmed destination IP's traffic is routed to a "null" route (often called `Null0`) at the network edge or via an upstream provider, effectively dropping all traffic to that IP — including the attack traffic — to protect the rest of the network, at the cost of also making that specific IP unreachable for legitimate users during the mitigation window.

---

## Summary

DoS and DDoS attacks disrupt service availability by overwhelming a target's bandwidth, connection state, or application resources, ranging from raw volumetric floods (SYN floods, UDP/amplification floods, ICMP floods) to low-and-slow application-layer attacks (Slowloris, Slowhttptest) that exhaust resources with minimal traffic volume. These attack families are well represented in both CICIDS-2017 (`DDoS`, `DoS Hulk`, `DoS GoldenEye`, `DoS Slowloris`, `DoS Slowhttptest`) and NSL-KDD (`neptune`, `smurf`, `pod`, `teardrop`, `land`, `back`, `apache2`, `udpstorm`), making them among the better-represented and more statistically distinctive attack classes for machine-learning-based intrusion detection. NetGuard AI trains its Random Forest classifier on these labeled examples to distinguish DoS/DDoS sub-types with an associated confidence score, supporting — but not replacing — the broader set of general network defenses (SYN cookies, rate limiting, upstream scrubbing, ingress filtering, and application-layer hardening) that organizations use to actually mitigate these attacks in production.
