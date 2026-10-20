"""
MITRE ATT&CK® Enterprise Matrix Knowledge Base (v14.1)
Structured representation of all 14 enterprise tactics across the Cyber Kill Chain,
mapped to network intrusion detection signatures, threat actors, and automated SOAR containment playbooks.
"""

MITRE_TACTICS_DB = [
    {
        "tactic_id": "TA0043",
        "tactic_name": "Reconnaissance",
        "icon": "🔭",
        "description": "Gathering victim network intelligence, IP discovery, and perimeter scanning.",
        "techniques": [
            {
                "id": "T1595",
                "name": "Active Scanning",
                "sub": "T1595.001 (Port Scanning)",
                "description": "Scanning IP addresses and listening ports to identify active hosts and exposed network services.",
                "actors": ["APT28", "Sandworm", "Lazarus Group"],
                "detection": "Bursts of TCP SYN packets across sequential or random destination ports with low packet counts per flow.",
                "mitigation": "Deploy stateful perimeter firewall rules to rate-limit SYN packets and drop port sweeps.",
                "snort": 'alert tcp any any -> $HOME_NET any (flags:S; threshold:type threshold, track by_src, count 20, seconds 5; msg:"NetGuard PortScan Sweep Detected"; sid:2000001;)',
                "iptables": "sudo iptables -A INPUT -p tcp -m multiport --dports 1:65535 -m recent --name portscan --set -j DROP",
                "trigger_keywords": ["portscan", "port scan", "sweep", "nmap", "probe"],
            },
            {
                "id": "T1590",
                "name": "Gather Network Info",
                "sub": "T1590.005 (IP Addresses)",
                "description": "Adversaries cataloging network topologies, subnets, and gateway routing interfaces.",
                "actors": ["FIN7", "APT29"],
                "detection": "Repeated DNS queries for internal network zones and ICMP ping sweeps across subnet boundaries.",
                "mitigation": "Disable unnecessary ICMP reply across gateway interfaces and restrict internal DNS lookups.",
                "snort": 'alert icmp any any -> $HOME_NET any (itype:8; threshold:type both, track by_src, count 30, seconds 10; msg:"NetGuard ICMP Recon Sweep"; sid:2000002;)',
                "iptables": "sudo iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT",
                "trigger_keywords": ["recon", "gather", "dns", "icmp"],
            },
        ],
    },
    {
        "tactic_id": "TA0042",
        "tactic_name": "Resource Development",
        "icon": "🏗️",
        "description": "Establishing infrastructure, botnets, and proxy relays to support operations.",
        "techniques": [
            {
                "id": "T1584",
                "name": "Compromise Infrastructure",
                "sub": "T1584.005 (Botnet Relays)",
                "description": "Hijacking third-party network devices and IoT hardware to form distributed staging proxies.",
                "actors": ["Mirai", "Volt Typhoon", "Mustang Panda"],
                "detection": "Multiple inbound flows from compromised consumer IP spaces coordinating bursts toward internal edge routers.",
                "mitigation": "Enforce dynamic reputation-based threat intel IP blacklisting at border BGP gateways.",
                "snort": 'alert tcp any any -> $HOME_NET any (msg:"NetGuard Botnet Relay Connection"; threshold:type limit, track by_src, count 1, seconds 60; sid:2000011;)',
                "iptables": "sudo iptables -A INPUT -m set --match-set botnet_blacklist src -j DROP",
                "trigger_keywords": ["botnet", "relay", "compromised", "infrastructure"],
            },
        ],
    },
    {
        "tactic_id": "TA0001",
        "tactic_name": "Initial Access",
        "icon": "🚪",
        "description": "Techniques used to gain an initial unauthorized entry into the network perimeter.",
        "techniques": [
            {
                "id": "T1190",
                "name": "Exploit Public Application",
                "sub": "T1190 (Web Infiltration)",
                "description": "Attacking vulnerabilities in Internet-facing web servers, APIs, or database gateways (SQLi, XSS, RCE).",
                "actors": ["Hafnium", "Volt Typhoon", "LockBit"],
                "detection": "Abnormal payload lengths on port 80/443, repeated HTTP POST error codes, and signature keywords.",
                "mitigation": "Enforce Web Application Firewall (WAF) deep packet inspection and patch external perimeter services.",
                "snort": 'alert tcp any any -> $HTTP_SERVERS 80 (msg:"NetGuard Exploit Payload Pattern"; content:"UNION SELECT"; nocase; sid:2000003;)',
                "iptables": "sudo iptables -A INPUT -p tcp --dport 80 -m string --algo bm --string 'UNION SELECT' -j DROP",
                "trigger_keywords": ["web", "sqli", "xss", "infiltration", "exploit"],
            },
            {
                "id": "T1133",
                "name": "External Remote Services",
                "sub": "T1133 (VPN/RDP/SSH)",
                "description": "Leveraging exposed VPNs, RDP gateways, or SSH services to access enterprise subnets directly.",
                "actors": ["APT33", "Wizard Spider"],
                "detection": "Persistent off-hours connections from foreign ASNs on ports 3389, 22, and 443.",
                "mitigation": "Enforce mandatory MFA and IP geo-fencing on all administrative interfaces.",
                "snort": 'alert tcp any any -> $HOME_NET [22,3389] (flags:S; msg:"NetGuard External Remote Service Access"; sid:2000004;)',
                "iptables": "sudo iptables -A INPUT -p tcp -m multiport --dports 22,3389 -s 10.0.0.0/8 -j ACCEPT",
                "trigger_keywords": ["vpn", "rdp", "remote"],
            },
        ],
    },
    {
        "tactic_id": "TA0002",
        "tactic_name": "Execution",
        "icon": "⚡",
        "description": "Adversary execution of malicious code, commands, or automated exploitation scripts.",
        "techniques": [
            {
                "id": "T1059",
                "name": "Command & Scripting Interpreter",
                "sub": "T1059.004 (Unix Shell / PowerShell)",
                "description": "Executing reverse shells or automated script payloads over active network connections.",
                "actors": ["MuddyWater", "APT41", "Turla"],
                "detection": "Network interactive byte bursts matching shell metacharacters (/bin/sh, powershell.exe -enc) on unencrypted ports.",
                "mitigation": "Block egress connections from non-standard ports and restrict interactive shell spawn capabilities.",
                "snort": 'alert tcp any any -> $HOME_NET any (msg:"NetGuard Remote Shell Execution"; content:"/bin/bash"; nocase; sid:2000012;)',
                "iptables": "sudo iptables -A FORWARD -p tcp -m string --algo bm --string '/bin/sh' -j DROP",
                "trigger_keywords": ["execution", "shell", "powershell", "interpreter", "command"],
            },
        ],
    },
    {
        "tactic_id": "TA0003",
        "tactic_name": "Persistence",
        "icon": "⚓",
        "description": "Maintaining foothold across system restarts and credential changes.",
        "techniques": [
            {
                "id": "T1136",
                "name": "Create Account",
                "sub": "T1136.002 (Domain / SSH Keys)",
                "description": "Injecting rogue administrative accounts or unauthorized SSH keys to maintain persistent remote access.",
                "actors": ["BlackCat", "Lazarus Group"],
                "detection": "Unauthorized LDAP/Kerberos user addition requests followed by immediate remote admin authentication.",
                "mitigation": "Audit Active Directory account creations in real-time and restrict remote key provisioning.",
                "snort": 'alert tcp any any -> $DC_SERVERS 389 (msg:"NetGuard LDAP Rogue Account Creation"; content:"sAMAccountName"; sid:2000013;)',
                "iptables": "sudo iptables -A INPUT -p tcp --dport 389 -s ! 10.0.1.0/24 -j DROP",
                "trigger_keywords": ["persistence", "account", "backdoor", "maintain"],
            },
        ],
    },
    {
        "tactic_id": "TA0004",
        "tactic_name": "Privilege Escalation",
        "icon": "📈",
        "description": "Techniques adversaries use to gain higher-level permissions on system or domain resources.",
        "techniques": [
            {
                "id": "T1068",
                "name": "Exploitation for Privilege Escalation",
                "sub": "T1068 (Kernel / RPC Exploitation)",
                "description": "Exploiting network-reachable services (PrintNightmare, ZeroLogon) to elevate from unprivileged to Domain Admin.",
                "actors": ["Silence", "Dragonfly", "APT29"],
                "detection": "High-volume Netlogon / DCE-RPC traffic patterns with anomalous privilege flag requests.",
                "mitigation": "Enforce RPC packet signing, deploy host kernel patches, and isolate critical domain controllers.",
                "snort": 'alert tcp any any -> $DC_SERVERS 135 (msg:"NetGuard DC RPC Elevation Probe"; flow:to_server,established; sid:2000014;)',
                "iptables": "sudo iptables -A INPUT -p tcp --dport 135 -s 10.0.0.0/16 -j ACCEPT; sudo iptables -A INPUT -p tcp --dport 135 -j DROP",
                "trigger_keywords": ["privilege", "elevation", "zerologon", "rpc", "kernel"],
            },
        ],
    },
    {
        "tactic_id": "TA0005",
        "tactic_name": "Defense Evasion",
        "icon": "🥷",
        "description": "Techniques used by adversaries to avoid detection throughout their compromise.",
        "techniques": [
            {
                "id": "T1036",
                "name": "Masquerading",
                "sub": "T1036.004 (Port/Protocol Masquerade)",
                "description": "Tunneling malicious or C2 traffic through legitimate ports such as HTTPS (443) or DNS (53) to bypass egress firewalls.",
                "actors": ["Turla", "APT41"],
                "detection": "Discrepancy between protocol header markers and declared destination port (e.g. non-DNS binary payload on port 53).",
                "mitigation": "Deploy Deep Packet Inspection (DPI) firewalls with application protocol verification.",
                "snort": 'alert udp any any -> any 53 (msg:"NetGuard Masqueraded DNS Protocol"; content:!"|01 00|"; depth:2; offset:2; sid:2000006;)',
                "iptables": "sudo iptables -A FORWARD -p udp --dport 53 -m length --length 512:65535 -j DROP",
                "trigger_keywords": ["masquerade", "evasion", "tunneling", "stealth", "anomaly"],
            },
        ],
    },
    {
        "tactic_id": "TA0006",
        "tactic_name": "Credential Access",
        "icon": "🔑",
        "description": "Attempts to compromise credentials such as usernames and passwords via brute-force or spraying.",
        "techniques": [
            {
                "id": "T1110",
                "name": "Brute Force",
                "sub": "T1110.001 (Password Guessing)",
                "description": "Systematic repeated authentication attempts against SSH, FTP, or Telnet services.",
                "actors": ["Cozy Bear", "DarkSide", "BlackCat"],
                "detection": "Rapid succession of short-duration flows with identical destination port and zero forward payload variance.",
                "mitigation": "Enforce account lockouts after 5 consecutive failed attempts and deploy Fail2ban.",
                "snort": 'alert tcp any any -> $HOME_NET [21,22] (flags:S; threshold:type threshold, track by_src, count 10, seconds 20; msg:"NetGuard Brute Force Attack"; sid:2000005;)',
                "iptables": "sudo iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set --name SSH_BRUTE; sudo iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 -j DROP",
                "trigger_keywords": ["bruteforce", "brute", "patator", "ftp-patator", "ssh-patator"],
            },
        ],
    },
    {
        "tactic_id": "TA0007",
        "tactic_name": "Discovery",
        "icon": "🔍",
        "description": "Techniques adversaries use to observe the internal system and enterprise network.",
        "techniques": [
            {
                "id": "T1046",
                "name": "Network Service Discovery",
                "sub": "T1046 (Service Enumeration)",
                "description": "Iterating across hosts and port ranges to discover vulnerable services, open SMB shares, and databases.",
                "actors": ["APT32", "Emotet", "Qakbot"],
                "detection": "High fan-out ratio: single source host attempting SYN connections to dozens of unique internal IPs.",
                "mitigation": "Segment subnets with zero-trust network access controls (micro-segmentation).",
                "snort": 'alert tcp $HOME_NET any -> $HOME_NET any (flags:S; threshold:type both, track by_src, count 25, seconds 5; msg:"NetGuard Internal Service Discovery"; sid:2000007;)',
                "iptables": "sudo iptables -A FORWARD -s 192.168.1.0/24 -d 10.0.0.0/24 -p tcp --dport 445 -j DROP",
                "trigger_keywords": ["discovery", "service", "portscan", "smb"],
            },
        ],
    },
    {
        "tactic_id": "TA0008",
        "tactic_name": "Lateral Movement",
        "icon": "↔️",
        "description": "Navigating through systems on a network to locate the adversary's primary objective.",
        "techniques": [
            {
                "id": "T1021",
                "name": "Remote Services",
                "sub": "T1021.002 (SMB/Windows Admin Shares)",
                "description": "Spreading eastward across network segments using SMB (port 445) or WMI to execute payloads on adjacent workstations.",
                "actors": ["WannaCry", "NotPetya", "LockBit"],
                "detection": "Sudden lateral SMB tree connect requests between workstation subnets without domain controller mediation.",
                "mitigation": "Block workstation-to-workstation SMB (port 445) traffic via internal VLAN segmentation.",
                "snort": 'alert tcp $HOME_WORKSTATIONS any -> $HOME_WORKSTATIONS 445 (msg:"NetGuard Peer SMB Lateral Movement"; sid:2000015;)',
                "iptables": "sudo iptables -A FORWARD -p tcp --dport 445 -s 192.168.20.0/24 -d 192.168.20.0/24 -j DROP",
                "trigger_keywords": ["lateral", "smb", "psexec", "wmi", "movement"],
            },
        ],
    },
    {
        "tactic_id": "TA0009",
        "tactic_name": "Collection",
        "icon": "📦",
        "description": "Gathering data of interest (credentials, sensitive intellectual property, documents) prior to exfiltration.",
        "techniques": [
            {
                "id": "T1005",
                "name": "Data from Local System",
                "sub": "T1005 (File Staging)",
                "description": "Harvesting proprietary databases, source code repositories, and user directories into local compressed archives.",
                "actors": ["Lapsus$", "FIN8"],
                "detection": "Rapid, sustained read operations on internal file servers followed by staging to a temporary staging host.",
                "mitigation": "Enforce strict least-privilege folder ACLs and continuous file integrity monitoring (FIM).",
                "snort": 'alert tcp $HOME_NET any -> $FILE_SERVERS [139,445] (msg:"NetGuard Mass File Access Staging"; threshold:type both, track by_src, count 100, seconds 10; sid:2000016;)',
                "iptables": "sudo iptables -A INPUT -p tcp --dport 445 -m connlimit --connlimit-above 15 -j REJECT",
                "trigger_keywords": ["collection", "staging", "harvest", "archive"],
            },
        ],
    },
    {
        "tactic_id": "TA0011",
        "tactic_name": "Command & Control",
        "icon": "📡",
        "description": "Adversaries communicating with compromised systems to direct actions.",
        "techniques": [
            {
                "id": "T1071",
                "name": "Application Layer Protocol",
                "sub": "T1071.001 (Web C2)",
                "description": "Using standard HTTP/HTTPS channels for periodic beaconing to C2 botnet controllers.",
                "actors": ["SolarWinds/UNC2452", "Conti", "TrickBot"],
                "detection": "Periodic heartbeat intervals (low variance in Flow IAT Mean) and consistent beacon payload lengths.",
                "mitigation": "Block known malicious threat intel C2 IPs and enforce outbound proxy SSL inspection.",
                "snort": 'alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"NetGuard Botnet Beaconing Observed"; flow:established,to_server; sid:2000008;)',
                "iptables": "sudo iptables -A OUTPUT -d 185.220.101.5 -j DROP",
                "trigger_keywords": ["botnet", "c2", "beacon", "command", "bot"],
            },
        ],
    },
    {
        "tactic_id": "TA0010",
        "tactic_name": "Exfiltration",
        "icon": "📤",
        "description": "Stealing data from your network via encrypted channels.",
        "techniques": [
            {
                "id": "T1041",
                "name": "Exfiltration Over C2 Channel",
                "sub": "T1041",
                "description": "Transmitting sensitive files, credentials, or databases to external attacker servers.",
                "actors": ["Clop Ransomware", "REvil"],
                "detection": "Asymmetric volume ratio: Forward packet length vastly exceeds backward length over sustained duration.",
                "mitigation": "Enforce egress data transfer caps and Data Loss Prevention (DLP) monitoring.",
                "snort": 'alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"NetGuard Massive Data Exfiltration"; flow:established; stream_size:client,>,10000000; sid:2000009;)',
                "iptables": "sudo iptables -A OUTPUT -p tcp -m quota --quota 52428800 -j ACCEPT",
                "trigger_keywords": ["exfiltration", "data theft", "upload"],
            },
        ],
    },
    {
        "tactic_id": "TA0040",
        "tactic_name": "Impact",
        "icon": "💥",
        "description": "Disrupting availability or destroying network integrity via Denial of Service.",
        "techniques": [
            {
                "id": "T1498",
                "name": "Network Denial of Service",
                "sub": "T1498.001 (Direct Flood DoS/DDoS)",
                "description": "Overwhelming network bandwidth or state tables with volumetric packet floods (SYN flood, UDP amplification, Slowloris).",
                "actors": ["Mirai", "Killnet", "Anonymous Sudan"],
                "detection": "Massive flow packets/sec (> 1,000 pps), high ratio of SYN flags, and zero backward return packets.",
                "mitigation": "Deploy BGP Anycast scrubbing, SYN proxy cookies, and upstream rate limiting.",
                "snort": 'alert tcp any any -> $HOME_NET 80 (flags:S; threshold:type threshold, track by_dst, count 500, seconds 2; msg:"NetGuard Volumetric SYN Flood DoS"; sid:2000010;)',
                "iptables": "sudo iptables -A INPUT -p tcp --syn -m limit --limit 50/s --limit-burst 100 -j ACCEPT; sudo iptables -A INPUT -p tcp --syn -j DROP",
                "trigger_keywords": ["dos", "ddos", "syn flood", "hulk", "goldeneye", "slowloris", "attack"],
            },
        ],
    },
]


def get_mitre_tactics_count():
    return len(MITRE_TACTICS_DB)


def get_mitre_techniques_count():
    return sum(len(t["techniques"]) for t in MITRE_TACTICS_DB)


def find_technique(tech_id: str):
    for tactic in MITRE_TACTICS_DB:
        for tech in tactic["techniques"]:
            if tech["id"].upper() == tech_id.upper():
                return tech, tactic
    return None, None
