"""
NetGuard AI — 3D Global Threat Intelligence Map Engine
======================================================
Provides spatial telemetry aggregation, global threat vector tracking,
and geodesic arc calculations for real-time WebGL/Three.js cyber globe visualization.
"""

from __future__ import annotations

import datetime
import hashlib
import math
import random
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Tuple

from src.threat_intel import GEO_COORDINATE_POOL, threat_intel_engine


@dataclass
class ThreatEvent:
    event_id: str
    timestamp: str
    src_ip: str
    src_country: str
    src_country_code: str
    src_city: str
    src_lat: float
    src_lon: float
    dst_ip: str
    dst_city: str
    dst_lat: float
    dst_lon: float
    attack_type: str
    severity: str  # Critical, High, Medium, Low
    protocol: str  # TCP, UDP, ICMP
    bandwidth_mbps: float
    packet_rate_kpps: float
    mitre_tactic: str
    status: str  # BLOCKED, INTERCEPTED, ANALYZING


# Default Security Operations Center (SOC) Perimeter Headquarters
DEFAULT_SOC_LOCATION = {
    "name": "NetGuard Central Defense HQ",
    "city": "Silicon Valley",
    "country": "United States",
    "lat": 37.3861,
    "lon": -122.0839,
    "ip": "192.168.1.1",
}

COMMON_ATTACK_VECTORS = [
    ("DDoS Amplification (SSDP/DNS)", "Critical", "UDP", "Impact / T1498"),
    ("Cobalt Strike C2 Beacon", "Critical", "TCP", "Command and Control / T1071"),
    ("SQL Injection / Data Exfiltration", "High", "TCP", "Exfiltration / T1048"),
    ("Brute Force SSH Auth Spray", "High", "TCP", "Credential Access / T1110"),
    ("Zero-Day Exploitation Attempt", "Critical", "TCP", "Exploitation / T1190"),
    ("Mirai Botnet SYN Flood", "Critical", "TCP", "Impact / T1498"),
    ("Automated Port Sweep / Nmap", "Medium", "TCP", "Discovery / T1046"),
    ("Fast-Flux DNS Tunneling", "High", "UDP", "Command and Control / T1568"),
    ("Ransomware Lateral Sweep", "Critical", "TCP", "Lateral Movement / T1021"),
    ("XSS / CSRF Perimeter Probe", "Low", "TCP", "Initial Access / T1189"),
]


class ThreatMapEngine:
    """
    Stateful engine managing active cyber attacks across global coordinates.
    Computes geodesic arcs, top threat origins, and real-time visualization feeds.
    """

    def __init__(self, soc_location: Optional[Dict[str, Any]] = None, max_history: int = 250):
        self.soc_location = soc_location or DEFAULT_SOC_LOCATION
        self.max_history = max_history
        self._history: List[ThreatEvent] = []
        self._seed_baseline_threats(count=35)

    def _seed_baseline_threats(self, count: int = 35) -> None:
        """Seed initial threat events across diverse global coordinates."""
        seed_count = min(count, self.max_history)
        now = datetime.datetime.now(datetime.timezone.utc)
        for i in range(seed_count):
            event_time = now - datetime.timedelta(seconds=seed_count * 8 - i * 8)
            event = self.generate_synthetic_event(timestamp=event_time.strftime("%H:%M:%S"))
            self.record_event(event)

    def generate_synthetic_event(
        self,
        timestamp: Optional[str] = None,
        force_critical: bool = False,
        fixed_country: Optional[str] = None,
    ) -> ThreatEvent:
        """Generates a realistic threat event originating from a global endpoint."""
        now_str = timestamp or datetime.datetime.now(datetime.timezone.utc).strftime("%H:%M:%S")

        # Pick origin coordinate
        if fixed_country:
            matching = [p for p in GEO_COORDINATE_POOL if p["country"].lower() == fixed_country.lower()]
            loc = matching[0] if matching else random.choice(GEO_COORDINATE_POOL)
        else:
            loc = random.choice(GEO_COORDINATE_POOL)

        # Generate realistic public IP from the country
        octets = [
            str(random.randint(45, 215)),
            str(random.randint(10, 250)),
            str(random.randint(1, 254)),
            str(random.randint(1, 254)),
        ]
        src_ip = ".".join(octets)

        # Pick attack vector
        vector = random.choice(COMMON_ATTACK_VECTORS)
        attack_type, severity, protocol, mitre = vector

        if force_critical:
            severity = "Critical"

        bandwidth = round(random.uniform(15.0, 950.0) if severity in ("Critical", "High") else random.uniform(0.5, 25.0), 2)
        packet_rate = round(bandwidth * random.uniform(0.8, 1.4), 2)

        event_id = hashlib.md5(f"{src_ip}-{now_str}-{random.random()}".encode("utf-8")).hexdigest()[:8]
        status = "BLOCKED" if severity in ("Critical", "High") else random.choice(["BLOCKED", "INTERCEPTED", "ANALYZING"])

        return ThreatEvent(
            event_id=f"EVT-{event_id.upper()}",
            timestamp=now_str,
            src_ip=src_ip,
            src_country=loc["country"],
            src_country_code=loc["code"],
            src_city=loc["city"],
            src_lat=loc["lat"] + random.uniform(-0.5, 0.5),
            src_lon=loc["lon"] + random.uniform(-0.5, 0.5),
            dst_ip=self.soc_location["ip"],
            dst_city=self.soc_location["city"],
            dst_lat=self.soc_location["lat"],
            dst_lon=self.soc_location["lon"],
            attack_type=attack_type,
            severity=severity,
            protocol=protocol,
            bandwidth_mbps=bandwidth,
            packet_rate_kpps=packet_rate,
            mitre_tactic=mitre,
            status=status,
        )

    def record_event(self, event: ThreatEvent) -> None:
        """Appends a new event and keeps the ring buffer within max_history."""
        self._history.append(event)
        if len(self._history) > self.max_history:
            self._history.pop(0)

    def pulse_attack(self, count: int = 1) -> List[ThreatEvent]:
        """Triggers a live pulse of simulated cyber attacks."""
        new_events = [self.generate_synthetic_event() for _ in range(count)]
        for ev in new_events:
            self.record_event(ev)
        return new_events

    def get_recent_events(self, limit: int = 50, severity_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """Returns recent threat events as dictionaries, optionally filtered."""
        events = self._history
        if severity_filter and severity_filter.lower() != "all":
            events = [e for e in events if e.severity.lower() == severity_filter.lower()]
        
        selected = events[-limit:] if limit > 0 else events
        return [asdict(e) for e in reversed(selected)]

    def get_top_origin_countries(self, limit: int = 6) -> List[Dict[str, Any]]:
        """Aggregates attack volume and critical count by source country."""
        country_counts: Dict[str, Dict[str, Any]] = {}

        for ev in self._history:
            c = ev.src_country
            code = ev.src_country_code
            if c not in country_counts:
                country_counts[c] = {
                    "country": c,
                    "code": code,
                    "total_attacks": 0,
                    "critical_attacks": 0,
                    "total_mbps": 0.0,
                    "lat": ev.src_lat,
                    "lon": ev.src_lon,
                }
            country_counts[c]["total_attacks"] += 1
            if ev.severity == "Critical":
                country_counts[c]["critical_attacks"] += 1
            country_counts[c]["total_mbps"] += ev.bandwidth_mbps

        sorted_countries = sorted(
            country_counts.values(),
            key=lambda x: (x["critical_attacks"], x["total_attacks"]),
            reverse=True,
        )
        return sorted_countries[:limit]

    def get_threat_arc_data(self, limit: int = 40) -> List[Dict[str, Any]]:
        """
        Formats threat arcs for Three.js 3D Earth visualization.
        Produces source/destination lat/lon, altitude curve, and color coding.
        """
        recent = self._history[-limit:] if limit > 0 else self._history
        arcs = []

        severity_colors = {
            "Critical": "#ef4444",  # Crimson Red
            "High": "#f97316",      # Bright Orange
            "Medium": "#eab308",    # Cyber Amber
            "Low": "#10b981",       # Neon Emerald
        }

        for ev in recent:
            color = severity_colors.get(ev.severity, "#ef4444")
            arcs.append({
                "id": ev.event_id,
                "src_lat": ev.src_lat,
                "src_lon": ev.src_lon,
                "src_city": ev.src_city,
                "src_country": ev.src_country,
                "dst_lat": ev.dst_lat,
                "dst_lon": ev.dst_lon,
                "dst_city": ev.dst_city,
                "severity": ev.severity,
                "color": color,
                "attack_type": ev.attack_type,
                "bandwidth_mbps": ev.bandwidth_mbps,
                "status": ev.status,
            })
        return arcs

    def get_summary_metrics(self) -> Dict[str, Any]:
        """Calculates global posture indicators."""
        total = len(self._history)
        critical = sum(1 for e in self._history if e.severity == "Critical")
        blocked = sum(1 for e in self._history if e.status == "BLOCKED")
        total_bw = sum(e.bandwidth_mbps for e in self._history)
        unique_countries = len(set(e.src_country for e in self._history))

        dominant_type = "None"
        if self._history:
            types = [e.attack_type for e in self._history]
            dominant_type = max(set(types), key=types.count)

        return {
            "total_events": total,
            "critical_events": critical,
            "blocked_events": blocked,
            "mitigation_rate": round((blocked / total * 100) if total > 0 else 100.0, 1),
            "total_bandwidth_gbps": round(total_bw / 1024.0, 2),
            "unique_countries": unique_countries,
            "dominant_threat": dominant_type,
            "soc_hq": self.soc_location["name"],
        }


# Singleton instance
global_threat_map_engine = ThreatMapEngine()
