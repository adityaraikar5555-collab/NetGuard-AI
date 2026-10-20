"""
Pure-Python PCAP / PCAPNG Ingestion and Bidirectional Flow Reconstructor for NetGuard AI.

Reads raw Wireshark/tcpdump .pcap binary files and aggregates packets into
bidirectional network flows, extracting CICIDS-2017 & NSL-KDD compatible flow features.
Zero external system dependencies required.
"""

from io import BytesIO
from pathlib import Path
import struct
from typing import Any, Dict, List, Optional, Tuple, Union
import numpy as np
import pandas as pd


class PCAPExtractor:
    """
    Parses standard PCAP capture files and constructs statistical bidirectional flows.
    """

    def parse_file(self, file_source: Union[str, Path, bytes, BytesIO], max_packets: int = 15000) -> pd.DataFrame:
        """
        Parses a PCAP file or byte buffer into a DataFrame of bidirectional network flows.
        """
        raw_bytes = None
        if isinstance(file_source, (str, Path)):
            with open(file_source, "rb") as f:
                raw_bytes = f.read()
        elif isinstance(file_source, BytesIO):
            raw_bytes = file_source.getvalue()
        elif isinstance(file_source, bytes):
            raw_bytes = file_source
        else:
            raise ValueError("Unsupported file source for PCAP parser.")

        packets = self._extract_packets(raw_bytes, max_packets)
        if not packets:
            return pd.DataFrame()

        flows = self._aggregate_into_flows(packets)
        return flows

    def _extract_packets(self, data: bytes, max_packets: int) -> List[Dict[str, Any]]:
        """Parses Ethernet/IP packets from PCAP binary data."""
        if len(data) < 24:
            return []

        # Check PCAP Global Header magic
        magic_bytes = data[:4]
        if magic_bytes in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
            endian = "<"
        elif magic_bytes in (b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1"):
            endian = ">"
        else:
            endian = "<"

        offset = 24
        packets = []

        while offset + 16 <= len(data) and len(packets) < max_packets:
            hdr = data[offset : offset + 16]
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f"{endian}IIII", hdr)
            offset += 16

            if offset + incl_len > len(data):
                break

            pkt_payload = data[offset : offset + incl_len]
            offset += incl_len

            parsed_pkt = self._parse_ethernet_frame(pkt_payload, float(ts_sec) + float(ts_usec) * 1e-6)
            if parsed_pkt:
                packets.append(parsed_pkt)

        return packets

    def _parse_ethernet_frame(self, data: bytes, timestamp: float) -> Optional[Dict[str, Any]]:
        """Extracts IPv4/TCP/UDP packet attributes from Ethernet frame."""
        if len(data) < 14:
            return None

        eth_type = struct.unpack("!H", data[12:14])[0]
        ip_offset = 14

        # 802.1Q VLAN tag check
        if eth_type == 0x8100:
            eth_type = struct.unpack("!H", data[16:18])[0]
            ip_offset = 18

        if eth_type != 0x0800:  # IPv4 only
            return None

        if len(data) < ip_offset + 20:
            return None

        ip_hdr = data[ip_offset : ip_offset + 20]
        ihl = (ip_hdr[0] & 0x0F) * 4
        total_len = struct.unpack("!H", ip_hdr[2:4])[0]
        protocol = ip_hdr[9]
        src_ip = ".".join(str(b) for b in ip_hdr[12:16])
        dst_ip = ".".join(str(b) for b in ip_hdr[16:20])

        proto_name = "OTHER"
        src_port = 0
        dst_port = 0
        tcp_flags = {"SYN": 0, "FIN": 0, "RST": 0, "PSH": 0, "ACK": 0, "URG": 0}

        l4_offset = ip_offset + ihl
        if protocol == 6 and len(data) >= l4_offset + 20:  # TCP
            proto_name = "TCP"
            tcp_hdr = data[l4_offset : l4_offset + 20]
            src_port, dst_port = struct.unpack("!HH", tcp_hdr[:4])
            flag_byte = tcp_hdr[13]
            tcp_flags = {
                "FIN": 1 if flag_byte & 0x01 else 0,
                "SYN": 1 if flag_byte & 0x02 else 0,
                "RST": 1 if flag_byte & 0x04 else 0,
                "PSH": 1 if flag_byte & 0x08 else 0,
                "ACK": 1 if flag_byte & 0x10 else 0,
                "URG": 1 if flag_byte & 0x20 else 0,
            }
        elif protocol == 17 and len(data) >= l4_offset + 8:  # UDP
            proto_name = "UDP"
            udp_hdr = data[l4_offset : l4_offset + 8]
            src_port, dst_port = struct.unpack("!HH", udp_hdr[:4])

        return {
            "timestamp": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": proto_name,
            "length": total_len or len(data),
            "flags": tcp_flags,
        }

    def _aggregate_into_flows(self, packets: List[Dict[str, Any]]) -> pd.DataFrame:
        """Groups packets into bidirectional flows and computes statistical features."""
        flow_groups: Dict[Tuple, List[Dict[str, Any]]] = {}

        for p in packets:
            # 5-tuple session key
            ep1 = (p["src_ip"], p["src_port"])
            ep2 = (p["dst_ip"], p["dst_port"])
            if ep1 <= ep2:
                key = (p["src_ip"], p["dst_ip"], p["src_port"], p["dst_port"], p["protocol"])
                direction = "fwd"
            else:
                key = (p["dst_ip"], p["src_ip"], p["dst_port"], p["src_port"], p["protocol"])
                direction = "bwd"

            p["dir"] = direction
            flow_groups.setdefault(key, []).append(p)

        rows = []
        for key, pkts in flow_groups.items():
            src_ip, dst_ip, src_port, dst_port, proto = key
            fwd_pkts = [p for p in pkts if p["dir"] == "fwd"]
            bwd_pkts = [p for p in pkts if p["dir"] == "bwd"]

            timestamps = [p["timestamp"] for p in pkts]
            duration = max(1.0, (max(timestamps) - min(timestamps)) * 1e6)  # microseconds

            fwd_lengths = [p["length"] for p in fwd_pkts] or [0]
            bwd_lengths = [p["length"] for p in bwd_pkts] or [0]
            all_lengths = [p["length"] for p in pkts]

            fwd_bytes = sum(fwd_lengths)
            bwd_bytes = sum(bwd_lengths)
            total_bytes = fwd_bytes + bwd_bytes
            total_pkts = len(pkts)

            syn_count = sum(p["flags"]["SYN"] for p in pkts)
            rst_count = sum(p["flags"]["RST"] for p in pkts)
            ack_count = sum(p["flags"]["ACK"] for p in pkts)
            psh_count = sum(p["flags"]["PSH"] for p in pkts)
            fin_count = sum(p["flags"]["FIN"] for p in pkts)

            # Build record with CICIDS-2017 naming
            row = {
                "Source IP": src_ip,
                "Destination IP": dst_ip,
                "Source Port": src_port,
                "Destination Port": dst_port,
                "Protocol": proto,
                "Flow Duration": duration,
                "Total Fwd Packets": len(fwd_pkts),
                "Total Backward Packets": len(bwd_pkts),
                "Total Length of Fwd Packets": fwd_bytes,
                "Total Length of Bwd Packets": bwd_bytes,
                "Fwd Packet Length Max": float(max(fwd_lengths)),
                "Fwd Packet Length Min": float(min(fwd_lengths)),
                "Fwd Packet Length Mean": float(np.mean(fwd_lengths)),
                "Bwd Packet Length Max": float(max(bwd_lengths)),
                "Bwd Packet Length Min": float(min(bwd_lengths)),
                "Bwd Packet Length Mean": float(np.mean(bwd_lengths)),
                "Flow Bytes/s": float(total_bytes / (duration / 1e6)),
                "Flow Packets/s": float(total_pkts / (duration / 1e6)),
                "Flow IAT Mean": float(duration / max(1, total_pkts - 1)),
                "Fwd IAT Total": float(duration if len(fwd_pkts) > 1 else 0),
                "Bwd IAT Total": float(duration if len(bwd_pkts) > 1 else 0),
                "SYN Flag Count": syn_count,
                "RST Flag Count": rst_count,
                "ACK Flag Count": ack_count,
                "PSH Flag Count": psh_count,
                "FIN Flag Count": fin_count,
                "Average Packet Size": float(np.mean(all_lengths)),
                "Down/Up Ratio": float(len(bwd_pkts) / max(1, len(fwd_pkts))),
            }
            rows.append(row)

        return pd.DataFrame(rows)


pcap_extractor = PCAPExtractor()
