"""
Packet analyzer: turns a raw Scapy packet into a simple, flat `PacketInfo`
record that the rest of the system understands.

Why? The detection engine should not care WHERE a packet came from (live
network card, PCAP file, CSV file or the simulator). Converting everything
to the same small record means one detection engine serves every source.
"""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass, fields
from datetime import datetime
from typing import Any

from utils.logger import get_logger

logger = get_logger(__name__)

# Well-known ports used to label application-layer protocols.
PORT_PROTOCOLS = {
    53: "DNS",
    80: "HTTP",
    8080: "HTTP",
    443: "HTTPS",
    22: "SSH",
    21: "FTP",
    23: "TELNET",
    25: "SMTP",
    3389: "RDP",
}

# Application labels that always run over TCP
TCP_APP_PROTOCOLS = {"TCP", "HTTP", "HTTPS", "SSH", "FTP", "TELNET", "SMTP", "RDP"}

# Scapy TCP flag letters -> human readable names
TCP_FLAG_NAMES = {
    "F": "FIN", "S": "SYN", "R": "RST", "P": "PSH",
    "A": "ACK", "U": "URG", "E": "ECE", "C": "CWR",
}


@dataclass
class PacketInfo:
    """One analysed packet. All fields are plain Python types."""

    timestamp: float            # UNIX epoch seconds
    src_ip: str
    dst_ip: str
    protocol: str               # TCP / UDP / ICMP / DNS / HTTP / HTTPS / ARP / OTHER
    src_port: int | None = None
    dst_port: int | None = None
    length: int = 0             # bytes on the wire
    tcp_flags: str = ""         # e.g. "S" (SYN), "SA" (SYN+ACK), "PA"
    icmp_type: int | None = None  # 8 = echo request, 0 = echo reply
    info: str = ""              # short human description
    source: str = "live"        # live / pcap / csv / simulated

    # ----- convenience helpers used by the detection rules -----
    @property
    def transport(self) -> str:
        """Underlying transport (DNS/HTTP map back to UDP/TCP)."""
        if self.tcp_flags or self.protocol in TCP_APP_PROTOCOLS:
            return "TCP"  # any packet with TCP flags is TCP (incl. DNS over TCP)
        if self.protocol in ("UDP", "DNS"):
            return "UDP"
        return self.protocol

    @property
    def is_syn(self) -> bool:
        """True for a connection-opening SYN (SYN set, ACK not set)."""
        return "S" in self.tcp_flags and "A" not in self.tcp_flags

    @property
    def is_icmp_echo_request(self) -> bool:
        return self.protocol == "ICMP" and self.icmp_type in (8, None)

    @property
    def time_str(self) -> str:
        return datetime.fromtimestamp(self.timestamp).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["time"] = self.time_str
        return data

    @classmethod
    def from_dict(cls, row: dict[str, Any]) -> "PacketInfo":
        """Build a PacketInfo from a CSV/DataFrame row (handles blanks & NaN)."""

        def _int_or_none(value: Any) -> int | None:
            if value is None or value == "":
                return None
            try:
                number = float(value)
            except (TypeError, ValueError):
                return None
            return None if math.isnan(number) else int(number)

        def _str(value: Any) -> str:
            if value is None or (isinstance(value, float) and math.isnan(value)):
                return ""
            return str(value)

        allowed = {f.name for f in fields(cls)}
        clean = {k: v for k, v in row.items() if k in allowed}
        return cls(
            timestamp=float(clean["timestamp"]),
            src_ip=_str(clean.get("src_ip")),
            dst_ip=_str(clean.get("dst_ip")),
            protocol=_str(clean.get("protocol")).upper() or "OTHER",
            src_port=_int_or_none(clean.get("src_port")),
            dst_port=_int_or_none(clean.get("dst_port")),
            length=_int_or_none(clean.get("length")) or 0,
            tcp_flags=_str(clean.get("tcp_flags")),
            icmp_type=_int_or_none(clean.get("icmp_type")),
            info=_str(clean.get("info")),
            source=_str(clean.get("source")) or "csv",
        )


def describe_tcp_flags(flags: str) -> str:
    """'SA' -> 'SYN,ACK'"""
    return ",".join(TCP_FLAG_NAMES.get(ch, ch) for ch in flags) if flags else ""


def _label_by_port(src_port: int | None, dst_port: int | None, default: str) -> str:
    for port in (dst_port, src_port):
        if port in PORT_PROTOCOLS:
            return PORT_PROTOCOLS[port]
    return default


def load_protocol_layers() -> None:
    """Register Ethernet/IP/IPv6/TCP/UDP/ICMP/DNS/ARP with Scapy.

    Scapy decodes a frame the moment it is captured or read from a file, using
    the layers imported AT THAT TIME. If they are not loaded yet, a frame is
    decoded as `Ether / Raw` and `analyze_packet()` cannot find the IP header.
    Call this before starting a live capture or reading a PCAP.
    """
    import scapy.layers.dns  # noqa: F401
    import scapy.layers.inet  # noqa: F401
    import scapy.layers.inet6  # noqa: F401
    import scapy.layers.l2  # noqa: F401


def analyze_packet(packet: Any, source: str = "live") -> PacketInfo | None:
    """Convert a Scapy packet to PacketInfo.

    Returns None for packets we cannot interpret (they are simply skipped).
    Scapy is imported lazily so the rest of the app loads fast.
    """
    from scapy.layers.dns import DNS
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import ARP

    try:
        timestamp = float(getattr(packet, "time", 0) or datetime.now().timestamp())
        length = len(packet)

        # ---------- ARP (layer 2, no IP header) ----------
        if packet.haslayer(ARP):
            arp = packet[ARP]
            op = "who-has" if arp.op == 1 else "is-at"
            return PacketInfo(
                timestamp=timestamp, src_ip=arp.psrc, dst_ip=arp.pdst,
                protocol="ARP", length=length,
                info=f"ARP {op} {arp.pdst}", source=source,
            )

        # ---------- Network layer: IPv4 or IPv6 ----------
        if packet.haslayer(IP):
            ip_layer = packet[IP]
        elif packet.haslayer(IPv6):
            ip_layer = packet[IPv6]
        else:
            return None  # not an IP packet (e.g. spanning-tree frames)

        src_ip, dst_ip = str(ip_layer.src), str(ip_layer.dst)

        # ---------- Transport layer ----------
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            flags = str(tcp.flags)
            sport, dport = int(tcp.sport), int(tcp.dport)
            protocol = _label_by_port(sport, dport, "TCP")
            info = f"{sport} -> {dport} [{describe_tcp_flags(flags)}]"
            # Plain-text HTTP request line, e.g. "GET /index.html HTTP/1.1"
            payload = bytes(tcp.payload)
            if payload[:4] in (b"GET ", b"POST", b"HEAD", b"PUT ") or payload[:5] == b"HTTP/":
                protocol = "HTTP"
                info = payload.split(b"\r\n", 1)[0].decode(errors="replace")[:80]
            return PacketInfo(
                timestamp=timestamp, src_ip=src_ip, dst_ip=dst_ip, protocol=protocol,
                src_port=sport, dst_port=dport, length=length, tcp_flags=flags,
                info=info, source=source,
            )

        if packet.haslayer(UDP):
            udp = packet[UDP]
            sport, dport = int(udp.sport), int(udp.dport)
            protocol = _label_by_port(sport, dport, "UDP")
            info = f"{sport} -> {dport}"
            if packet.haslayer(DNS):
                protocol = "DNS"
                dns = packet[DNS]
                # Newer Scapy stores questions as a list; older versions as one packet.
                questions = dns.qd if isinstance(dns.qd, list) else [dns.qd]
                if questions and questions[0] is not None:
                    try:
                        qname = questions[0].qname.decode(errors="replace").rstrip(".")
                        info = f"DNS {'response' if dns.qr else 'query'}: {qname}"
                    except AttributeError:
                        pass
            return PacketInfo(
                timestamp=timestamp, src_ip=src_ip, dst_ip=dst_ip, protocol=protocol,
                src_port=sport, dst_port=dport, length=length, info=info, source=source,
            )

        if packet.haslayer(ICMP):
            icmp = packet[ICMP]
            icmp_type = int(icmp.type)
            names = {0: "Echo Reply", 3: "Destination Unreachable", 8: "Echo Request",
                     11: "Time Exceeded"}
            return PacketInfo(
                timestamp=timestamp, src_ip=src_ip, dst_ip=dst_ip, protocol="ICMP",
                length=length, icmp_type=icmp_type,
                info=f"ICMP {names.get(icmp_type, f'type {icmp_type}')}", source=source,
            )

        return PacketInfo(
            timestamp=timestamp, src_ip=src_ip, dst_ip=dst_ip, protocol="OTHER",
            length=length, info=packet.summary()[:80], source=source,
        )
    except Exception as exc:  # malformed packet - never crash the capture loop
        logger.debug("Could not analyse packet: %s", exc)
        return None
