"""
Offline demo traffic.

Three offline sources feed the SAME detection engine used for live capture:

1. `generate_synthetic_traffic()` - builds realistic packet records in memory:
   normal browsing/DNS traffic plus a port scan, a SYN flood, an ICMP flood
   and beaconing to a watch-listed IP. Nothing is ever sent on the network.
2. `load_csv_file()`  - replays packet records from data/sample_traffic.csv.
3. `load_pcap_file()` - replays a real PCAP file (e.g. saved from Wireshark).
   Each packet goes through the real Scapy packet analyzer.

All simulated packets carry source="simulated" (or "csv"/"pcap") so every
alert they produce is clearly labelled as NOT coming from live traffic.

The scenario uses private (192.168.x.x / 10.x.x.x) and RFC 5737 documentation
addresses (192.0.2.x, 198.51.100.x, 203.0.113.x) which never route publicly.
"""

from __future__ import annotations

import random
import time
from pathlib import Path

import pandas as pd

from monitoring.packet_analyzer import (PacketInfo, _label_by_port, analyze_packet,
                                       load_protocol_layers)
from utils.logger import get_logger

logger = get_logger(__name__)

# ----- addresses used in the demo scenario -----
LAN_HOSTS = [f"192.168.1.{i}" for i in range(10, 26)]
DNS_SERVER = "192.168.1.1"
WEB_SERVERS = ["93.184.216.34", "151.101.1.69", "104.16.132.229"]

PORT_SCANNER = "10.0.0.66"
SCAN_TARGET = "192.168.1.10"
SYN_FLOODER = "203.0.113.50"
SYN_TARGET = "192.168.1.20"
ICMP_FLOODER = "198.51.100.23"
ICMP_TARGET = "192.168.1.15"
C2_SERVER = "203.0.113.66"      # present in config.DEFAULT_SUSPICIOUS_IPS
INFECTED_HOST = "192.168.1.12"

DOMAINS = ["example.com", "github.com", "python.org", "wikipedia.org", "stackoverflow.com"]

# Column order for the CSV file
CSV_COLUMNS = ["timestamp", "src_ip", "dst_ip", "protocol", "src_port", "dst_port",
               "length", "tcp_flags", "icmp_type", "info", "source"]


# ------------------------------------------------------------- builders
def _tcp(ts, src, dst, sport, dport, flags, length=60, info="", source="simulated"):
    protocol = _label_by_port(sport, dport, "TCP")
    return PacketInfo(timestamp=round(ts, 6), src_ip=src, dst_ip=dst, protocol=protocol,
                      src_port=sport, dst_port=dport, length=length, tcp_flags=flags,
                      info=info or f"{sport} -> {dport} [{flags}]", source=source)


def _udp(ts, src, dst, sport, dport, length=80, info="", source="simulated"):
    protocol = _label_by_port(sport, dport, "UDP")
    return PacketInfo(timestamp=round(ts, 6), src_ip=src, dst_ip=dst, protocol=protocol,
                      src_port=sport, dst_port=dport, length=length,
                      info=info or f"{sport} -> {dport}", source=source)


def _icmp(ts, src, dst, icmp_type=8, length=74, source="simulated"):
    label = "Echo Request" if icmp_type == 8 else "Echo Reply"
    return PacketInfo(timestamp=round(ts, 6), src_ip=src, dst_ip=dst, protocol="ICMP",
                      length=length, icmp_type=icmp_type, info=f"ICMP {label}",
                      source=source)


# ------------------------------------------------------------- scenario
def generate_synthetic_traffic(start_time: float | None = None, duration: float = 60.0,
                               seed: int = 42, include_attacks: bool = True) -> list[PacketInfo]:
    """Return a time-ordered list of simulated packets.

    Timeline (seconds after start):
        0-60   normal traffic (DNS, HTTPS, HTTP, occasional ping)
        0-60   infected host beacons to a watch-listed C2 IP every 8 s
        10     port scan   10.0.0.66      -> 192.168.1.10 (90 ports in ~1.8 s)
        25     SYN flood   203.0.113.50   -> 192.168.1.20:80 (600 SYNs in 5 s)
        40     ICMP flood  198.51.100.23  -> 192.168.1.15 (400 pings in 4 s)
    """
    rng = random.Random(seed)
    t0 = time.time() - duration if start_time is None else start_time
    packets: list[PacketInfo] = []

    # ---- 1. normal background traffic ----
    t = t0
    while t < t0 + duration:
        t += rng.expovariate(4.0)  # ~4 "conversations" per second
        host = rng.choice(LAN_HOSTS)
        sport = rng.randint(49152, 65535)
        kind = rng.random()
        if kind < 0.35:  # DNS query + response
            domain = rng.choice(DOMAINS)
            packets.append(_udp(t, host, DNS_SERVER, sport, 53, 72, f"DNS query: {domain}"))
            packets.append(_udp(t + 0.01, DNS_SERVER, host, 53, sport, 120,
                                f"DNS response: {domain}"))
        elif kind < 0.85:  # HTTPS connection: handshake + data
            server = rng.choice(WEB_SERVERS)
            packets += [
                _tcp(t, host, server, sport, 443, "S", 66),
                _tcp(t + 0.02, server, host, 443, sport, "SA", 66),
                _tcp(t + 0.03, host, server, sport, 443, "A", 54),
                _tcp(t + 0.05, host, server, sport, 443, "PA", rng.randint(300, 900)),
                _tcp(t + 0.09, server, host, 443, sport, "PA", rng.randint(800, 1500)),
            ]
        elif kind < 0.95:  # plain HTTP request
            server = rng.choice(WEB_SERVERS)
            packets += [
                _tcp(t, host, server, sport, 80, "S", 66),
                _tcp(t + 0.02, server, host, 80, sport, "SA", 66),
                _tcp(t + 0.04, host, server, sport, 80, "PA", 420, "GET /index.html HTTP/1.1"),
                _tcp(t + 0.08, server, host, 80, sport, "PA", 1400, "HTTP/1.1 200 OK"),
            ]
        else:  # a normal, occasional ping
            server = rng.choice(WEB_SERVERS)
            packets.append(_icmp(t, host, server, 8))
            packets.append(_icmp(t + 0.015, server, host, 0))

    # ---- 2. beaconing to a watch-listed command-and-control server ----
    for i in range(int(duration // 8)):
        t = t0 + 2 + i * 8
        sport = rng.randint(49152, 65535)
        packets.append(_tcp(t, INFECTED_HOST, C2_SERVER, sport, 4444, "S", 66,
                            "Beacon to C2 server"))
        packets.append(_tcp(t + 0.05, C2_SERVER, INFECTED_HOST, 4444, sport, "SA", 66))

    if include_attacks:
        # ---- 3. port scan: one SYN to each of 90 ports, target answers RST ----
        # (kept below the SYN-flood threshold so each attack maps to one rule)
        t = t0 + 10
        ports = list(range(1, 91))
        rng.shuffle(ports)
        for port in ports:
            t += 0.02
            sport = rng.randint(40000, 60000)
            packets.append(_tcp(t, PORT_SCANNER, SCAN_TARGET, sport, port, "S", 58))
            reply = "SA" if port in (22, 80, 443) else "RA"
            packets.append(_tcp(t + 0.001, SCAN_TARGET, PORT_SCANNER, port, sport, reply, 54))

        # ---- 4. SYN flood: 600 SYNs, never completing the handshake ----
        t = t0 + 25
        for _ in range(600):
            t += 5.0 / 600
            packets.append(_tcp(t, SYN_FLOODER, SYN_TARGET, rng.randint(1024, 65535),
                                80, "S", 60))

        # ---- 5. ICMP flood: 400 echo requests ----
        t = t0 + 40
        for _ in range(400):
            t += 4.0 / 400
            packets.append(_icmp(t, ICMP_FLOODER, ICMP_TARGET, 8, 1042))

    packets = [p for p in packets if p.timestamp <= t0 + duration + 1]
    packets.sort(key=lambda p: p.timestamp)
    logger.info("Generated %d simulated packets", len(packets))
    return packets


# ------------------------------------------------------------- CSV
def packets_to_dataframe(packets: list[PacketInfo]) -> pd.DataFrame:
    if not packets:
        return pd.DataFrame(columns=CSV_COLUMNS)
    return pd.DataFrame([p.to_dict() for p in packets])


def save_csv_file(packets: list[PacketInfo], path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    df = packets_to_dataframe(packets)[CSV_COLUMNS]
    df.to_csv(path, index=False)
    return path


def load_csv_file(path: str | Path, source_label: str = "csv") -> list[PacketInfo]:
    """Load packet records from CSV. Required columns: timestamp, src_ip, dst_ip, protocol."""
    df = pd.read_csv(path)
    missing = {"timestamp", "src_ip", "dst_ip", "protocol"} - set(df.columns)
    if missing:
        raise ValueError(f"CSV file is missing required columns: {', '.join(sorted(missing))}")
    packets = []
    for row in df.to_dict(orient="records"):
        try:
            packet = PacketInfo.from_dict(row)
        except (KeyError, TypeError, ValueError) as exc:
            logger.debug("Skipping bad CSV row %s: %s", row, exc)
            continue
        packet.source = source_label
        packets.append(packet)
    packets.sort(key=lambda p: p.timestamp)
    logger.info("Loaded %d packets from %s", len(packets), path)
    return packets


# ------------------------------------------------------------- PCAP
def packet_info_to_scapy(p: PacketInfo):
    """Rebuild a Scapy packet from a PacketInfo (used to write the sample PCAP)."""
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.l2 import Ether
    from scapy.packet import Raw

    # Fixed MAC addresses: avoids Scapy trying to resolve them on the network.
    base = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src=p.src_ip,
                                                                         dst=p.dst_ip)
    if p.tcp_flags:
        pkt = base / TCP(sport=p.src_port, dport=p.dst_port, flags=p.tcp_flags)
        if p.protocol == "HTTP" and p.info.startswith(("GET", "HTTP/")):
            pkt = pkt / Raw(load=(p.info + "\r\nHost: example.com\r\n\r\n").encode())
    elif p.protocol == "DNS":
        is_response = p.info.startswith("DNS response")
        qname = p.info.split(": ", 1)[-1] if ": " in p.info else "example.com"
        pkt = base / UDP(sport=p.src_port, dport=p.dst_port) / DNS(
            rd=1, qr=int(is_response), qd=[DNSQR(qname=qname)])
    elif p.protocol in ("UDP",) or p.src_port is not None:
        pkt = base / UDP(sport=p.src_port, dport=p.dst_port)
    elif p.protocol == "ICMP":
        pkt = base / ICMP(type=p.icmp_type if p.icmp_type is not None else 8)
    else:
        pkt = base
    pkt.time = p.timestamp
    return pkt


def save_pcap_file(packets: list[PacketInfo], path: str | Path) -> Path:
    """Write packets to a PCAP file (writing a file does NOT send any traffic)."""
    from scapy.utils import wrpcap

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(path), [packet_info_to_scapy(p) for p in packets])
    return path


def load_pcap_file(path: str | Path, max_packets: int = 200_000) -> list[PacketInfo]:
    """Read a PCAP/PCAPNG file and analyse every packet with the real analyzer."""
    # Register Ethernet/IP/TCP... with Scapy so the reader decodes packets
    # instead of returning raw bytes.
    load_protocol_layers()
    from scapy.utils import PcapReader

    packets: list[PacketInfo] = []
    with PcapReader(str(path)) as reader:
        for index, raw in enumerate(reader):
            if index >= max_packets:
                logger.warning("PCAP truncated at %d packets", max_packets)
                break
            info = analyze_packet(raw, source="pcap")
            if info is not None:
                packets.append(info)
    packets.sort(key=lambda p: p.timestamp)
    logger.info("Loaded %d packets from PCAP %s", len(packets), path)
    return packets
