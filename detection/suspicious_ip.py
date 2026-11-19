"""
Suspicious IP detection (watch-list / blacklist).

Idea: threat-intelligence feeds publish IP addresses known to be malicious
(botnet C2 servers, scanners, Tor exit nodes ...). Any communication with
such an address deserves an alert, whichever direction it goes.

Logic: if the packet's source OR destination IP is in the watch-list, raise
an alert (once per IP per cooldown period to avoid alert floods).
"""

from __future__ import annotations

import ipaddress

from detection.base import Alert, DetectionRule
from monitoring.packet_analyzer import PacketInfo
from utils.logger import get_logger

logger = get_logger(__name__)


def normalize_ip_list(ips) -> set[str]:
    """Validate a list of IPs; invalid entries are logged and skipped."""
    valid = set()
    for raw in ips:
        text = str(raw).strip()
        if not text:
            continue
        try:
            valid.add(str(ipaddress.ip_address(text)))
        except ValueError:
            logger.warning("Ignoring invalid suspicious IP entry: %r", text)
    return valid


class SuspiciousIPRule(DetectionRule):
    name = "Suspicious IP"
    description = "Traffic to or from an IP address on the configured watch-list."

    def __init__(self, settings, cooldown_seconds=30.0, suspicious_ips=None):
        super().__init__(settings, cooldown_seconds)
        self.suspicious_ips = normalize_ip_list(suspicious_ips or [])

    def set_ips(self, ips) -> None:
        self.suspicious_ips = normalize_ip_list(ips)

    def inspect(self, packet: PacketInfo) -> Alert | None:
        if packet.src_ip in self.suspicious_ips:
            bad_ip, direction = packet.src_ip, "inbound from"
        elif packet.dst_ip in self.suspicious_ips:
            bad_ip, direction = packet.dst_ip, "outbound to"
        else:
            return None

        if self.in_cooldown(bad_ip, packet.timestamp):
            return None

        port = f" port {packet.dst_port}" if packet.dst_port is not None else ""
        return self.make_alert(
            bad_ip, packet, observed=1,
            description=(f"Traffic {direction} watch-listed IP {bad_ip} "
                         f"({packet.protocol}{port})"),
            details=f"{packet.src_ip} -> {packet.dst_ip}; {packet.info}",
        )
