"""
ICMP Flood (ping flood) detection.

Idea: `ping` sends ICMP Echo Request packets. A few are normal for
troubleshooting; thousands per second from one host is a flood meant to
exhaust bandwidth or CPU on the target.

Logic: count ICMP Echo Requests (type 8) per source IP inside the sliding
window. If the count reaches `threshold`, raise an alert.
"""

from __future__ import annotations

from detection.base import Alert, DetectionRule, SlidingWindow
from monitoring.packet_analyzer import PacketInfo


class IcmpFloodRule(DetectionRule):
    name = "ICMP Flood"
    description = ("Unusually high number of ICMP Echo Request (ping) packets from a "
                   "single source within a short time window.")

    def __init__(self, settings, cooldown_seconds=30.0):
        super().__init__(settings, cooldown_seconds)
        self.window = SlidingWindow(settings.window_seconds)

    def inspect(self, packet: PacketInfo) -> Alert | None:
        if not packet.is_icmp_echo_request:
            return None

        key = packet.src_ip
        self.window.window_seconds = self.settings.window_seconds
        self.window.add(key, packet.timestamp, packet.dst_ip)
        count = self.window.count(key)

        if count < self.settings.threshold or self.in_cooldown(key, packet.timestamp, count):
            return None

        return self.make_alert(
            key, packet, observed=count,
            description=(f"Possible ICMP flood: {count} ping requests from "
                         f"{packet.src_ip} within {self.settings.window_seconds:g}s"),
            details=f"ICMP echo requests: {count}; threshold: {self.settings.threshold}",
        )
