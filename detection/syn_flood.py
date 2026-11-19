"""
SYN Flood detection.

Idea: a TCP connection starts with the 3-way handshake SYN -> SYN/ACK -> ACK.
In a SYN flood (a Denial-of-Service attack) the attacker sends huge numbers
of SYN packets and never completes the handshake, filling the server's
table of half-open connections so real users cannot connect.

Logic: count TCP packets that have the SYN flag set and the ACK flag NOT set
(i.e. new connection requests) per source IP. If the count inside the
sliding window reaches `threshold`, raise an alert.
"""

from __future__ import annotations

from detection.base import Alert, DetectionRule, SlidingWindow
from monitoring.packet_analyzer import PacketInfo


class SynFloodRule(DetectionRule):
    name = "SYN Flood"
    description = ("Unusually high number of TCP SYN (connection request) packets "
                   "from a single source within a short time window.")

    def __init__(self, settings, cooldown_seconds=30.0):
        super().__init__(settings, cooldown_seconds)
        self.window = SlidingWindow(settings.window_seconds)

    def inspect(self, packet: PacketInfo) -> Alert | None:
        if packet.transport != "TCP" or not packet.is_syn:
            return None

        key = packet.src_ip
        self.window.window_seconds = self.settings.window_seconds
        self.window.add(key, packet.timestamp, packet.dst_ip)
        count = self.window.count(key)

        if count < self.settings.threshold or self.in_cooldown(key, packet.timestamp, count):
            return None

        targets = self.window.distinct_values(key)
        return self.make_alert(
            key, packet, observed=count,
            description=(f"Possible SYN flood: {count} TCP SYN packets from "
                         f"{packet.src_ip} within {self.settings.window_seconds:g}s"),
            details=(f"SYN count: {count}; threshold: {self.settings.threshold}; "
                     f"targets: {', '.join(sorted(targets)[:5])}"),
        )
