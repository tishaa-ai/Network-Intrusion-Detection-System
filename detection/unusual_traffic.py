"""
Unusual Traffic (abnormal packet rate) detection.

Idea: a generic "volume" rule. Even if traffic doesn't match a specific
attack signature, a single host suddenly sending far more packets than
usual (data exfiltration, malware spreading, a misbehaving app ...) is worth
an analyst's attention.

Logic: count ALL packets per source IP inside the sliding window. If the
count reaches `threshold`, raise an alert including the packet rate.
"""

from __future__ import annotations

from detection.base import Alert, DetectionRule, SlidingWindow
from monitoring.packet_analyzer import PacketInfo


class UnusualTrafficRule(DetectionRule):
    name = "Unusual Traffic"
    description = ("Abnormally high packet rate (any protocol) from a single source "
                   "within a short time window.")

    def __init__(self, settings, cooldown_seconds=30.0):
        super().__init__(settings, cooldown_seconds)
        self.window = SlidingWindow(settings.window_seconds)

    def inspect(self, packet: PacketInfo) -> Alert | None:
        key = packet.src_ip
        self.window.window_seconds = self.settings.window_seconds
        self.window.add(key, packet.timestamp)
        count = self.window.count(key)

        if count < self.settings.threshold or self.in_cooldown(key, packet.timestamp, count):
            return None

        rate = count / self.settings.window_seconds
        return self.make_alert(
            key, packet, observed=count,
            description=(f"Abnormal traffic rate: {packet.src_ip} sent {count} packets "
                         f"in {self.settings.window_seconds:g}s (~{rate:.0f} pkt/s)"),
            details=f"Packets: {count}; threshold: {self.settings.threshold}",
        )
