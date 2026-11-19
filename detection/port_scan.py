"""
Port Scan detection.

Idea: a normal client talks to a few ports on a server (80, 443 ...).
A scanner such as Nmap probes MANY different ports on the same host in a
short time to discover which services are open.

Logic: for every (source IP -> destination IP) pair, remember which
destination ports were contacted in the last `window_seconds`. If the number
of DISTINCT ports reaches `threshold`, raise an alert.

We count TCP SYN packets (connection attempts) and UDP packets, which covers
the most common scan types (TCP SYN/connect scan and UDP scan).
"""

from __future__ import annotations

from detection.base import Alert, DetectionRule, SlidingWindow
from monitoring.packet_analyzer import PacketInfo


class PortScanRule(DetectionRule):
    name = "Port Scan"
    description = ("Many different destination ports contacted on one host by the "
                   "same source within a short time window.")

    def __init__(self, settings, cooldown_seconds=30.0):
        super().__init__(settings, cooldown_seconds)
        self.window = SlidingWindow(settings.window_seconds)

    def inspect(self, packet: PacketInfo) -> Alert | None:
        if packet.dst_port is None:
            return None
        is_tcp_attempt = packet.transport == "TCP" and packet.is_syn
        is_udp_probe = packet.transport == "UDP"
        if not (is_tcp_attempt or is_udp_probe):
            return None

        key = (packet.src_ip, packet.dst_ip)
        self.window.window_seconds = self.settings.window_seconds
        self.window.add(key, packet.timestamp, packet.dst_port)
        ports = self.window.distinct_values(key)

        if len(ports) < self.settings.threshold or self.in_cooldown(key, packet.timestamp, len(ports)):
            return None

        sample = ", ".join(str(p) for p in sorted(ports)[:10])
        return self.make_alert(
            key, packet, observed=len(ports),
            description=(f"Possible port scan: {packet.src_ip} probed {len(ports)} "
                         f"different ports on {packet.dst_ip} within "
                         f"{self.settings.window_seconds:g}s"),
            details=f"Distinct ports: {len(ports)} (e.g. {sample}...); "
                    f"threshold: {self.settings.threshold}",
        )
