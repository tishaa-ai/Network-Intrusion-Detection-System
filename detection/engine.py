"""
Detection engine: runs every enabled rule against every packet.

    packet ──► [Port Scan] [SYN Flood] [ICMP Flood] [Suspicious IP] [Unusual Traffic]
                     └────────────── any alerts ──────────────┘
                                         │
                                         ▼
                                  list[Alert] returned

The engine itself knows nothing about specific attacks - it simply loops over
`self.rules`. That is what makes it modular: adding a rule = adding a class.
"""

from __future__ import annotations

from typing import Iterable

import config
from config import RuleSettings
from detection.base import Alert, DetectionRule
from detection.icmp_flood import IcmpFloodRule
from detection.port_scan import PortScanRule
from detection.suspicious_ip import SuspiciousIPRule
from detection.syn_flood import SynFloodRule
from detection.unusual_traffic import UnusualTrafficRule
from monitoring.packet_analyzer import PacketInfo
from utils.logger import get_logger

logger = get_logger(__name__)

# Register new rule classes here.
ALL_RULE_CLASSES: list[type[DetectionRule]] = [
    PortScanRule,
    SynFloodRule,
    IcmpFloodRule,
    SuspiciousIPRule,
    UnusualTrafficRule,
]


class DetectionEngine:
    def __init__(self, rule_settings: dict[str, RuleSettings] | None = None,
                 suspicious_ips: Iterable[str] | None = None,
                 cooldown_seconds: float = config.ALERT_COOLDOWN_SECONDS):
        settings = rule_settings or config.DEFAULT_RULE_SETTINGS
        if suspicious_ips is None:
            suspicious_ips = config.DEFAULT_SUSPICIOUS_IPS

        self.rules: list[DetectionRule] = []
        for rule_class in ALL_RULE_CLASSES:
            # Each rule gets its OWN copy of the settings so tests/dashboard
            # changes never modify the defaults in config.py by accident.
            rule_settings_obj = settings.get(rule_class.name, RuleSettings()).copy()
            if rule_class is SuspiciousIPRule:
                rule = rule_class(rule_settings_obj, cooldown_seconds, suspicious_ips)
            else:
                rule = rule_class(rule_settings_obj, cooldown_seconds)
            self.rules.append(rule)

        self.packets_processed = 0
        logger.info("Detection engine ready with rules: %s",
                    ", ".join(r.name for r in self.rules))

    def get_rule(self, name: str) -> DetectionRule:
        for rule in self.rules:
            if rule.name == name:
                return rule
        raise KeyError(f"No detection rule named {name!r}")

    def process_packet(self, packet: PacketInfo) -> list[Alert]:
        """Run all rules on one packet and return any alerts raised."""
        self.packets_processed += 1
        alerts: list[Alert] = []
        for rule in self.rules:
            try:
                alert = rule.evaluate(packet)
            except Exception:  # a buggy rule must not stop the other rules
                logger.exception("Rule %s failed on packet %s", rule.name, packet)
                continue
            if alert is not None:
                logger.warning("ALERT [%s] %s: %s", alert.severity, alert.rule,
                               alert.description)
                alerts.append(alert)
        return alerts

    def process_packets(self, packets: Iterable[PacketInfo]) -> list[Alert]:
        """Convenience helper: process many packets in timestamp order."""
        alerts: list[Alert] = []
        for packet in sorted(packets, key=lambda p: p.timestamp):
            alerts.extend(self.process_packet(packet))
        return alerts

    def reset(self) -> None:
        """Clear all sliding windows and cooldowns."""
        for rule in self.rules:
            rule.reset()
        self.packets_processed = 0
