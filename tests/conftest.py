"""Shared pytest fixtures. Also makes the project root importable."""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config import RuleSettings  # noqa: E402
from monitoring.packet_analyzer import PacketInfo  # noqa: E402

BASE_TIME = 1_700_000_000.0  # fixed timestamp so tests are repeatable


@pytest.fixture
def make_packet():
    """Factory: make_packet(offset_seconds, src, dst, protocol=..., ...)."""

    def _make(offset, src, dst, protocol="TCP", src_port=None, dst_port=None,
              tcp_flags="", icmp_type=None, length=60, source="simulated"):
        return PacketInfo(timestamp=BASE_TIME + offset, src_ip=src, dst_ip=dst,
                          protocol=protocol, src_port=src_port, dst_port=dst_port,
                          length=length, tcp_flags=tcp_flags, icmp_type=icmp_type,
                          source=source)

    return _make


@pytest.fixture
def settings():
    """Small thresholds make the tests easy to read."""
    return {
        "Port Scan": RuleSettings(threshold=10, window_seconds=10, severity="High"),
        "SYN Flood": RuleSettings(threshold=50, window_seconds=10, severity="High"),
        "ICMP Flood": RuleSettings(threshold=20, window_seconds=10, severity="Medium"),
        "Suspicious IP": RuleSettings(threshold=1, window_seconds=60, severity="High",
                                      escalation_factor=0),
        "Unusual Traffic": RuleSettings(threshold=1000, window_seconds=10, severity="Low"),
    }
