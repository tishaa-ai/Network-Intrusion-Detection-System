"""
Central configuration for the Network Intrusion Detection System (NIDS).

Every tunable value (thresholds, time windows, severities, file paths) lives
here so that a beginner only has to look in ONE place to change behaviour.
The dashboard's "Detection Rules" page edits a *copy* of these defaults at
runtime, so this file always holds the safe starting values.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path

# --------------------------------------------------------------------------
# File-system paths
# --------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
LOG_DIR = BASE_DIR / "logs"

DATABASE_PATH = DATA_DIR / "nids_alerts.db"
LOG_FILE_PATH = LOG_DIR / "nids.log"
SAMPLE_CSV_PATH = DATA_DIR / "sample_traffic.csv"
SAMPLE_PCAP_PATH = DATA_DIR / "sample_traffic.pcap"

# --------------------------------------------------------------------------
# Severity levels (ordered from least to most serious)
# --------------------------------------------------------------------------
SEVERITY_LEVELS = ["Low", "Medium", "High", "Critical"]

# Colours used consistently by every chart and table in the dashboard.
SEVERITY_COLORS = {
    "Low": "#3fb950",       # green
    "Medium": "#d29922",    # amber
    "High": "#f0883e",      # orange
    "Critical": "#f85149",  # red
}

# --------------------------------------------------------------------------
# Detection rule settings
# --------------------------------------------------------------------------


@dataclass
class RuleSettings:
    """Settings shared by every detection rule.

    enabled          -- turn the rule on or off
    threshold        -- how many events inside the window trigger an alert
    window_seconds   -- length of the sliding time window
    severity         -- base severity of an alert from this rule
    escalation_factor-- if the observed count reaches threshold * factor,
                        the alert is escalated one severity level
                        (e.g. High -> Critical). 0 disables escalation.
    """

    enabled: bool = True
    threshold: int = 10
    window_seconds: float = 10.0
    severity: str = "Medium"
    escalation_factor: float = 3.0

    def copy(self) -> "RuleSettings":
        return replace(self)


# Names used as keys here MUST match each rule class's `name` attribute.
DEFAULT_RULE_SETTINGS: dict[str, RuleSettings] = {
    # 15+ different destination ports on one host in 10 s => port scan
    "Port Scan": RuleSettings(threshold=15, window_seconds=10, severity="High"),
    # 100+ TCP SYN (no ACK) packets from one source in 10 s => SYN flood
    "SYN Flood": RuleSettings(threshold=100, window_seconds=10, severity="High"),
    # 50+ ICMP echo requests from one source in 10 s => ICMP (ping) flood
    "ICMP Flood": RuleSettings(threshold=50, window_seconds=10, severity="Medium"),
    # Any packet to/from a watch-listed IP (threshold 1 = first packet)
    "Suspicious IP": RuleSettings(
        threshold=1, window_seconds=60, severity="High", escalation_factor=0
    ),
    # 300+ packets of any kind from one source in 10 s => abnormal rate
    "Unusual Traffic": RuleSettings(threshold=300, window_seconds=10, severity="Low"),
}

# After a rule raises an alert for a given source, it stays quiet for this many
# seconds for the SAME source. This prevents one attack producing 1,000 alerts.
ALERT_COOLDOWN_SECONDS = 30.0

# --------------------------------------------------------------------------
# Suspicious / watch-listed IP addresses
# --------------------------------------------------------------------------
# These are RFC 5737 "documentation" addresses (192.0.2.0/24, 198.51.100.0/24,
# 203.0.113.0/24). They are reserved for examples and never route on the real
# internet, so they are safe to use in a demo. Replace them with real threat
# intelligence (e.g. a known C2 server list) in a production deployment.
DEFAULT_SUSPICIOUS_IPS: list[str] = [
    "203.0.113.66",
    "198.51.100.200",
    "192.0.2.99",
]

# --------------------------------------------------------------------------
# Monitoring settings
# --------------------------------------------------------------------------
# Maximum number of packets kept in memory for the dashboard. Older packets
# are dropped automatically (alerts are kept permanently in SQLite).
MAX_PACKETS_IN_MEMORY = 50_000

# How often (seconds) the live monitoring page refreshes itself.
DASHBOARD_REFRESH_SECONDS = 2


@dataclass
class AppConfig:
    """Bundle of runtime-editable settings used by the dashboard."""

    rules: dict[str, RuleSettings] = field(
        default_factory=lambda: {k: v.copy() for k, v in DEFAULT_RULE_SETTINGS.items()}
    )
    suspicious_ips: list[str] = field(default_factory=lambda: list(DEFAULT_SUSPICIOUS_IPS))
    cooldown_seconds: float = ALERT_COOLDOWN_SECONDS


def ensure_directories() -> None:
    """Create the data/ and logs/ folders if they do not exist yet."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
