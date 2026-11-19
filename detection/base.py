"""
Building blocks shared by every detection rule:

* `Alert`          -- the record a rule produces when it detects something.
* `SlidingWindow`  -- counts events per key (e.g. per source IP) inside the
                      last N seconds.
* `DetectionRule`  -- abstract base class. A new rule only has to implement
                      `inspect()`; enabling, cooldown and severity escalation
                      are handled here.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections import defaultdict, deque
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any, Hashable

import config
from config import RuleSettings
from monitoring.packet_analyzer import PacketInfo


@dataclass
class Alert:
    """A security alert raised by a detection rule."""

    timestamp: float        # when the triggering packet was seen (epoch seconds)
    rule: str               # detection type, e.g. "Port Scan"
    severity: str           # Low / Medium / High / Critical
    src_ip: str
    dst_ip: str
    description: str        # one-line, human readable explanation
    details: str = ""       # extra evidence (counts, ports, ...)
    traffic_source: str = "live"  # live / pcap / csv / simulated

    @property
    def time_str(self) -> str:
        return datetime.fromtimestamp(self.timestamp).strftime("%Y-%m-%d %H:%M:%S")

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["time"] = self.time_str
        return data


class SlidingWindow:
    """Keeps (timestamp, value) events per key and forgets old ones.

    Example: key = source IP, value = destination port. After `add()` you can
    ask how many events (or how many DISTINCT values) the key had in the
    last `window_seconds`.
    """

    def __init__(self, window_seconds: float):
        self.window_seconds = window_seconds
        self._events: dict[Hashable, deque] = defaultdict(deque)
        self._last_cleanup = 0.0

    def add(self, key: Hashable, timestamp: float, value: Any = None) -> deque:
        events = self._events[key]
        events.append((timestamp, value))
        self._expire(events, timestamp)
        # Every 60 s of traffic, drop keys that have gone completely quiet so
        # memory does not grow forever during long captures.
        if timestamp - self._last_cleanup > 60:
            self._cleanup(timestamp)
        return events

    def count(self, key: Hashable) -> int:
        return len(self._events.get(key, ()))

    def distinct_values(self, key: Hashable) -> set:
        return {value for _, value in self._events.get(key, ())}

    def _expire(self, events: deque, now: float) -> None:
        cutoff = now - self.window_seconds
        while events and events[0][0] < cutoff:
            events.popleft()

    def _cleanup(self, now: float) -> None:
        self._last_cleanup = now
        for key in list(self._events):
            self._expire(self._events[key], now)
            if not self._events[key]:
                del self._events[key]

    def clear(self) -> None:
        self._events.clear()


class DetectionRule(ABC):
    """Base class for all detection rules.

    To add a new rule:
        1. subclass DetectionRule,
        2. set `name` and `description`,
        3. implement `inspect(packet)` and return an Alert or None,
        4. add default settings for `name` in config.DEFAULT_RULE_SETTINGS,
        5. register the class in detection/engine.py (ALL_RULE_CLASSES).
    """

    name: str = "Base Rule"
    description: str = ""

    def __init__(self, settings: RuleSettings,
                 cooldown_seconds: float = config.ALERT_COOLDOWN_SECONDS):
        self.settings = settings
        self.cooldown_seconds = cooldown_seconds
        # key -> (timestamp, severity) of the most recent alert for that key
        self._last_alert: dict[Hashable, tuple[float, str]] = {}

    # ---- public API used by the engine ----
    def evaluate(self, packet: PacketInfo) -> Alert | None:
        if not self.settings.enabled:
            return None
        return self.inspect(packet)

    def reset(self) -> None:
        """Forget all state (called when a new capture/demo starts)."""
        self._last_alert.clear()
        for value in vars(self).values():
            if isinstance(value, SlidingWindow):
                value.clear()

    # ---- to be implemented by each rule ----
    @abstractmethod
    def inspect(self, packet: PacketInfo) -> Alert | None:
        """Look at one packet; return an Alert if the rule fires."""

    # ---- helpers for subclasses ----
    def in_cooldown(self, key: Hashable, now: float, observed: int = 1) -> bool:
        """True if we should stay quiet for `key` right now.

        We stay quiet if we alerted for `key` less than `cooldown_seconds` ago,
        UNLESS the attack has grown enough to deserve a higher severity
        (e.g. a SYN flood escalating from High to Critical).
        """
        last = self._last_alert.get(key)
        if last is None:
            return False
        last_time, last_severity = last
        if (now - last_time) >= self.cooldown_seconds:
            return False
        levels = config.SEVERITY_LEVELS
        return levels.index(self.severity_for(observed)) <= levels.index(last_severity)

    def severity_for(self, observed: int) -> str:
        """Base severity, escalated one level for very large counts."""
        base = self.settings.severity
        factor = self.settings.escalation_factor
        levels = config.SEVERITY_LEVELS
        if factor and observed >= self.settings.threshold * factor:
            index = min(levels.index(base) + 1, len(levels) - 1)
            return levels[index]
        return base

    def make_alert(self, key: Hashable, packet: PacketInfo, observed: int,
                   description: str, details: str = "",
                   src_ip: str | None = None, dst_ip: str | None = None) -> Alert:
        """Create an alert and start the cooldown for `key`."""
        severity = self.severity_for(observed)
        self._last_alert[key] = (packet.timestamp, severity)
        return Alert(
            timestamp=packet.timestamp,
            rule=self.name,
            severity=severity,
            src_ip=src_ip if src_ip is not None else packet.src_ip,
            dst_ip=dst_ip if dst_ip is not None else packet.dst_ip,
            description=description,
            details=details,
            traffic_source=packet.source,
        )
