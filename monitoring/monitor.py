"""
NIDSMonitor - the "brain" that connects every part of the system:

    PacketCapture / offline source
            │  PacketInfo
            ▼
      NIDSMonitor.ingest()  ──►  DetectionEngine  ──►  AlertDatabase (SQLite)
            │
            └── keeps recent packets in memory for the dashboard

Live capture and offline demo BOTH call `ingest()`, so they are guaranteed to
use exactly the same detection logic.
"""

from __future__ import annotations

import threading
from collections import deque
from typing import Callable, Iterable

import pandas as pd

import config
from config import AppConfig
from database import AlertDatabase
from detection.base import Alert
from detection.engine import DetectionEngine
from monitoring.packet_analyzer import PacketInfo
from monitoring.packet_capture import PacketCapture
from utils.logger import get_logger

logger = get_logger(__name__)

RECENT_ALERTS_IN_MEMORY = 500


class NIDSMonitor:
    def __init__(self, database: AlertDatabase | None = None,
                 app_config: AppConfig | None = None):
        self.db = database or AlertDatabase()
        self.app_config = app_config or AppConfig()
        self._lock = threading.RLock()  # capture thread + UI thread share state
        self.packets: deque[PacketInfo] = deque(maxlen=config.MAX_PACKETS_IN_MEMORY)
        self.engine = self._build_engine()
        self.capture: PacketCapture | None = None
        self.mode = "Idle"            # Idle / Live / Offline Demo
        self.data_label = ""          # e.g. "Simulated traffic"
        self.total_packets = 0
        self.session_alerts = 0
        # Alerts raised in THIS session (newest last). Same objects the engine
        # returned and the database stored - used by the live dashboard panel.
        self.recent_alerts: deque[Alert] = deque(maxlen=RECENT_ALERTS_IN_MEMORY)
        self.last_error: str | None = None

    # ------------------------------------------------------------ config
    def _build_engine(self) -> DetectionEngine:
        cfg = self.app_config
        return DetectionEngine(cfg.rules, cfg.suspicious_ips, cfg.cooldown_seconds)

    def apply_config(self, app_config: AppConfig) -> None:
        """Replace rule settings (clears the sliding windows)."""
        with self._lock:
            self.app_config = app_config
            self.engine = self._build_engine()
        logger.info("Detection configuration updated")

    # ------------------------------------------------------------ ingest
    def ingest(self, packet: PacketInfo) -> list[Alert]:
        """Analyse one packet: store it, run detection, save any alerts."""
        with self._lock:
            self.packets.append(packet)
            self.total_packets += 1
            alerts = self.engine.process_packet(packet)
            if alerts:
                self.session_alerts += len(alerts)
                self.recent_alerts.extend(alerts)
        if alerts:
            try:
                self.db.insert_alerts(alerts)
            except Exception as exc:
                self.last_error = f"Could not save alerts: {exc}"
        return alerts

    def ingest_many(self, packets: Iterable[PacketInfo],
                    progress: Callable[[float], None] | None = None) -> list[Alert]:
        packets = sorted(packets, key=lambda p: p.timestamp)
        all_alerts: list[Alert] = []
        total = len(packets) or 1
        for index, packet in enumerate(packets, start=1):
            all_alerts.extend(self.ingest(packet))
            if progress and (index % 250 == 0 or index == total):
                progress(index / total)
        return all_alerts

    # ------------------------------------------------------------ offline
    def run_offline(self, packets: list[PacketInfo], label: str,
                    progress: Callable[[float], None] | None = None) -> list[Alert]:
        """Replay offline/simulated packets through the detection engine."""
        if self.is_live:
            raise RuntimeError("Stop live monitoring before running the offline demo.")
        if self.capture is not None:  # leftover interrupted capture
            self.stop_live()
        self.reset_session()
        with self._lock:
            self.mode = "Offline Demo"
            self.data_label = label
        alerts = self.ingest_many(packets, progress)
        logger.info("Offline replay '%s': %d packets, %d alerts", label, len(packets),
                    len(alerts))
        return alerts

    # ------------------------------------------------------------ live
    @property
    def is_live(self) -> bool:
        return self.capture is not None and self.capture.is_running

    def check_capture(self) -> None:
        """Notice a capture that died on its own (adapter lost, driver error)."""
        with self._lock:
            capture = self.capture
            if capture is None or self.mode != "Live":
                return
            error = capture.check_health()
            if error:
                self.mode = "Interrupted"
                self.last_error = error
                self.data_label = f"Live capture on {capture.interface_label} (interrupted)"

    def start_live(self, interface: str | None, bpf_filter: str | None = None,
                   capture_factory: Callable[..., PacketCapture] = PacketCapture) -> None:
        if self.is_live:
            return
        if self.capture is not None:   # an interrupted capture - clean it up first
            self.capture.stop()
            self.capture = None
        self.reset_session()
        capture = capture_factory(self.ingest, interface, bpf_filter)
        try:
            capture.start()
        except RuntimeError as exc:
            self.last_error = str(exc)
            logger.error("%s", exc)
            raise
        with self._lock:
            self.capture = capture
            self.mode = "Live"
            self.data_label = f"Live capture on {capture.interface_label}"
            self.last_error = None

    def stop_live(self) -> None:
        if self.capture is not None:
            self.capture.stop()
        with self._lock:
            self.capture = None
            if self.mode in ("Live", "Interrupted"):
                if self.mode == "Live":
                    self.data_label += " (stopped)"
                self.mode = "Idle"

    # ------------------------------------------------------------ state
    def reset_session(self, clear_database: bool = False) -> None:
        """Clear packets, counters and detection state (optionally the DB too)."""
        with self._lock:
            self.packets.clear()
            self.engine.reset()
            self.total_packets = 0
            self.session_alerts = 0
            self.recent_alerts.clear()
            self.mode = "Idle"
            self.data_label = ""
            self.last_error = None
        if clear_database:
            self.db.clear_alerts()

    def packets_dataframe(self) -> pd.DataFrame:
        """Thread-safe snapshot of in-memory packets as a DataFrame."""
        with self._lock:
            rows = [p.to_dict() for p in self.packets]
        df = pd.DataFrame(rows)
        if not df.empty:
            # "time" is already formatted in the computer's local time zone
            df["datetime"] = pd.to_datetime(df["time"])
        return df

    def session_alerts_dataframe(self, limit: int | None = None) -> pd.DataFrame:
        """Alerts raised in this session, newest first (same columns as the DB)."""
        with self._lock:
            alerts = list(self.recent_alerts)
        alerts.reverse()
        if limit:
            alerts = alerts[:limit]
        return pd.DataFrame([a.to_dict() for a in alerts])

    def status(self) -> dict:
        self.check_capture()
        with self._lock:
            capture = self.capture
            return {
                "mode": self.mode,
                "label": self.data_label,
                "is_live": self.is_live,
                "interrupted": self.mode == "Interrupted",
                "total_packets": self.total_packets,
                "session_alerts": self.session_alerts,
                "packets_in_memory": len(self.packets),
                "started_at": capture.started_at if capture else None,
                "capture": capture.stats() if capture else None,
                "last_error": self.last_error,
            }
