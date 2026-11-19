"""
SQLite storage for security alerts.

SQLite is a file-based database built into Python (no server to install).
Each method opens its own short-lived connection, which keeps things
thread-safe: the live-capture thread and the dashboard can both write/read.

Table `alerts`:
    id, timestamp, time, rule, severity, src_ip, dst_ip,
    description, details, traffic_source, created_at
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Iterable, Iterator

import pandas as pd

import config
from detection.base import Alert
from utils.logger import get_logger

logger = get_logger(__name__)

ALERT_COLUMNS = ["id", "time", "rule", "severity", "src_ip", "dst_ip",
                 "description", "details", "traffic_source", "timestamp"]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       REAL    NOT NULL,
    time            TEXT    NOT NULL,
    rule            TEXT    NOT NULL,
    severity        TEXT    NOT NULL,
    src_ip          TEXT,
    dst_ip          TEXT,
    description     TEXT,
    details         TEXT,
    traffic_source  TEXT,
    created_at      TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_rule     ON alerts(rule);
CREATE INDEX IF NOT EXISTS idx_alerts_src_ip   ON alerts(src_ip);
"""


class AlertDatabase:
    def __init__(self, db_path: str | Path = config.DATABASE_PATH):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._create_schema()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        """Open a connection, commit on success, roll back on error, always close."""
        conn = sqlite3.connect(self.db_path, timeout=10)
        try:
            yield conn
            conn.commit()
        except sqlite3.Error:
            conn.rollback()
            logger.exception("Database error")
            raise
        finally:
            conn.close()

    def _create_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(_SCHEMA)

    # ------------------------------------------------------------------ write
    def insert_alerts(self, alerts: Iterable[Alert]) -> int:
        """Store alerts; returns how many rows were inserted."""
        now = datetime.now().isoformat(timespec="seconds")
        rows = [
            (a.timestamp, a.time_str, a.rule, a.severity, a.src_ip, a.dst_ip,
             a.description, a.details, a.traffic_source, now)
            for a in alerts
        ]
        if not rows:
            return 0
        with self._connect() as conn:
            conn.executemany(
                """INSERT INTO alerts (timestamp, time, rule, severity, src_ip, dst_ip,
                                       description, details, traffic_source, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                rows,
            )
        return len(rows)

    def insert_alert(self, alert: Alert) -> int:
        return self.insert_alerts([alert])

    def clear_alerts(self) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM alerts")
        logger.info("All alerts deleted from the database")

    # ------------------------------------------------------------------- read
    def get_alerts(self, severities: list[str] | None = None,
                   rules: list[str] | None = None,
                   ip_search: str | None = None,
                   limit: int | None = None) -> pd.DataFrame:
        """Return alerts (newest first) matching the optional filters.

        All filter values are passed as SQL *parameters* (the `?` marks), never
        pasted into the SQL string - this prevents SQL injection.
        """
        query = f"SELECT {', '.join(ALERT_COLUMNS)} FROM alerts WHERE 1=1"
        params: list = []
        if severities:
            query += f" AND severity IN ({','.join('?' * len(severities))})"
            params.extend(severities)
        if rules:
            query += f" AND rule IN ({','.join('?' * len(rules))})"
            params.extend(rules)
        if ip_search and ip_search.strip():
            query += " AND (src_ip LIKE ? OR dst_ip LIKE ?)"
            pattern = f"%{ip_search.strip()}%"
            params.extend([pattern, pattern])
        query += " ORDER BY timestamp DESC, id DESC"
        if limit:
            query += " LIMIT ?"
            params.append(int(limit))

        with self._connect() as conn:
            return pd.read_sql_query(query, conn, params=params)

    def count_alerts(self, severities: list[str] | None = None) -> int:
        query = "SELECT COUNT(*) FROM alerts"
        params: list = []
        if severities:
            query += f" WHERE severity IN ({','.join('?' * len(severities))})"
            params.extend(severities)
        with self._connect() as conn:
            return int(conn.execute(query, params).fetchone()[0])

    # ----------------------------------------------------------------- export
    @staticmethod
    def alerts_to_csv(df: pd.DataFrame) -> str:
        """Convert an alerts DataFrame to CSV text (used by the download button)."""
        return df.to_csv(index=False)

    def export_csv(self, output_path: str | Path, **filters) -> Path:
        """Write (optionally filtered) alerts to a CSV file and return its path."""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        df = self.get_alerts(**filters)
        df.to_csv(output_path, index=False)
        logger.info("Exported %d alerts to %s", len(df), output_path)
        return output_path
