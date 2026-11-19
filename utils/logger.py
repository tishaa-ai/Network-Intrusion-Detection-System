"""
Application logging.

Every module calls `get_logger(__name__)`. Messages go to:
  * the console (INFO and above), and
  * logs/nids.log  (DEBUG and above, rotated at 1 MB, 3 backups kept).

A SOC analyst would normally ship these logs to a SIEM (Splunk, ELK, ...).
"""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler

import config

_LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
_configured = False


def _configure_root_logger() -> None:
    """Attach handlers to the project's root logger exactly once."""
    global _configured
    if _configured:
        return

    config.ensure_directories()
    root = logging.getLogger("nids")
    root.setLevel(logging.DEBUG)
    root.propagate = False  # keep our messages out of Streamlit's own logger

    formatter = logging.Formatter(_LOG_FORMAT)

    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    console.setFormatter(formatter)
    root.addHandler(console)

    try:
        file_handler = RotatingFileHandler(
            config.LOG_FILE_PATH, maxBytes=1_000_000, backupCount=3, encoding="utf-8"
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)
    except OSError as exc:  # e.g. read-only folder - still log to console
        root.warning("File logging disabled: %s", exc)

    # Scapy prints "No libpcap provider available" on Windows without Npcap.
    # The dashboard explains this itself, so keep the console tidy.
    for noisy in ("scapy.runtime", "scapy.loading"):
        logging.getLogger(noisy).setLevel(logging.ERROR)

    _configured = True


def get_logger(name: str) -> logging.Logger:
    """Return a logger that lives under the 'nids' namespace."""
    _configure_root_logger()
    short_name = name.split(".")[-1] if name != "__main__" else "app"
    return logging.getLogger(f"nids.{short_name}")
