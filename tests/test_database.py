"""Tests for SQLite alert storage, filtering, CSV export and the monitor."""

import csv

import pandas as pd
import pytest

import config
from config import AppConfig
from database import AlertDatabase
from detection.base import Alert
from monitoring.monitor import NIDSMonitor
from monitoring.offline_demo import generate_synthetic_traffic, load_csv_file, save_csv_file


@pytest.fixture
def db(tmp_path):
    return AlertDatabase(tmp_path / "test_alerts.db")


def sample_alerts():
    base = 1_700_000_000.0
    return [
        Alert(base, "Port Scan", "High", "10.0.0.66", "192.168.1.10",
              "Possible port scan", "20 ports", "simulated"),
        Alert(base + 5, "SYN Flood", "Critical", "203.0.113.50", "192.168.1.20",
              "Possible SYN flood", "300 SYN", "simulated"),
        Alert(base + 10, "ICMP Flood", "Medium", "198.51.100.23", "192.168.1.15",
              "Possible ICMP flood", "60 pings", "live"),
    ]


def test_alerts_are_stored_and_read_back(db):
    assert db.insert_alerts(sample_alerts()) == 3
    df = db.get_alerts()
    assert len(df) == 3
    assert db.count_alerts() == 3
    # Newest first
    assert list(df["rule"]) == ["ICMP Flood", "SYN Flood", "Port Scan"]
    row = df[df["rule"] == "SYN Flood"].iloc[0]
    assert row["severity"] == "Critical"
    assert row["src_ip"] == "203.0.113.50"
    assert row["description"] == "Possible SYN flood"
    assert row["time"]  # human readable timestamp saved


def test_filter_by_severity_and_rule(db):
    db.insert_alerts(sample_alerts())
    assert len(db.get_alerts(severities=["High", "Critical"])) == 2
    assert list(db.get_alerts(rules=["ICMP Flood"])["src_ip"]) == ["198.51.100.23"]
    assert db.get_alerts(severities=["Low"]).empty
    assert db.count_alerts(severities=["Critical"]) == 1


def test_search_by_ip(db):
    db.insert_alerts(sample_alerts())
    assert len(db.get_alerts(ip_search="203.0.113.50")) == 1
    assert len(db.get_alerts(ip_search="192.168.1.")) == 3  # matches dst_ip too
    assert db.get_alerts(ip_search="8.8.8.8").empty


def test_search_is_safe_from_sql_injection(db):
    db.insert_alerts(sample_alerts())
    assert db.get_alerts(ip_search="' OR '1'='1").empty
    assert db.count_alerts() == 3  # table intact


def test_csv_export_file(db, tmp_path):
    db.insert_alerts(sample_alerts())
    out = db.export_csv(tmp_path / "exports" / "alerts.csv")
    with open(out, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    assert len(rows) == 3
    assert {"time", "rule", "severity", "src_ip", "dst_ip", "description"} <= set(rows[0])
    assert {r["rule"] for r in rows} == {"Port Scan", "SYN Flood", "ICMP Flood"}


def test_csv_export_respects_filters(db, tmp_path):
    db.insert_alerts(sample_alerts())
    out = db.export_csv(tmp_path / "high.csv", severities=["Critical"])
    df = pd.read_csv(out)
    assert list(df["rule"]) == ["SYN Flood"]


def test_csv_text_for_download_button(db):
    db.insert_alerts(sample_alerts())
    text = db.alerts_to_csv(db.get_alerts())
    assert text.splitlines()[0].startswith("id,time,rule,severity")
    assert len(text.strip().splitlines()) == 4  # header + 3 alerts


def test_clear_alerts(db):
    db.insert_alerts(sample_alerts())
    db.clear_alerts()
    assert db.count_alerts() == 0


def test_monitor_offline_demo_stores_real_alerts(tmp_path):
    """End-to-end: simulated packets -> engine -> SQLite."""
    monitor = NIDSMonitor(AlertDatabase(tmp_path / "e2e.db"), AppConfig())
    packets = generate_synthetic_traffic(start_time=1_700_000_000)
    alerts = monitor.run_offline(packets, "test scenario")

    stored = monitor.db.get_alerts()
    assert len(stored) == len(alerts) > 0
    assert set(stored["traffic_source"]) == {"simulated"}
    assert {"Port Scan", "SYN Flood", "ICMP Flood", "Suspicious IP"} <= set(stored["rule"])

    status = monitor.status()
    assert status["mode"] == "Offline Demo"
    assert status["total_packets"] == len(packets)
    assert not monitor.packets_dataframe().empty


def test_monitor_apply_config_changes_thresholds(tmp_path):
    monitor = NIDSMonitor(AlertDatabase(tmp_path / "cfg.db"), AppConfig())
    cfg = AppConfig()
    for rule in cfg.rules.values():
        rule.enabled = False
    monitor.apply_config(cfg)
    alerts = monitor.run_offline(generate_synthetic_traffic(start_time=1_700_000_000), "x")
    assert alerts == []
    # The defaults in config.py must not have been modified
    assert all(r.enabled for r in config.DEFAULT_RULE_SETTINGS.values())


def test_csv_traffic_roundtrip(tmp_path):
    packets = generate_synthetic_traffic(start_time=1_700_000_000)
    path = save_csv_file(packets, tmp_path / "traffic.csv")
    loaded = load_csv_file(path)
    assert len(loaded) == len(packets)
    assert loaded[0].src_ip == packets[0].src_ip
    assert loaded[0].source == "csv"


def test_csv_missing_columns_raises(tmp_path):
    bad = tmp_path / "bad.csv"
    bad.write_text("a,b\n1,2\n", encoding="utf-8")
    with pytest.raises(ValueError, match="missing required columns"):
        load_csv_file(bad)


def test_bundled_sample_files_exist():
    assert config.SAMPLE_CSV_PATH.exists(), "run python generate_sample_data.py"
    assert config.SAMPLE_PCAP_PATH.exists(), "run python generate_sample_data.py"
