"""Integration tests for LIVE capture -> analyzer -> engine -> database -> dashboard.

Most tests replace Scapy's AsyncSniffer with a fake one so they run anywhere
(no Npcap, no admin, no network). The fake hands REAL Scapy packets to the
same callback the real sniffer uses, so everything after the driver is the
production code path.

One test captures from the real network adapter. It only runs when you ask
for it:   $env:NIDS_LIVE_TEST = "1"; python -m pytest tests/test_live_capture.py -v
"""

from __future__ import annotations

import os
import socket
import time
from types import SimpleNamespace

import pytest
from scapy.layers.inet import ICMP, IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from config import AppConfig
from database import AlertDatabase
from monitoring import packet_capture
from monitoring.monitor import NIDSMonitor
from monitoring.offline_demo import generate_synthetic_traffic
from monitoring.packet_analyzer import analyze_packet
from monitoring.packet_capture import (PacketCapture, _describe_interface, list_interfaces,
                                       recommended_interface, resolve_interface)

WIFI_ID = r"\Device\NPF_{11111111-2222-3333-4444-555555555555}"
SCANNER, VICTIM = "10.0.0.66", "192.168.1.10"
# Fixed MACs: a bare Ether() makes Scapy resolve the MAC (ARP) - tests must
# never touch the network.
MACS = {"src": "02:00:00:00:00:01", "dst": "02:00:00:00:00:02"}


# ------------------------------------------------------------------ fakes
def fake_iface(name, description, ip, network_name, flags):
    return SimpleNamespace(name=name, description=description, ip=ip,
                           network_name=network_name, flags=flags)


# A typical Windows 11 laptop as listed by Scapy with Npcap (example values).
WINDOWS_IFACES = [
    fake_iface("Local Area Connection* 10", "WAN Miniport (Network Monitor)", "",
               r"\Device\NPF_{WAN0}", "UP+RUNNING+OK"),
    fake_iface("Bluetooth Network Connection", "Bluetooth Device (Personal Area Network)",
               "169.254.10.20", r"\Device\NPF_{BT00}", "UP+RUNNING+WIRELESS+DISCONNECTED"),
    fake_iface("Wi-Fi", "Example 802.11ac Wireless LAN Adapter", "192.168.1.50",
               WIFI_ID, "UP+RUNNING+WIRELESS+OK"),
    fake_iface("Local Area Connection* 1", "Microsoft Wi-Fi Direct Virtual Adapter",
               "169.254.10.21", r"\Device\NPF_{WFD0}", "UP+RUNNING+WIRELESS+DISCONNECTED"),
    fake_iface("Loopback Pseudo-Interface 1", "Software Loopback Interface 1", "127.0.0.1",
               r"\Device\NPF_Loopback", "LOOPBACK+UP+RUNNING+OK+DISCONNECTED"),
]


def described(ifaces=WINDOWS_IFACES, default_id=WIFI_ID):
    return sorted((_describe_interface(i, default_id) for i in ifaces),
                  key=packet_capture._rank)


class FakeSniffer:
    """Stand-in for scapy.sendrecv.AsyncSniffer."""

    last: "FakeSniffer | None" = None
    start_error: Exception | None = None  # simulate an error inside the thread

    def __init__(self, iface=None, prn=None, store=False, filter=None):
        self.iface, self.prn, self.filter = iface, prn, filter
        self.running = False
        self.exception = None
        self.stopped = False
        FakeSniffer.last = self

    def start(self):
        if FakeSniffer.start_error is not None:
            self.exception = FakeSniffer.start_error
            return  # thread died immediately, running stays False
        self.running = True

    def stop(self):
        self.running = False
        self.stopped = True

    # test helpers
    def deliver(self, packets):
        for pkt in packets:
            self.prn(pkt)

    def die(self, exception=None):
        """Simulate the adapter disappearing mid-capture."""
        self.exception = exception
        self.running = False


@pytest.fixture
def fake_capture(monkeypatch):
    import scapy.sendrecv

    FakeSniffer.last = None
    FakeSniffer.start_error = None
    monkeypatch.setattr(scapy.sendrecv, "AsyncSniffer", FakeSniffer)
    monkeypatch.setattr(packet_capture, "check_capture_support", lambda: (True, "ok"))
    monkeypatch.setattr(packet_capture, "list_interfaces", lambda: described())
    monkeypatch.setattr(packet_capture, "STARTUP_CHECK_SECONDS", 0.05)
    return FakeSniffer


@pytest.fixture
def monitor(tmp_path):
    return NIDSMonitor(AlertDatabase(tmp_path / "live.db"), AppConfig())


def syn_scan_frames(n_ports=20, start=None):
    """Real Scapy frames: one host SYN-probing many ports."""
    start = time.time() if start is None else start
    frames = []
    for i, port in enumerate(range(20, 20 + n_ports)):
        pkt = Ether(**MACS) / IP(src=SCANNER, dst=VICTIM) / TCP(sport=40000 + i, dport=port,
                                                         flags="S")
        pkt.time = start + i * 0.05
        frames.append(pkt)
    return frames


# ------------------------------------------------------------ interfaces
def test_wifi_is_ranked_first_and_recommended():
    ifaces = described()
    assert ifaces[0]["friendly_name"] == "Wi-Fi"
    best = recommended_interface(ifaces)
    assert best["name"] == WIFI_ID and best["connected"] and best["is_wireless"]
    assert "Wi-Fi" in best["label"] and "192.168.1.50" in best["label"]


def test_apipa_and_disconnected_adapters_are_not_connected():
    by_name = {i["friendly_name"]: i for i in described()}
    assert not by_name["Bluetooth Network Connection"]["connected"]   # 169.254.x.x
    assert not by_name["Local Area Connection* 10"]["connected"]      # no IP
    assert by_name["Loopback Pseudo-Interface 1"]["is_loopback"]


ETHERNET = fake_iface("Ethernet", "Intel(R) Ethernet Connection I219-V", "192.168.0.20",
                      r"\Device\NPF_{ETH0}", "UP+RUNNING+OK")


@pytest.mark.parametrize("default_id, expected", [(WIFI_ID, "Wi-Fi"),
                                                  (r"\Device\NPF_{ETH0}", "Ethernet")])
def test_default_route_wins_when_two_adapters_connected(default_id, expected):
    ifaces = described(WINDOWS_IFACES + [ETHERNET], default_id)
    assert ifaces[0]["friendly_name"] == expected
    assert recommended_interface(ifaces)["friendly_name"] == expected
    assert "default route" in ifaces[0]["label"]


def test_wifi_recommended_even_when_default_route_unknown():
    ifaces = described(default_id="")
    assert recommended_interface(ifaces)["friendly_name"] == "Wi-Fi"


@pytest.mark.parametrize("value", ["Wi-Fi", "wi-fi", WIFI_ID,
                                   "Example 802.11ac Wireless LAN Adapter", None, ""])
def test_resolve_interface_accepts_any_windows_name(value):
    assert resolve_interface(value, described())["name"] == WIFI_ID


def test_resolve_unknown_interface_lists_alternatives():
    with pytest.raises(RuntimeError, match="not found.*'Wi-Fi'"):
        resolve_interface("Ethernet 7", described())


def test_resolve_with_no_interfaces_mentions_npcap():
    with pytest.raises(RuntimeError, match="Npcap"):
        resolve_interface("Wi-Fi", [])


# ------------------------------------------------- live -> engine -> db
def test_live_packets_reach_engine_and_database(fake_capture, monitor):
    monitor.start_live("Wi-Fi", "tcp or icmp")
    sniffer = fake_capture.last
    assert sniffer.iface == WIFI_ID          # friendly name resolved to the Npcap id
    assert sniffer.filter == "tcp or icmp"
    assert monitor.is_live and monitor.status()["mode"] == "Live"

    sniffer.deliver(syn_scan_frames())

    status = monitor.status()
    assert status["total_packets"] == 20
    assert status["capture"]["frames_seen"] == 20
    assert status["capture"]["interface"] == "Wi-Fi"
    stored = monitor.db.get_alerts()
    assert "Port Scan" in set(stored["rule"])
    assert set(stored["traffic_source"]) == {"live"}
    session = monitor.session_alerts_dataframe()
    assert status["session_alerts"] == len(session) == len(stored)
    assert session.iloc[0]["src_ip"] == SCANNER


def test_live_and_offline_use_the_same_detection_logic(fake_capture, tmp_path):
    """Same traffic through live capture and offline replay -> identical alerts."""
    frames = syn_scan_frames(60, start=1_700_000_000.0) + [
        Ether(**MACS) / IP(src="198.51.100.23", dst=VICTIM) / ICMP(type=8) for _ in range(60)]
    for i, f in enumerate(frames[60:]):
        f.time = 1_700_000_005.0 + i * 0.01

    live = NIDSMonitor(AlertDatabase(tmp_path / "a.db"), AppConfig())
    live.start_live("Wi-Fi")
    fake_capture.last.deliver(frames)
    live.stop_live()

    offline = NIDSMonitor(AlertDatabase(tmp_path / "b.db"), AppConfig())
    offline.run_offline([analyze_packet(f, source="live") for f in frames], "replay")

    def summary(m):
        return [(a.rule, a.severity, a.src_ip, a.description) for a in m.recent_alerts]

    assert summary(live) == summary(offline)
    assert {"Port Scan", "ICMP Flood"} <= {r for r, *_ in summary(live)}


def test_non_ip_frames_are_counted_but_not_analysed(fake_capture, monitor):
    monitor.start_live("Wi-Fi")
    lldp = Ether(type=0x88CC, **MACS) / Raw(b"\x00" * 20)
    fake_capture.last.deliver([lldp, lldp])
    cap = monitor.status()["capture"]
    assert cap["frames_seen"] == 2 and cap["packets_analysed"] == 0
    assert cap["skipped_frames"] == 2
    assert monitor.status()["total_packets"] == 0


def test_processing_error_does_not_stop_capture(fake_capture, monitor, monkeypatch):
    monitor.start_live("Wi-Fi")
    calls = {"n": 0}

    def flaky_engine(packet):
        calls["n"] += 1
        if calls["n"] == 1:
            raise ValueError("boom")
        return []

    monkeypatch.setattr(monitor.engine, "process_packet", flaky_engine)
    fake_capture.last.deliver(syn_scan_frames(3))
    assert monitor.is_live
    assert monitor.status()["capture"]["processing_errors"] == 1
    assert calls["n"] == 3


# ---------------------------------------------------- errors & interruptions
def test_permission_error_is_reported_clearly(fake_capture, monitor):
    fake_capture.start_error = PermissionError("Error opening adapter: Access is denied.")
    with pytest.raises(RuntimeError, match="Permission denied.*Administrator"):
        monitor.start_live("Wi-Fi")
    assert not monitor.is_live
    assert "Permission denied" in monitor.status()["last_error"]


def test_invalid_filter_is_reported_clearly(fake_capture, monitor):
    fake_capture.start_error = Exception("Cannot set filter: syntax error")
    with pytest.raises(RuntimeError, match="Invalid BPF capture filter"):
        monitor.start_live("Wi-Fi", "tcp and and")


def test_unknown_interface_fails_before_sniffing(fake_capture, monitor):
    with pytest.raises(RuntimeError, match="not found"):
        monitor.start_live("Ethernet 7")
    assert fake_capture.last is None


def test_capture_support_missing_npcap(monkeypatch, monitor):
    monkeypatch.setattr(packet_capture, "check_capture_support",
                        lambda: (False, "Npcap was not found."))
    with pytest.raises(RuntimeError, match="Npcap was not found"):
        monitor.start_live("Wi-Fi")


def test_capture_interruption_is_detected(fake_capture, monitor):
    monitor.start_live("Wi-Fi")
    fake_capture.last.deliver(syn_scan_frames(5))
    fake_capture.last.die()                       # adapter disconnected

    status = monitor.status()
    assert status["mode"] == "Interrupted" and status["interrupted"]
    assert not status["is_live"]
    assert "stopped unexpectedly" in status["last_error"]
    assert status["total_packets"] == 5           # data captured so far is kept


def test_interruption_with_thread_exception(fake_capture, monitor):
    monitor.start_live("Wi-Fi")
    fake_capture.last.die(OSError("Error opening adapter: The device is not ready"))
    assert "adapter could not be opened" in monitor.status()["last_error"]


def test_restart_after_interruption(fake_capture, monitor):
    monitor.start_live("Wi-Fi")
    first = fake_capture.last
    first.die()
    assert monitor.status()["interrupted"]
    monitor.start_live("Wi-Fi")
    assert monitor.is_live and fake_capture.last is not first
    assert monitor.status()["mode"] == "Live" and monitor.status()["last_error"] is None


def test_stop_live_is_clean(fake_capture, monitor):
    monitor.start_live("Wi-Fi")
    sniffer = fake_capture.last
    monitor.stop_live()
    assert sniffer.stopped and not monitor.is_live
    status = monitor.status()
    assert status["mode"] == "Idle" and status["last_error"] is None
    assert "(stopped)" in status["label"]


def test_offline_demo_blocked_while_live_and_works_after(fake_capture, monitor):
    monitor.start_live("Wi-Fi")
    with pytest.raises(RuntimeError, match="Stop live monitoring"):
        monitor.run_offline(generate_synthetic_traffic(start_time=1_700_000_000), "demo")
    fake_capture.last.die()                       # interrupted capture
    alerts = monitor.run_offline(generate_synthetic_traffic(start_time=1_700_000_000), "demo")
    assert alerts and monitor.status()["mode"] == "Offline Demo"
    assert monitor.capture is None


# ------------------------------------------------------------- dashboard
def test_dashboard_shows_live_counts_and_alerts(fake_capture, monkeypatch, tmp_path):
    """Drive the real Streamlit app: start capture, feed packets, check the page."""
    import config
    import streamlit as st
    from streamlit.testing.v1 import AppTest

    monkeypatch.setattr(config, "DATABASE_PATH", tmp_path / "dash.db")
    st.cache_resource.clear()  # fresh NIDSMonitor using the temp database
    try:
        at = AppTest.from_file(str(config.BASE_DIR / "app.py"), default_timeout=30).run()
        at.sidebar.radio[0].set_value("📡 Live Network Monitoring").run()
        assert not at.exception

        assert at.selectbox[0].value == WIFI_ID          # Wi-Fi preselected
        assert at.selectbox[0].options[0].startswith("Wi-Fi")
        at.checkbox[0].check().run()
        next(b for b in at.button if "Start Monitoring" in b.label).click().run()
        assert not at.exception
        assert fake_capture.last is not None and fake_capture.last.iface == WIFI_ID

        fake_capture.last.deliver(syn_scan_frames(20))
        at.run()
        metrics = {m.label: m.value for m in at.metric}
        assert metrics["Status"] == "Capturing"
        assert metrics["Packets Analysed"] == "20"
        assert int(metrics["Alerts (this session)"]) >= 1
        alert_tables = [df.value for df in at.dataframe if "rule" in df.value.columns]
        assert any("Port Scan" in set(t["rule"]) for t in alert_tables)

        next(b for b in at.button if "Stop Monitoring" in b.label).click().run()
        assert {m.label: m.value for m in at.metric}["Status"] == "Stopped"
    finally:
        st.cache_resource.clear()


# ------------------------------------------------------ real adapter (opt-in)
@pytest.mark.skipif(os.environ.get("NIDS_LIVE_TEST") != "1",
                    reason="set NIDS_LIVE_TEST=1 to capture from the real network adapter")
def test_real_live_capture_on_recommended_interface(tmp_path):
    supported, message = packet_capture.check_capture_support()
    assert supported, message
    iface = recommended_interface(list_interfaces())
    assert iface is not None and iface["connected"], "no connected adapter found"

    # Generate a little of OUR OWN traffic so the test does not depend on
    # background activity: one DNS lookup and one TCP connection.
    target_ip = socket.gethostbyname("example.com")
    cfg = AppConfig()
    cfg.suspicious_ips = [target_ip]   # watch-list it -> must raise a live alert

    mon = NIDSMonitor(AlertDatabase(tmp_path / "real.db"), cfg)
    mon.start_live(iface["name"], f"host {target_ip}")
    try:
        with socket.create_connection((target_ip, 80), timeout=5) as conn:
            conn.sendall(b"HEAD / HTTP/1.0\r\nHost: example.com\r\n\r\n")
            conn.recv(256)
        deadline = time.time() + 10
        while time.time() < deadline and not mon.recent_alerts:
            time.sleep(0.2)
    finally:
        mon.stop_live()

    status = mon.status()
    assert status["total_packets"] > 0, "no live packets captured"
    stored = mon.db.get_alerts()
    assert "Suspicious IP" in set(stored["rule"])
    assert set(stored["traffic_source"]) == {"live"}


def test_capture_support_detected_in_fresh_process():
    """Regression: in a fresh process (like a new `streamlit run`), the Npcap
    check and interface list must give the same answer as after Scapy has been
    fully imported. Previously only `scapy.config` was imported, so Windows
    reported "Npcap not found" and listed no interfaces."""
    import subprocess
    import sys

    import config

    code = (
        "from monitoring.packet_capture import check_capture_support, list_interfaces\n"
        "def snap():\n"
        "    ifs = list_interfaces()\n"
        "    return (check_capture_support()[0], len(ifs),\n"
        "            [i['name'] for i in ifs if i['is_default']])\n"
        "first = snap()\n"
        "import scapy.all\n"
        "after = snap()\n"
        "print(first == after, first, after)\n"
    )
    result = subprocess.run([sys.executable, "-c", code], cwd=config.BASE_DIR,
                            capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip().startswith("True"), result.stdout


def test_fresh_process_capture_decodes_ip_layers():
    """Regression: in a fresh process, frames handed to the capture callback
    must be decoded as IP/TCP, not Ether/Raw. Starting the capture has to load
    the protocol layers BEFORE the sniffer decodes anything."""
    import subprocess
    import sys

    import config

    code = (
        "import scapy.sendrecv, scapy.layers.l2 as l2\n"
        "from monitoring import packet_capture as pc\n"
        "raw = bytes.fromhex('020000000002020000000001080045000028000100004006'\n"
        "                    'f8d70a000042c0a8010a9c400050000000000000000050022000'\n"
        "                    '00000000')\n"
        "got = []\n"
        "class Sniffer:\n"
        "    def __init__(self, prn=None, **kw): self.prn, self.running, self.exception = prn, False, None\n"
        "    def start(self): self.running = True; self.prn(l2.Ether(raw))  # decoded NOW\n"
        "    def stop(self): self.running = False\n"
        "scapy.sendrecv.AsyncSniffer = Sniffer\n"
        "pc.check_capture_support = lambda: (True, 'ok')\n"
        "pc.STARTUP_CHECK_SECONDS = 0.01\n"
        "cap = pc.PacketCapture(got.append, None)\n"
        "pc.platform.system = lambda: 'Linux'  # skip interface lookup\n"
        "cap.start(); cap.stop()\n"
        "print(got[0].protocol if got else 'NOT ANALYSED', got[0].src_ip if got else '')\n"
    )
    result = subprocess.run([sys.executable, "-c", code], cwd=config.BASE_DIR,
                            capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    assert result.stdout.split() == ["HTTP", "10.0.0.66"], result.stdout
