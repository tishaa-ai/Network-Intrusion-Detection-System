"""Tests for the detection engine: every rule must really fire on attack
traffic and stay quiet on normal traffic."""

from config import RuleSettings
from detection.engine import DetectionEngine
from monitoring.offline_demo import (generate_synthetic_traffic, load_pcap_file,
                                     save_pcap_file)
from monitoring.packet_analyzer import analyze_packet

SCANNER, VICTIM = "10.0.0.66", "192.168.1.10"


def rules_fired(alerts):
    return {a.rule for a in alerts}


# ------------------------------------------------------------- Port scan
def test_port_scan_detected(make_packet, settings):
    engine = DetectionEngine(settings, suspicious_ips=[])
    packets = [make_packet(i * 0.1, SCANNER, VICTIM, src_port=40000 + i, dst_port=port,
                           tcp_flags="S") for i, port in enumerate(range(20, 40))]
    alerts = engine.process_packets(packets)

    scan_alerts = [a for a in alerts if a.rule == "Port Scan"]
    assert scan_alerts, "port scan should be detected"
    first = scan_alerts[0]
    assert first.src_ip == SCANNER and first.dst_ip == VICTIM
    assert first.severity == "High"
    assert "port scan" in first.description.lower()
    assert first.timestamp == packets[9].timestamp  # fires exactly at the 10th port


def test_port_scan_not_triggered_by_normal_browsing(make_packet, settings):
    engine = DetectionEngine(settings, suspicious_ips=[])
    # 30 connections, but only to ports 80 and 443
    packets = [make_packet(i * 0.2, "192.168.1.20", "93.184.216.34", src_port=50000 + i,
                           dst_port=443 if i % 2 else 80, tcp_flags="S") for i in range(30)]
    assert "Port Scan" not in rules_fired(engine.process_packets(packets))


def test_port_scan_respects_time_window(make_packet, settings):
    engine = DetectionEngine(settings, suspicious_ips=[])
    # 20 ports, but one every 2 s -> only ~5 ports inside any 10 s window
    packets = [make_packet(i * 2.0, SCANNER, VICTIM, dst_port=1000 + i, tcp_flags="S")
               for i in range(20)]
    assert "Port Scan" not in rules_fired(engine.process_packets(packets))


def test_port_scan_ignores_syn_ack_replies(make_packet, settings):
    engine = DetectionEngine(settings, suspicious_ips=[])
    packets = [make_packet(port * 0.1, VICTIM, SCANNER, src_port=port, dst_port=40000 + port,
                           tcp_flags="SA") for port in range(20)]
    assert "Port Scan" not in rules_fired(engine.process_packets(packets))


# ------------------------------------------------------------- SYN flood
def test_syn_flood_detected_and_escalates(make_packet, settings):
    engine = DetectionEngine(settings, suspicious_ips=[])
    packets = [make_packet(i * 0.01, "203.0.113.50", VICTIM, src_port=1024 + i, dst_port=80,
                           tcp_flags="S") for i in range(200)]
    alerts = [a for a in engine.process_packets(packets) if a.rule == "SYN Flood"]

    assert [a.severity for a in alerts] == ["High", "Critical"]
    assert "50 TCP SYN" in alerts[0].description           # at threshold (50)
    assert "150 TCP SYN" in alerts[1].description          # at 50 * 3 (escalation)


def test_completed_handshakes_are_not_a_syn_flood(make_packet, settings):
    engine = DetectionEngine(settings, suspicious_ips=[])
    # ACK / PSH-ACK packets of established connections must not be counted
    packets = [make_packet(i * 0.01, "192.168.1.20", VICTIM, src_port=50000, dst_port=443,
                           tcp_flags="PA" if i % 2 else "A") for i in range(300)]
    assert "SYN Flood" not in rules_fired(engine.process_packets(packets))


# ------------------------------------------------------------- ICMP flood
def test_icmp_flood_detected(make_packet, settings):
    engine = DetectionEngine(settings, suspicious_ips=[])
    packets = [make_packet(i * 0.05, "198.51.100.23", VICTIM, protocol="ICMP", icmp_type=8)
               for i in range(30)]
    alerts = [a for a in engine.process_packets(packets) if a.rule == "ICMP Flood"]
    assert len(alerts) == 1
    assert alerts[0].severity == "Medium"
    assert alerts[0].src_ip == "198.51.100.23"


def test_normal_ping_is_not_a_flood(make_packet, settings):
    engine = DetectionEngine(settings, suspicious_ips=[])
    # 4 pings one second apart, like Windows `ping` does
    packets = [make_packet(i, "192.168.1.20", "8.8.8.8", protocol="ICMP", icmp_type=8)
               for i in range(4)]
    assert not engine.process_packets(packets)


def test_icmp_echo_replies_not_counted(make_packet, settings):
    engine = DetectionEngine(settings, suspicious_ips=[])
    packets = [make_packet(i * 0.01, VICTIM, "198.51.100.23", protocol="ICMP", icmp_type=0)
               for i in range(100)]
    assert "ICMP Flood" not in rules_fired(engine.process_packets(packets))


# ------------------------------------------------------------- Suspicious IP
def test_suspicious_ip_inbound_and_outbound(make_packet, settings):
    engine = DetectionEngine(settings, suspicious_ips=["203.0.113.66", "not-an-ip"])
    inbound = make_packet(0, "203.0.113.66", VICTIM, dst_port=22, tcp_flags="S")
    outbound = make_packet(1, "192.168.1.12", "203.0.113.66", dst_port=4444, tcp_flags="S")

    first = engine.process_packet(inbound)
    assert [a.rule for a in first] == ["Suspicious IP"]
    assert "inbound" in first[0].description
    # Same bad IP again within the cooldown -> no duplicate alert
    assert engine.process_packet(outbound) == []


def test_suspicious_ip_alerts_again_after_cooldown(make_packet, settings):
    engine = DetectionEngine(settings, suspicious_ips=["203.0.113.66"], cooldown_seconds=30)
    a = engine.process_packet(make_packet(0, "192.168.1.12", "203.0.113.66", dst_port=4444,
                                          tcp_flags="S"))
    b = engine.process_packet(make_packet(31, "192.168.1.12", "203.0.113.66", dst_port=4444,
                                          tcp_flags="S"))
    assert len(a) == 1 and len(b) == 1
    assert "outbound" in b[0].description


def test_clean_ip_does_not_alert(make_packet, settings):
    engine = DetectionEngine(settings, suspicious_ips=["203.0.113.66"])
    assert engine.process_packet(make_packet(0, "192.168.1.12", "93.184.216.34",
                                             dst_port=443, tcp_flags="S")) == []


# ------------------------------------------------------------- Unusual traffic
def test_unusual_traffic_rate(make_packet, settings):
    settings["Unusual Traffic"] = RuleSettings(threshold=100, window_seconds=10, severity="Low")
    engine = DetectionEngine(settings, suspicious_ips=[])
    packets = [make_packet(i * 0.01, "192.168.1.50", "93.184.216.34", protocol="UDP",
                           src_port=5000, dst_port=5000) for i in range(120)]
    alerts = [a for a in engine.process_packets(packets) if a.rule == "Unusual Traffic"]
    assert len(alerts) == 1
    assert alerts[0].severity == "Low"


# ------------------------------------------------------------- engine
def test_disabled_rule_never_fires(make_packet, settings):
    settings["ICMP Flood"].enabled = False
    engine = DetectionEngine(settings, suspicious_ips=[])
    packets = [make_packet(i * 0.01, "198.51.100.23", VICTIM, protocol="ICMP", icmp_type=8)
               for i in range(100)]
    assert "ICMP Flood" not in rules_fired(engine.process_packets(packets))


def test_engine_reset_clears_state(make_packet, settings):
    engine = DetectionEngine(settings, suspicious_ips=[])
    for i in range(9):
        engine.process_packet(make_packet(i * 0.1, SCANNER, VICTIM, dst_port=i, tcp_flags="S"))
    engine.reset()
    # After reset, the 10th port is only the 1st one seen -> no alert
    assert engine.process_packet(make_packet(1, SCANNER, VICTIM, dst_port=99,
                                             tcp_flags="S")) == []


def test_full_demo_scenario_triggers_every_attack_rule():
    """The offline demo must produce real alerts from the real engine."""
    engine = DetectionEngine()  # default thresholds from config.py
    alerts = engine.process_packets(generate_synthetic_traffic(start_time=1_700_000_000))
    fired = rules_fired(alerts)
    assert {"Port Scan", "SYN Flood", "ICMP Flood", "Suspicious IP"} <= fired
    assert all(a.traffic_source == "simulated" for a in alerts)
    attackers = {a.src_ip for a in alerts if a.rule != "Suspicious IP"}
    assert attackers == {"10.0.0.66", "203.0.113.50", "198.51.100.23"}


def test_no_false_positives_on_normal_traffic():
    engine = DetectionEngine()
    normal = generate_synthetic_traffic(start_time=1_700_000_000, include_attacks=False)
    alerts = engine.process_packets(normal)
    # Only the deliberate C2 beacon to the watch-listed IP should alert.
    assert rules_fired(alerts) == {"Suspicious IP"}


# ------------------------------------------------------------- Scapy analyzer / PCAP
def test_analyzer_decodes_real_scapy_packets():
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.packet import Raw

    syn = analyze_packet(IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=22,
                                                                  flags="S"))
    assert (syn.protocol, syn.src_port, syn.dst_port, syn.is_syn) == ("SSH", 1234, 22, True)

    http = analyze_packet(IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=5555, dport=80,
                          flags="PA") / Raw(b"GET /login HTTP/1.1\r\nHost: x\r\n\r\n"))
    assert http.protocol == "HTTP" and http.info.startswith("GET /login")

    dns = analyze_packet(IP(src="10.0.0.1", dst="10.0.0.53") / UDP(sport=5353, dport=53)
                         / DNS(rd=1, qd=[DNSQR(qname="example.com")]))
    assert dns.protocol == "DNS" and "example.com" in dns.info

    ping = analyze_packet(IP(src="10.0.0.1", dst="10.0.0.2") / ICMP(type=8))
    assert ping.protocol == "ICMP" and ping.is_icmp_echo_request


def test_pcap_roundtrip_detects_attacks(tmp_path):
    """Write the demo traffic to a real PCAP, read it back with Scapy, detect."""
    packets = generate_synthetic_traffic(start_time=1_700_000_000)
    pcap = save_pcap_file(packets, tmp_path / "demo.pcap")
    loaded = load_pcap_file(pcap)
    assert len(loaded) == len(packets)
    alerts = DetectionEngine().process_packets(loaded)
    assert {"Port Scan", "SYN Flood", "ICMP Flood", "Suspicious IP"} <= rules_fired(alerts)
    assert all(a.traffic_source == "pcap" for a in alerts)
