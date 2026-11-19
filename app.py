"""
Network Intrusion Detection System - Streamlit dashboard.

Run with:
    streamlit run app.py

Pages (sidebar):
    1. Overview                 - key metrics and charts
    2. Live Network Monitoring  - live capture (Scapy) + offline demo
    3. Packet Analysis          - inspect / filter captured packets
    4. Intrusion Alerts         - filter, search and review alerts
    5. Detection Rules          - tune thresholds, severities, watch-list
    6. Reports and Export       - summary report and CSV export
    7. About Project
"""

from __future__ import annotations

import tempfile
from datetime import datetime
from pathlib import Path

import pandas as pd
import streamlit as st

import config
from config import AppConfig, RuleSettings
from dashboard import visualizations as viz
from database import AlertDatabase
from detection.engine import ALL_RULE_CLASSES
from monitoring.monitor import NIDSMonitor
from monitoring.offline_demo import (generate_synthetic_traffic, load_csv_file,
                                     load_pcap_file)
from monitoring.packet_capture import (check_capture_support, list_interfaces,
                                       recommended_interface)
from utils.logger import get_logger

logger = get_logger(__name__)

st.set_page_config(page_title="NIDS - Network Intrusion Detection System",
                   page_icon="🛡️", layout="wide")

# ---------------------------------------------------------------- styling
st.markdown(
    """
    <style>
    .block-container {padding-top: 3.5rem;}
    div[data-testid="stMetric"] {
        background: #111a2e; border: 1px solid #1f2a44; border-radius: 10px;
        padding: 14px 16px;
    }
    div[data-testid="stMetricLabel"] p {color: #8b949e; font-size: 0.85rem;}
    .nids-sub {color: #8b949e; margin-top: 0;}
    .badge {display: inline-block; padding: 3px 10px; border-radius: 999px;
            font-size: 0.8rem; font-weight: 600;}
    .badge-live {background: #0f3d1f; color: #3fb950; border: 1px solid #3fb950;}
    .badge-demo {background: #3d2e0f; color: #d29922; border: 1px solid #d29922;}
    .badge-idle {background: #1f2a44; color: #8b949e; border: 1px solid #30363d;}
    .badge-error {background: #3d0f12; color: #f85149; border: 1px solid #f85149;}
    </style>
    """,
    unsafe_allow_html=True,
)


# ---------------------------------------------------------------- shared state
@st.cache_resource
def get_monitor() -> NIDSMonitor:
    """One monitor for the whole app. It survives page reloads, so a running
    live capture is not lost when the browser tab refreshes."""
    return NIDSMonitor(AlertDatabase(config.DATABASE_PATH), AppConfig())


monitor = get_monitor()
db = monitor.db

PAGES = [
    "🏠 Overview",
    "📡 Live Network Monitoring",
    "🔬 Packet Analysis",
    "🚨 Intrusion Alerts",
    "⚙️ Detection Rules",
    "📄 Reports and Export",
    "ℹ️ About Project",
]
SOURCE_LABELS = {"live": "Live", "simulated": "Simulated", "csv": "Simulated (CSV)",
                 "pcap": "Offline PCAP"}


# ---------------------------------------------------------------- helpers
def status_badge() -> str:
    status = monitor.status()
    if status["is_live"]:
        return '<span class="badge badge-live">● LIVE MONITORING</span>'
    if status["mode"] == "Offline Demo":
        return '<span class="badge badge-demo">● OFFLINE DEMO DATA</span>'
    if status["interrupted"]:
        return '<span class="badge badge-error">● CAPTURE INTERRUPTED</span>'
    return '<span class="badge badge-idle">● IDLE</span>'


def page_header(title: str, subtitle: str) -> None:
    st.markdown(f"## {title}")
    st.markdown(f'<p class="nids-sub">{subtitle} &nbsp; {status_badge()}</p>',
                unsafe_allow_html=True)
    status = monitor.status()
    if status["mode"] == "Offline Demo":
        st.info(f"🧪 **Showing offline / simulated traffic** - {status['label']}. "
                "These packets were NOT captured from your live network.", icon="ℹ️")
    if "demo_message" in st.session_state:  # set by run_offline_demo()
        st.success(st.session_state.pop("demo_message"), icon="✅")


def severity_style(df: pd.DataFrame):
    """Colour the severity column of an alerts table."""
    def colour(value: str) -> str:
        c = config.SEVERITY_COLORS.get(value)
        return f"background-color: {c}33; color: {c}; font-weight: 600" if c else ""
    if df.empty or "severity" not in df.columns:
        return df
    return df.style.map(colour, subset=["severity"])


def prepare_alerts_table(alerts: pd.DataFrame) -> pd.DataFrame:
    if alerts.empty:
        return alerts
    table = alerts.copy()
    table["data"] = table["traffic_source"].map(SOURCE_LABELS).fillna(table["traffic_source"])
    return table[["time", "severity", "rule", "src_ip", "dst_ip", "description", "data"]]


def run_offline_demo(source: str, uploaded_file=None, clear_db: bool = True) -> None:
    """Load offline packets and replay them through the detection engine."""
    try:
        if source == "Synthetic generator":
            packets = generate_synthetic_traffic()
            label = "Synthetic attack scenario (simulated)"
        elif source == "Sample CSV file":
            packets = load_csv_file(config.SAMPLE_CSV_PATH)
            label = f"Sample CSV - {config.SAMPLE_CSV_PATH.name} (simulated)"
        elif source == "Sample PCAP file":
            packets = load_pcap_file(config.SAMPLE_PCAP_PATH)
            label = f"Sample PCAP - {config.SAMPLE_PCAP_PATH.name} (simulated)"
        else:  # uploaded file
            if uploaded_file is None:
                st.warning("Please choose a .pcap, .pcapng or .csv file first.")
                return
            suffix = Path(uploaded_file.name).suffix.lower()
            with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
                tmp.write(uploaded_file.getbuffer())
                tmp_path = Path(tmp.name)
            try:
                if suffix == ".csv":
                    packets = load_csv_file(tmp_path)
                else:
                    packets = load_pcap_file(tmp_path)
            finally:
                tmp_path.unlink(missing_ok=True)
            label = f"Uploaded file - {uploaded_file.name}"
    except FileNotFoundError:
        st.error("Sample file not found. Run `python generate_sample_data.py` to create it.")
        return
    except Exception as exc:
        logger.exception("Offline demo failed")
        st.error(f"Could not load traffic: {exc}")
        return

    if not packets:
        st.warning("No IP packets were found in that source.")
        return

    if clear_db:
        db.clear_alerts()
    bar = st.progress(0.0, text="Running detection engine...")
    alerts = monitor.run_offline(packets, label,
                                 progress=lambda f: bar.progress(f, text=f"Analysing... {f:.0%}"))
    bar.empty()
    # The sidebar and other widgets were drawn BEFORE this ran, so save the
    # message and re-run the script to refresh everything with the new data.
    st.session_state["demo_message"] = (
        f"Analysed **{len(packets):,}** packets with the detection engine and "
        f"generated **{len(alerts)}** alerts.")
    st.rerun()


# ---------------------------------------------------------------- sidebar
with st.sidebar:
    st.markdown("## 🛡️ NIDS")
    st.caption("Network Intrusion Detection System")
    page = st.radio("Navigation", PAGES, label_visibility="collapsed")
    st.divider()
    st.markdown(status_badge(), unsafe_allow_html=True)
    s = monitor.status()
    st.caption(f"Packets this session: **{s['total_packets']:,}**  \n"
               f"Alerts this session: **{s['session_alerts']:,}**")
    st.divider()
    st.caption("⚠️ Only monitor networks and devices you own or are explicitly "
               "authorised to monitor. This tool is passive: it never sends traffic.")


# ================================================================ PAGES
def page_overview() -> None:
    page_header("Security Overview", "Network traffic and intrusion summary")
    packets = monitor.packets_dataframe()
    alerts = db.get_alerts()
    status = monitor.status()

    if packets.empty and alerts.empty:
        st.warning("No traffic analysed yet. Start live monitoring, or run the offline "
                   "demo to see the detection engine in action.")
        if st.button("▶ Run offline demo now (synthetic traffic)", type="primary"):
            run_offline_demo("Synthetic generator")
        return

    high = int(alerts["severity"].isin(["High", "Critical"]).sum()) if not alerts.empty else 0
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total Packets", f"{status['total_packets']:,}")
    c2.metric("Total Alerts", f"{len(alerts):,}")
    c3.metric("High / Critical Alerts", f"{high:,}")
    c4.metric("Unique Source IPs", f"{packets['src_ip'].nunique() if not packets.empty else 0:,}")
    mode_text = {"Offline Demo": "Demo"}.get(status["mode"], status["mode"])
    c5.metric("Monitoring Status", "LIVE" if status["is_live"] else mode_text)

    left, right = st.columns(2)
    left.plotly_chart(viz.traffic_over_time(packets), width="stretch", key="chart_1")
    right.plotly_chart(viz.protocol_distribution(packets), width="stretch", key="chart_2")

    left, right = st.columns(2)
    left.plotly_chart(viz.alerts_by_severity(alerts), width="stretch", key="chart_3")
    right.plotly_chart(viz.top_talkers(packets), width="stretch", key="chart_4")

    st.subheader("🚨 Recent Security Alerts")
    if alerts.empty:
        st.success("No alerts - no suspicious activity detected.")
    else:
        st.dataframe(severity_style(prepare_alerts_table(alerts.head(10))),
                     width="stretch", hide_index=True)

    st.subheader("🎯 Suspicious Source IP Addresses")
    sources = viz.suspicious_sources(alerts)
    if sources.empty:
        st.caption("No suspicious sources yet.")
    else:
        st.dataframe(sources.style.map(
            lambda v: f"color: {config.SEVERITY_COLORS.get(v, '')}; font-weight: 600",
            subset=["worst_severity"]), width="stretch", hide_index=True)


def live_status_panel(expected_live: bool = False) -> None:
    """Auto-refreshing panel (re-runs every few seconds while capturing)."""
    status = monitor.status()
    if expected_live and not status["is_live"]:
        # Capture ended (interrupted or stopped elsewhere): redraw the whole page
        # so the buttons, badge and sidebar show the new state.
        st.rerun(scope="app")
    packets = monitor.packets_dataframe()
    cap = status["capture"] or {}

    c1, c2, c3, c4, c5 = st.columns(5)
    state = ("Capturing" if status["is_live"]
             else "Interrupted" if status["interrupted"] else "Stopped")
    c1.metric("Status", state)
    c2.metric("Packets Analysed", f"{status['total_packets']:,}",
              help="Packets decoded and passed to the detection engine.")
    c3.metric("Alerts (this session)", f"{status['session_alerts']:,}")
    c4.metric("Packets / second", f"{cap.get('packets_per_second', 0.0):.1f}")
    elapsed = 0
    if status["started_at"]:
        elapsed = int(datetime.now().timestamp() - status["started_at"])
        c5.metric("Running For", f"{elapsed // 60}m {elapsed % 60}s")
    else:
        c5.metric("Running For", "-")

    if cap:
        since = cap["seconds_since_last_packet"]
        last = "no packets yet" if since is None else f"last packet {since:.0f}s ago"
        st.caption(f"Interface **{cap['interface']}** · frames received "
                   f"**{cap['frames_seen']:,}** · non-IP frames skipped "
                   f"**{cap['skipped_frames']:,}** · {last}")
        if status["is_live"] and since is None and elapsed > 10:
            st.warning("No packets received yet. Check that the selected adapter is the "
                       "one connected to your network (usually Wi-Fi or Ethernet).")

    # (Start-up errors are shown next to the Start button instead.)
    if status["last_error"] and (status["is_live"] or status["interrupted"]):
        st.error(status["last_error"])

    st.markdown("**🚨 Real-time alerts (this session)**")
    session_alerts = monitor.session_alerts_dataframe(limit=20)
    if session_alerts.empty:
        st.caption("No alerts in this session yet.")
    else:
        st.dataframe(severity_style(prepare_alerts_table(session_alerts)), width="stretch",
                     hide_index=True)

    st.plotly_chart(viz.traffic_over_time(packets), width="stretch",
                    key="live_traffic")
    st.markdown("**Latest packets**")
    if packets.empty:
        st.caption("Waiting for packets...")
    else:
        cols = ["time", "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "length",
                "info"]
        st.dataframe(packets[cols].tail(50).iloc[::-1], width="stretch", hide_index=True,
                     height=320)


def page_live_monitoring() -> None:
    page_header("Live Network Monitoring", "Capture live packets or replay offline traffic")
    live_tab, demo_tab = st.tabs(["📡 Live Capture", "🧪 Offline Demo Mode"])

    with live_tab:
        supported, message = check_capture_support()
        if supported:
            st.caption(f"✅ {message}")
        else:
            st.warning(f"Live capture unavailable: {message}")

        interfaces = list_interfaces() if supported else []
        by_id = {i["name"]: i for i in interfaces}
        best = recommended_interface(interfaces)
        ids = list(by_id)
        iface_name = st.selectbox(
            "Network interface", ids or [None],
            index=ids.index(best["name"]) if best and best["name"] in ids else 0,
            format_func=lambda i: by_id[i]["label"] if i in by_id else "(no interfaces found)",
            disabled=monitor.is_live or not ids,
            help="Pick the adapter connected to your network - on most laptops 'Wi-Fi'. "
                 "Adapters marked 'not connected' will capture little or nothing.")
        if iface_name in by_id and not by_id[iface_name]["connected"]:
            st.caption("⚠️ This adapter is not connected - you will see few or no packets.")
        bpf = st.text_input("Capture filter (optional, BPF syntax)",
                            placeholder="e.g.  tcp or udp or icmp", disabled=monitor.is_live)
        authorised = st.checkbox("I confirm I own this network/device or have explicit "
                                 "permission to monitor it.", value=monitor.is_live)

        b1, b2, _ = st.columns([1, 1, 3])
        if b1.button("▶ Start Monitoring", type="primary",
                     disabled=monitor.is_live or not supported or not authorised
                              or not ids):
            try:
                with st.spinner("Starting packet capture..."):
                    monitor.start_live(iface_name, bpf)
                st.rerun()
            except RuntimeError as exc:
                st.error(str(exc))
        if b2.button("⏹ Stop Monitoring", disabled=not monitor.is_live):
            monitor.stop_live()
            st.rerun()

        st.divider()
        if monitor.is_live:
            st.fragment(run_every=config.DASHBOARD_REFRESH_SECONDS)(live_status_panel)(True)
        else:
            live_status_panel()

    with demo_tab:
        st.markdown(
            "Offline demo mode replays **recorded or simulated traffic** through the "
            "**same detection engine** used for live capture. It needs no administrator "
            "rights and no Npcap, and it never sends packets on your network.")
        source = st.radio("Traffic source", ["Synthetic generator", "Sample CSV file",
                                             "Sample PCAP file", "Upload my own file"],
                          horizontal=True)
        descriptions = {
            "Synthetic generator": "Generates ~2,000 realistic packets: normal web/DNS "
                                   "traffic plus a port scan, SYN flood, ICMP flood and "
                                   "beaconing to a watch-listed IP.",
            "Sample CSV file": f"Replays packet records from `data/{config.SAMPLE_CSV_PATH.name}`.",
            "Sample PCAP file": f"Parses real packets from `data/{config.SAMPLE_PCAP_PATH.name}` "
                                "with Scapy (you can open this file in Wireshark too).",
            "Upload my own file": "Analyse a .pcap/.pcapng (e.g. saved from Wireshark) or a "
                                  "CSV in the same format as the sample.",
        }
        st.caption(descriptions[source])
        uploaded = None
        if source == "Upload my own file":
            uploaded = st.file_uploader("PCAP or CSV file", type=["pcap", "pcapng", "cap", "csv"])
        clear_db = st.checkbox("Clear previously stored alerts before running", value=True)
        if st.button("▶ Run Offline Demo", type="primary", disabled=monitor.is_live):
            run_offline_demo(source, uploaded, clear_db)
        if monitor.is_live:
            st.caption("Stop live monitoring to run the offline demo.")


def page_packet_analysis() -> None:
    page_header("Packet Analysis", "Inspect and filter analysed packets")
    packets = monitor.packets_dataframe()
    if packets.empty:
        st.warning("No packets yet - start live monitoring or run the offline demo.")
        return

    c1, c2, c3 = st.columns([2, 2, 1])
    protocols = sorted(packets["protocol"].unique())
    chosen = c1.multiselect("Protocol", protocols, default=protocols)
    ip_query = c2.text_input("Search IP address", placeholder="e.g. 192.168.1.10")
    port_query = c3.text_input("Port", placeholder="e.g. 443")

    view = packets[packets["protocol"].isin(chosen)]
    if ip_query.strip():
        q = ip_query.strip()
        view = view[view["src_ip"].str.contains(q, regex=False)
                    | view["dst_ip"].str.contains(q, regex=False)]
    if port_query.strip():
        try:
            port = int(port_query)
            view = view[(view["src_port"] == port) | (view["dst_port"] == port)]
        except ValueError:
            st.error("Port must be a number.")

    st.caption(f"Showing {len(view):,} of {len(packets):,} packets")
    cols = ["time", "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "tcp_flags",
            "length", "info", "source"]
    st.dataframe(view[cols].iloc[::-1], width="stretch", hide_index=True, height=380)
    st.download_button("⬇ Download these packets (CSV)", view[cols].to_csv(index=False),
                       file_name="packets.csv", mime="text/csv")

    left, right = st.columns(2)
    left.plotly_chart(viz.protocol_distribution(view), width="stretch", key="chart_5")
    right.plotly_chart(viz.top_destination_ports(view), width="stretch", key="chart_6")
    left, right = st.columns(2)
    left.plotly_chart(viz.top_talkers(view, "src_ip"), width="stretch", key="chart_7")
    right.plotly_chart(viz.packet_size_histogram(view), width="stretch", key="chart_8")


def page_alerts() -> None:
    page_header("Intrusion Alerts", "Review, filter and search security alerts")
    rule_names = [r.name for r in ALL_RULE_CLASSES]

    c1, c2, c3 = st.columns([2, 2, 2])
    severities = c1.multiselect("Severity", config.SEVERITY_LEVELS,
                                default=config.SEVERITY_LEVELS)
    rules = c2.multiselect("Detection type", rule_names, default=rule_names)
    ip_search = c3.text_input("Search by IP address", placeholder="e.g. 203.0.113.50")

    alerts = db.get_alerts(severities=severities or None, rules=rules or None,
                           ip_search=ip_search)
    if not severities or not rules:
        alerts = alerts.iloc[0:0]

    m1, m2, m3, m4 = st.columns(4)
    for col, level in zip((m1, m2, m3, m4), reversed(config.SEVERITY_LEVELS)):
        col.metric(level, int((alerts["severity"] == level).sum()) if not alerts.empty else 0)

    if alerts.empty:
        st.info("No alerts match the current filters.")
        return

    st.plotly_chart(viz.alert_timeline(alerts), width="stretch", key="chart_9")
    st.dataframe(severity_style(prepare_alerts_table(alerts)), width="stretch",
                 hide_index=True, height=360)

    with st.expander("🔍 Alert details (evidence)"):
        for _, row in alerts.head(50).iterrows():
            st.markdown(f"**[{row['severity']}] {row['rule']}** - {row['time']}  \n"
                        f"{row['description']}  \n`{row['details']}`")

    d1, d2 = st.columns([1, 4])
    d1.download_button("⬇ Export filtered alerts (CSV)", db.alerts_to_csv(alerts),
                       file_name=f"nids_alerts_{datetime.now():%Y%m%d_%H%M%S}.csv",
                       mime="text/csv")
    with d2.popover("🗑 Clear all alerts"):
        st.write("This permanently deletes every alert in the database.")
        if st.button("Yes, delete all alerts", type="primary"):
            db.clear_alerts()
            st.rerun()


def page_rules() -> None:
    page_header("Detection Rules", "Tune thresholds, time windows and severities")
    st.markdown("Each rule uses a **sliding time window**: it counts events per source "
                "IP over the last *N* seconds and raises an alert when the count reaches "
                "the **threshold**. If the count reaches *threshold × escalation factor*, "
                "severity is raised one level.")
    cfg = monitor.app_config
    new_rules: dict[str, RuleSettings] = {}

    with st.form("rules_form"):
        for rule_class in ALL_RULE_CLASSES:
            current = cfg.rules.get(rule_class.name, RuleSettings())
            with st.expander(f"**{rule_class.name}**  —  {current.severity} severity, "
                             f"threshold {current.threshold} in {current.window_seconds:g}s",
                             expanded=False):
                st.caption(rule_class.description)
                c1, c2, c3, c4, c5 = st.columns(5)
                key = rule_class.name.replace(" ", "_")
                enabled = c1.toggle("Enabled", current.enabled, key=f"{key}_en")
                threshold = c2.number_input("Threshold", 1, 100_000, int(current.threshold),
                                            key=f"{key}_th")
                window = c3.number_input("Window (seconds)", 1.0, 3600.0,
                                         float(current.window_seconds), step=1.0,
                                         key=f"{key}_win")
                severity = c4.selectbox("Severity", config.SEVERITY_LEVELS,
                                        config.SEVERITY_LEVELS.index(current.severity),
                                        key=f"{key}_sev")
                escalation = c5.number_input("Escalation factor (0 = off)", 0.0, 100.0,
                                             float(current.escalation_factor), step=0.5,
                                             key=f"{key}_esc")
                new_rules[rule_class.name] = RuleSettings(enabled, int(threshold), window,
                                                          severity, escalation)

        st.markdown("**Suspicious IP watch-list** (one IP per line)")
        ip_text = st.text_area("Suspicious IPs", "\n".join(cfg.suspicious_ips), height=120,
                               label_visibility="collapsed")
        cooldown = st.number_input("Alert cooldown per source (seconds)", 0.0, 3600.0,
                                   float(cfg.cooldown_seconds), step=5.0,
                                   help="Prevents one ongoing attack from creating "
                                        "hundreds of duplicate alerts.")
        c1, c2 = st.columns([1, 5])
        save = c1.form_submit_button("💾 Apply Rules", type="primary")
        reset = c2.form_submit_button("↺ Reset to defaults")

    if save:
        ips = [line.strip() for line in ip_text.splitlines() if line.strip()]
        monitor.apply_config(AppConfig(new_rules, ips, cooldown))
        st.success("Rules applied. They take effect for the next packets analysed "
                   "(re-run the offline demo to see the effect).")
    if reset:
        monitor.apply_config(AppConfig())
        for k in list(st.session_state):
            if k.endswith(("_en", "_th", "_win", "_sev", "_esc")):
                del st.session_state[k]
        st.rerun()

    st.subheader("Active rule summary")
    summary = pd.DataFrame([{
        "Rule": name, "Enabled": "✅" if s.enabled else "❌", "Threshold": s.threshold,
        "Window (s)": s.window_seconds, "Severity": s.severity,
        "Escalates at": (f"{s.threshold * s.escalation_factor:g}" if s.escalation_factor
                         else "-"),
    } for name, s in monitor.app_config.rules.items()])
    st.dataframe(summary, width="stretch", hide_index=True)


def page_reports() -> None:
    page_header("Reports and Export", "Summaries for incident reporting")
    alerts = db.get_alerts()
    packets = monitor.packets_dataframe()
    status = monitor.status()

    if alerts.empty:
        st.info("No alerts stored yet. Run the offline demo or live monitoring first.")
    else:
        left, right = st.columns(2)
        left.plotly_chart(viz.alerts_by_rule(alerts), width="stretch", key="chart_10")
        right.plotly_chart(viz.alerts_by_severity(alerts), width="stretch", key="chart_11")

        st.subheader("Summary by detection type")
        pivot = (alerts.pivot_table(index="rule", columns="severity", values="id",
                                    aggfunc="count", fill_value=0)
                 .reindex(columns=config.SEVERITY_LEVELS, fill_value=0))
        pivot["Total"] = pivot.sum(axis=1)
        st.dataframe(pivot, width="stretch")

    st.subheader("Export")
    report_lines = [
        "NETWORK INTRUSION DETECTION SYSTEM - INCIDENT SUMMARY",
        f"Generated: {datetime.now():%Y-%m-%d %H:%M:%S}",
        f"Data source: {status['label'] or status['mode']}",
        f"Packets analysed (this session): {status['total_packets']:,}",
        f"Unique source IPs: {packets['src_ip'].nunique() if not packets.empty else 0}",
        f"Total alerts stored: {len(alerts)}",
        "",
        "ALERTS BY SEVERITY",
    ]
    for level in reversed(config.SEVERITY_LEVELS):
        count = int((alerts["severity"] == level).sum()) if not alerts.empty else 0
        report_lines.append(f"  {level:<9}{count}")
    report_lines += ["", "TOP SUSPICIOUS SOURCES"]
    for _, row in viz.suspicious_sources(alerts).head(10).iterrows():
        report_lines.append(f"  {row['src_ip']:<16} {row['worst_severity']:<9} "
                            f"{row['alerts']} alert(s): {row['detections']}")
    report_lines += ["", "ALERT LOG"]
    for _, row in alerts.iterrows():
        report_lines.append(f"  {row['time']}  [{row['severity']}] {row['rule']}: "
                            f"{row['description']}")
    report = "\n".join(report_lines)

    c1, c2, c3 = st.columns(3)
    c1.download_button("⬇ All alerts (CSV)", db.alerts_to_csv(alerts),
                       file_name="nids_alerts.csv", mime="text/csv", width="stretch")
    c2.download_button("⬇ Incident summary (TXT)", report, file_name="nids_report.txt",
                       mime="text/plain", width="stretch")
    if c3.button("💾 Save CSV to data/exports/", width="stretch"):
        path = db.export_csv(config.DATA_DIR / "exports" /
                             f"alerts_{datetime.now():%Y%m%d_%H%M%S}.csv")
        st.success(f"Saved to {path}")
    with st.expander("Preview incident summary"):
        st.code(report, language="text")


def page_about() -> None:
    page_header("About This Project", "How the NIDS works")
    st.markdown(
        """
### What is it?
A **Network Intrusion Detection System (NIDS)** watches network traffic and raises
alerts when it sees patterns that look like attacks. This project is a
**signature/threshold-based** NIDS written in Python.

### How it works
```
 Packet source ─► Packet Analyzer ─► Detection Engine ─► SQLite ─► Dashboard
 (live Scapy,      (raw packet ->      (5 rules with       (alerts)   (Streamlit
  PCAP, CSV,        PacketInfo)         sliding windows)              + Plotly)
  simulator)
```
1. **Capture** – Scapy's `AsyncSniffer` reads packets from the network card (via Npcap on
   Windows) in a background thread. Offline mode reads a PCAP/CSV or generates traffic.
2. **Analyse** – each packet is decoded into a simple record: time, IPs, ports, protocol,
   TCP flags, size.
3. **Detect** – every rule inspects every packet and keeps per-source counters over a
   sliding time window.
4. **Alert** – alerts get a severity, description and timestamp, are stored in SQLite and
   shown on the dashboard.

### Detection rules
| Rule | What it looks for | Default |
|---|---|---|
| Port Scan | One source touching many distinct ports on one host | 15 ports / 10 s |
| SYN Flood | Many TCP SYNs (no ACK) from one source | 100 SYN / 10 s |
| ICMP Flood | Many ping (echo request) packets from one source | 50 / 10 s |
| Suspicious IP | Any traffic to/from a watch-listed IP | first packet |
| Unusual Traffic | Abnormally high packet rate from one source | 300 / 10 s |

### Safety
* Passive only – the tool never sends packets.
* Only monitor networks you own or are explicitly authorised to monitor.
* Demo data uses private and RFC 5737 documentation IP addresses.

### Tech stack
Python · Scapy · Streamlit · Pandas · Plotly · SQLite · logging · pytest
        """
    )


ROUTES = {
    PAGES[0]: page_overview,
    PAGES[1]: page_live_monitoring,
    PAGES[2]: page_packet_analysis,
    PAGES[3]: page_alerts,
    PAGES[4]: page_rules,
    PAGES[5]: page_reports,
    PAGES[6]: page_about,
}
ROUTES[page]()
