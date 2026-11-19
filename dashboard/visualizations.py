"""
Plotly chart builders for the dashboard.

Each function takes a pandas DataFrame and returns a Plotly Figure. They
never crash on empty data - they return a friendly "no data" figure instead.
"""

from __future__ import annotations

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

import config

# Dark "SOC" look shared by every chart
ACCENT = "#00c2ff"
PROTOCOL_COLORS = {
    "TCP": "#00c2ff", "UDP": "#a371f7", "ICMP": "#f0883e", "DNS": "#3fb950",
    "HTTP": "#d29922", "HTTPS": "#58a6ff", "ARP": "#8b949e", "SSH": "#db61a2",
    "OTHER": "#6e7681",
}
SEVERITY_ORDER = config.SEVERITY_LEVELS


def _style(fig: go.Figure, height: int = 340) -> go.Figure:
    fig.update_layout(
        template="plotly_dark",
        height=height,
        margin=dict(l=10, r=10, t=40, b=10),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#c9d1d9", size=12),
        legend=dict(bgcolor="rgba(0,0,0,0)"),
        title_font=dict(size=15, color="#e6edf3"),
    )
    fig.update_xaxes(gridcolor="#21262d", zerolinecolor="#21262d")
    fig.update_yaxes(gridcolor="#21262d", zerolinecolor="#21262d")
    return fig


def empty_figure(message: str = "No data yet", height: int = 340) -> go.Figure:
    fig = go.Figure()
    fig.add_annotation(text=message, showarrow=False, font=dict(size=14, color="#8b949e"),
                       xref="paper", yref="paper", x=0.5, y=0.5)
    fig.update_xaxes(visible=False)
    fig.update_yaxes(visible=False)
    return _style(fig, height)


# ------------------------------------------------------------- packets
def protocol_distribution(packets: pd.DataFrame) -> go.Figure:
    if packets.empty:
        return empty_figure("No packets captured yet")
    counts = packets["protocol"].value_counts().reset_index()
    counts.columns = ["protocol", "packets"]
    fig = px.pie(counts, names="protocol", values="packets", hole=0.55,
                 title="Protocol Distribution", color="protocol",
                 color_discrete_map=PROTOCOL_COLORS)
    fig.update_traces(textposition="inside", textinfo="percent+label")
    return _style(fig)


def _bin_size(packets: pd.DataFrame) -> str:
    """Pick a sensible time bucket based on how long the capture is."""
    span = packets["timestamp"].max() - packets["timestamp"].min()
    if span <= 120:
        return "1s"
    if span <= 1800:
        return "10s"
    if span <= 7200:
        return "1min"
    return "5min"


def traffic_over_time(packets: pd.DataFrame) -> go.Figure:
    if packets.empty:
        return empty_figure("No packets captured yet")
    bucket = _bin_size(packets)
    series = (packets.set_index("datetime").groupby("protocol")
              .resample(bucket).size().rename("packets").reset_index())
    fig = px.area(series, x="datetime", y="packets", color="protocol",
                  title=f"Traffic Over Time (packets per {bucket})",
                  color_discrete_map=PROTOCOL_COLORS)
    fig.update_layout(xaxis_title=None, yaxis_title="Packets", hovermode="x unified")
    return _style(fig)


def top_talkers(packets: pd.DataFrame, column: str = "src_ip", n: int = 10) -> go.Figure:
    if packets.empty:
        return empty_figure("No packets captured yet")
    counts = packets[column].value_counts().head(n).reset_index()
    counts.columns = [column, "packets"]
    label = "Source" if column == "src_ip" else "Destination"
    fig = px.bar(counts.iloc[::-1], x="packets", y=column, orientation="h",
                 title=f"Top {n} {label} IPs by Packets")
    fig.update_traces(marker_color=ACCENT)
    fig.update_layout(yaxis_title=None, xaxis_title="Packets")
    return _style(fig)


def top_destination_ports(packets: pd.DataFrame, n: int = 15) -> go.Figure:
    ports = packets.dropna(subset=["dst_port"]) if not packets.empty else packets
    if ports.empty:
        return empty_figure("No TCP/UDP packets yet")
    counts = ports["dst_port"].astype(int).astype(str).value_counts().head(n).reset_index()
    counts.columns = ["port", "packets"]
    fig = px.bar(counts, x="port", y="packets", title=f"Top {n} Destination Ports")
    fig.update_traces(marker_color="#a371f7")
    fig.update_xaxes(type="category", title=None)
    return _style(fig)


def packet_size_histogram(packets: pd.DataFrame) -> go.Figure:
    if packets.empty:
        return empty_figure("No packets captured yet")
    fig = px.histogram(packets, x="length", nbins=40, color="protocol",
                       title="Packet Size Distribution (bytes)",
                       color_discrete_map=PROTOCOL_COLORS)
    fig.update_layout(xaxis_title="Bytes", yaxis_title="Packets", bargap=0.05)
    return _style(fig)


# ------------------------------------------------------------- alerts
def alerts_by_severity(alerts: pd.DataFrame) -> go.Figure:
    if alerts.empty:
        return empty_figure("No alerts yet")
    counts = (alerts["severity"].value_counts()
              .reindex(SEVERITY_ORDER, fill_value=0).reset_index())
    counts.columns = ["severity", "alerts"]
    fig = px.bar(counts, x="severity", y="alerts", color="severity",
                 title="Alerts by Severity", color_discrete_map=config.SEVERITY_COLORS,
                 category_orders={"severity": SEVERITY_ORDER}, text="alerts")
    fig.update_layout(showlegend=False, xaxis_title=None, yaxis_title="Alerts")
    return _style(fig)


def alerts_by_rule(alerts: pd.DataFrame) -> go.Figure:
    if alerts.empty:
        return empty_figure("No alerts yet")
    counts = (alerts.groupby(["rule", "severity"]).size().rename("alerts").reset_index())
    fig = px.bar(counts, x="alerts", y="rule", color="severity", orientation="h",
                 title="Alerts by Detection Type", color_discrete_map=config.SEVERITY_COLORS,
                 category_orders={"severity": SEVERITY_ORDER})
    fig.update_layout(yaxis_title=None, xaxis_title="Alerts")
    return _style(fig)


def alert_timeline(alerts: pd.DataFrame) -> go.Figure:
    if alerts.empty:
        return empty_figure("No alerts yet")
    data = alerts.copy()
    data["datetime"] = pd.to_datetime(data["time"])
    fig = px.scatter(data, x="datetime", y="rule", color="severity",
                     hover_data={"src_ip": True, "dst_ip": True, "description": True,
                                 "datetime": False},
                     title="Alert Timeline", color_discrete_map=config.SEVERITY_COLORS,
                     category_orders={"severity": SEVERITY_ORDER})
    fig.update_traces(marker=dict(size=14, line=dict(width=1, color="#0d1117")))
    fig.update_layout(xaxis_title=None, yaxis_title=None)
    return _style(fig)


def suspicious_sources(alerts: pd.DataFrame) -> pd.DataFrame:
    """Table: one row per attacking source IP with alert count and worst severity."""
    if alerts.empty:
        return pd.DataFrame(columns=["src_ip", "alerts", "worst_severity", "detections"])
    rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    grouped = alerts.groupby("src_ip").agg(
        alerts=("id", "count"),
        worst_severity=("severity", lambda s: max(s, key=lambda v: rank.get(v, -1))),
        detections=("rule", lambda r: ", ".join(sorted(set(r)))),
        last_seen=("time", "max"),
    ).reset_index()
    grouped["_rank"] = grouped["worst_severity"].map(rank)
    return (grouped.sort_values(["_rank", "alerts"], ascending=False)
            .drop(columns="_rank").reset_index(drop=True))
