"""
Live packet capture using Scapy.

Scapy's `AsyncSniffer` runs the capture in a background thread and calls our
callback for every packet. We analyse the packet and pass the resulting
PacketInfo on to whoever started the capture (the NIDSMonitor).

Windows requirements for LIVE capture:
  * Npcap must be installed (https://npcap.com) - it is the driver that lets
    programs read raw packets on Windows (Wireshark uses it too).
  * If Npcap was installed with "Restrict Npcap driver's access to
    Administrators only", VS Code / the terminal must be run as Administrator.

Interface names on Windows
  Every adapter has three names. Scapy (and this module) accept any of them:
    * friendly name   e.g. "Wi-Fi"            (what Windows Settings shows)
    * description     e.g. "Example 802.11ac Wireless LAN ..." (the driver)
    * network name    e.g. "\\Device\\NPF_{11111111-...}"   (unique Npcap id)
  The dashboard always passes the unique network name so the choice is exact.

The OFFLINE demo does not use this module and needs neither.

PASSIVE ONLY: this module only listens. It never sends a packet.
"""

from __future__ import annotations

import platform
import threading
import time
from typing import Any, Callable

from monitoring.packet_analyzer import PacketInfo, analyze_packet, load_protocol_layers
from utils.logger import get_logger

logger = get_logger(__name__)

# How long start() waits for the sniffer thread to report an error such as
# "permission denied" or "adapter not found".
STARTUP_CHECK_SECONDS = 1.0


def _load_scapy():
    """Import Scapy's platform layer and return `conf`.

    IMPORTANT: importing only `scapy.config` is not enough. On Windows Scapy
    loads Npcap and fills `conf.ifaces` when `scapy.arch` is imported. Without
    this, `conf.use_pcap` is False and the interface list is empty, so the
    dashboard would wrongly report "Npcap not found" on a fresh start.
    """
    import scapy.arch  # noqa: F401  (side effect: detects Npcap, loads interfaces)
    import scapy.route  # noqa: F401  (side effect: routing table -> conf.iface = default)
    from scapy.config import conf
    return conf


def check_capture_support() -> tuple[bool, str]:
    """Return (supported, message) describing whether live capture can work."""
    try:
        conf = _load_scapy()
    except Exception as exc:  # pragma: no cover - scapy is a hard dependency
        return False, f"Scapy could not be imported: {exc}"

    if platform.system() == "Windows" and not conf.use_pcap:
        return False, ("Npcap was not found. Install Npcap from https://npcap.com "
                       "(tick 'WinPcap API-compatible mode') to enable live capture. "
                       "Offline demo mode works without it.")
    return True, "Packet capture driver available."


# ---------------------------------------------------------------- interfaces
def _describe_interface(iface: Any, default_id: str) -> dict[str, Any]:
    """Turn a Scapy interface object into a plain dict for the dashboard."""
    network_name = str(getattr(iface, "network_name", "") or getattr(iface, "name", ""))
    friendly = str(getattr(iface, "name", "") or network_name)
    description = str(getattr(iface, "description", "") or friendly)
    ip = str(getattr(iface, "ip", "") or "")
    if ip == "None":
        ip = ""
    flags = str(getattr(iface, "flags", "") or "").upper()
    text = f"{friendly} {description}".lower()

    is_loopback = "LOOPBACK" in flags or "loopback" in text or ip.startswith("127.")
    is_wireless = "WIRELESS" in flags or "wi-fi" in text or "wireless" in text or "wlan" in text
    # 169.254.x.x is a self-assigned (APIPA) address = no real network.
    has_real_ip = bool(ip) and not ip.startswith("169.254.") and not is_loopback
    connected = "DISCONNECTED" not in flags and (has_real_ip or is_loopback)
    is_virtual = "miniport" in text or "virtual" in text or "pseudo" in text

    state = "connected" if connected else "not connected"
    tags = []
    if network_name == default_id:
        tags.append("default route")
    if is_wireless:
        tags.append("wireless")
    label = f"{friendly} - {description} [{ip or 'no IP'}, {state}]"
    if tags:
        label += f" ({', '.join(tags)})"
    if friendly == description:  # Linux/macOS: name and description are the same
        label = f"{friendly} [{ip or 'no IP'}, {state}]"

    return {
        "name": network_name,           # unique id passed to the sniffer
        "friendly_name": friendly,
        "description": description,
        "ip": ip,
        "is_default": network_name == default_id,
        "is_wireless": is_wireless,
        "is_loopback": is_loopback,
        "is_virtual": is_virtual,
        "connected": connected,
        "label": label,
    }


def _rank(info: dict[str, Any]) -> tuple:
    """Lower = better. Default-route, connected, physical adapters first."""
    return (
        not info["is_default"],
        not info["connected"],
        info["is_loopback"],
        info["is_virtual"],
        not info["is_wireless"],
        info["friendly_name"].lower(),
    )


def list_interfaces() -> list[dict[str, Any]]:
    """List network interfaces, best candidates for capture first.

    Each entry has: name (unique id for the sniffer), friendly_name,
    description, ip, is_default, is_wireless, is_loopback, connected, label.
    """
    interfaces: list[dict[str, Any]] = []
    try:
        conf = _load_scapy()
        if not conf.ifaces:  # empty on Windows when Npcap is not installed
            return interfaces
        default_iface = conf.iface
        default_id = str(getattr(default_iface, "network_name", "") or default_iface or "")
        for iface in conf.ifaces.values():
            interfaces.append(_describe_interface(iface, default_id))
    except Exception as exc:
        logger.warning("Could not list interfaces: %s", exc)
    interfaces.sort(key=_rank)
    return interfaces


def recommended_interface(interfaces: list[dict[str, Any]] | None = None) -> dict[str, Any] | None:
    """The interface the dashboard preselects (usually Wi-Fi or Ethernet)."""
    interfaces = list_interfaces() if interfaces is None else sorted(interfaces, key=_rank)
    for info in interfaces:
        if info["connected"] and not info["is_loopback"]:
            return info
    return interfaces[0] if interfaces else None


def resolve_interface(value: str | None,
                      interfaces: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Find an interface by friendly name ("Wi-Fi"), description or Npcap id.

    `None` / "" picks the recommended interface. Matching ignores case.
    Raises RuntimeError with the list of valid names if nothing matches.
    """
    interfaces = list_interfaces() if interfaces is None else interfaces
    if not interfaces:
        raise RuntimeError("No network interfaces were found. Is Npcap installed and "
                           "is the Npcap service running?")
    if not value or not str(value).strip():
        best = recommended_interface(interfaces)
        assert best is not None
        return best

    wanted = str(value).strip().lower()
    for key in ("name", "friendly_name", "description"):
        for info in interfaces:
            if info[key].lower() == wanted:
                return info
    available = ", ".join(f"'{i['friendly_name']}'" for i in interfaces)
    raise RuntimeError(f"Network interface '{value}' was not found. "
                       f"Available interfaces: {available}")


# ---------------------------------------------------------------- capture
class PacketCapture:
    """Start/stop a background Scapy sniffer and watch its health."""

    def __init__(self, on_packet: Callable[[PacketInfo], None],
                 interface: str | None = None, bpf_filter: str | None = None):
        self.on_packet = on_packet
        self.interface = interface or None
        self.interface_label = interface or "default interface"
        self.bpf_filter = (bpf_filter or "").strip() or None
        self.frames_seen = 0          # every frame the driver delivered
        self.packet_count = 0         # frames successfully analysed (sent to engine)
        self.processing_errors = 0
        self.last_packet_at: float | None = None
        self.error: str | None = None
        self.started_at: float | None = None
        self.stopped_at: float | None = None
        self._sniffer = None
        self._stop_requested = False
        self._lock = threading.Lock()

    # Called by Scapy (in the sniffer thread) for EVERY captured packet.
    def _handle(self, raw_packet) -> None:
        with self._lock:
            self.frames_seen += 1
            self.last_packet_at = time.time()
        info = analyze_packet(raw_packet, source="live")
        if info is None:
            return  # non-IP frame (e.g. 802.1X, LLDP) - counted but not analysed
        with self._lock:
            self.packet_count += 1
        try:
            self.on_packet(info)
        except Exception:
            with self._lock:
                self.processing_errors += 1
            logger.exception("Error while processing captured packet")

    @property
    def is_running(self) -> bool:
        return bool(self._sniffer is not None and getattr(self._sniffer, "running", False))

    def start(self) -> None:
        """Start capturing. Raises RuntimeError with a friendly message on failure."""
        from scapy import sendrecv

        supported, message = check_capture_support()
        if not supported:
            raise RuntimeError(message)

        if self.interface is not None or platform.system() == "Windows":
            info = resolve_interface(self.interface)
            self.interface = info["name"]
            self.interface_label = info["friendly_name"]
            if not info["connected"]:
                logger.warning("Interface %s is not connected - few or no packets expected",
                               info["friendly_name"])

        logger.info("Starting live capture on %s (%s, filter=%s)",
                    self.interface_label, self.interface, self.bpf_filter)
        self._stop_requested = False
        # Must happen BEFORE sniffing, or frames are decoded without IP/TCP layers.
        load_protocol_layers()
        try:
            self._sniffer = sendrecv.AsyncSniffer(iface=self.interface, prn=self._handle,
                                                  store=False, filter=self.bpf_filter)
            self._sniffer.start()
        except Exception as exc:
            self._sniffer = None
            raise RuntimeError(self._friendly_error(exc)) from exc

        # Errors such as "permission denied" happen inside the sniffer thread a
        # moment after start(); wait briefly so we can report them to the user.
        deadline = time.time() + STARTUP_CHECK_SECONDS
        while time.time() < deadline and getattr(self._sniffer, "exception", None) is None:
            time.sleep(0.05)
        thread_error = getattr(self._sniffer, "exception", None)
        if thread_error is not None or not self._sniffer.running:
            detail = thread_error or "sniffer stopped immediately"
            self._sniffer = None
            raise RuntimeError(self._friendly_error(detail))
        self.started_at = time.time()
        self.error = None

    def check_health(self) -> str | None:
        """Return an error message if the capture died without stop() being called.

        Scapy ends the sniffer thread quietly when the adapter disappears
        (Wi-Fi disconnected, laptop asleep, driver reset), so we look for it.
        """
        if self.error:
            return self.error
        sniffer = self._sniffer
        if sniffer is None or self._stop_requested or getattr(sniffer, "running", False):
            return None
        thread_error = getattr(sniffer, "exception", None)
        if thread_error is not None:
            self.error = self._friendly_error(thread_error)
        else:
            self.error = (f"Live capture on {self.interface_label} stopped unexpectedly. "
                          "The adapter may have been disconnected or put to sleep. "
                          "Check the connection and press Start Monitoring again.")
        self.stopped_at = time.time()
        logger.error("%s", self.error)
        return self.error

    def stop(self) -> None:
        self._stop_requested = True
        if self._sniffer is None:
            return
        try:
            if self._sniffer.running:
                self._sniffer.stop()
        except Exception as exc:  # stopping should never crash the UI
            logger.warning("Error while stopping sniffer: %s", exc)
        finally:
            self._sniffer = None
            self.stopped_at = time.time()
            logger.info("Live capture stopped: %d frames seen, %d packets analysed",
                        self.frames_seen, self.packet_count)

    def stats(self) -> dict[str, Any]:
        with self._lock:
            frames, analysed = self.frames_seen, self.packet_count
            errors, last = self.processing_errors, self.last_packet_at
        end = self.stopped_at or time.time()
        elapsed = max(end - self.started_at, 0.001) if self.started_at else 0.0
        return {
            "interface": self.interface_label,
            "frames_seen": frames,
            "packets_analysed": analysed,
            "skipped_frames": frames - analysed,
            "processing_errors": errors,
            "packets_per_second": analysed / elapsed if elapsed else 0.0,
            "seconds_since_last_packet": (time.time() - last) if last else None,
        }

    @staticmethod
    def _friendly_error(exc) -> str:
        text = str(exc)
        lowered = text.lower()
        if ("permission" in lowered or "access is denied" in lowered
                or "operation not permitted" in lowered or "access denied" in lowered):
            return ("Permission denied. Run VS Code / the terminal as Administrator, or "
                    "reinstall Npcap with 'Restrict Npcap driver's access to "
                    f"Administrators only' unticked. ({text})")
        if "filter" in lowered or "syntax" in lowered:
            return f"Invalid BPF capture filter. Example of a valid filter: 'tcp or icmp'. ({text})"
        if ("error opening adapter" in lowered or "no such device" in lowered
                or "not found" in lowered or "interface" in lowered):
            return ("The network adapter could not be opened. Make sure it is enabled "
                    f"and connected, then choose it again in the list. ({text})")
        return f"Live capture failed: {text}"
