"""
Regenerate the offline demo files:

    data/sample_traffic.csv   - packet records (open it in Excel to inspect)
    data/sample_traffic.pcap  - the same traffic as a real PCAP (open in Wireshark)

Usage:
    python generate_sample_data.py

This only WRITES FILES. It does not send any packets on the network.
"""

from __future__ import annotations

from datetime import datetime

import config
from monitoring.offline_demo import generate_synthetic_traffic, save_csv_file, save_pcap_file


def main() -> None:
    config.ensure_directories()
    # Fixed start time + fixed random seed => identical files every run.
    start = datetime(2025, 1, 15, 10, 0, 0).timestamp()
    packets = generate_synthetic_traffic(start_time=start, duration=60, seed=7)
    for packet in packets:
        packet.source = "csv"

    csv_path = save_csv_file(packets, config.SAMPLE_CSV_PATH)
    pcap_path = save_pcap_file(packets, config.SAMPLE_PCAP_PATH)
    print(f"Wrote {len(packets)} packets to:")
    print(f"  {csv_path}")
    print(f"  {pcap_path}")


if __name__ == "__main__":
    main()
