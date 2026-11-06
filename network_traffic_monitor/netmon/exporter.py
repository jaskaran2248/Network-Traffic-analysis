"""Save captured packets to CSV (readable) or PCAP (Wireshark-compatible)."""

import csv
from typing import Iterable

from scapy.utils import wrpcap

from .parser import PacketRecord

CSV_HEADER = ["No", "Date/Time", "Source", "Destination", "Protocol",
              "Length", "Src Port", "Dst Port", "Info"]


def save_csv(records: Iterable[PacketRecord], path: str) -> int:
    count = 0
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(CSV_HEADER)
        for r in records:
            writer.writerow([r.no, r.date_time_str, r.src, r.dst, r.protocol, r.length,
                             "" if r.sport is None else r.sport,
                             "" if r.dport is None else r.dport, r.info])
            count += 1
    return count


def save_pcap(records: Iterable[PacketRecord], path: str) -> int:
    pkts = [r.raw for r in records if r.raw is not None]
    wrpcap(path, pkts)
    return len(pkts)
