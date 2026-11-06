"""Command-line (terminal) live monitor."""

import queue
import sys
import time

from .capture import CaptureEngine
from .exporter import save_csv, save_pcap
from .stats import TrafficStats, human_bytes

HEADER = f"{'No':>6}  {'Time':<12} {'Source':<39} {'Destination':<39} {'Proto':<7} {'Len':>5}  Info"


def run_cli(iface="", bpf="", simulate=False, count=0, duration=0,
            csv_path="", pcap_path="", quiet=False):
    engine = CaptureEngine(iface=iface, bpf=bpf, simulate=simulate)
    stats = TrafficStats()
    records = []
    if not quiet:
        print(HEADER)
        print("-" * len(HEADER))
    engine.start()
    start = time.time()
    last_summary = start
    try:
        while True:
            try:
                err = engine.errors.get_nowait()
                print(f"\n[!] {err}", file=sys.stderr)
                break
            except queue.Empty:
                pass
            try:
                rec = engine.packets.get(timeout=0.2)
            except queue.Empty:
                rec = None
            if rec is not None:
                stats.add(rec)
                records.append(rec)
                if not quiet:
                    print(f"{rec.no:>6}  {rec.time_str:<12} {rec.src:<39} {rec.dst:<39} "
                          f"{rec.protocol:<7} {rec.length:>5}  {rec.info}")
                    sys.stdout.flush()
            now = time.time()
            if quiet and now - last_summary >= 1:
                pps, bps = stats.current_rate()
                print(f"\r{stats.total_packets} packets | {pps:.0f} pkt/s | "
                      f"{human_bytes(bps)}/s", end="", flush=True)
                last_summary = now
            if count and stats.total_packets >= count:
                break
            if duration and now - start >= duration:
                break
    except KeyboardInterrupt:
        pass
    finally:
        engine.stop()

    print("\n\n===== Capture summary =====")
    print(f"Packets : {stats.total_packets}")
    print(f"Data    : {human_bytes(stats.total_bytes)}")
    print(f"Elapsed : {time.time() - start:.1f} s")
    for proto, n in stats.protocols.most_common():
        print(f"  {proto:<8}{n:>8}")
    if csv_path:
        print(f"Saved {save_csv(records, csv_path)} packets to {csv_path}")
    if pcap_path:
        print(f"Saved {save_pcap(records, pcap_path)} packets to {pcap_path}")
    return stats.total_packets
