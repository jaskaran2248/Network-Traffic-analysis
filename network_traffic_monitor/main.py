#!/usr/bin/env python3
"""Real-Time Network Traffic Monitor - entry point.

Examples
--------
  python main.py                      # GUI, live capture (needs admin/root)
  python main.py --demo               # GUI with simulated traffic (no admin needed)
  python main.py --cli                # terminal mode, live capture
  python main.py --cli --demo --count 30
  python main.py --list-interfaces
"""

import argparse
import sys


def main():
    p = argparse.ArgumentParser(description="Real-time network traffic / packet monitor")
    p.add_argument("-i", "--iface", default="", help="network interface (default: auto)")
    p.add_argument("-f", "--filter", default="", help='BPF capture filter, e.g. "tcp port 443"')
    p.add_argument("--demo", action="store_true", help="use simulated traffic (no admin rights needed)")
    p.add_argument("--cli", action="store_true", help="run in the terminal instead of the GUI")
    p.add_argument("-c", "--count", type=int, default=0, help="CLI: stop after N packets")
    p.add_argument("-d", "--duration", type=int, default=0, help="CLI: stop after N seconds")
    p.add_argument("--csv", default="", help="CLI: save captured packets to this CSV file")
    p.add_argument("--pcap", default="", help="CLI: save captured packets to this PCAP file")
    p.add_argument("-q", "--quiet", action="store_true", help="CLI: show only a live counter")
    p.add_argument("--list-interfaces", action="store_true", help="list interfaces and exit")
    args = p.parse_args()

    if args.list_interfaces:
        from netmon.capture import list_interfaces
        for name in list_interfaces():
            print(name)
        return 0

    use_cli = args.cli
    if not use_cli:
        try:
            import tkinter  # noqa: F401
        except ImportError:
            print("tkinter is not available - falling back to terminal mode.\n"
                  "(Linux: sudo apt install python3-tk)", file=sys.stderr)
            use_cli = True

    if use_cli:
        from netmon.cli import run_cli
        run_cli(args.iface, args.filter, args.demo, args.count, args.duration,
                args.csv, args.pcap, args.quiet)
    else:
        from netmon.gui import run_gui
        run_gui(simulate=args.demo, iface=args.iface, bpf=args.filter)
    return 0


if __name__ == "__main__":
    sys.exit(main())
