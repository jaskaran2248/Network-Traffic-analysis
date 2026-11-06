# Real-Time Network Traffic Monitor

A Python application that **captures network packets in real time** and shows
the traffic live – with the exact time of each packet, source / destination,
protocol, size and a description of the activity (TCP flags, DNS queries,
ARP requests, ICMP pings ...).

Built with **Python 3**, **Scapy** (packet capture / decoding) and **Tkinter** (GUI).

## Features

| Feature | Description |
|---|---|
| Live packet table | Every packet appears instantly: No., time (ms precision), source, destination, protocol, length, info |
| Real-time clock | Current date and time shown in the status bar |
| Activity description | Human-readable info: `Standard query A github.com`, `49500 -> 443 [S] ...`, `Who has 192.168.1.1?` |
| Protocol detection | TCP, UDP, HTTP, HTTPS, DNS, ICMP, ARP, SSH, DHCP, NTP, IPv6 ... (colour coded) |
| Live statistics | Total packets, total data, packets/sec, speed (KB/s) |
| Traffic graph | Packets-per-second for the last 60 seconds |
| Protocol chart | Bar chart of protocol distribution |
| Top talkers | Source addresses sending the most data |
| Packet details | Click a row to see the full layer-by-layer decode |
| Filters | BPF capture filter (e.g. `tcp port 443`), display filter by protocol, text/IP search |
| Export | Save to **CSV** (for Excel / reports) or **PCAP** (open in Wireshark) |
| Demo mode | Simulated traffic so the project works without administrator rights |
| CLI mode | Terminal version with live output, summary, and CSV/PCAP export |

## Project structure

```
network_traffic_monitor/
├── main.py              # entry point (GUI or CLI)
├── requirements.txt
├── README.md
├── netmon/
│   ├── capture.py       # capture thread (Scapy sniffer + traffic simulator)
│   ├── parser.py        # packet -> record (protocol, ports, info text)
│   ├── stats.py         # counters, rates, top talkers, history
│   ├── exporter.py      # CSV / PCAP saving
│   ├── gui.py           # Tkinter interface
│   └── cli.py           # terminal interface
└── tests/
    └── test_netmon.py   # unit tests
```

## Installation

1. Install **Python 3.8+** (https://python.org). On Linux also: `sudo apt install python3-tk`
2. Install the dependency:
   ```
   pip install -r requirements.txt
   ```
3. **Windows only:** install **Npcap** from https://npcap.com (tick "WinPcap API-compatible mode"). Needed for live capture.

## Running

Live capture needs administrator / root rights.

| Platform | Command |
|---|---|
| Windows | open **Command Prompt as Administrator**, then `python main.py` |
| Linux / macOS | `sudo python3 main.py` |

Click **▶ Start**. To try the program without admin rights (or for a
classroom demo with no network), tick **Demo mode** or run:

```
python main.py --demo
```

### Command-line options

```
python main.py --list-interfaces              # show interface names
python main.py -i "Wi-Fi" -f "tcp port 443"   # GUI on a chosen interface with a BPF filter
python main.py --cli                          # terminal live view
python main.py --cli --demo -c 50             # 50 simulated packets then summary
python main.py --cli -d 30 --csv out.csv --pcap out.pcap   # capture 30 s and save
```

Press **Ctrl+C** in terminal mode to stop and see the summary.

### Generate some traffic to watch
Open a website, run `ping google.com`, or `nslookup github.com` while capturing.

## How it works

1. `CaptureEngine` runs `scapy.sniff()` in a **background thread** so the GUI never freezes.
2. Each packet is decoded by `parse_packet()` into a `PacketRecord`
   (timestamp, addresses, protocol, size, info) and placed in a thread-safe `queue.Queue`.
3. The GUI polls the queue every 100 ms, updates the table and the `TrafficStats`
   object, and redraws the graphs every second.
4. Demo mode swaps the sniffer for `TrafficSimulator`, which builds genuine Scapy
   packets that go through exactly the same parsing/GUI pipeline.

## Running the tests

```
python -m unittest discover -s tests -v
```

## Troubleshooting

| Problem | Fix |
|---|---|
| "Permission denied" / no packets | Run as Administrator / `sudo`. Or use `--demo`. |
| Windows: capture error mentioning WinPcap/Npcap | Install Npcap (see above) |
| No packets on Linux with empty interface | Pick an interface (e.g. `eth0`, `wlan0`) from the drop-down |
| `ModuleNotFoundError: tkinter` | `sudo apt install python3-tk` (the app falls back to terminal mode) |
| BPF filter error | Check syntax, e.g. `host 8.8.8.8`, `udp port 53`, `icmp` |

## Ethics / legal note

Only capture traffic on networks you own or are authorised to monitor
(e.g. your own computer or lab network). Capturing other people's traffic
without permission may be illegal.

## Possible extensions
GeoIP lookup of remote addresses, alert rules (port scans, traffic spikes),
SQLite logging, reverse DNS names, bandwidth per application.
