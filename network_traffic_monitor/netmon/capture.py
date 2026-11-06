"""Packet capture engine: live sniffing (Scapy) or a built-in traffic simulator.

The engine runs in a background thread and pushes PacketRecord objects into a
thread-safe queue that the GUI / CLI drains.
"""

import queue
import random
import threading
import time
from typing import List, Optional

from scapy.all import conf, get_if_list, sniff
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether

from .parser import PacketRecord, parse_packet


def list_interfaces() -> List[str]:
    try:
        return list(get_if_list())
    except Exception:
        return []


class CaptureEngine:
    """Capture packets in a background thread.

    Parameters
    ----------
    iface:    interface name (None = Scapy default / all on Linux)
    bpf:      optional BPF capture filter, e.g. "tcp port 80"
    simulate: generate synthetic traffic instead of sniffing (needs no admin rights)
    rate:     simulated packets per second
    """

    def __init__(self, iface: Optional[str] = None, bpf: Optional[str] = None,
                 simulate: bool = False, rate: int = 40, max_queue: int = 50000):
        self.iface = iface or None
        self.bpf = (bpf or "").strip() or None
        self.simulate = simulate
        self.rate = max(1, int(rate))
        self.packets: "queue.Queue[PacketRecord]" = queue.Queue(maxsize=max_queue)
        self.errors: "queue.Queue[str]" = queue.Queue()
        self.dropped = 0
        self._counter = 0
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------------ control
    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self):
        if self.running:
            return
        self._stop.clear()
        target = self._run_simulation if self.simulate else self._run_sniffer
        self._thread = threading.Thread(target=target, name="capture", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 3.0):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout)

    def reset_counter(self):
        with self._lock:
            self._counter = 0
        self.dropped = 0

    # ----------------------------------------------------------------- internals
    def _handle(self, pkt):
        with self._lock:
            self._counter += 1
            no = self._counter
        record = parse_packet(pkt, no)
        try:
            self.packets.put_nowait(record)
        except queue.Full:
            self.dropped += 1

    def _run_sniffer(self):
        kwargs = dict(prn=self._handle, store=False, timeout=1)
        if self.iface:
            kwargs["iface"] = self.iface
        if self.bpf:
            kwargs["filter"] = self.bpf
        try:
            while not self._stop.is_set():
                sniff(**kwargs)  # returns every second so stop() reacts quickly
        except PermissionError:
            self.errors.put("Permission denied: run as Administrator (Windows) or with "
                            "sudo/root (Linux/macOS) to capture live packets.")
        except Exception as exc:
            msg = str(exc) or exc.__class__.__name__
            hint = ""
            if "winpcap" in msg.lower() or "npcap" in msg.lower() or "layer 2" in msg.lower():
                hint = " Install Npcap (Windows) / libpcap (Linux/macOS)."
            self.errors.put(f"Capture error: {msg}.{hint}")

    def _run_simulation(self):
        gen = TrafficSimulator()
        interval = 1.0 / self.rate
        next_t = time.time()
        while not self._stop.is_set():
            self._handle(gen.next_packet())
            next_t += interval * random.uniform(0.4, 1.6)
            delay = next_t - time.time()
            if delay > 0:
                self._stop.wait(delay)
            else:
                next_t = time.time()


class TrafficSimulator:
    """Generates realistic-looking packets (real Scapy objects) for demos/tests."""

    LOCAL = "192.168.1.23"
    SERVERS = ["142.250.77.14", "151.101.1.69", "104.18.32.7", "31.13.72.36",
               "52.95.110.1", "13.107.42.14", "93.184.216.34", "172.217.160.78"]
    DOMAINS = ["www.google.com", "github.com", "stackoverflow.com", "www.wikipedia.org",
               "cdn.example.net", "mail.university.edu", "api.openai.com", "youtube.com"]

    def __init__(self):
        self._kinds = ["https", "https", "https", "http", "dns", "dns", "udp",
                       "icmp", "ssh", "arp", "ntp"]

    def next_packet(self):
        kind = random.choice(self._kinds)
        server = random.choice(self.SERVERS)
        eph = random.randint(49152, 65535)
        inbound = random.random() < 0.55
        a, b = (server, self.LOCAL) if inbound else (self.LOCAL, server)
        eth = Ether(src="aa:bb:cc:00:00:01", dst="aa:bb:cc:00:00:02")

        if kind in ("https", "http", "ssh"):
            port = {"https": 443, "http": 80, "ssh": 22}[kind]
            sp, dp = (port, eph) if inbound else (eph, port)
            flags = random.choices(["A", "PA", "S", "SA", "FA", "R"], [50, 30, 6, 6, 5, 3])[0]
            payload = b"x" * (random.choice([0, 0, 64, 512, 1200, 1400]) if "P" in flags else 0)
            pkt = eth / IP(src=a, dst=b) / TCP(sport=sp, dport=dp, flags=flags,
                                               seq=random.randint(1, 10**6),
                                               ack=random.randint(1, 10**6)) / payload
        elif kind == "dns":
            name = random.choice(self.DOMAINS)
            qtype = random.choice(["A", "AAAA"])
            if inbound:
                pkt = eth / IP(src="192.168.1.1", dst=self.LOCAL) / UDP(sport=53, dport=eph) / \
                    DNS(id=1, qr=1, qd=DNSQR(qname=name, qtype=qtype), ancount=1)
            else:
                pkt = eth / IP(src=self.LOCAL, dst="192.168.1.1") / UDP(sport=eph, dport=53) / \
                    DNS(id=1, rd=1, qd=DNSQR(qname=name, qtype=qtype))
        elif kind == "udp":
            pkt = eth / IP(src=a, dst=b) / UDP(sport=random.randint(1024, 60000),
                                               dport=random.randint(1024, 60000)) / (b"d" * random.randint(20, 900))
        elif kind == "icmp":
            pkt = eth / IP(src=a, dst=b) / ICMP(type=0 if inbound else 8,
                                                id=random.randint(1, 500), seq=random.randint(1, 50))
        elif kind == "ntp":
            sp, dp = (123, eph) if inbound else (eph, 123)
            pkt = eth / IP(src=a, dst=b) / UDP(sport=sp, dport=dp) / (b"n" * 48)
        else:  # arp
            if random.random() < 0.5:
                pkt = Ether(src="aa:bb:cc:00:00:09", dst="ff:ff:ff:ff:ff:ff") / ARP(
                    op=1, psrc="192.168.1.1", pdst=self.LOCAL, hwsrc="aa:bb:cc:00:00:09")
            else:
                pkt = Ether(src="aa:bb:cc:00:00:01", dst="aa:bb:cc:00:00:09") / ARP(
                    op=2, psrc=self.LOCAL, pdst="192.168.1.1", hwsrc="aa:bb:cc:00:00:01")
        pkt.time = time.time()
        return pkt
