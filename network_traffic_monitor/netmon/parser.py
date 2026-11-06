"""Turn raw Scapy packets into simple, display-friendly records."""

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional

from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether

# Well-known ports -> application protocol label
PORT_PROTOCOLS = {
    20: "FTP", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP", 110: "POP3",
    143: "IMAP", 465: "SMTP", 587: "SMTP", 993: "IMAP", 995: "POP3",
    80: "HTTP", 8080: "HTTP", 8000: "HTTP", 443: "HTTPS", 8443: "HTTPS",
    67: "DHCP", 68: "DHCP", 123: "NTP", 161: "SNMP", 3389: "RDP",
    1900: "SSDP", 5353: "MDNS", 53: "DNS",
}

DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 15: "MX", 16: "TXT",
             28: "AAAA", 33: "SRV", 255: "ANY"}

ICMP_TYPES = {0: "Echo reply", 3: "Destination unreachable", 8: "Echo request",
              11: "Time exceeded"}

PROTOCOLS = ["TCP", "UDP", "HTTP", "HTTPS", "DNS", "ICMP", "ARP", "SSH",
             "DHCP", "NTP", "ICMPv6", "IPv6", "OTHER"]


@dataclass
class PacketRecord:
    no: int
    timestamp: float
    src: str
    dst: str
    protocol: str
    length: int
    sport: Optional[int] = None
    dport: Optional[int] = None
    info: str = ""
    raw: Any = None

    @property
    def time_str(self) -> str:
        return datetime.fromtimestamp(self.timestamp).strftime("%H:%M:%S.%f")[:-3]

    @property
    def date_time_str(self) -> str:
        return datetime.fromtimestamp(self.timestamp).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def _dns_info(pkt) -> str:
    d = pkt[DNS]
    name, qtype = "?", ""
    try:
        qd = d.qd
        if qd is not None:
            if isinstance(qd, (list, tuple)):
                qd = qd[0]
            name = qd.qname.decode(errors="replace").rstrip(".") or "."
            qtype = DNS_TYPES.get(int(qd.qtype), str(qd.qtype))
    except Exception:
        pass
    if d.qr == 0:
        return f"Standard query {qtype} {name}".strip()
    return f"Standard response {qtype} {name} (answers: {d.ancount})".strip()


def _app_protocol(sport, dport, default):
    for port in (dport, sport):
        if port in PORT_PROTOCOLS:
            return PORT_PROTOCOLS[port]
    return default


def parse_packet(pkt, no: int, keep_raw: bool = True) -> PacketRecord:
    """Convert a Scapy packet into a PacketRecord. Never raises."""
    ts = float(getattr(pkt, "time", 0) or 0)
    length = len(pkt)
    raw = pkt if keep_raw else None
    try:
        sport = dport = None
        src = dst = "-"
        proto = "OTHER"
        info = ""

        if pkt.haslayer(ARP):
            a = pkt[ARP]
            src, dst, proto = a.psrc, a.pdst, "ARP"
            if a.op == 1:
                info = f"Who has {a.pdst}? Tell {a.psrc}"
            elif a.op == 2:
                info = f"{a.psrc} is at {a.hwsrc}"
            else:
                info = f"ARP op {a.op}"
        elif pkt.haslayer(IP) or pkt.haslayer(IPv6):
            if pkt.haslayer(IP):
                ip = pkt[IP]
                src, dst, proto = ip.src, ip.dst, "IP"
            else:
                ip = pkt[IPv6]
                src, dst, proto = ip.src, ip.dst, "IPv6"

            if pkt.haslayer(TCP):
                t = pkt[TCP]
                sport, dport = int(t.sport), int(t.dport)
                payload = len(t.payload)
                proto = "DNS" if pkt.haslayer(DNS) else _app_protocol(sport, dport, "TCP")
                info = (f"{sport} -> {dport} [{t.sprintf('%TCP.flags%')}] "
                        f"Seq={t.seq} Ack={t.ack} Win={t.window} Len={payload}")
                if pkt.haslayer(DNS):
                    info = _dns_info(pkt)
            elif pkt.haslayer(UDP):
                u = pkt[UDP]
                sport, dport = int(u.sport), int(u.dport)
                if pkt.haslayer(DNS):
                    proto = "DNS"
                    info = _dns_info(pkt)
                else:
                    proto = _app_protocol(sport, dport, "UDP")
                    info = f"{sport} -> {dport} Len={len(u.payload)}"
            elif pkt.haslayer(ICMP):
                ic = pkt[ICMP]
                proto = "ICMP"
                info = ICMP_TYPES.get(int(ic.type), f"Type {ic.type}")
                if int(ic.type) in (0, 8):
                    info += f" id={ic.id} seq={ic.seq}"
            elif proto == "IPv6" and getattr(ip, "nh", None) == 58:
                proto = "ICMPv6"
                info = "ICMPv6 message"
            else:
                num = getattr(ip, "proto", getattr(ip, "nh", "?"))
                info = f"IP protocol {num}"
        elif pkt.haslayer(Ether):
            e = pkt[Ether]
            src, dst, proto = e.src, e.dst, "OTHER"
            info = f"Ethernet type 0x{e.type:04x}"
        else:
            info = pkt.summary()

        return PacketRecord(no, ts, src, dst, proto, length, sport, dport, info, raw)
    except Exception as exc:  # pragma: no cover - defensive
        return PacketRecord(no, ts, "-", "-", "OTHER", length, None, None,
                            f"unparsed ({exc.__class__.__name__})", raw)
