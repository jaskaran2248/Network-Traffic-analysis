import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.all import ARP, DNS, DNSQR, ICMP, IP, TCP, UDP, Ether  # noqa: E402

from netmon.capture import CaptureEngine, TrafficSimulator  # noqa: E402
from netmon.exporter import save_csv, save_pcap  # noqa: E402
from netmon.parser import parse_packet  # noqa: E402
from netmon.stats import TrafficStats, human_bytes  # noqa: E402


class ParserTests(unittest.TestCase):
    def test_https(self):
        p = Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=50000, dport=443, flags="S")
        r = parse_packet(p, 1)
        self.assertEqual((r.src, r.dst, r.protocol, r.dport), ("1.1.1.1", "2.2.2.2", "HTTPS", 443))
        self.assertIn("[S]", r.info)

    def test_http_and_ssh(self):
        self.assertEqual(parse_packet(IP() / TCP(dport=80), 1).protocol, "HTTP")
        self.assertEqual(parse_packet(IP() / TCP(dport=22), 2).protocol, "SSH")

    def test_plain_tcp_udp(self):
        self.assertEqual(parse_packet(IP() / TCP(sport=1234, dport=5678), 1).protocol, "TCP")
        self.assertEqual(parse_packet(IP() / UDP(sport=1234, dport=5678), 2).protocol, "UDP")

    def test_dns(self):
        p = IP() / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com"))
        r = parse_packet(p, 1)
        self.assertEqual(r.protocol, "DNS")
        self.assertIn("example.com", r.info)

    def test_icmp(self):
        r = parse_packet(IP() / ICMP(), 1)
        self.assertEqual(r.protocol, "ICMP")
        self.assertIn("Echo request", r.info)

    def test_arp(self):
        r = parse_packet(Ether() / ARP(op=1, psrc="10.0.0.1", pdst="10.0.0.2"), 1)
        self.assertEqual(r.protocol, "ARP")
        self.assertIn("Who has 10.0.0.2", r.info)

    def test_never_raises_on_odd_packet(self):
        r = parse_packet(Ether(type=0x1234), 1)
        self.assertEqual(r.protocol, "OTHER")


class StatsTests(unittest.TestCase):
    def test_counts(self):
        s = TrafficStats()
        for i in range(10):
            s.add(parse_packet(IP(src="9.9.9.9") / TCP(dport=443), i))
        self.assertEqual(s.total_packets, 10)
        self.assertEqual(s.protocols["HTTPS"], 10)
        self.assertEqual(s.top_talkers(1)[0][0], "9.9.9.9")
        pps, _ = s.current_rate()
        self.assertEqual(pps, 10.0)
        self.assertEqual(len(s.pps_history()), 60)

    def test_human_bytes(self):
        self.assertEqual(human_bytes(512), "512 B")
        self.assertEqual(human_bytes(2048), "2.0 KB")


class EngineTests(unittest.TestCase):
    def test_simulation_produces_packets(self):
        e = CaptureEngine(simulate=True, rate=200)
        e.start()
        time.sleep(1.0)
        e.stop()
        self.assertFalse(e.running)
        self.assertGreater(e.packets.qsize(), 50)
        rec = e.packets.get_nowait()
        self.assertEqual(rec.no, 1)
        self.assertGreater(rec.length, 0)

    def test_simulator_all_kinds_parse(self):
        sim = TrafficSimulator()
        seen = set()
        for i in range(400):
            seen.add(parse_packet(sim.next_packet(), i).protocol)
        self.assertTrue({"HTTPS", "DNS", "ARP", "ICMP"} <= seen)


class ExportTests(unittest.TestCase):
    def test_csv_and_pcap(self):
        sim = TrafficSimulator()
        recs = [parse_packet(sim.next_packet(), i + 1) for i in range(20)]
        with tempfile.TemporaryDirectory() as d:
            c, p = os.path.join(d, "a.csv"), os.path.join(d, "a.pcap")
            self.assertEqual(save_csv(recs, c), 20)
            self.assertEqual(save_pcap(recs, p), 20)
            with open(c, encoding="utf-8") as fh:
                self.assertEqual(len(fh.readlines()), 21)
            self.assertGreater(os.path.getsize(p), 100)


if __name__ == "__main__":
    unittest.main()
