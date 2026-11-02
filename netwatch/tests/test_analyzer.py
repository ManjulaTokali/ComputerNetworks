import unittest

try:
    from scapy.all import ARP, DNS, DNSQR, Ether, ICMP, IP, IPv6, Raw, TCP, UDP
    from scapy.all import ICMPv6EchoRequest
    from netwatch.analyzer import packet_to_dict
    HAVE_SCAPY = True
except ImportError:
    HAVE_SCAPY = False


@unittest.skipUnless(HAVE_SCAPY, "Scapy not installed")
class AnalyzerTests(unittest.TestCase):
    def test_tcp(self):
        d = packet_to_dict(Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=1234, dport=80, flags="S") / Raw(b"hello"))
        self.assertEqual((d["proto"], d["src"], d["dst"], d["sport"], d["dport"]), ("TCP", "1.1.1.1", "2.2.2.2", 1234, 80))
        self.assertEqual(d["size"], len(Ether() / IP() / TCP() / Raw(b"hello")))
        self.assertEqual([l["name"] for l in d["details"]["layers"]][:3], ["Ethernet", "IP", "TCP"])

    def test_udp(self):
        d = packet_to_dict(Ether() / IP(dst="8.8.8.8") / UDP(sport=5000, dport=53) / DNS(qd=DNSQR(qname="a.com")))
        self.assertEqual((d["proto"], d["dport"]), ("UDP", 53))

    def test_icmp(self):
        d = packet_to_dict(Ether() / IP(dst="8.8.8.8") / ICMP())
        self.assertEqual((d["proto"], d["sport"], d["info"]), ("ICMP", None, "Echo request"))

    def test_icmp_error_uses_outer_protocol(self):
        inner = IP(dst="9.9.9.9") / TCP()
        d = packet_to_dict(Ether() / IP(src="3.3.3.3", dst="1.1.1.1") / ICMP(type=3) / inner)
        self.assertEqual((d["proto"], d["src"]), ("ICMP", "3.3.3.3"))

    def test_icmpv6_and_arp_and_hex(self):
        d6 = packet_to_dict(Ether() / IPv6(dst="::1") / ICMPv6EchoRequest())
        self.assertEqual(d6["proto"], "ICMP")
        arp = packet_to_dict(Ether() / ARP(psrc="10.0.0.1", pdst="10.0.0.2"))
        self.assertEqual((arp["proto"], arp["src"], arp["dst"]), ("ARP", "10.0.0.1", "10.0.0.2"))
        self.assertTrue(arp["details"]["hex"].startswith("0000"))
