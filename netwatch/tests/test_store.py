import csv
import io
import unittest

from netwatch.store import PacketStore
from tests.helpers import make_packet


def filled():
    s = PacketStore()
    s.add(make_packet("TCP", "10.0.0.1", "10.0.0.2", 100, 1000.0))
    s.add(make_packet("UDP", "10.0.0.3", "8.8.8.8", 200, 1001.0, 5353, 53))
    s.add(make_packet("ICMP", "10.0.0.1", "8.8.8.8", 60, 1002.0, None, None))
    s.add(make_packet("ARP", "10.0.0.5", "10.0.0.1", 42, 1003.0, None, None))
    return s


class StoreTests(unittest.TestCase):
    def test_numbers_and_time_are_assigned(self):
        s = filled()
        self.assertEqual(s.get(1)["no"], 1)
        self.assertRegex(s.get(4)["time"], r"^\d\d:\d\d:\d\d\.\d{3}$")
        self.assertIsNone(s.get(99))

    def test_stats(self):
        st = filled().stats()
        self.assertEqual((st["total"], st["tcp"], st["udp"], st["icmp"], st["other"]), (4, 1, 1, 1, 1))
        self.assertEqual(st["bytes"], 402)
        self.assertEqual(st["avg_size"], 100.5)
        self.assertEqual(sum(st["timeline"]["packets"]), 4)
        self.assertEqual(sum(st["timeline"]["bytes"]), 402)

    def test_empty_stats(self):
        st = PacketStore().stats()
        self.assertEqual((st["total"], st["avg_size"], st["timeline"]["labels"]), (0, 0, []))

    def test_filters(self):
        s = filled()
        self.assertEqual(s.query(proto="tcp")[1], 1)
        self.assertEqual(s.query(proto="OTHER")[1], 1)
        self.assertEqual(s.query(src="10.0.0.1")[1], 2)
        self.assertEqual(s.query(dst="8.8.8.8")[1], 2)
        self.assertEqual(s.query(proto="ICMP", dst="8.8.8.8")[1], 1)
        self.assertEqual(s.query(src="nope")[1], 0)

    def test_rows_omit_details_and_respect_limit(self):
        rows, matched = filled().query(limit=2)
        self.assertEqual((len(rows), matched, rows[-1]["no"]), (2, 4, 4))
        self.assertNotIn("details", rows[0])

    def test_max_packets_drops_oldest(self):
        s = PacketStore(max_packets=3)
        for i in range(5):
            s.add(make_packet(ts=1000.0 + i))
        self.assertEqual(len(s), 3)
        self.assertIsNone(s.get(1))
        self.assertIsNotNone(s.get(5))

    def test_timeline_buckets_for_long_captures(self):
        s = PacketStore()
        s.add(make_packet(ts=0))
        s.add(make_packet(ts=600))
        tl = s.stats()["timeline"]
        self.assertEqual(tl["bucket"], 10)
        self.assertLessEqual(len(tl["labels"]), 61)

    def test_csv(self):
        rows, _ = filled().query()
        parsed = list(csv.reader(io.StringIO(PacketStore.to_csv(rows))))
        self.assertEqual(parsed[0][:5], ["No", "Time", "Source IP", "Destination IP", "Protocol"])
        self.assertEqual(len(parsed), 5)
        self.assertEqual(parsed[3][5:7], ["", ""])  # ICMP has no ports

    def test_clear(self):
        s = filled()
        s.clear()
        self.assertEqual(len(s), 0)
