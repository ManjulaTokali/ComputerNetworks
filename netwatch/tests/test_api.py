import csv
import io
import unittest

from app import create_app
from netwatch.store import PacketStore
from tests.helpers import make_packet


class FakeCapture:
    running = False
    fail = False

    def start(self, iface=None):
        if self.fail:
            raise RuntimeError("no permission")
        self.running = True
        self.iface = iface

    def stop(self):
        self.running = False


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.store = PacketStore()
        self.cap = FakeCapture()
        self.client = create_app(self.store, self.cap).test_client()
        self.store.add(make_packet("TCP", "10.0.0.1", "10.0.0.2", 100, 1000.0))
        self.store.add(make_packet("UDP", "10.0.0.3", "8.8.8.8", 300, 1001.0, 5353, 53))

    def test_index_page(self):
        r = self.client.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"NetWatch", r.data)

    def test_static_assets(self):
        for path in ("/static/app.js", "/static/style.css"):
            self.assertEqual(self.client.get(path).status_code, 200)

    def test_status(self):
        d = self.client.get("/api/status").get_json()
        self.assertEqual((d["capturing"], d["count"]), (False, 2))

    def test_stats(self):
        d = self.client.get("/api/stats").get_json()
        self.assertEqual((d["total"], d["tcp"], d["udp"], d["bytes"], d["avg_size"]), (2, 1, 1, 400, 200))

    def test_packets_and_filters(self):
        d = self.client.get("/api/packets").get_json()
        self.assertEqual((len(d["packets"]), d["total"]), (2, 2))
        self.assertEqual(self.client.get("/api/packets?proto=UDP").get_json()["matched"], 1)
        self.assertEqual(self.client.get("/api/packets?src=10.0.0.1").get_json()["matched"], 1)
        self.assertEqual(self.client.get("/api/packets?dst=8.8").get_json()["matched"], 1)
        self.assertEqual(self.client.get("/api/packets?limit=abc").status_code, 200)

    def test_packet_detail(self):
        d = self.client.get("/api/packets/1").get_json()
        self.assertEqual(d["src"], "10.0.0.1")
        self.assertIn("layers", d["details"])
        self.assertEqual(self.client.get("/api/packets/99").status_code, 404)

    def test_export_csv(self):
        r = self.client.get("/api/export.csv?proto=TCP")
        self.assertEqual(r.mimetype, "text/csv")
        self.assertIn("attachment", r.headers["Content-Disposition"])
        rows = list(csv.reader(io.StringIO(r.get_data(as_text=True))))
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[1][4], "TCP")

    def test_capture_start_stop(self):
        d = self.client.post("/api/capture/start", json={"interface": "eth0"})
        self.assertEqual(d.status_code, 200)
        self.assertEqual(self.cap.iface, "eth0")
        self.assertEqual(self.store.source, "live")
        self.assertEqual(self.store.stats()["total"], 0)  # a new capture starts empty
        self.assertTrue(self.client.get("/api/status").get_json()["capturing"])
        self.assertEqual(self.client.post("/api/capture/start").status_code, 409)
        self.assertEqual(self.client.post("/api/upload").status_code, 409)
        self.client.post("/api/capture/stop")
        self.assertFalse(self.client.get("/api/status").get_json()["capturing"])

    def test_capture_failure_is_reported(self):
        self.cap.fail = True
        r = self.client.post("/api/capture/start")
        self.assertEqual(r.status_code, 400)
        self.assertIn("no permission", r.get_json()["error"])

    def test_upload_without_file(self):
        self.assertEqual(self.client.post("/api/upload").status_code, 400)

    def test_upload_garbage_file(self):
        data = {"file": (io.BytesIO(b"this is not a pcap"), "bad.pcap")}
        r = self.client.post("/api/upload", data=data, content_type="multipart/form-data")
        self.assertIn(r.status_code, (400, 503))  # 503 only if Scapy is missing
        self.assertEqual(len(self.store), 2)  # existing data untouched

    def test_clear(self):
        self.client.post("/api/clear")
        self.assertEqual(self.client.get("/api/stats").get_json()["total"], 0)


try:
    import scapy  # noqa: F401
    HAVE_SCAPY = True
except ImportError:
    HAVE_SCAPY = False


@unittest.skipUnless(HAVE_SCAPY, "Scapy not installed")
class UploadTests(unittest.TestCase):
    def test_upload_real_pcap(self):
        import os
        import tempfile
        from scapy.all import Ether, IP, TCP, wrpcap
        path = os.path.join(tempfile.mkdtemp(), "t.pcap")
        wrpcap(path, [Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=1, dport=80)])
        store = PacketStore()
        client = create_app(store, FakeCapture()).test_client()
        with open(path, "rb") as f:
            r = client.post("/api/upload", data={"file": (f, "t.pcap")}, content_type="multipart/form-data")
        self.assertEqual(r.get_json()["loaded"], 1)
        self.assertEqual(store.get(1)["proto"], "TCP")
