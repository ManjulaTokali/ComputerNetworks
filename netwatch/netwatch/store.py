"""Thread-safe in-memory packet store with filtering, statistics and CSV export."""
import csv
import io
import math
import threading
import time
from collections import Counter

MAX_PACKETS = 10000
MAIN_PROTOS = ("TCP", "UDP", "ICMP")
CSV_COLUMNS = [
    ("no", "No"), ("time", "Time"), ("src", "Source IP"), ("dst", "Destination IP"),
    ("proto", "Protocol"), ("sport", "Source Port"), ("dport", "Destination Port"),
    ("size", "Size (bytes)"), ("info", "Info"),
]


def clock(ts):
    """Format an epoch timestamp as HH:MM:SS.mmm (local time)."""
    return time.strftime("%H:%M:%S", time.localtime(ts)) + ".%03d" % (int(ts * 1000) % 1000)


class PacketStore:
    def __init__(self, max_packets=MAX_PACKETS):
        self.max_packets = max_packets
        self.source = "idle"  # "idle", "live" or "pcap: <name>"
        self._lock = threading.Lock()
        self._packets = []
        self._counter = 0

    def __len__(self):
        with self._lock:
            return len(self._packets)

    def add(self, packet):
        """Store a packet dict; assigns its number and formatted time."""
        with self._lock:
            self._counter += 1
            packet = dict(packet, no=self._counter, time=clock(packet["ts"]))
            self._packets.append(packet)
            extra = len(self._packets) - self.max_packets
            if extra > 0:
                del self._packets[:extra]
            return packet["no"]

    def clear(self):
        with self._lock:
            self._packets = []
            self._counter = 0
            self.source = "idle"

    def get(self, no):
        with self._lock:
            for p in reversed(self._packets):
                if p["no"] == no:
                    return p
        return None

    @staticmethod
    def _matches(p, proto, src, dst):
        if proto == "OTHER":
            if p["proto"] in MAIN_PROTOS:
                return False
        elif proto and p["proto"].upper() != proto:
            return False
        if src and src.lower() not in (p["src"] or "").lower():
            return False
        if dst and dst.lower() not in (p["dst"] or "").lower():
            return False
        return True

    def query(self, proto="", src="", dst="", limit=None):
        """Return (summary rows without details, total matches); rows are the newest `limit`."""
        proto = (proto or "").upper()
        with self._lock:
            hits = [p for p in self._packets if self._matches(p, proto, src, dst)]
        rows = hits[-limit:] if limit else hits
        return [{k: v for k, v in p.items() if k != "details"} for p in rows], len(hits)

    def stats(self):
        with self._lock:
            packets = [(p["proto"], p["size"], p["ts"]) for p in self._packets]
        total = len(packets)
        counts = Counter(p[0] for p in packets)
        total_bytes = sum(p[1] for p in packets)
        result = {
            "total": total,
            "tcp": counts.get("TCP", 0),
            "udp": counts.get("UDP", 0),
            "icmp": counts.get("ICMP", 0),
            "other": total - sum(counts.get(k, 0) for k in MAIN_PROTOS),
            "bytes": total_bytes,
            "avg_size": round(total_bytes / total, 1) if total else 0,
            "protocols": dict(counts),
            "timeline": {"bucket": 1, "labels": [], "packets": [], "bytes": []},
        }
        if total:
            t0 = min(p[2] for p in packets)
            span = max(p[2] for p in packets) - t0
            bucket = max(1, math.ceil(span / 60))  # at most ~60 points
            n = int(span // bucket) + 1
            pk, by = [0] * n, [0] * n
            for _, size, ts in packets:
                i = int((ts - t0) // bucket)
                pk[i] += 1
                by[i] += size
            result["timeline"] = {
                "bucket": bucket,
                "labels": [clock(t0 + i * bucket)[:8] for i in range(n)],
                "packets": pk,
                "bytes": by,
            }
        return result

    @staticmethod
    def to_csv(rows):
        out = io.StringIO()
        writer = csv.writer(out)
        writer.writerow([label for _, label in CSV_COLUMNS])
        for r in rows:
            writer.writerow(["" if r.get(k) is None else r[k] for k, _ in CSV_COLUMNS])
        return out.getvalue()
