def make_packet(proto="TCP", src="10.0.0.1", dst="10.0.0.2", size=100, ts=1000.0, sport=1234, dport=80):
    """A packet dict shaped like the analyzer's output."""
    return {"ts": ts, "src": src, "dst": dst, "proto": proto, "sport": sport, "dport": dport,
            "size": size, "info": "test",
            "details": {"layers": [{"name": proto, "fields": [["x", "1"]]}], "hex": "0000  00"}}
