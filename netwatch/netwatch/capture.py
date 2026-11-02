"""Live packet capture using Scapy's AsyncSniffer (imported lazily)."""
import threading
import time


class LiveCapture:
    def __init__(self, store):
        self.store = store
        self._sniffer = None
        self._lock = threading.Lock()

    @property
    def running(self):
        s = self._sniffer
        return bool(s and getattr(s, "thread", None) and s.thread.is_alive())

    def start(self, iface=None):
        with self._lock:
            if self.running:
                raise RuntimeError("Capture is already running.")
            try:
                from scapy.all import AsyncSniffer
                from .analyzer import packet_to_dict
            except ImportError:
                raise RuntimeError("Scapy is not installed. Run: pip install -r requirements.txt")

            def handle(pkt):
                try:
                    self.store.add(packet_to_dict(pkt))
                except Exception:
                    pass  # never let one odd packet stop the capture

            sniffer = AsyncSniffer(iface=iface or None, prn=handle, store=False)
            sniffer.start()
            time.sleep(0.6)  # give it a moment to fail if it lacks permission
            exc = getattr(sniffer, "exception", None)
            if exc is not None or not sniffer.thread.is_alive():
                msg = str(exc) if exc else "capture could not start"
                raise RuntimeError(
                    "Could not start capture (%s). Run with administrator/root privileges "
                    "(and install Npcap on Windows), or upload a PCAP file instead." % msg)
            self._sniffer = sniffer

    def stop(self):
        with self._lock:
            sniffer, self._sniffer = self._sniffer, None
            if sniffer is not None:
                try:
                    sniffer.stop()
                except Exception:
                    pass
