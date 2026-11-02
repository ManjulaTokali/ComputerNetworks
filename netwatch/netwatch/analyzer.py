"""Convert Scapy packets into plain, JSON-friendly dictionaries."""
from scapy.all import ARP, ICMP, IP, IPv6, TCP, UDP, PcapReader
from scapy.packet import NoPayload

ICMP_TYPES = {0: "Echo reply", 3: "Destination unreachable", 5: "Redirect",
              8: "Echo request", 11: "Time exceeded"}
MAX_HEX_BYTES = 512


def _layers(pkt):
    layers, layer = [], pkt
    while layer is not None and not isinstance(layer, NoPayload):
        layers.append(layer)
        layer = layer.payload
    return layers


def _field_text(layer, field):
    try:
        text = str(field.i2repr(layer, layer.getfieldval(field.name)))
    except Exception:
        text = str(layer.fields.get(field.name))
    return text if len(text) <= 200 else text[:200] + "..."


def _hexdump(data):
    lines = []
    shown = data[:MAX_HEX_BYTES]
    for off in range(0, len(shown), 16):
        chunk = shown[off:off + 16]
        hex_part = " ".join("%02x" % b for b in chunk)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append("%04x  %-47s  %s" % (off, hex_part, text))
    if len(data) > MAX_HEX_BYTES:
        lines.append("... %d more bytes" % (len(data) - MAX_HEX_BYTES))
    return "\n".join(lines)


def packet_to_dict(pkt):
    """Summarise one Scapy packet (protocol is decided by the outermost transport layer)."""
    layers = _layers(pkt)
    src = dst = sport = dport = None
    proto, info, transport = "Other", "", None

    for layer in layers:
        if src is None and isinstance(layer, (IP, IPv6)):
            src, dst = layer.src, layer.dst
        elif src is None and isinstance(layer, ARP):
            src, dst, proto = layer.psrc, layer.pdst, "ARP"
            info = ("Who has %s? Tell %s" % (layer.pdst, layer.psrc) if layer.op == 1
                    else "%s is at %s" % (layer.psrc, layer.hwsrc))
        if isinstance(layer, (TCP, UDP, ICMP)) or type(layer).__name__.startswith("ICMPv6"):
            transport = layer
            break

    if src is None:  # not IP or ARP: fall back to MAC addresses
        src, dst = getattr(pkt, "src", None), getattr(pkt, "dst", None)

    if isinstance(transport, TCP):
        proto, sport, dport = "TCP", int(transport.sport), int(transport.dport)
        info = "[%s] Seq=%s Ack=%s Win=%s" % (transport.flags, transport.seq, transport.ack, transport.window)
    elif isinstance(transport, UDP):
        proto, sport, dport = "UDP", int(transport.sport), int(transport.dport)
        info = "Len=%s" % transport.len
    elif isinstance(transport, ICMP):
        proto = "ICMP"
        info = ICMP_TYPES.get(int(transport.type), "Type %s" % transport.type)
    elif transport is not None:
        proto, info = "ICMP", type(transport).__name__

    raw = getattr(pkt, "original", None) or bytes(pkt)
    return {
        "ts": float(pkt.time),
        "src": src, "dst": dst, "proto": proto,
        "sport": sport, "dport": dport,
        "size": len(raw), "info": info,
        "details": {
            "layers": [{"name": l.name,
                        "fields": [[f.name, _field_text(l, f)] for f in l.fields_desc]}
                       for l in layers],
            "hex": _hexdump(raw),
        },
    }


def read_pcap(path, limit):
    """Read a .pcap/.pcapng file; returns (packet dicts, truncated flag)."""
    packets, truncated = [], False
    with PcapReader(path) as reader:
        for pkt in reader:
            if len(packets) >= limit:
                truncated = True
                break
            packets.append(packet_to_dict(pkt))
    return packets, truncated
