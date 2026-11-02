# NetWatch: Network Packet Analyzer and Traffic Monitor

A small Computer Networks project: capture or load network traffic, analyse it with Scapy,
and explore it in a browser dashboard. Built with Python, Flask, Scapy, HTML/CSS/JavaScript and Chart.js.

## Run it

```bash
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000

- **Live capture** needs elevated rights: run with `sudo python app.py` (Linux/macOS) or from an
  Administrator terminal with [Npcap](https://npcap.com) installed (Windows).
- **No privileges?** Use *Upload PCAP* with any `.pcap`/`.pcapng` file (for example one saved from Wireshark).
- Charts load Chart.js from the jsDelivr CDN, so the browser needs internet access for the graphs.
  Everything else works offline.

## Features

| Area | What you get |
|---|---|
| Dashboard | Total packets, TCP/UDP/ICMP counts, total bytes, average packet size |
| Capture | Start/stop live capture (choose an interface) or upload a PCAP file |
| Packet table | Number, time, source, destination, protocol, ports, size |
| Filters | Protocol (TCP/UDP/ICMP/Other), source IP, destination IP (partial match, e.g. `192.168.1.`) |
| Details | Click a row for every layer's fields plus a hex/ASCII dump |
| Charts | Protocol distribution, packets over time, traffic volume (bytes over time) |
| Export | CSV of the packets matching the current filters |

Notes: ARP is shown as its own protocol (counted under "Other" in the dashboard totals). ICMPv6 is counted as ICMP.
The newest 10,000 packets are kept in memory (`MAX_PACKETS` in `netwatch/store.py`); the table shows the latest 500 matches.
Starting a capture or uploading a file replaces the current packets.

## API

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/status` | Capture state, packet count, source |
| GET | `/api/interfaces` | Interfaces available to Scapy |
| POST | `/api/capture/start` | Body `{"interface": "eth0"}` (optional) |
| POST | `/api/capture/stop` | Stop live capture |
| POST | `/api/upload` | Multipart field `file` (PCAP/PCAPNG) |
| POST | `/api/clear` | Remove all packets |
| GET | `/api/packets` | Query `proto`, `src`, `dst`, `limit` |
| GET | `/api/packets/<no>` | Full packet details |
| GET | `/api/stats` | Counts, bytes, protocol distribution, timeline |
| GET | `/api/export.csv` | CSV; accepts the same filters |

## Structure

```
app.py                 Flask app and API routes
netwatch/analyzer.py   Scapy packet -> dict, PCAP reader
netwatch/capture.py    Live capture (AsyncSniffer)
netwatch/store.py      In-memory store: filters, statistics, CSV
templates/index.html   Dashboard page
static/                style.css, app.js (Chart.js wiring)
tests/                 unittest suite
```

## Tests

```bash
python -m unittest discover -s . -t . -v      # or: pytest
```

Store and API tests always run; analyzer and real-PCAP upload tests run when Scapy is installed.

Only capture traffic on networks you own or are authorised to monitor.
