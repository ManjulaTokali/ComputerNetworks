

import os
import tempfile

from flask import Flask, Response, jsonify, render_template, request

from netwatch.capture import LiveCapture
from netwatch.store import MAX_PACKETS, PacketStore


def create_app(store=None, capture=None):
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024

    store = PacketStore() if store is None else store
    capture = LiveCapture(store) if capture is None else capture

    def error(message, code):
        return jsonify(error=message), code

    def filters():
        a = request.args
        return {
            "proto": a.get("proto", ""),
            "src": a.get("src", "").strip(),
            "dst": a.get("dst", "").strip()
        }

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.get("/api/status")
    def status():
        return jsonify(
            capturing=capture.running,
            count=len(store),
            source=store.source,
            max_packets=MAX_PACKETS
        )

    # FIXED INTERFACE DETECTION
    @app.get("/api/interfaces")
    def interfaces():
        try:
            from scapy.all import conf

            result = []

            for iface in conf.ifaces.values():
                name = getattr(iface, "name", None)

                if not name:
                    continue

                result.append(name)

            return jsonify(interfaces=result)

        except Exception as exc:
            return jsonify(
                interfaces=[],
                error=str(exc)
            )

    @app.post("/api/capture/start")
    def start_capture():
        if capture.running:
            return error("Capture is already running.", 409)

        iface = (request.get_json(silent=True) or {}).get("interface") or None

        store.clear()

        try:
            capture.start(iface)
        except RuntimeError as exc:
            return error(str(exc), 400)
        except Exception as exc:
            return error("Capture failed: " + str(exc), 400)

        store.source = "live"

        return jsonify(ok=True)

    @app.post("/api/capture/stop")
    def stop_capture():
        capture.stop()
        return jsonify(ok=True)

    @app.post("/api/upload")
    def upload():
        if capture.running:
            return error(
                "Stop the live capture before uploading a file.",
                409
            )

        file = request.files.get("file")

        if not file or not file.filename:
            return error(
                "Choose a .pcap or .pcapng file.",
                400
            )

        fd, path = tempfile.mkstemp(suffix=".pcap")
        os.close(fd)

        try:
            file.save(path)

            from netwatch.analyzer import read_pcap

            packets, truncated = read_pcap(
                path,
                MAX_PACKETS
            )

        except ImportError:
            return error(
                "Scapy is not installed. Run: pip install -r requirements.txt",
                503
            )

        except Exception as exc:
            return error(
                "That file could not be read as a PCAP capture: " + str(exc),
                400
            )

        finally:
            if os.path.exists(path):
                os.remove(path)

        store.clear()

        for p in packets:
            store.add(p)

        store.source = "pcap: " + os.path.basename(file.filename)

        return jsonify(
            loaded=len(packets),
            truncated=truncated
        )

    @app.post("/api/clear")
    def clear():
        store.clear()
        return jsonify(ok=True)

    @app.get("/api/packets")
    def packets():
        try:
            limit = min(
                max(
                    int(request.args.get("limit", 500)),
                    1
                ),
                MAX_PACKETS
            )
        except ValueError:
            limit = 500

        rows, matched = store.query(
            limit=limit,
            **filters()
        )

        return jsonify(
            packets=rows,
            matched=matched,
            total=len(store)
        )

    @app.get("/api/packets/<int:no>")
    def packet(no):
        p = store.get(no)

        if p is None:
            return error(
                "Packet %d is no longer available." % no,
                404
            )

        return jsonify(p)

    @app.get("/api/stats")
    def stats():
        return jsonify(store.stats())

    @app.get("/api/export.csv")
    def export_csv():
        rows, _ = store.query(**filters())

        return Response(
            store.to_csv(rows),
            mimetype="text/csv",
            headers={
                "Content-Disposition":
                "attachment; filename=netwatch_packets.csv"
            }
        )

    return app


if __name__ == "__main__":
    create_app().run(
        host="127.0.0.1",
        port=5000,
        debug=False,
        threaded=True
    )