from __future__ import annotations

import argparse
import os
from pathlib import Path

from flask import Flask, jsonify, render_template, request

from bitchat_web.mesh import MeshNode


def create_app(node: MeshNode | None = None) -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 128 * 1024
    data_dir = Path(os.environ.get("BITCHAT_DATA_DIR", Path.cwd() / ".bitchat-web"))
    mesh = node or MeshNode(data_dir)
    app.extensions["mesh_node"] = mesh

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/api/status")
    def status():
        return jsonify(mesh.status())

    @app.get("/api/updates")
    def updates():
        try:
            sequence = max(0, int(request.args.get("after", "0")))
        except ValueError:
            sequence = 0
        return jsonify(mesh.messages_after(sequence))

    @app.post("/api/settings")
    def settings():
        body = request.get_json(silent=True) or {}
        try:
            mesh.configure(str(body.get("nickname", "")), str(body.get("room_code", "")))
            return jsonify({"ok": True, "status": mesh.status()})
        except ValueError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400

    @app.post("/api/connect")
    def connect():
        body = request.get_json(silent=True) or {}
        try:
            channel = int(body.get("channel", mesh.transport.channel))
            if not 1 <= channel <= 30:
                raise ValueError("RFCOMM channel must be between 1 and 30")
            peer = mesh.connect(str(body.get("address", "")), channel)
            return jsonify({"ok": True, "peer": peer})
        except (ValueError, RuntimeError, OSError) as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400

    @app.post("/api/disconnect/<link_id>")
    def disconnect(link_id: str):
        mesh.transport.disconnect(link_id)
        return jsonify({"ok": True})

    @app.post("/api/messages")
    def send_message():
        body = request.get_json(silent=True) or {}
        try:
            recipient_id = body.get("recipient_id") or None
            message = mesh.send_message(
                str(body.get("text", "")), str(recipient_id) if recipient_id else None
            )
            return jsonify({"ok": True, "message": message})
        except ValueError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400

    @app.post("/api/panic")
    def panic():
        mesh.panic()
        return jsonify({"ok": True})

    @app.errorhandler(413)
    def too_large(_error):
        return jsonify({"ok": False, "error": "Request is too large"}), 413

    return app


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the bitchat Python web client")
    parser.add_argument("--host", default="127.0.0.1", help="Web UI bind address")
    parser.add_argument("--port", type=int, default=5000, help="Web UI port")
    args = parser.parse_args()
    create_app().run(host=args.host, port=args.port, debug=False, threaded=True)
