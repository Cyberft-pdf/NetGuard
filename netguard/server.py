"""A tiny local web server that shows NetGuard in the user's browser.

It listens on 127.0.0.1 only, so nothing outside this computer can reach it, and a
per-run token stops other websites open in the browser from starting scans.
"""
import json
import secrets
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import checks

PAGE = Path(__file__).parent / "static" / "index.html"
TOKEN = secrets.token_urlsafe(16)
_scan_lock = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    def _host_ok(self) -> bool:
        port = self.server.server_port
        return self.headers.get("Host") in (f"127.0.0.1:{port}", f"localhost:{port}")

    def _send(self, code: int, body: bytes, content_type: str = "text/plain; charset=utf-8"):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if not self._host_ok():
            return self._send(403, b"Forbidden")
        if self.path not in ("/", "/index.html"):
            return self._send(404, b"Not found")
        html = PAGE.read_text(encoding="utf-8").replace("{{TOKEN}}", TOKEN)
        self._send(200, html.encode(), "text/html; charset=utf-8")

    def do_POST(self):
        if not self._host_ok() or self.headers.get("X-NetGuard-Token") != TOKEN:
            return self._send(403, b"Forbidden")
        if self.path != "/api/scan":
            return self._send(404, b"Not found")
        with _scan_lock:
            report = checks.run_all_checks()
        self._send(200, json.dumps(report).encode(), "application/json")

    def log_message(self, *args):
        pass


def main():
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    url = f"http://127.0.0.1:{server.server_port}/"
    print("NetGuard is running.")
    print(f"If your browser didn't open, go to {url}")
    print("Close this window (or press Ctrl+C) to quit.")
    threading.Timer(0.5, webbrowser.open, (url,)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
