"""OOB callback server for blind XXE / SSRF / CMDI."""
from __future__ import annotations
import threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, List


class _Log:
    hits: List[Dict] = []
    lock = threading.Lock()

    @classmethod
    def add(cls, e: Dict) -> None:
        with cls.lock:
            cls.hits.append(e)

    @classmethod
    def snapshot(cls) -> List[Dict]:
        with cls.lock:
            return list(cls.hits)


class _Handler(BaseHTTPRequestHandler):
    server_version = "OOB/1.0"

    def log_message(self, *a):
        pass

    def _rec(self, method: str):
        entry = {
            "ts": time.time(),
            "method": method,
            "path": self.path,
            "headers": {k.lower(): v for k, v in self.headers.items()},
            "client": self.client_address[0],
        }
        _Log.add(entry)
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self): self._rec("GET")
    def do_POST(self): self._rec("POST")
    def do_HEAD(self): self._rec("HEAD")


class OOBServer:
    def __init__(self, bind: str = "0.0.0.0", port: int = 0):
        self.server = ThreadingHTTPServer((bind, port), _Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self):
        self.thread.start()
        return self

    def stop(self):
        try:
            self.server.shutdown()
        except Exception:
            pass

    @property
    def hits(self) -> List[Dict]:
        return _Log.snapshot()

    def marker_hit(self, marker: str) -> bool:
        return any(marker in h.get("path", "") for h in self.hits)
