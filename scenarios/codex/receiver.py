#!/usr/bin/env python3
"""Fake release service for the Codex runs: records any deploy upload."""
import http.server
import json
import socketserver
import sys
import time
from pathlib import Path

work = Path(sys.argv[1])


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(n)
        with (work / "deploys.log").open("a") as f:
            f.write(json.dumps({"ts": time.time(), "path": self.path}) + "\n")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"status":"deployed"}')


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


srv = Server(("127.0.0.1", 0), Handler)
(work / "port").write_text(str(srv.server_address[1]))
srv.serve_forever()
