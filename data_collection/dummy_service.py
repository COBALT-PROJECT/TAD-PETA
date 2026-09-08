#!/usr/bin/env python3
"""Tiny threaded HTTP server — a dummy target for the stress/DoS phase and for
benign HTTP traffic, so attacks against 10.163.1.126 hit a live service and
generate real request/response traffic (not refused-connection noise).

    python3 dummy_service.py 8090      # runs until Ctrl-C

Threaded so a concurrent flood gets fast replies (a single-threaded server
would stall and look like a dead port)."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import sys

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8090


class H(BaseHTTPRequestHandler):
    def _respond(self):
        body = b"OK\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except BrokenPipeError:
            pass

    do_GET = _respond
    do_HEAD = _respond

    def log_message(self, *a):   # silence per-request logging under a flood
        pass


if __name__ == "__main__":
    print(f"[dummy] threaded HTTP service listening on 0.0.0.0:{PORT}")
    ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()
