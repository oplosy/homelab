"""Test-only HTTP stub for the edge proxy host checks (Molecule only).

Usage: http_stub.py ADDRESS PORT STATUS LOGFILE

Answers every request with STATUS and the body "secureedge-stub", and
appends "METHOD PATH CONTENT_LENGTH" and the indented request headers to
LOGFILE so checks can see what reached it.
"""

from __future__ import annotations

import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ADDRESS, PORT, STATUS, LOG = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
BODY = b"secureedge-stub\n"


class Handler(BaseHTTPRequestHandler):
    def answer(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        remaining = length
        while remaining > 0:
            chunk = self.rfile.read(min(remaining, 65536))
            if not chunk:
                break
            remaining -= len(chunk)
        with open(LOG, "a", encoding="utf-8") as log:
            log.write(f"{self.command} {self.path} {length}\n")
            for name, value in self.headers.items():
                log.write(f"  {name}: {value}\n")
        self.send_response(STATUS)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = answer

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass


ThreadingHTTPServer((ADDRESS, PORT), Handler).serve_forever()
