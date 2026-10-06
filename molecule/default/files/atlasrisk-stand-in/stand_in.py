"""Molecule stand-in for AtlasRisk's API and risk-worker images.

It keeps the real images' command line:

    migrate                -> exit 0 once PostgreSQL accepts connections,
                              reporting "no migrations to run" like goose
    -listen ADDRESS:PORT   -> the API: answer every GET with JSON describing
                              the settings it was given (never secrets)
    (no arguments)         -> the risk worker: run until SIGTERM
"""

from __future__ import annotations

import json
import os
import signal
import socket
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit


def database() -> tuple[str, int, str]:
    url = urlsplit(os.environ["ATLASRISK_DATABASE_URL"])
    return url.hostname or "", url.port or 5432, url.path.lstrip("/")


def database_reachable() -> bool:
    host, port, _ = database()
    try:
        with socket.create_connection((host, port), timeout=3):
            return True
    except OSError:
        return False


def migrate() -> int:
    for _ in range(60):
        if database_reachable():
            print("goose: no migrations to run. current version: 0", file=sys.stderr)
            return 0
        time.sleep(1)
    print("migrate: database unreachable", file=sys.stderr)
    return 1


class Api(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 (http.server naming)
        host, port, name = database()
        body = json.dumps({
            "stand_in": "atlasrisk-api",
            "path": self.path,
            "database": f"{host}:{port}/{name}",
            "database_reachable": database_reachable(),
            "s3_endpoint": os.environ.get("ATLASRISK_S3_ENDPOINT", ""),
            "s3_bucket": os.environ.get("ATLASRISK_S3_BUCKET", ""),
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        pass


def main(args: list[str]) -> int:
    # PID 1 ignores SIGTERM unless it installs a handler.
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    if args == ["migrate"]:
        return migrate()
    if len(args) == 2 and args[0] == "-listen":
        host, port = args[1].rsplit(":", 1)
        ThreadingHTTPServer((host, int(port)), Api).serve_forever()
        return 0
    if not args:
        print(json.dumps({"event": "worker started", "database_reachable": database_reachable()}))
        while True:
            time.sleep(3600)
    print(f"unexpected arguments: {args}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
