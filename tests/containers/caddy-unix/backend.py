#!/usr/bin/env python3
"""Minimal HTTP backend served only through a Unix-domain socket."""

from __future__ import annotations

import http.server
import os
import socketserver
from pathlib import Path


SOCKET_PATH = Path("/run/nordility/web.sock")


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        payload = b"nordility-unix-ok\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, _format: str, *args: object) -> None:
        del args


def main() -> None:
    SOCKET_PATH.parent.mkdir(parents=True, exist_ok=True)
    try:
        SOCKET_PATH.unlink()
    except FileNotFoundError:
        pass
    with socketserver.UnixStreamServer(str(SOCKET_PATH), Handler) as server:
        os.chmod(SOCKET_PATH, 0o660)
        server.serve_forever()


if __name__ == "__main__":
    main()
