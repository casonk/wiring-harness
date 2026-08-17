#!/usr/bin/env python3

import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

if len(sys.argv) != 3:
    raise SystemExit("usage: macos-edge-http-backend PORT RESPONSE")

PORT = int(sys.argv[1])
BODY = sys.argv[2].encode()


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        body = BODY
        if self.path == "/proxy-auth":
            body = self.headers.get("X-Snowbridge-Auth-User", "").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *args: object) -> None:
        return


ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
