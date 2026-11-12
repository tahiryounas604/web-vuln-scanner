"""Intentionally-vulnerable test fixture for web-vuln-scanner.

LOCAL TEST USE ONLY. Never expose this server to a network: in
``vulnerable`` mode it deliberately reflects input, leaks a fake SQL error,
redirects anywhere, lists a directory, and discloses versions.

Two modes (``--mode vulnerable`` / ``--mode patched``) so the scanner's
tests can assert detection on the vulnerable build and silence on the
patched build. The patched build keeps the same endpoints and behaviour,
minus the flaws.

Run:  python3 fixture_app.py --mode vulnerable --port 8901
"""

from __future__ import annotations

import argparse
import html as html_lib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

SECURITY_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


def make_handler(mode: str):
    patched = mode == "patched"

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        # -- helpers ------------------------------------------------------
        def version_string(self):
            # Controls the Server header exactly per mode.
            return "FixtureServer/1.2.3" if not patched else "FixtureServer"

        def _send(self, status, body, extra_headers=None, content_type="text/html"):
            data = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            if not patched:
                self.send_header("X-Powered-By", "FixturePHP/7.4.3")
                self.send_header("Set-Cookie", "session=abc123; Path=/")
            else:
                for k, v in SECURITY_HEADERS.items():
                    self.send_header(k, v)
                self.send_header(
                    "Set-Cookie",
                    "session=abc123; Path=/; Secure; HttpOnly; SameSite=Lax")
            for k, v in (extra_headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def _cors_headers(self):
            origin = self.headers.get("Origin", "")
            if not patched:
                if origin:
                    return {"Access-Control-Allow-Origin": origin,
                            "Access-Control-Allow-Credentials": "true"}
            return {}

        def _home(self):
            body = (
                "<html><head><title>Fixture</title></head><body>"
                "<h1>Fixture app</h1>"
                "<p><a href=\"/search?q=hello\">search</a></p>"
                "<p><a href=\"/product?id=1\">product</a></p>"
                "<p><a href=\"/files/\">files</a></p>"
                "</body></html>"
            )
            self._send(200, body, self._cors_headers())

        def _search(self, query):
            q = query.get("q", [""])[0]
            if not patched and "'" in q:
                self._send(200, "You have an error in your SQL syntax; "
                                "check the manual that corresponds to your "
                                "MySQL server version for the right syntax "
                                "to use near ''' at line 1",
                         self._cors_headers())
                return
            shown = html_lib.escape(q) if patched else q
            self._send(200, f"<html><body><p>Results for: {shown}</p>"
                            "</body></html>", self._cors_headers())

        def _product(self, query):
            pid = query.get("id", [""])[0]
            if not patched and "'" in pid:
                self._send(200, "You have an error in your SQL syntax; "
                                "check the manual that corresponds to your "
                                "MySQL server version for the right syntax "
                                "to use near ''' at line 1",
                         self._cors_headers())
                return
            self._send(200, f"<html><body><p>Product {html_lib.escape(pid)}"
                            "</p></body></html>", self._cors_headers())

        def _redirect(self, query):
            url = query.get("url", [""])[0] or query.get("next", [""])[0]
            if not patched:
                # Vulnerable: redirects to any supplied URL.
                self.send_response(302)
                self.send_header("Location", url or "/")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            # Patched: only relative, same-site paths.
            if url.startswith("/"):
                self.send_response(302)
                self.send_header("Location", url)
                self.send_header("Content-Length", "0")
                self.end_headers()
            else:
                self._send(400, "<html><body><p>Invalid redirect target"
                                "</p></body></html>", self._cors_headers())

        def _files(self):
            if not patched:
                self._send(200, "<html><head><title>Index of /files/</title>"
                                "</head><body><h1>Index of /files/</h1>"
                                "<ul><li>secret.txt</li><li>backup.sql</li>"
                                "</ul></body></html>", self._cors_headers())
            else:
                self._send(403, "<html><body><p>Forbidden</p></body></html>",
                           self._cors_headers())

        # -- routing ------------------------------------------------------
        def do_GET(self):
            parsed = urlparse(self.path)
            query = parse_qs(parsed.query)
            if parsed.path == "/":
                self._home()
            elif parsed.path == "/search":
                self._search(query)
            elif parsed.path == "/product":
                self._product(query)
            elif parsed.path == "/redirect":
                self._redirect(query)
            elif parsed.path == "/login":
                self._redirect(query)
            elif parsed.path == "/files/":
                self._files()
            else:
                self._send(404, "<html><body><p>Not found</p></body></html>",
                           self._cors_headers())

        def log_message(self, *args):  # keep test output quiet
            pass

    return Handler


def create_server(mode: str, host: str = "127.0.0.1", port: int = 0):
    return ThreadingHTTPServer((host, port), make_handler(mode))


def main():
    p = argparse.ArgumentParser(description="web-vuln-scanner test fixture")
    p.add_argument("--mode", choices=["vulnerable", "patched"],
                   default="vulnerable")
    p.add_argument("--port", type=int, default=8901)
    p.add_argument("--host", default="127.0.0.1")
    args = p.parse_args()
    server = create_server(args.mode, args.host, args.port)
    print(f"fixture ({args.mode}) on http://{args.host}:{server.server_address[1]}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
