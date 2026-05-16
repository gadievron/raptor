"""Fake-target regression tests for WebScanner crawl controls."""

from __future__ import annotations

import http.server
import threading
from contextlib import contextmanager
from pathlib import Path

from packages.web.scanner import WebScanner


class _FakeTargetHandler(http.server.BaseHTTPRequestHandler):
    hits: list[str] = []

    def do_GET(self):
        type(self).hits.append(self.path)
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        if self.path == "/":
            body = b'<a href="/page-1?first=1">one</a><a href="/page-2?second=2">two</a>'
        elif self.path.startswith("/page-1"):
            body = b'<a href="/page-1/deeper?deep=1">deep</a>'
        else:
            body = b"ok"
        self.wfile.write(body)

    def log_message(self, format, *args):  # pragma: no cover - keep tests quiet
        pass


@contextmanager
def _fake_target():
    handler = type("FakeTargetHandler", (_FakeTargetHandler,), {"hits": []})
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        yield f"http://{host}:{port}", handler
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_scanner_threads_crawl_limits_to_fake_target(tmp_path: Path):
    """A scanner-level fake target should honor operator crawl limits."""
    with _fake_target() as (base_url, handler):
        scanner = WebScanner(base_url, llm=None, out_dir=tmp_path, max_depth=0, max_pages=1)

        result = scanner.scan()

    assert result["discovery"]["total_pages"] == 1
    assert handler.hits == ["/"]
    crawl_artifact = tmp_path / "crawl_results.json"
    assert crawl_artifact.exists()
