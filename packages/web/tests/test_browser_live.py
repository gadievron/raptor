"""Live browser-engine verification against a loopback fixture.

Exercises REAL Chromium via Playwright: rendered-DOM crawling,
execution-proof XSS (reflected and fragment/DOM shapes), the
origin gate, and the reflection-without-execution negative. Skips
when playwright or a launchable Chromium is absent, so CI degrades
to the mocked scanner-wiring tests.
"""

from __future__ import annotations

import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

import pytest

try:
    from packages.web.browser import BrowserEngine, browser_available
    _BROWSER_OK = browser_available()
except ImportError:
    _BROWSER_OK = False

pytestmark = pytest.mark.skipif(
    not _BROWSER_OK, reason="playwright/chromium not available",
)


class _FixtureHandler(BaseHTTPRequestHandler):
    """Small hostile-ish site: SPA page, reflected sink, DOM sink."""

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        parsed = urlparse(self.path)
        if parsed.path == "/spa":
            # The link and form exist only after JavaScript runs.
            body = (
                "<html><body><div id='app'></div><script>"
                "const a = document.createElement('a');"
                "a.href = '/js-only-page';"
                "a.textContent = 'hidden';"
                "document.getElementById('app').appendChild(a);"
                "const f = document.createElement('form');"
                "f.action = '/js-form'; f.method = 'post';"
                "f.innerHTML = \"<input name='jsfield' type='text'>\";"
                "document.getElementById('app').appendChild(f);"
                "</script>"
                "<img src='https://evil.example/beacon.png'>"
                "</body></html>"
            )
        elif parsed.path == "/echo-unsafe":
            # Reflected, unescaped: payload executes.
            value = parse_qs(parsed.query).get("q", [""])[0]
            body = f"<html><body><div>{value}</div></body></html>"
        elif parsed.path == "/echo-escaped":
            # Reflected but HTML-escaped: reflection without execution.
            value = parse_qs(parsed.query).get("q", [""])[0]
            escaped = value.replace("<", "&lt;").replace(">", "&gt;")
            body = f"<html><body><div>{escaped}</div></body></html>"
        elif parsed.path == "/dom-sink":
            # Classic DOM XSS: fragment flows into innerHTML.
            body = (
                "<html><body><div id='out'></div><script>"
                "document.getElementById('out').innerHTML ="
                "  decodeURIComponent(location.hash.slice(1));"
                "</script></body></html>"
            )
        else:
            body = "<html><body>plain</body></html>"
        raw = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *_args: object) -> None:
        pass


class TestBrowserEngineLive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _FixtureHandler)
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"
        cls.thread = threading.Thread(
            target=cls.server.serve_forever, daemon=True,
        )
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join(timeout=5)

    def test_rendered_crawl_sees_js_built_dom_and_blocks_off_origin(self):
        with BrowserEngine(self.base) as engine:
            rendered = engine.render(f"{self.base}/spa")

            self.assertIsNotNone(rendered)
            self.assertIn(f"{self.base}/js-only-page", rendered.links)
            self.assertEqual(len(rendered.forms), 1)
            self.assertIn("jsfield", rendered.forms[0]["inputs"])
            # The page tried to fetch https://evil.example — the origin
            # gate must have swallowed it.
            self.assertGreaterEqual(engine.blocked_requests, 1)

    def test_reflected_xss_execution_proof(self):
        with BrowserEngine(self.base) as engine:
            proof = engine.prove_xss(f"{self.base}/echo-unsafe?q=1", "q")

            self.assertIsNotNone(proof)
            self.assertEqual(proof.parameter, "q")
            self.assertTrue(proof.tokens)

    def test_escaped_reflection_is_not_execution(self):
        """The whole point of the browser oracle: reflection alone must
        not count."""
        with BrowserEngine(self.base) as engine:
            self.assertIsNone(
                engine.prove_xss(f"{self.base}/echo-escaped?q=1", "q"),
            )

    def test_dom_fragment_sink_detected_without_server_roundtrip(self):
        with BrowserEngine(self.base) as engine:
            proof = engine.prove_xss(f"{self.base}/dom-sink", None)

            self.assertIsNotNone(proof)
            self.assertEqual(proof.parameter, "#fragment")

    def test_plain_page_has_no_dom_sink(self):
        with BrowserEngine(self.base) as engine:
            self.assertIsNone(engine.prove_xss(f"{self.base}/plain", None))

    def test_off_origin_render_refused(self):
        with BrowserEngine(self.base) as engine:
            self.assertIsNone(engine.render("https://evil.example/"))

    def test_fragment_payload_survives_url_encoding(self):
        """prove_xss quotes the fragment; the fixture decodes it — the
        canary must round-trip exactly (regression for quote/decode
        mismatches)."""
        with BrowserEngine(self.base) as engine:
            proof = engine.prove_xss(f"{self.base}/dom-sink", None)
            self.assertIsNotNone(proof)
            self.assertIn("onerror", unquote(proof.payload))


if __name__ == "__main__":
    unittest.main()
