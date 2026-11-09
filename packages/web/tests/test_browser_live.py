"""Live browser-engine verification against a loopback fixture.

Exercises REAL Chromium via Playwright: rendered-DOM crawling,
execution-proof XSS (reflected and fragment/DOM shapes), the
origin gate, and the reflection-without-execution negative. Skips
when the runtime or required containment is absent in generic pytest runs.
The dedicated wrapper-acceptance lane provisions Chromium and rejects skips.
"""

from __future__ import annotations

import sys
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

import pytest

from packages.web.browser import BrowserEngine, browser_available
from packages.web.tests.http_server import start_http_server

pytestmark = [pytest.mark.slow, pytest.mark.integration,
              pytest.mark.linux_native, pytest.mark.darwin_native]


_INNER_WAIVER = False


@pytest.fixture(scope="module", autouse=True)
def installed_native_browser():
    # Explicit waiver only in these owned functional cases when nesting fails.
    # The native policy case separately requires default-mode refusal.
    from packages.web import _browser_sandbox
    global _INNER_WAIVER
    previous = _INNER_WAIVER
    with pytest.MonkeyPatch.context() as patch:
        for name in ('HTTPS_PROXY', 'HTTP_PROXY', 'NO_PROXY', 'https_proxy', 'http_proxy', 'no_proxy'):
            patch.delenv(name, raising=False)
        patch.setattr(_browser_sandbox, '_DRIVER_DIAGNOSTICS', True)
        _INNER_WAIVER = sys.platform == 'darwin' and not _browser_sandbox.macos_nested_seatbelt_available()
        try:
            if not browser_available(allow_unsandboxed_chromium=_INNER_WAIVER):
                pytest.skip("playwright/chromium or required outer containment not available")
            yield
        finally:
            _INNER_WAIVER = previous


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
        cls.thread = start_http_server(cls.server, cls.addClassCleanup)
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    def test_rendered_crawl_sees_js_built_dom_and_blocks_off_origin(self):
        with BrowserEngine(self.base, allow_unsandboxed_chromium=_INNER_WAIVER) as engine:
            rendered = engine.render(f"{self.base}/spa")

            self.assertIsNotNone(rendered)
            self.assertIn(f"{self.base}/js-only-page", rendered.links)
            self.assertEqual(len(rendered.forms), 1)
            self.assertIn("jsfield", rendered.forms[0]["inputs"])
            # The page tried to fetch https://evil.example — the origin
            # gate must have swallowed it.
            self.assertGreaterEqual(engine.blocked_requests, 1)

    def test_reflected_xss_execution_proof(self):
        with BrowserEngine(self.base, allow_unsandboxed_chromium=_INNER_WAIVER) as engine:
            proof = engine.prove_xss(f"{self.base}/echo-unsafe?q=1", "q")

            self.assertIsNotNone(proof)
            self.assertEqual(proof.parameter, "q")
            self.assertTrue(proof.tokens)

    def test_escaped_reflection_is_not_execution(self):
        """The whole point of the browser oracle: reflection alone must
        not count."""
        with BrowserEngine(self.base, allow_unsandboxed_chromium=_INNER_WAIVER) as engine:
            self.assertIsNone(
                engine.prove_xss(f"{self.base}/echo-escaped?q=1", "q"),
            )

    def test_dom_fragment_sink_detected_without_server_roundtrip(self):
        with BrowserEngine(self.base, allow_unsandboxed_chromium=_INNER_WAIVER) as engine:
            proof = engine.prove_xss(f"{self.base}/dom-sink", None)

            self.assertIsNotNone(proof)
            self.assertEqual(proof.parameter, "#fragment")

    def test_plain_page_has_no_dom_sink(self):
        with BrowserEngine(self.base, allow_unsandboxed_chromium=_INNER_WAIVER) as engine:
            self.assertIsNone(engine.prove_xss(f"{self.base}/plain", None))

    def test_off_origin_render_refused(self):
        with BrowserEngine(self.base, allow_unsandboxed_chromium=_INNER_WAIVER) as engine:
            self.assertIsNone(engine.render("https://evil.example/"))

    def test_fragment_payload_survives_url_encoding(self):
        """prove_xss quotes the fragment; the fixture decodes it — the
        canary must round-trip exactly (regression for quote/decode
        mismatches)."""
        with BrowserEngine(self.base, allow_unsandboxed_chromium=_INNER_WAIVER) as engine:
            proof = engine.prove_xss(f"{self.base}/dom-sink", None)
            self.assertIsNotNone(proof)
            self.assertIn("onerror", unquote(proof.payload))


if __name__ == "__main__":
    unittest.main()


class TestOriginGateHardening(unittest.TestCase):
    """Redirects and WebSockets — the two egress paths context.route
    does not cover by itself."""

    @classmethod
    def setUpClass(cls):
        class _EvilHandler(BaseHTTPRequestHandler):
            hits: list[str] = []

            def do_GET(self):  # noqa: N802
                type(self).hits.append(self.path)
                body = b"evil"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                pass

        class _TargetHandler(BaseHTTPRequestHandler):
            evil_port = 0
            received: list[tuple[str, dict[str, str]]] = []
            received_fields: list[tuple[str, list[tuple[str, str]]]] = []
            posts: list[tuple[str, bytes]] = []

            def do_GET(self):  # noqa: N802
                type(self).received.append((self.path, dict(self.headers)))
                type(self).received_fields.append((self.path, list(self.headers.items())))
                if self.path == "/redirect-out":
                    self.send_response(302)
                    self.send_header(
                        "Location",
                        f"http://127.0.0.1:{type(self).evil_port}/redirect-hop",
                    )
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if self.path == "/redirect-in":
                    self.send_response(302)
                    self.send_header("Location", "/target-final")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if self.path == "/ws-page":
                    body = (
                        "<html><body><script>"
                        f"new WebSocket('ws://127.0.0.1:{type(self).evil_port}/ws');"
                        "</script></body></html>"
                    ).encode()
                else:
                    body = b"<html><body>ok</body></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):  # noqa: N802
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                type(self).posts.append((self.path, body))
                if self.path == "/binary-redirect":
                    self.send_response(307)
                    self.send_header("Location", "/binary-final")
                else:
                    self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *_args):
                pass

        cls.evil_handler = _EvilHandler
        cls.target_handler = _TargetHandler
        cls.evil = ThreadingHTTPServer(("127.0.0.1", 0), _EvilHandler)
        cls.threads = [start_http_server(cls.evil, cls.addClassCleanup)]
        _TargetHandler.evil_port = cls.evil.server_port
        cls.target = ThreadingHTTPServer(("127.0.0.1", 0), _TargetHandler)
        cls.threads.append(start_http_server(cls.target, cls.addClassCleanup))
        cls.base = f"http://127.0.0.1:{cls.target.server_port}"

    def test_redirect_hop_cannot_leave_origin(self):
        """continue_() lets Chromium follow redirects internally where
        the gate never sees the hop; the fetch-and-fulfill gate makes
        every hop a fresh gated request."""
        self.evil_handler.hits.clear()
        with BrowserEngine(self.base, allow_unsandboxed_chromium=_INNER_WAIVER) as engine:
            engine.render(f"{self.base}/redirect-out")
            blocked = engine.blocked_requests
            blocked_hosts = engine.blocked_hosts

        self.assertEqual(
            [h for h in self.evil_handler.hits if "redirect-hop" in h], [],
        )
        self.assertGreaterEqual(blocked, 1)
        self.assertIn(f"127.0.0.1:{self.evil.server_port}", blocked_hosts)

    def test_target_header_preserves_session_cookie_across_redirect(self):
        self.target_handler.received.clear()
        self.target_handler.received_fields.clear()
        from packages.web.origin_verify import HEADER_NAME

        with BrowserEngine(
            self.base, cookies={"session": "fixture-session"},
            extra_headers={HEADER_NAME: "a" * 64},
            allow_unsandboxed_chromium=_INNER_WAIVER,
        ) as engine:
            assert engine._context.cookies(self.base)
            engine.render(f"{self.base}/redirect-in")

        hops = [(path, headers) for path, headers in self.target_handler.received
                if path in ("/redirect-in", "/target-final")]
        self.assertEqual(len(hops), 2)
        for path, headers in hops:
            self.assertEqual(headers.get(HEADER_NAME), "a" * 64)
            self.assertIn("session=fixture-session", headers.get("Cookie", ""), path)
        fields = [values for path, values in self.target_handler.received_fields
                  if path in ("/redirect-in", "/target-final")]
        for values in fields:
            self.assertEqual(sum(name.lower() == "x-origin-verify" for name, _ in values), 1)

    def test_binary_post_body_survives_same_origin_redirect(self):
        self.target_handler.posts.clear()
        with BrowserEngine(self.base, allow_unsandboxed_chromium=_INNER_WAIVER) as engine:
            page = engine._context.new_page()
            try:
                page.goto(f"{self.base}/target-final")
                status = page.evaluate("""async () => {
                    const body = new Uint8Array([0, 255, 1, 128, 42]);
                    return (await fetch('/binary-redirect', {
                        method: 'POST', body, headers: {'Content-Type': 'application/octet-stream'}
                    })).status;
                }""")
            finally:
                page.close()
        self.assertEqual(status, 200)
        self.assertEqual(self.target_handler.posts, [
            ("/binary-redirect", b"\x00\xff\x01\x80*"),
            ("/binary-final", b"\x00\xff\x01\x80*"),
        ])

    def test_websocket_cannot_leave_origin(self):
        self.evil_handler.hits.clear()
        with BrowserEngine(self.base, allow_unsandboxed_chromium=_INNER_WAIVER) as engine:
            engine.render(f"{self.base}/ws-page")
            blocked = engine.blocked_requests

        # The evil server must never see the Upgrade request.
        self.assertEqual(self.evil_handler.hits, [])
        self.assertGreaterEqual(blocked, 1)
