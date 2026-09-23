"""Out-of-band callback listener and the blind-SSRF replay funnel."""

from __future__ import annotations

import http.client
import pytest
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, urlparse

from packages.web.oob import OobContext, OobListener, token_of
from packages.web.scanner import WebScanner, _parse_oob_listen


def _fetch(url: str) -> int:
    """Plain loopback GET (no proxy indirection, unlike urllib)."""
    parsed = urlparse(url)
    conn = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=5)
    try:
        conn.request("GET", parsed.path or "/")
        return conn.getresponse().status
    finally:
        conn.close()


class TestParseOobListen(unittest.TestCase):
    def test_forms(self):
        self.assertEqual(_parse_oob_listen("8880"), ("0.0.0.0", 8880))
        self.assertEqual(
            _parse_oob_listen("127.0.0.1:0"), ("127.0.0.1", 0),
        )
        for bad in ("", "notaport", "1.2.3.4:", "1.2.3.4:99999"):
            with self.assertRaises(ValueError):
                _parse_oob_listen(bad)


class TestOobListener(unittest.TestCase):
    def setUp(self):
        self.listener = OobListener(bind_host="127.0.0.1", port=0)
        self.listener.start()
        self.addCleanup(self.listener.stop)

    def test_mint_hit_correlate(self):
        context = OobContext(url="https://t/api", param="target")
        canary = self.listener.mint(context)
        parsed = urlparse(canary)
        self.assertEqual(
            (parsed.scheme, parsed.netloc),
            ("http", f"127.0.0.1:{self.listener.port}"),
        )

        self.assertEqual(_fetch(canary), 200)

        hits = self.listener.hits_for(token_of(canary))
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].source_ip, "127.0.0.1")
        pairs = self.listener.correlated()
        self.assertEqual(len(pairs), 1)
        self.assertIs(pairs[0][0], context)

    def test_unknown_tokens_are_counted_not_recorded(self):
        base = self.listener.callback_base
        self.assertEqual(_fetch(f"{base}/{'0' * 16}"), 200)
        self.assertEqual(_fetch(f"{base}/not-a-token"), 200)

        self.assertEqual(self.listener.correlated(), [])
        self.assertEqual(self.listener.stats["unknown_token_requests"], 2)

    def test_wait_for_times_out(self):
        canary = self.listener.mint(OobContext(url="https://t", param="p"))
        self.assertIsNone(
            self.listener.wait_for(token_of(canary), timeout=0.3),
        )

    def test_callback_host_overrides_url_construction(self):
        listener = OobListener(
            bind_host="127.0.0.1", port=0,
            callback_host="oob.operator.example:8443",
        )
        listener.start()
        self.addCleanup(listener.stop)
        canary = listener.mint(OobContext(url="https://t", param="p"))
        parsed = urlparse(canary)
        self.assertEqual(
            (parsed.scheme, parsed.netloc),
            ("http", "oob.operator.example:8443"),
        )

    def test_token_budget_is_enforced(self):
        with patch("packages.web.oob._MAX_TOKENS", 2):
            self.listener.mint(OobContext(url="https://t", param="a"))
            self.listener.mint(OobContext(url="https://t", param="b"))
            with self.assertRaises(RuntimeError):
                self.listener.mint(OobContext(url="https://t", param="c"))


class _SsrfClient:
    """Scan-client double simulating a server that fetches URL params."""

    def __init__(self, vulnerable: bool):
        self.vulnerable = vulnerable
        self.reveal_secrets = False

    def get(self, url: str, params: dict | None = None, **_kw):
        if self.vulnerable and params:
            for value in params.values():
                if str(value).startswith("http://"):
                    _fetch(str(value))
        return MagicMock(status_code=200, content=b"", text="")


class TestScannerOobFunnel(unittest.TestCase):
    def _scanner(self, tmpdir: str, vulnerable: bool) -> WebScanner:
        with patch("packages.web.scanner.WebClient"), patch(
            "packages.web.scanner.WebCrawler"
        ):
            scanner = WebScanner(
                "https://target.example", None, Path(tmpdir),
                oob_listen="127.0.0.1:0", oob_grace=0.3,
            )
        scanner.client = _SsrfClient(vulnerable)
        return scanner

    def test_vulnerable_target_yields_replay_verified_finding(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = self._scanner(tmpdir, vulnerable=True)
            scanner._oob_inject([("https://target.example/api", "url")])

            findings = scanner._phase_oob()

            self.assertEqual(len(findings), 1)
            finding = findings[0]
            self.assertEqual(finding.vuln_type, "ssrf")
            self.assertEqual(finding.cwe_id, "CWE-918")
            self.assertEqual(finding.status, "confirmed")
            self.assertEqual(finding.oracle_signal, "oob_callback_replayed")
            self.assertTrue(finding.confirmed)
            self.assertIn("oob", scanner._phases_completed)

    def test_single_unreproduced_callback_stays_needs_review(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = self._scanner(tmpdir, vulnerable=True)
            scanner._oob_inject([("https://target.example/api", "url")])
            # The "vulnerability" disappears before the replay leg: the
            # first callback alone must not confirm anything.
            scanner.client.vulnerable = False

            findings = scanner._phase_oob()

            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].status, "needs_review")
            self.assertEqual(findings[0].confidence, "low")
            self.assertEqual(
                findings[0].oracle_signal, "oob_callback_once",
            )

    def test_clean_target_yields_nothing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = self._scanner(tmpdir, vulnerable=False)
            scanner._oob_inject([("https://target.example/api", "url")])
            self.assertEqual(scanner._phase_oob(), [])

    def test_oob_off_by_default(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("packages.web.scanner.WebClient"), patch(
                "packages.web.scanner.WebCrawler"
            ):
                scanner = WebScanner(
                    "https://target.example", None, Path(tmpdir),
                )
            self.assertIsNone(scanner.oob_listener)
            scanner._oob_inject([("https://target.example/api", "url")])
            self.assertEqual(scanner._phase_oob(), [])


class TestCanaryReplacesTheOriginalParameter(unittest.TestCase):
    """Fuzz cells are discovered WITH their parameter in the query
    (`?u=orig`), and requests APPENDS `params=` to an existing query —
    so an append-shaped injection leg sends `?u=orig&u=<canary>` and a
    first-occurrence-wins backend never sees the canary: the OOB
    pipeline is dark while coverage reports the leg ran. Both legs must
    REPLACE the original value; a real loopback first-param-wins server
    is the arbiter."""

    def _serve_first_param_wins(self):
        import http.server
        import threading
        from urllib.parse import parse_qsl

        requests_seen: list[str] = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                requests_seen.append(self.path)
                first_wins: dict[str, str] = {}
                for name, value in parse_qsl(urlparse(self.path).query):
                    first_wins.setdefault(name, value)
                fetch_url = first_wins.get("u", "")
                if fetch_url.startswith("http://"):
                    _fetch(fetch_url)
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server, requests_seen

    def test_first_param_wins_backend_sees_the_canary_on_both_legs(self):
        from packages.web.client import WebClient

        server, requests_seen = self._serve_first_param_wins()
        self.addCleanup(server.shutdown)
        self.addCleanup(server.server_close)
        host, port = server.server_address
        base = f"http://{host}:{port}"

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("packages.web.scanner.WebClient"), patch(
                "packages.web.scanner.WebCrawler"
            ):
                scanner = WebScanner(
                    base, None, Path(tmpdir),
                    oob_listen="127.0.0.1:0", oob_grace=0.3,
                )
            scanner.client = WebClient(
                base, rate_limit=0, block_private_ips=False,
            )
            self.addCleanup(scanner.client.close)

            cell_url = f"{base}/page.php?u=orig&x=1"
            scanner._oob_inject([(cell_url, "u")])
            findings = scanner._phase_oob()

        # The backend fetched the canary on the injection leg AND the
        # fresh-token replay leg — replay-verified, confirmed.
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, "confirmed")
        self.assertEqual(
            findings[0].oracle_signal, "oob_callback_replayed",
        )
        # Wire-shape pin: a cell URL already carrying `?u=orig` yields
        # exactly ONE `u` on the wire (replaced, not duplicated), and
        # the untouched sibling parameter survives.
        self.assertEqual(len(requests_seen), 2)
        for path in requests_seen:
            query = dict()
            pairs = parse_qs(urlparse(path).query)
            query.update(pairs)
            self.assertEqual(len(query.get("u", [])), 1, path)
            self.assertTrue(
                query["u"][0].startswith("http://127.0.0.1"), path,
            )
            self.assertEqual(query.get("x"), ["1"], path)


class TestListenerHardening(unittest.TestCase):
    """The listener faces the hostile network: idle-connection floods
    must not pin unbounded threads, and wire values must not smuggle
    control characters into finding evidence."""

    def setUp(self):
        self.listener = OobListener(bind_host="127.0.0.1", port=0)
        self.listener.start()
        self.addCleanup(self.listener.stop)

    @pytest.mark.slow
    def test_idle_connection_flood_stays_bounded_and_responsive(self):
        import socket
        import threading
        import time

        # Compressed clock: cap and reap semantics are what's under
        # test, not the production constants' literal values.
        with patch("packages.web.oob._MAX_LIVE_CONNECTIONS", 16), \
                patch("packages.web.oob._CONNECTION_TIMEOUT_S", 2):
            listener = OobListener(bind_host="127.0.0.1", port=0)
            listener.start()
            self.addCleanup(listener.stop)
            baseline = threading.active_count()
            idlers = []
            try:
                for _ in range(48):
                    sock = socket.create_connection(
                        ("127.0.0.1", listener.port), timeout=5,
                    )
                    idlers.append(sock)  # held open, never written to
                # Over-cap connections are dropped, in-cap ones pin at
                # most the live-connection cap of handler threads.
                self.assertLessEqual(
                    threading.active_count() - baseline, 16 + 8,
                )
                # And once flood connections drop off, their slots free
                # up and a real callback gets through — the flood
                # degrades service while it holds slots, it must not
                # wedge the listener permanently.
                for sock in idlers[:8]:
                    sock.close()
                canary = listener.mint(
                    OobContext(url="https://t", param="p"),
                )
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    try:
                        if _fetch(canary) == 200:
                            break
                    except OSError:
                        time.sleep(0.1)
                self.assertTrue(listener.hits_for(token_of(canary)))
            finally:
                for sock in idlers:
                    sock.close()

    def test_folded_header_cannot_smuggle_crlf_into_evidence(self):
        """Python's header parser preserves obs-fold continuations —
        the recorded value must still be a single control-free line."""
        import socket

        canary = self.listener.mint(OobContext(url="https://t", param="p"))
        token = token_of(canary)
        request = (
            f"GET /{token} HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{self.listener.port}\r\n"
            "User-Agent: legit\r\n"
            " INJECTED Blind-SSRF CONFIRMED by operator\r\n"
            "Connection: close\r\n"
            "\r\n"
        )
        with socket.create_connection(
            ("127.0.0.1", self.listener.port), timeout=5,
        ) as sock:
            sock.sendall(request.encode())
            sock.recv(1024)

        hits = self.listener.hits_for(token)
        self.assertEqual(len(hits), 1)
        self.assertNotRegex(hits[0].user_agent, r"[\r\n\x00-\x1f]")
        self.assertIn("INJECTED", hits[0].user_agent)  # content kept, flat


class TestListenerLifecycle(unittest.TestCase):
    def test_listener_stops_when_the_scan_segment_dies(self):
        """The listener starts inside Phase 6; a failure before Phase
        6o must not leave the bound socket alive past the scan."""
        import socket
        import tempfile
        from pathlib import Path
        from unittest.mock import patch

        from packages.web.scanner import WebScanner

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("packages.web.scanner.WebClient"), patch(
                "packages.web.scanner.WebCrawler"
            ):
                scanner = WebScanner(
                    "https://t.example", None, Path(tmpdir),
                    oob_listen="127.0.0.1:0",
                )
            scanner.oob_listener.start()
            port = scanner.oob_listener.port
            self.assertEqual(
                socket.socket().connect_ex(("127.0.0.1", port)), 0,
            )

            scanner.close()

            sock = socket.socket()
            try:
                self.assertNotEqual(
                    sock.connect_ex(("127.0.0.1", port)), 0,
                )
            finally:
                sock.close()

class _HeaderSsrfClient:
    """Client double: the 'server' dereferences URL-bearing headers."""

    def __init__(self, vulnerable: bool = True):
        self.vulnerable = vulnerable
        self.reveal_secrets = False
        self.header_fetches: list[tuple[str, str]] = []

    def get(self, url: str, params: dict | None = None,
            headers: dict | None = None, **_kw):
        if self.vulnerable:
            for name, value in (headers or {}).items():
                if str(value).startswith("http://"):
                    self.header_fetches.append((name, str(value)))
                    _fetch(str(value))
        return MagicMock(status_code=200, content=b"", text="")


class TestCallbackVerifiedHeaderSsrf(unittest.TestCase):
    def _scanner(self, tmpdir: str) -> WebScanner:
        with patch("packages.web.scanner.WebClient"), patch(
            "packages.web.scanner.WebCrawler"
        ):
            scanner = WebScanner(
                "https://target.example", None, Path(tmpdir),
                oob_listen="127.0.0.1:0", oob_grace=0.3,
            )
        scanner.client = _HeaderSsrfClient()
        return scanner

    def test_check_plants_canaries_in_url_bearing_headers(self):
        from packages.web.checks.ssrf import BlindSsrfHeaderCheck

        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = self._scanner(tmpdir)
            check = scanner._instantiate_check(BlindSsrfHeaderCheck)
            self.assertIsNotNone(check.oob_mint)

            check.run(scanner.client, "https://target.example")

            planted = {name for name, _ in scanner.client.header_fetches}
            self.assertEqual(
                planted, {"Referer", "X-Wap-Profile", "X-Callback-Url"},
            )
            self.assertGreaterEqual(
                scanner.oob_listener.stats["tokens_minted"], 3,
            )
            scanner.oob_listener.stop()

    def test_header_callback_replays_through_the_header_and_confirms(self):
        from packages.web.checks.ssrf import BlindSsrfHeaderCheck

        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = self._scanner(tmpdir)
            check = scanner._instantiate_check(BlindSsrfHeaderCheck)
            check.run(scanner.client, "https://target.example")

            findings = scanner._phase_oob()

            self.assertEqual(len(findings), 3)
            finding = findings[0]
            self.assertEqual(finding.status, "confirmed")
            self.assertEqual(finding.oracle_signal, "oob_callback_replayed")
            self.assertIn("header", finding.description)
            # The replay leg used header injection, not query params.
            replayed = [
                name for name, _ in scanner.client.header_fetches
            ]
            self.assertGreaterEqual(len(replayed), 6)  # plant + replay

    def test_no_listener_means_no_mint_and_no_extra_requests(self):
        from packages.web.checks.ssrf import BlindSsrfHeaderCheck

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("packages.web.scanner.WebClient"), patch(
                "packages.web.scanner.WebCrawler"
            ):
                scanner = WebScanner(
                    "https://target.example", None, Path(tmpdir),
                )
            scanner.client = _HeaderSsrfClient()
            check = scanner._instantiate_check(BlindSsrfHeaderCheck)
            self.assertIsNone(check.oob_mint)

            check.run(scanner.client, "https://target.example")

            self.assertEqual(scanner.client.header_fetches, [])


if __name__ == "__main__":
    unittest.main()


class TestCanaryWireShapeWithDuplicatedParams(unittest.TestCase):
    """Adversarial cell shape: the crawler can record a URL that
    already carries the parameter TWICE (`?u=1&u=2`). Both original
    occurrences must be stripped — first-wins AND last-wins (PHP-style)
    backends must each see only the canary."""

    def test_all_original_occurrences_are_replaced(self):
        import requests
        from urllib.parse import parse_qsl

        from packages.web.oracle import _strip_query_params

        cell = "http://t.example/p?u=1&x=1&u=2"
        canary = "http://cb.example/tok"
        stripped = _strip_query_params(cell, {"u": canary})
        prepared = requests.Request(
            "GET", stripped, params={"u": canary},
        ).prepare()
        pairs = parse_qsl(urlparse(prepared.url).query)
        u_values = [v for k, v in pairs if k == "u"]
        self.assertEqual(u_values, [canary])   # first-wins == last-wins
        self.assertIn(("x", "1"), pairs)
