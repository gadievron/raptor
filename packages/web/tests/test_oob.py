"""Out-of-band callback listener and the blind-SSRF replay funnel."""

from __future__ import annotations

import http.client
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch
from urllib.parse import urlparse

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
        self.assertTrue(
            canary.startswith(f"http://127.0.0.1:{self.listener.port}/"),
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
        self.assertTrue(
            canary.startswith("http://oob.operator.example:8443/"),
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


if __name__ == "__main__":
    unittest.main()


class TestListenerHardening(unittest.TestCase):
    """The listener faces the hostile network: idle-connection floods
    must not pin unbounded threads, and wire values must not smuggle
    control characters into finding evidence."""

    def setUp(self):
        self.listener = OobListener(bind_host="127.0.0.1", port=0)
        self.listener.start()
        self.addCleanup(self.listener.stop)

    def test_idle_connection_flood_stays_bounded_and_responsive(self):
        import socket
        import threading

        baseline = threading.active_count()
        idlers = []
        try:
            for _ in range(120):
                sock = socket.create_connection(
                    ("127.0.0.1", self.listener.port), timeout=5,
                )
                idlers.append(sock)  # held open, never written to
            # Over-cap connections are dropped, in-cap ones pin at most
            # _MAX_LIVE_CONNECTIONS handler threads.
            from packages.web.oob import _MAX_LIVE_CONNECTIONS
            self.assertLessEqual(
                threading.active_count() - baseline,
                _MAX_LIVE_CONNECTIONS + 8,
            )
            # And once flood connections drop off, their slots free up
            # and a real callback gets through — the flood degrades
            # service while it holds slots, it must not wedge the
            # listener permanently.
            import time
            for sock in idlers[:16]:
                sock.close()
            canary = self.listener.mint(
                OobContext(url="https://t", param="p"),
            )
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                try:
                    if _fetch(canary) == 200:
                        break
                except OSError:
                    time.sleep(0.2)
            self.assertTrue(self.listener.hits_for(token_of(canary)))
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
