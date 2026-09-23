"""Windowed, path-scoped OOB expectations — the bare-host correlation
tier — and its consumers (host-header/reset checks, Phase 6o
corroboration findings, the browser render oracle)."""

from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from packages.web.oob import OobContext, OobListener
from packages.web.tests.test_oob import _fetch


class TestExpectationRegistry(unittest.TestCase):
    def setUp(self):
        self.listener = OobListener(bind_host="127.0.0.1", port=0)
        self.listener.start()
        self.addCleanup(self.listener.stop)

    def test_non_token_hit_matches_marker_within_window(self):
        expectation = self.listener.expect(
            OobContext(url="https://t", param="X-Forwarded-Host",
                       kind="reset_poisoning"),
            path_marker="reset",
        )
        base = self.listener.callback_base
        _fetch(f"{base}/account/reset-password?tok=abc")
        _fetch(f"{base}/unrelated")

        correlated = self.listener.correlated_expectations()
        self.assertEqual(len(correlated), 1)
        self.assertIs(correlated[0], expectation)
        self.assertEqual(len(expectation.hits), 1)
        self.assertIn("reset-password", expectation.hits[0].path)
        # Non-matching request still counted as unknown, not attributed.
        self.assertGreaterEqual(
            self.listener.stats["unknown_token_requests"], 2,
        )

    def test_empty_marker_matches_any_path(self):
        self.listener.expect(
            OobContext(url="https://t", param="Host", kind="host_header"),
        )
        _fetch(f"{self.listener.callback_base}/whatever")
        self.assertEqual(len(self.listener.correlated_expectations()), 1)

    def test_expired_window_records_nothing(self):
        expectation = self.listener.expect(
            OobContext(url="https://t", param="Host", kind="host_header"),
        )
        expectation.expires_at = time.monotonic() - 1
        _fetch(f"{self.listener.callback_base}/late")
        self.assertEqual(self.listener.correlated_expectations(), [])

    def test_hits_per_expectation_bounded(self):
        expectation = self.listener.expect(
            OobContext(url="https://t", param="Host", kind="host_header"),
        )
        with patch("packages.web.oob._MAX_HITS_PER_EXPECTATION", 3):
            for i in range(6):
                _fetch(f"{self.listener.callback_base}/p{i}")
        self.assertEqual(len(expectation.hits), 3)

    def test_window_is_immune_to_wall_clock_steps(self):
        """Expiry rides time.monotonic(): a forward NTP step used to
        expire every open window instantly (and a backward one to
        stretch them)."""
        self.listener.expect(
            OobContext(url="https://t", param="Host", kind="host_header"),
            window_s=300.0,
        )
        real_time = time.time
        with patch("packages.web.oob.time.time",
                   lambda: real_time() + 10_000):
            _fetch(f"{self.listener.callback_base}/inside-window")
        self.assertEqual(len(self.listener.correlated_expectations()), 1)

    def test_expectation_budget_enforced(self):
        with patch("packages.web.oob._MAX_EXPECTATIONS", 1):
            self.listener.expect(
                OobContext(url="https://t", param="a", kind="host_header"),
            )
            with self.assertRaises(RuntimeError):
                self.listener.expect(
                    OobContext(url="https://t", param="b",
                               kind="host_header"),
                )

    def test_token_hits_unaffected_by_open_expectations(self):
        from packages.web.oob import token_of

        self.listener.expect(
            OobContext(url="https://t", param="Host", kind="host_header"),
        )
        canary = self.listener.mint(
            OobContext(url="https://t", param="url"),
        )
        _fetch(canary)
        self.assertEqual(len(self.listener.hits_for(token_of(canary))), 1)
        # The token request must not double-count into the expectation.
        self.assertEqual(self.listener.correlated_expectations(), [])


class TestCheckWiring(unittest.TestCase):
    def _scanner(self, tmpdir: str):
        from packages.web.scanner import WebScanner

        with patch("packages.web.scanner.WebClient"), patch(
            "packages.web.scanner.WebCrawler"
        ):
            scanner = WebScanner(
                "https://t.example", None, Path(tmpdir),
                oob_listen="127.0.0.1:0", oob_grace=0.2,
            )
        return scanner

    def test_host_header_check_opens_expectations_and_probes(self):
        from packages.web.checks.host_header import HostHeaderInjectionCheck

        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = self._scanner(tmpdir)
            self.addCleanup(scanner.oob_listener.stop)
            check = scanner._instantiate_check(HostHeaderInjectionCheck)
            client = MagicMock()
            client.get.return_value = MagicMock(
                status_code=200, text="plain", headers={},
            )

            check.run(client, "https://t.example")

            stats = scanner.oob_listener.stats
            # One expectation covering both probed headers — a hit
            # carries no token, so per-header attribution would claim
            # more than the evidence supports.
            self.assertEqual(stats["expectations"], 1)
            self.assertIn(
                "/", scanner.oob_listener._expectations[0].context.param,
            )
            injected = [
                call.kwargs.get("headers") or call.args[1]
                for call in client.get.call_args_list
                if (call.kwargs.get("headers") or {}).values()
            ]
            listener_host = scanner._resolve_oob_host()
            self.assertTrue(any(
                listener_host in (headers or {}).values()
                for headers in injected
            ))

    def test_reset_check_registers_reset_marker(self):
        from packages.web.checks.host_header import (
            PasswordResetPoisoningCheck,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = self._scanner(tmpdir)
            self.addCleanup(scanner.oob_listener.stop)
            check = scanner._instantiate_check(PasswordResetPoisoningCheck)
            client = MagicMock()
            client.get.return_value = MagicMock(
                status_code=200, text="ok", headers={},
            )

            check.run(client, "https://t.example")

            expectations = scanner.oob_listener._expectations
            self.assertTrue(expectations)
            self.assertEqual(expectations[0].path_marker, "reset")
            self.assertEqual(
                expectations[0].context.kind, "reset_poisoning",
            )

    def test_checks_silent_without_listener(self):
        from packages.web.checks.host_header import HostHeaderInjectionCheck
        from packages.web.scanner import WebScanner

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("packages.web.scanner.WebClient"), patch(
                "packages.web.scanner.WebCrawler"
            ):
                scanner = WebScanner("https://t.example", None, Path(tmpdir))
            check = scanner._instantiate_check(HostHeaderInjectionCheck)
            self.assertIsNone(check.oob_host)
            self.assertIsNone(check.oob_expect)


class TestPhase6oCorroboration(unittest.TestCase):
    def test_expectation_hit_becomes_needs_review_never_confirmed(self):
        from packages.web.scanner import WebScanner

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("packages.web.scanner.WebClient"), patch(
                "packages.web.scanner.WebCrawler"
            ):
                scanner = WebScanner(
                    "https://t.example", None, Path(tmpdir),
                    oob_listen="127.0.0.1:0", oob_grace=0.2,
                )
            scanner.client = MagicMock()
            scanner.client.reveal_secrets = False
            scanner.oob_listener.start()
            scanner.oob_listener.expect(
                OobContext(url="https://t.example/reset",
                           param="X-Forwarded-Host",
                           kind="reset_poisoning",
                           extra={"injected": "cb.example:80"}),
                path_marker="reset",
            )
            _fetch(
                f"{scanner.oob_listener.callback_base}/reset?tok=stolen",
            )

            findings = scanner._phase_oob()

            self.assertEqual(len(findings), 1)
            finding = findings[0]
            self.assertEqual(finding.status, "needs_review")
            self.assertEqual(
                finding.oracle_signal, "oob_callback_correlated",
            )
            self.assertFalse(finding.confirmed)
            self.assertIn("corroboration", finding.evidence)


class TestCachePoisonRenderOracle(unittest.TestCase):
    def test_blocked_listener_host_yields_finding(self):
        from packages.web.scanner import WebScanner

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("packages.web.scanner.WebClient"), patch(
                "packages.web.scanner.WebCrawler"
            ):
                scanner = WebScanner(
                    "https://t.example", None, Path(tmpdir),
                    oob_listen="127.0.0.1:0",
                )
            scanner.client = MagicMock()
            scanner.oob_listener.start()
            self.addCleanup(scanner.oob_listener.stop)
            listener_host = scanner._resolve_oob_host()
            engine = MagicMock()
            state = {"hosts": []}
            type(engine).blocked_hosts = property(
                lambda self_: list(state["hosts"]),
            )
            self.addCleanup(delattr, type(engine), "blocked_hosts")

            def _render(url):
                state["hosts"].append(listener_host)
                return MagicMock()

            engine.render.side_effect = _render
            finding = scanner._browser_cache_poison_probe(engine)

            self.assertIsNotNone(finding)
            self.assertEqual(finding.status, "needs_review")
            self.assertEqual(finding.oracle_signal, "cache_poison_render")
            self.assertIn("no bytes left the target origin",
                          finding.evidence)

            # Only unrelated hosts recorded during the render: no
            # finding.
            state["hosts"] = []
            engine.render.side_effect = lambda url: (
                state["hosts"].append("unrelated.example") or MagicMock()
            )
            self.assertIsNone(scanner._browser_cache_poison_probe(engine))


class TestLazyListenerStart(unittest.TestCase):
    def test_wiring_checks_does_not_bind_the_port(self):
        from packages.web.checks.headers import CspCheck
        from packages.web.scanner import WebScanner

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("packages.web.scanner.WebClient"), patch(
                "packages.web.scanner.WebCrawler"
            ):
                scanner = WebScanner(
                    "https://t.example", None, Path(tmpdir),
                    oob_listen="127.0.0.1:0",
                )
            check = scanner._instantiate_check(CspCheck)
            # Wiring alone must not start the listener — a passive
            # receipt's checks are wired but never probe.
            self.assertIsNone(scanner.oob_listener._server)
            # First USE resolves and starts.
            self.assertIsNotNone(check.oob_host)
            self.assertIsNotNone(scanner.oob_listener._server)
            scanner.oob_listener.stop()


class TestPoisonProbeDiff(unittest.TestCase):
    def test_pre_probe_blocked_host_is_not_evidence(self):
        """Session-accumulated blocked hosts (a page echoing an
        earlier canary) must not satisfy the poisoned-render oracle —
        only attempts recorded DURING the probe render count."""
        from packages.web.scanner import WebScanner

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("packages.web.scanner.WebClient"), patch(
                "packages.web.scanner.WebCrawler"
            ):
                scanner = WebScanner(
                    "https://t.example", None, Path(tmpdir),
                    oob_listen="127.0.0.1:0",
                )
            scanner.client = MagicMock()
            listener_host = scanner._resolve_oob_host()
            self.addCleanup(scanner.oob_listener.stop)

            engine = MagicMock()
            # Host already blocked BEFORE the probe render; the render
            # itself adds nothing new.
            engine.blocked_hosts = [listener_host]
            engine.render.return_value = MagicMock()
            self.assertIsNone(scanner._browser_cache_poison_probe(engine))

            # Recorded during the probe render: evidence.
            state = {"hosts": []}
            type(engine).blocked_hosts = property(
                lambda self_: list(state["hosts"]),
            )
            def _render(url):
                state["hosts"].append(listener_host)
                return MagicMock()
            engine.render.side_effect = _render
            finding = scanner._browser_cache_poison_probe(engine)
            self.assertIsNotNone(finding)
            del type(engine).blocked_hosts


class TestCorroborationTierGetsNoArtifacts(unittest.TestCase):
    def test_no_reproducer_or_template_for_unproven_vectors(self):
        from packages.web.models import WebFinding
        from packages.web.poc import build_nuclei_template, build_reproducer

        for vector in ("oob_expectation", "host_poisoned_markup"):
            finding = WebFinding(
                id="WEB-0031", title="corroboration", severity="high",
                confidence="low", status="needs_review",
                url="https://t.example/", evidence="e", description="d",
                recommendation="r", vuln_type="host_header",
                asvs_category="V13", check_id="V13.1.1",
                cwe_id="CWE-644", confirmed=False,
                target_url="https://t.example/",
                confirmation_payload="cb.example:80",
                response_evidence="in-window callback",
                oracle_signal="oob_callback_correlated",
                attack_vector=vector, method="GET",
                affected_parameters=["X-Forwarded-Host"],
            )
            self.assertIsNone(build_reproducer(finding), vector)
            self.assertIsNone(build_nuclei_template(finding), vector)


if __name__ == "__main__":
    unittest.main()
