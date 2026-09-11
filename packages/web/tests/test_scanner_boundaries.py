"""Scanner-level contracts: check-failure surfacing, degraded-coverage
accounting, principal-client lifecycle, verified-outcome sidecar format,
crawl seeding/fragments, and the raw data plane feeding live probes."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from core.json import load_jsonl
from packages.web.models import WebFinding


def _make_scanner(tmpdir: str, **kwargs):
    from packages.web.scanner import WebScanner

    with patch("packages.web.scanner.WebClient"), patch(
        "packages.web.scanner.WebCrawler",
    ):
        return WebScanner("http://example.com", None, Path(tmpdir), **kwargs)


def _oracle_finding(**overrides) -> WebFinding:
    kwargs = dict(
        id="WEB-0001",
        title="SQL Injection",
        severity="high",
        confidence="medium",
        status="needs_review",
        url="http://example.com/search",
        evidence="payload confirmed",
        description="SQLi",
        recommendation="Use parameterised queries",
        vuln_type="sqli",
        asvs_category="V5",
        check_id="V5.2.1",
        cwe_id="CWE-89",
        confirmed=True,
        target_url="http://example.com/search",
        confirmation_payload="' OR 1=1--",
        response_evidence="SQL syntax",
        baseline_evidence="HTTP 200, 20 bytes",
        attack_evidence="SQL syntax",
        diff_summary="baseline HTTP 200/20; attack HTTP 500/128",
        attack_vector="query_param",
        oracle_signal="sqli_error:sql syntax",
        method="GET",
        affected_parameters=["q"],
    )
    kwargs.update(overrides)
    return WebFinding(**kwargs)


def _discovery_mock():
    discovery = MagicMock()
    discovery.urls = ["http://example.com/search"]
    discovery.forms = []
    discovery.apis = []
    discovery.parameters = ["q"]
    discovery.fingerprint = {"server": "test"}
    discovery.stats.return_value = {"total_urls": 1}
    return discovery


class TestCheckFailureSurfacing(unittest.TestCase):
    """A crashed or transport-degraded check must never read as clean."""

    def _run_passive(self, scanner, check_cls):
        discovery = _discovery_mock()
        with patch(
            "packages.web.checks.registry.unauthenticated",
            return_value=[check_cls],
        ):
            scanner.execution_policy = MagicMock()
            return scanner._phase_passive_checks(discovery, {})

    def test_crashing_check_is_counted_and_reported(self):
        class ExplodingCheck:
            check_id = "V0.0.1"
            risk = "passive"
            __name__ = "ExplodingCheck"

            def __init__(self, llm=None):
                pass

            def run(self, *args, **kwargs):
                raise RuntimeError("signature drift")

        ExplodingCheck.__name__ = "ExplodingCheck"
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = _make_scanner(tmpdir)
            scanner.client.transport_errors = 0
            with self.assertLogs("raptor", level="WARNING") as captured:
                findings = self._run_passive(scanner, ExplodingCheck)
            self.assertEqual(findings, [])
            self.assertEqual(
                scanner._check_failures.get("passive_checks"),
                ["ExplodingCheck"],
            )
            joined = "\n".join(captured.output)
            self.assertIn("ExplodingCheck", joined)
            self.assertIn("crashed", joined)

    def test_transport_degraded_check_is_distinguished_from_clean(self):
        class SwallowingCheck:
            check_id = "V0.0.2"
            risk = "passive"

            def __init__(self, llm=None):
                pass

            def run(self, client, *args, **kwargs):
                # The common check shape: every probe error swallowed.
                client.transport_errors += 3
                return []

        SwallowingCheck.__name__ = "SwallowingCheck"
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = _make_scanner(tmpdir)
            scanner.client.transport_errors = 0
            with self.assertLogs("raptor", level="WARNING") as captured:
                self._run_passive(scanner, SwallowingCheck)
            self.assertEqual(
                scanner._check_degraded.get("passive_checks"),
                {"SwallowingCheck": 3},
            )
            self.assertIn("degraded", "\n".join(captured.output))

    def test_clean_check_is_not_marked_degraded(self):
        class CleanCheck:
            check_id = "V0.0.3"
            risk = "passive"

            def __init__(self, llm=None):
                pass

            def run(self, *args, **kwargs):
                return []

        CleanCheck.__name__ = "CleanCheck"
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = _make_scanner(tmpdir)
            scanner.client.transport_errors = 0
            self._run_passive(scanner, CleanCheck)
            self.assertEqual(scanner._check_failures, {})
            self.assertEqual(scanner._check_degraded, {})

    def test_checks_execute_serially_and_attribution_stays_exact(self):
        """Per-check transport-error attribution diffs a shared counter,
        which is only sound while the phase runs checks one at a time.
        This pins that assumption mechanically: if a thread pool ever
        creeps into a check window, the overlap detector fails loudly
        here instead of the attribution silently misassigning errors."""
        import time as _time

        overlap = {"active": False, "violations": 0}

        def make_check(name: str, errors: int):
            class _Check:
                check_id = f"V0.9.{errors}"
                risk = "passive"

                def __init__(self, llm=None):
                    pass

                def run(self, client, *args, **kwargs):
                    if overlap["active"]:
                        overlap["violations"] += 1
                    overlap["active"] = True
                    _time.sleep(0.01)
                    client.transport_errors += errors
                    overlap["active"] = False
                    return []

            _Check.__name__ = name
            return _Check

        checks = [make_check("AlphaCheck", 2), make_check("BetaCheck", 3)]
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = _make_scanner(tmpdir)
            scanner.client.transport_errors = 0
            discovery = _discovery_mock()
            with patch(
                "packages.web.checks.registry.unauthenticated",
                return_value=checks,
            ):
                scanner.execution_policy = MagicMock()
                scanner._phase_passive_checks(discovery, {})
        self.assertEqual(overlap["violations"], 0,
                         "check phases must run checks serially over the "
                         "shared client — delta attribution depends on it")
        self.assertEqual(
            scanner._check_degraded.get("passive_checks"),
            {"AlphaCheck": 2, "BetaCheck": 3},
        )

    def test_report_carries_failure_and_degradation_counters(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = _make_scanner(tmpdir)
            scanner.client.request_history = []
            scanner.client.reveal_secrets = False
            scanner._check_failures = {"passive_checks": ["ExplodingCheck"]}
            scanner._check_degraded = {"auth_checks": {"SlowCheck": 2}}
            result = scanner._phase_report(
                [], _discovery_mock(),
                {"stats": {}, "discovered_urls": [],
                 "discovered_parameters": [], "discovered_forms": []},
            )
            self.assertEqual(
                result["check_failures"], {"passive_checks": ["ExplodingCheck"]},
            )
            self.assertEqual(
                result["checks_degraded"], {"auth_checks": {"SlowCheck": 2}},
            )


class TestPrincipalClientLifecycle(unittest.TestCase):
    def test_access_control_phase_closes_its_extra_clients(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = _make_scanner(tmpdir)
            scanner.session = SimpleNamespace(authenticated=True)
            anonymous = MagicMock()
            scanner._make_principal_client = MagicMock(return_value=anonymous)
            with patch(
                "packages.web.access_control.run_access_differential",
            ) as run_diff:
                run_diff.return_value = SimpleNamespace(
                    targets_tested=0, requests_used=0, findings=[],
                )
                scanner._phase_access_control(_discovery_mock(), {})
            anonymous.close.assert_called_once()

    def test_access_control_phase_closes_clients_even_on_failure(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = _make_scanner(tmpdir)
            scanner.session = SimpleNamespace(authenticated=True)
            anonymous = MagicMock()
            scanner._make_principal_client = MagicMock(return_value=anonymous)
            with patch(
                "packages.web.access_control.run_access_differential",
                side_effect=RuntimeError("boom"),
            ):
                with self.assertRaises(RuntimeError):
                    scanner._phase_access_control(_discovery_mock(), {})
            anonymous.close.assert_called_once()


class TestVerifiedOutcomeSidecar(unittest.TestCase):
    def test_report_writes_reader_format_jsonl(self):
        from core.labeled_attempts import VerifiedOutcome
        from core.labeled_attempts.view import VERIFIED_OUTCOMES_FILENAME

        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = _make_scanner(tmpdir)
            scanner.client.request_history = []
            scanner.client.reveal_secrets = False
            scanner._phase_report(
                [_oracle_finding()], _discovery_mock(),
                {"stats": {}, "discovered_urls": [],
                 "discovered_parameters": [], "discovered_forms": []},
            )
            sidecar = Path(tmpdir) / VERIFIED_OUTCOMES_FILENAME
            self.assertTrue(sidecar.exists(), "reader-format sidecar missing")
            records = load_jsonl(sidecar)
            self.assertEqual(len(records), 1)
            # The shared reader must be able to project every line.
            outcome = VerifiedOutcome.from_dict(records[0])
            self.assertEqual(outcome.finding_id, "WEB-0001")
            self.assertEqual(outcome.status.value, "verified")

    def test_refuted_finding_never_lands_as_verified_in_the_sidecar(self):
        from core.labeled_attempts import VerifiedOutcome
        from core.labeled_attempts.view import VERIFIED_OUTCOMES_FILENAME

        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = _make_scanner(tmpdir)
            scanner.client.request_history = []
            scanner.client.reveal_secrets = False
            scanner._phase_report(
                [_oracle_finding(verification_status="refuted")],
                _discovery_mock(),
                {"stats": {}, "discovered_urls": [],
                 "discovered_parameters": [], "discovered_forms": []},
            )
            records = load_jsonl(Path(tmpdir) / VERIFIED_OUTCOMES_FILENAME)
            self.assertEqual(len(records), 1)
            outcome = VerifiedOutcome.from_dict(records[0])
            self.assertEqual(outcome.status.value, "refuted")


class TestVerificationFoldsOntoFindings(unittest.TestCase):
    def _annotate(self, statuses):
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = _make_scanner(tmpdir)
            scanner._raw_injection_hits = [
                {
                    "endpoint": "http://example.com/search",
                    "vulnerability_type": "sqli",
                    "verification": {"status": status},
                }
                for status in statuses
            ]
            finding = _oracle_finding()
            scanner._annotate_findings_with_verification([finding])
            return finding

    def test_all_refuted_hits_mark_the_finding_refuted(self):
        finding = self._annotate(["refuted"])
        self.assertEqual(finding.verification_status, "refuted")
        self.assertEqual(finding.confidence, "low")

    def test_verified_hit_marks_the_finding_verified(self):
        finding = self._annotate(["verified", "refuted"])
        self.assertEqual(finding.verification_status, "verified")
        self.assertEqual(finding.confidence, "high")

    def test_shape_skipped_only_leaves_detection_verdict_in_place(self):
        finding = self._annotate(["skipped"])
        self.assertIsNone(finding.verification_status)


class TestRawDataPlaneFeedsProbes(unittest.TestCase):
    def test_injection_targets_are_the_raw_crawled_urls(self):
        """Fuzz targets must carry the secrets the crawler actually saw:
        a display-redacted target list would probe URLs that never
        existed and make secret-parameter endpoints unfuzzable."""
        raw_url = "http://example.com/reset?token=abc123secret&user=bob"
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = _make_scanner(tmpdir)
            scanner.fuzzer = MagicMock()
            scanner.fuzzer.fuzz_parameter.return_value = []
            scanner.fuzzer.payload_cache_stats = (0, 0)
            scanner._phase_injection({
                "discovered_urls": [raw_url],
                "discovered_parameters": ["token"],
                "parameter_urls": {"token": [raw_url]},
                "discovered_forms": [],
            })
            fuzzed_urls = {
                call.args[0]
                for call in scanner.fuzzer.fuzz_parameter.call_args_list
            }
            self.assertIn(raw_url, fuzzed_urls)
            self.assertFalse(
                any("[REDACTED]" in url for url in fuzzed_urls),
                "a redacted display value leaked into the live target list",
            )


class TestCrawlerWorkQueue(unittest.TestCase):
    def _crawler(self):
        from packages.web.crawler import WebCrawler

        client = MagicMock()
        client.reveal_secrets = False
        client.base_url = "http://t.example"
        client._is_in_scope.return_value = True
        return WebCrawler(client, max_depth=2, max_pages=10), client

    def test_seed_urls_are_fetched_not_just_recorded(self):
        crawler, client = self._crawler()
        client.get.return_value = SimpleNamespace(
            status_code=200, headers={"Content-Type": "text/html"},
            content=b"<html></html>", text="<html></html>",
        )
        crawler.crawl(
            "http://t.example/",
            seeds=["http://t.example/hidden-admin"],
        )
        fetched = {call.args[0] for call in client.get.call_args_list}
        self.assertIn("http://t.example/hidden-admin", fetched)

    def test_fragments_are_stripped_from_discovered_links(self):
        crawler, client = self._crawler()
        page = (
            '<html><a href="#s1">a</a><a href="#s2">b</a>'
            '<a href="/docs#intro">c</a></html>'
        )
        client.get.return_value = SimpleNamespace(
            status_code=200, headers={"Content-Type": "text/html"},
            content=page.encode(), text=page,
        )
        crawler.crawl("http://t.example/page")
        self.assertNotIn(
            True,
            ["#" in url for url in crawler.discovered_urls],
            "fragment variants must collapse onto one resource",
        )
        # The three anchors collapse to two distinct resources.
        self.assertIn("http://t.example/docs", crawler.discovered_urls)
        # The page is never re-fetched once per anchor.
        fetches = [call.args[0] for call in client.get.call_args_list]
        self.assertEqual(fetches.count("http://t.example/page"), 1)


class TestFuzzerRequestShapes(unittest.TestCase):
    def test_post_fuzz_carries_sibling_form_fields(self):
        from packages.web.client import WebClient
        from packages.web.fuzzer import WebFuzzer

        client = WebClient("https://t.example")
        fuzzer = WebFuzzer(client)
        bodies = []

        def fake_post(url, data=None, json_data=None, headers=None,
                      allow_redirects=True):
            bodies.append(dict(data or {}))
            return SimpleNamespace(status_code=200, text="ok", content=b"ok")

        client.post = fake_post
        fuzzer._test_payload(
            "https://t.example/comment", "body", "' OR 1=1--", "sqli",
            method="POST",
            base_data={"csrf_token": "tok123", "title": "hello", "body": ""},
        )
        self.assertEqual(len(bodies), 2)  # baseline + attack
        for body in bodies:
            self.assertEqual(body["csrf_token"], "tok123")
            self.assertEqual(body["title"], "hello")
        self.assertEqual(bodies[1]["body"], "' OR 1=1--")

    def test_llm_payload_shapes_are_validated_before_use(self):
        from packages.web.client import WebClient
        from packages.web.fuzzer import WebFuzzer

        client = WebClient("https://t.example")
        llm = MagicMock()
        # A JSON string instead of an array: iterating it would send
        # one live request per character.
        llm.generate_structured.return_value = ({"payloads": "'--"}, None)
        fuzzer = WebFuzzer(client, llm)
        payloads = fuzzer._generate_payloads("q", "text", "sqli")
        self.assertEqual(
            payloads, fuzzer._get_basic_payloads("sqli", param_name="q"),
        )
        # Nothing memoised: a later healthy generation is not pinned out.
        self.assertEqual(fuzzer._payload_cache, {})

        llm.generate_structured.return_value = ({"payloads": []}, None)
        payloads = fuzzer._generate_payloads("q", "text", "sqli")
        self.assertEqual(
            payloads, fuzzer._get_basic_payloads("sqli", param_name="q"),
        )
        self.assertEqual(fuzzer._payload_cache, {})


class TestThreeGateVetoes(unittest.TestCase):
    def _fuzzer(self):
        from packages.web.client import WebClient
        from packages.web.fuzzer import WebFuzzer

        return WebFuzzer(WebClient("https://t.example"))

    def test_baseline_echo_across_newlines_is_vetoed(self):
        """A page that persistently echoes prior probes (guestbook /
        log viewer) must veto even when the evidence window spans a
        newline — the display-escaped snippet never matched there."""
        fuzzer = self._fuzzer()
        payload = "<script>alert(1)</script>"
        page = f"<ul>\n<li>guest wrote:\n{payload}\n</li>\n</ul>"
        responses = iter([
            SimpleNamespace(status_code=200, text=page, content=page.encode()),
            SimpleNamespace(
                status_code=200, text=page + "<!-- ts -->",
                content=(page + "<!-- ts -->").encode(),
            ),
        ])
        fuzzer.client.get = lambda url, params=None: next(responses)
        finding = fuzzer._test_payload(
            "https://t.example/guestbook", "q", payload, "xss",
        )
        self.assertIsNone(finding)

    def test_fresh_reflection_still_confirms(self):
        fuzzer = self._fuzzer()
        payload = "<script>alert(1)</script>"
        responses = iter([
            SimpleNamespace(status_code=200, text="clean page", content=b"clean page"),
            SimpleNamespace(
                status_code=200, text=f"result:\n{payload}\n",
                content=f"result:\n{payload}\n".encode(),
            ),
        ])
        fuzzer.client.get = lambda url, params=None: next(responses)
        finding = fuzzer._test_payload(
            "https://t.example/search", "q", payload, "xss",
        )
        self.assertIsNotNone(finding)
        self.assertEqual(finding["oracle_signal"], "xss_reflected_unescaped")


if __name__ == "__main__":
    unittest.main()
