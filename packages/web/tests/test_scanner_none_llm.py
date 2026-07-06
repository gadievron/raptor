#!/usr/bin/env python3
"""Tests for WebScanner handling of None LLM.

Requires bs4 and requests — skipped if missing.
"""

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

try:
    from packages.web.scanner import WebScanner
    from packages.web.models import WebFinding
    from packages.web.discovery import DiscoveryResult
    HAS_WEB_DEPS = True
except ImportError:
    HAS_WEB_DEPS = False


@unittest.skipUnless(HAS_WEB_DEPS, "bs4/requests not installed")
class TestWebScannerNoneLlm(unittest.TestCase):
    """Test that WebScanner works when LLM is None."""

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_init_with_none_llm(self, mock_client_cls, mock_crawler_cls):
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner("http://example.com", None, Path(tmpdir))
            self.assertIsNotNone(scanner.fuzzer)
            self.assertIsNone(scanner.llm)
            mock_client_cls.assert_called_once_with(
                "http://example.com",
                verify_ssl=True,
                reveal_secrets=False,
            )

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_init_threads_reveal_secrets_to_client(self, mock_client_cls, mock_crawler_cls):
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner(
                "http://example.com",
                None,
                Path(tmpdir),
                verify_ssl=False,
                reveal_secrets=True,
            )
            self.assertIsNotNone(scanner.fuzzer)
            mock_client_cls.assert_called_once_with(
                "http://example.com",
                verify_ssl=False,
                reveal_secrets=True,
            )

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_init_with_llm_creates_fuzzer(self, mock_client_cls, mock_crawler_cls):
        mock_llm = MagicMock()
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner("http://example.com", mock_llm, Path(tmpdir))
            self.assertIsNotNone(scanner.fuzzer)

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_scan_without_llm_skips_fuzzing(self, mock_client_cls, mock_crawler_cls):
        """With no LLM, scan completes using static fallback payloads."""
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner("http://example.com", None, Path(tmpdir))

            scanner.fuzzer = MagicMock()
            scanner.fuzzer.fuzz_parameter.return_value = []

            scanner.crawler.crawl.return_value = {
                "stats": {"total_pages": 1, "total_parameters": 3},
                "discovered_parameters": ["q", "id", "page"],
                "pages": []
            }

            result = scanner.scan()
            self.assertIn("injection", result["phases_completed"])
            self.assertGreaterEqual(scanner.fuzzer.fuzz_parameter.call_count, 3)

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_scan_with_llm_calls_fuzzer(self, mock_client_cls, mock_crawler_cls):
        """With LLM present, fuzzer is invoked for each parameter."""
        mock_llm = MagicMock()
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner("http://example.com", mock_llm, Path(tmpdir))
            scanner.fuzzer = MagicMock()
            scanner.fuzzer.fuzz_parameter.return_value = []

            scanner.crawler.crawl.return_value = {
                "stats": {"total_pages": 1, "total_parameters": 2},
                "discovered_parameters": ["q", "id"],
                "pages": []
            }

            scanner.scan()
            # self.fuzzer (the mock) should have been called for each URL parameter
            self.assertGreaterEqual(
                scanner.fuzzer.fuzz_parameter.call_count, 2,
                "Fuzzer should have been called for each discovered parameter",
            )

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_injection_honours_fuzz_budget(self, mock_client_cls, mock_crawler_cls):
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner(
                "http://example.com",
                None,
                Path(tmpdir),
                max_fuzz_urls=2,
                max_fuzz_params=3,
                max_fuzz_forms=1,
            )
            scanner.fuzzer = MagicMock()
            scanner.fuzzer.fuzz_parameter.return_value = []

            scanner._phase_injection({
                "discovered_urls": [
                    "http://example.com/a",
                    "http://example.com/b",
                    "http://example.com/c",
                ],
                "discovered_parameters": ["a", "b", "c", "d"],
                "discovered_forms": [
                    {
                        "action": "http://example.com/form",
                        "method": "POST",
                        "inputs": {"field": {"type": "text"}},
                    },
                    {
                        "action": "http://example.com/other",
                        "method": "POST",
                        "inputs": {"other": {"type": "text"}},
                    },
                ],
            })

            self.assertEqual(scanner.fuzzer.fuzz_parameter.call_count, 7)

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_passive_approval_level_skips_injection(
        self,
        mock_client_cls,
        mock_crawler_cls,
    ):
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner(
                "http://example.com",
                None,
                Path(tmpdir),
                approval_level="passive",
            )
            scanner.fuzzer = MagicMock()

            findings = scanner._phase_injection({
                "discovered_urls": ["http://example.com/search?q=1"],
                "discovered_parameters": ["q"],
                "discovered_forms": [],
            })

            self.assertEqual(findings, [])
            self.assertIn("injection_skipped", scanner._phases_completed)
            scanner.fuzzer.fuzz_parameter.assert_not_called()

    @patch("packages.web.ffuf.FfufRunner.run")
    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_external_ffuf_discovery_seeds_discovery_urls(
        self,
        mock_client_cls,
        mock_crawler_cls,
        mock_ffuf_run,
    ):
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner(
                "http://example.com",
                None,
                Path(tmpdir),
                ffuf_config=SimpleNamespace(),
            )
            mock_ffuf_run.return_value = {
                "tool": "ffuf",
                "results": [{"url": "http://example.com/admin"}],
            }
            discovery = DiscoveryResult(urls=["http://example.com/"])

            scanner._phase_external_discovery(discovery)

            self.assertIn("http://example.com/admin", discovery.urls)
            self.assertIn("external_discovery", scanner._phases_completed)

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_injection_finding_carries_verified_outcome_fields(
        self,
        mock_client_cls,
        mock_crawler_cls,
    ):
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner(
                "http://example.com",
                None,
                Path(tmpdir),
                max_fuzz_urls=1,
                max_fuzz_params=1,
                max_fuzz_forms=0,
            )
            scanner.fuzzer = MagicMock()
            scanner.fuzzer.fuzz_parameter.return_value = [
                {
                    "url": "http://example.com/search",
                    "parameter": "q",
                    "payload": "' OR 1=1--",
                    "vulnerability_type": "sqli",
                    "status_code": 500,
                    "response_length": 128,
                    "method": "GET",
                    "baseline_evidence": "HTTP 200, 20 bytes: normal search page",
                    "attack_evidence": "You have an error in your SQL syntax",
                    "diff_summary": "baseline HTTP 200/20 bytes; attack HTTP 500/128 bytes; oracle=sqli_error",
                    "confirmed": True,
                    "response_evidence": "You have an error in your SQL syntax",
                    "oracle_signal": "sqli_error:you have an error in your sql syntax",
                }
            ]

            findings = scanner._phase_injection({
                "discovered_urls": ["http://example.com/search"],
                "discovered_parameters": ["q"],
                "discovered_forms": [],
            })

            self.assertEqual(len(findings), 1)
            finding = findings[0].to_dict()
            self.assertEqual(finding["target_url"], "http://example.com/search")
            self.assertEqual(finding["confirmation_payload"], "' OR 1=1--")
            self.assertEqual(
                finding["response_evidence"],
                "You have an error in your SQL syntax",
            )
            self.assertEqual(finding["cwe_id"], "CWE-89")
            self.assertEqual(finding["oracle"], "web")
            self.assertEqual(finding["baseline_evidence"], "HTTP 200, 20 bytes: normal search page")
            self.assertEqual(finding["attack_evidence"], "You have an error in your SQL syntax")
            self.assertIn("baseline HTTP", finding["diff_summary"])
            self.assertEqual(finding["attack_vector"], "query_param")
            self.assertEqual(finding["method"], "GET")
            self.assertTrue(finding["confirmed"])
            self.assertFalse(finding["reproducible"])

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_report_writes_session_context_guard_and_verified_outcomes(
        self,
        mock_client_cls,
        mock_crawler_cls,
    ):
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner("http://example.com", None, Path(tmpdir))
            scanner.client.request_history = [{
                "method": "GET",
                "url": "http://example.com/search?q=test",
                "status_code": 200,
                "duration": 0.01,
                "content_length": 20,
                "timestamp": 1.0,
            }]
            scanner.client.reveal_secrets = False
            discovery = MagicMock()
            discovery.urls = ["http://example.com/search"]
            discovery.forms = []
            discovery.apis = []
            discovery.parameters = ["q"]
            discovery.fingerprint = {"server": "test"}
            discovery.stats.return_value = {"total_urls": 1}

            finding = WebFinding(
                id="WEB-0001",
                title="SQL Injection",
                severity="high",
                confidence="medium",
                status="needs_review",
                url="http://example.com/search",
                evidence="payload confirmed",
                description="SQLi",
                recommendation="Use parameterised queries",
                vuln_type="injection",
                asvs_category="V5",
                check_id="V5.2.1",
                cwe_id="CWE-89",
                confirmed=True,
                target_url="http://example.com/search",
                confirmation_payload="' OR 1=1--",
                response_evidence="SQL syntax",
                baseline_evidence="HTTP 200, 20 bytes",
                attack_evidence="SQL syntax",
                diff_summary="baseline HTTP 200/20 bytes; attack HTTP 500/128 bytes",
                attack_vector="query_param",
                method="GET",
            )

            result = scanner._phase_report(
                [finding],
                discovery,
                {
                    "stats": {"total_pages": 1},
                    "discovered_urls": ["http://example.com/search"],
                    "discovered_parameters": ["q"],
                    "discovered_forms": [],
                },
            )

            out = Path(tmpdir)
            self.assertTrue((out / "web-session-context.json").exists())
            self.assertTrue((out / "verified-outcomes.json").exists())
            self.assertTrue((out / "context-guard-report.json").exists())
            self.assertTrue((out / "scope-receipt.json").exists())
            self.assertTrue((out / "web-execution-policy.json").exists())
            self.assertTrue((out / "web-tool-adapters.json").exists())
            self.assertTrue((out / "web-evidence-ledger.json").exists())
            self.assertEqual(result["verified_outcomes"]["count"], 1)
            self.assertEqual(result["execution_policy"]["approval_level"], "active")
            self.assertEqual(result["evidence_ledger"]["confirmed_web_oracle_findings"], 1)
            self.assertEqual(result["context_guard"]["target_content_is_untrusted"], True)

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_understand_writes_url_native_context_map(self, mock_client_cls, mock_crawler_cls):
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner("http://example.com", None, Path(tmpdir))
            discovery = MagicMock()
            discovery.urls = ["http://example.com/search"]
            discovery.fingerprint = {"server": "test"}
            discovery.stats.return_value = {"total_urls": 1}

            context_map = scanner._phase_understand(
                {
                    "discovered_urls": ["http://example.com/search"],
                    "discovered_parameters": ["q", "redirect"],
                    "discovered_forms": [],
                },
                discovery,
            )

            self.assertEqual(context_map["kind"], "web_application")
            self.assertIn("research_landscape", context_map)
            self.assertIn(2025, context_map["research_landscape"]["archive_years_reviewed"])
            self.assertTrue((Path(tmpdir) / "context-map.json").exists())
            self.assertTrue((Path(tmpdir) / "web-context-map.json").exists())
            self.assertIn("understand", scanner._phases_completed)

    def test_research_landscape_prioritises_matching_archive_themes(self):
        from packages.web.research_landscape import assess_research_landscape

        discovery = MagicMock()
        discovery.urls = ["http://example.com/oauth/callback?redirect_uri=/cb"]
        discovery.forms = []
        discovery.apis = []
        discovery.parameters = ["redirect_uri", "filter", "url"]
        discovery.fingerprint = {"framework": "Next.js", "cache": "x-cache"}
        discovery.common_paths_found = []
        discovery.robots_disallow = []

        landscape = assess_research_landscape(
            discovery=discovery,
            crawl_data={"discovered_parameters": ["redirect_uri", "filter", "url"]},
            registered_check_ids=["V5.1.12", "V5.1.13", "V10.3.1", "V10.3.2"],
        )

        self.assertEqual(landscape["archive_years_reviewed"][0], 2006)
        self.assertIn(2025, landscape["archive_years_reviewed"])
        high_priority = {
            theme["id"]
            for theme in landscape["themes"]
            if theme["priority"] == "high"
        }
        self.assertIn("orm_filter_data_exposure", high_priority)
        self.assertIn("oauth_cookie_auth_chains", high_priority)

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_fuzz_prioritises_query_urls_and_their_own_parameters(
        self,
        mock_client_cls,
        mock_crawler_cls,
    ):
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner(
                "http://example.com",
                None,
                Path(tmpdir),
                max_fuzz_urls=2,
                max_fuzz_params=2,
                max_fuzz_forms=0,
            )
            scanner.fuzzer = MagicMock()
            scanner.fuzzer.fuzz_parameter.return_value = []

            scanner._phase_injection({
                "discovered_urls": [
                    "http://example.com",
                    "http://example.com/.git/",
                    (
                        "http://example.com/passive/params?"
                        "id=1&user=admin&debug=true&token=x&key=y&"
                        "redirect_uri=http://example.com&cmd=test&file=a&"
                        "template=home&q=search&email=a@example.com&url=http://example.com"
                    ),
                    "http://example.com/rce/expect?cmd=id",
                    "http://example.com/tools/ping?host=127.0.0.1",
                ],
                "discovered_parameters": ["action", "category", "debug"],
                "discovered_forms": [],
            })

            calls = [
                (call.args[0], call.args[1])
                for call in scanner.fuzzer.fuzz_parameter.call_args_list
            ]
            self.assertIn(("http://example.com/rce/expect?cmd=id", "cmd"), calls)
            self.assertIn(("http://example.com/tools/ping?host=127.0.0.1", "host"), calls)


if __name__ == "__main__":
    unittest.main()
