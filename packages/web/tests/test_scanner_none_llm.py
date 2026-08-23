#!/usr/bin/env python3
"""Tests for WebScanner handling of None LLM.

Requires bs4 and requests — skipped if missing.
"""

import json
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
                block_private_ips=True,
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
                block_private_ips=True,
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
                ffuf_config=SimpleNamespace(
                    extensions=(), headers=("X-Op: set",), cookies=(),
                ),
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
                oracle_signal="sqli_error:sql syntax",
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


class TestFfufReportKey(unittest.TestCase):
    """The compact ffuf summary stays at report['ffuf'] (back-compat)."""

    @patch("packages.web.scanner.FfufRunner")
    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_scan_runs_ffuf_only_when_configured(
        self,
        mock_client_cls,
        mock_crawler_cls,
        mock_ffuf_cls,
    ):
        from packages.web.ffuf import FfufConfig

        with tempfile.TemporaryDirectory() as tmpdir:
            wordlist = Path(tmpdir) / "words.txt"
            wordlist.write_text("admin\n", encoding="utf-8")
            ffuf_instance = mock_ffuf_cls.return_value
            ffuf_instance.run.return_value = {
                "tool": "ffuf",
                "returncode": 0,
                "result_count": 1,
                "results": [{"url": "http://example.com/admin", "status": 200}],
            }
            scanner = WebScanner(
                "http://example.com",
                None,
                Path(tmpdir),
                ffuf_config=FfufConfig(wordlist=wordlist),
            )
            scanner.crawler.crawl.return_value = {
                "stats": {"total_pages": 1, "total_parameters": 0},
                "discovered_parameters": [],
                "pages": [],
            }

            result = scanner.scan()

            ffuf_instance.run.assert_called_once()
            self.assertEqual(result["ffuf"]["tool"], "ffuf")
            self.assertEqual(result["ffuf"]["result_count"], 1)


class TestProjectFindingsCitizenship(unittest.TestCase):
    """Web runs emit core-schema findings.json so /project merge sees them."""

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_report_writes_core_schema_findings_json(
        self, mock_client_cls, mock_crawler_cls,
    ):
        from core.project.merge import merge_findings

        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner("http://example.com", None, Path(tmpdir))
            scanner.fuzzer = MagicMock()
            scanner.fuzzer.fuzz_parameter.return_value = [{
                "url": "http://example.com/search",
                "parameter": "q",
                "payload": "' OR 1=1--",
                "vulnerability_type": "sqli",
                "method": "GET",
                "status_code": 500,
                "response_length": 10,
                "confirmed": True,
                "response_evidence": "SQL syntax",
                "attack_evidence": "SQL syntax",
                "baseline_evidence": "HTTP 200, 5 bytes",
                "diff_summary": "baseline HTTP 200/5; attack HTTP 500/10; oracle=sqli_error:x",
                "oracle_signal": "sqli_error:sql syntax",
            }]
            scanner.verify_findings = False
            scanner.crawler.crawl.return_value = {
                "stats": {"total_pages": 1, "total_parameters": 1},
                "discovered_parameters": ["q"],
                "pages": [],
            }

            scanner.scan()

            artifact = Path(tmpdir) / "findings.json"
            self.assertTrue(artifact.exists())
            data = json.loads(artifact.read_text(encoding="utf-8"))
            self.assertGreaterEqual(len(data["findings"]), 1)
            injection = next(
                f for f in data["findings"] if f["vuln_type"] == "sqli"
            )
            self.assertEqual(injection["function"], "q")
            self.assertEqual(injection["line"], 0)
            self.assertEqual(injection["file"], "http://example.com/search")

            # The project merge layer accepts the run dir as-is.
            merged = merge_findings([Path(tmpdir)])
            self.assertTrue(
                any(f.get("vuln_type") == "sqli" for f in merged)
            )


class TestRankingIntegration(unittest.TestCase):
    """--rank reorders within budgets; never gates, never fatal."""

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_rank_reorders_fuzz_urls_within_budget(
        self, mock_client_cls, mock_crawler_cls,
    ):
        from core.llm.ranking import RankedItem, RankingResult, RankingStats

        ranked_calls = []

        def fake_rank(items, query, **kwargs):
            ranked_calls.append(query)
            reordered = list(reversed(items))
            return RankingResult(
                ranked=[
                    RankedItem(rank=i + 1, index=i, item=item, score=0.0,
                               iterations=1)
                    for i, item in enumerate(reordered)
                ],
                stats=RankingStats(),
            )

        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner(
                "http://example.com", MagicMock(), Path(tmpdir),
                max_fuzz_urls=1, rank=True,
            )
            scanner.fuzzer = MagicMock()
            fuzzed_urls = []

            def record_fuzz(url, param, **kwargs):
                fuzzed_urls.append(url)
                return []

            scanner.fuzzer.fuzz_parameter.side_effect = record_fuzz
            scanner.crawler.crawl.return_value = {
                "stats": {"total_pages": 2, "total_parameters": 1},
                "discovered_parameters": ["q"],
                "discovered_urls": [
                    "http://example.com/a?q=1",
                    "http://example.com/b?q=1",
                ],
                "pages": [],
            }

            with patch("core.llm.ranking.rank_items", side_effect=fake_rank):
                scanner.scan()

        # Ranking ran at the fuzz-URL gate (the only gate with >= 3
        # candidates in this fixture; smaller queues skip the spend).
        self.assertGreaterEqual(len(ranked_calls), 1)
        # Budget cap (1 URL) applied AFTER the rank reordering.
        self.assertEqual(len(set(fuzzed_urls)), 1)

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_rank_failure_keeps_heuristic_order(
        self, mock_client_cls, mock_crawler_cls,
    ):
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner(
                "http://example.com", MagicMock(), Path(tmpdir), rank=True,
            )
            scanner.fuzzer = MagicMock()
            scanner.fuzzer.fuzz_parameter.return_value = []
            scanner.crawler.crawl.return_value = {
                "stats": {"total_pages": 1, "total_parameters": 1},
                "discovered_parameters": ["q"],
                "discovered_urls": ["http://example.com/a?q=1"] * 4,
                "pages": [],
            }

            with patch(
                "core.llm.ranking.rank_items",
                side_effect=RuntimeError("model down"),
            ):
                result = scanner.scan()

        self.assertIn("injection", result["phases_completed"])

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_no_rank_flag_means_no_ranking_calls(
        self, mock_client_cls, mock_crawler_cls,
    ):
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner("http://example.com", MagicMock(), Path(tmpdir))
            scanner.fuzzer = MagicMock()
            scanner.fuzzer.fuzz_parameter.return_value = []
            scanner.crawler.crawl.return_value = {
                "stats": {"total_pages": 1, "total_parameters": 1},
                "discovered_parameters": ["q"],
                "pages": [],
            }

            with patch("core.llm.ranking.rank_items") as mock_rank:
                scanner.scan()

            mock_rank.assert_not_called()


class TestParamMiningPhase(unittest.TestCase):
    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_mined_parameters_join_the_fuzz_surface(
        self, mock_client_cls, mock_crawler_cls,
    ):
        from packages.web.discovery.param_mining import ParamMiningResult

        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner(
                "http://example.com", None, Path(tmpdir), mine_params=True,
            )
            scanner.fuzzer = MagicMock()
            fuzzed_params = set()

            def record(url, param, **kwargs):
                fuzzed_params.add(param)
                return []

            scanner.fuzzer.fuzz_parameter.side_effect = record
            scanner.crawler.crawl.return_value = {
                "stats": {"total_pages": 1, "total_parameters": 1},
                "discovered_parameters": ["q"],
                "discovered_urls": ["http://example.com/app"],
                "pages": [],
            }

            with patch(
                "packages.web.discovery.param_mining.mine_parameters",
                return_value=ParamMiningResult(
                    url="http://example.com/app", discovered=["debug"],
                ),
            ):
                result = scanner.scan()

        self.assertIn("param_mining", result["phases_completed"])
        self.assertIn("debug", fuzzed_params)

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_mining_off_by_default(self, mock_client_cls, mock_crawler_cls):
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner("http://example.com", None, Path(tmpdir))
            scanner.fuzzer = MagicMock()
            scanner.fuzzer.fuzz_parameter.return_value = []
            scanner.crawler.crawl.return_value = {
                "stats": {"total_pages": 1, "total_parameters": 0},
                "discovered_parameters": [],
                "pages": [],
            }

            result = scanner.scan()

        self.assertNotIn("param_mining", result["phases_completed"])


class TestSensitiveCandidateHandoff(unittest.TestCase):
    """ffuf hits classified sensitive become check candidates, never
    findings by themselves."""

    @patch("packages.web.scanner.FfufRunner")
    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_ffuf_hits_reach_sensitive_file_check(
        self, mock_client_cls, mock_crawler_cls, mock_ffuf_cls,
    ):
        from packages.web.ffuf import FfufConfig

        with tempfile.TemporaryDirectory() as tmpdir:
            wordlist = Path(tmpdir) / "words.txt"
            wordlist.write_text("env\n", encoding="utf-8")
            mock_ffuf_cls.return_value.run.return_value = {
                "tool": "ffuf",
                "returncode": 0,
                "result_count": 2,
                "results": [
                    {"url": "http://example.com/.env.backup", "status": 200},
                    {"url": "http://example.com/blog", "status": 200},
                ],
            }
            scanner = WebScanner(
                "http://example.com", None, Path(tmpdir),
                ffuf_config=FfufConfig(wordlist=wordlist),
            )
            scanner.fuzzer = MagicMock()
            scanner.fuzzer.fuzz_parameter.return_value = []
            scanner.crawler.crawl.return_value = {
                "stats": {"total_pages": 1, "total_parameters": 0},
                "discovered_parameters": [],
                "pages": [],
            }
            seen_ctx = {}

            class _SpyCheck:
                def __init__(self, llm=None):
                    pass

                def run(self, client, target_url, session=None, discovery=None):
                    seen_ctx.update(discovery or {})
                    return []

            with patch(
                "packages.web.scanner.registry.unauthenticated",
                return_value=[_SpyCheck],
            ):
                scanner.scan()

        candidates = dict(seen_ctx.get("external_paths") or [])
        # The dotfile-backup hit is a candidate; the ordinary page is not.
        self.assertIn("/.env.backup", candidates)
        self.assertNotIn("/blog", candidates)
