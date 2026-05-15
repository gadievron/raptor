#!/usr/bin/env python3
"""Tests for WebScanner handling of None LLM.

Requires bs4 and requests — skipped if missing.
"""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

try:
    from packages.web.scanner import WebScanner
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


if __name__ == "__main__":
    unittest.main()
