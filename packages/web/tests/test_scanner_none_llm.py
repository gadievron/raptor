#!/usr/bin/env python3
"""Tests for WebScanner handling of None LLM."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch


class TestWebScannerNoneLlm(unittest.TestCase):
    """Test that WebScanner works when LLM is None."""

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_init_with_none_llm(self, mock_client_cls, mock_crawler_cls):
        from packages.web.scanner import WebScanner

        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner("http://example.com", None, Path(tmpdir))
            self.assertIsNone(scanner.fuzzer)
            self.assertIsNone(scanner.llm)

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_init_with_llm_creates_fuzzer(self, mock_client_cls, mock_crawler_cls):
        from packages.web.scanner import WebScanner

        mock_llm = MagicMock()
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner("http://example.com", mock_llm, Path(tmpdir))
            self.assertIsNotNone(scanner.fuzzer)

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_scan_without_llm_skips_fuzzing(self, mock_client_cls, mock_crawler_cls):
        """With no LLM, scan completes but fuzzer is never invoked."""
        from packages.web.scanner import WebScanner

        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner("http://example.com", None, Path(tmpdir))

            # Confirm fuzzer is None (fuzzing cannot happen)
            self.assertIsNone(scanner.fuzzer)

            # Mock crawler to return results WITH parameters
            # (if fuzzer were called, it would process these)
            scanner.crawler.crawl.return_value = {
                "stats": {"total_pages": 1, "total_parameters": 3},
                "discovered_parameters": ["q", "id", "page"],
                "pages": []
            }

            result = scanner.scan()
            # Despite having parameters, no fuzzing occurred
            self.assertEqual(result["total_vulnerabilities"], 0)
            self.assertEqual(result["findings"], [])

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_scan_with_llm_calls_fuzzer(self, mock_client_cls, mock_crawler_cls):
        """With LLM present, fuzzer is invoked for each parameter."""
        from packages.web.scanner import WebScanner

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
            # Fuzzer should have been called for each parameter
            self.assertEqual(scanner.fuzzer.fuzz_parameter.call_count, 2)


if __name__ == "__main__":
    unittest.main()
