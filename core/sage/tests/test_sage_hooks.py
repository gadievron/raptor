#!/usr/bin/env python3
"""Tests for SAGE pipeline hooks."""

import asyncio
import unittest
from unittest.mock import patch, MagicMock, AsyncMock


class TestRecallContextForScan(unittest.TestCase):
    """Test pre-scan recall hook."""

    @patch("core.sage.hooks._get_client", return_value=None)
    def test_returns_empty_when_unavailable(self, _):
        from core.sage.hooks import recall_context_for_scan
        result = recall_context_for_scan("/path/to/repo")
        self.assertEqual(result, [])

    @patch("core.sage.hooks._get_client")
    def test_returns_results_when_available(self, mock_get_client):
        mock_client = MagicMock()

        async def mock_query(text, domain_tag, top_k=5):
            return [{"content": "test finding", "confidence": 0.9, "domain": domain_tag}]

        mock_client.query = mock_query
        mock_get_client.return_value = mock_client

        from core.sage.hooks import recall_context_for_scan
        results = recall_context_for_scan("/path/to/repo", languages=["python"])
        self.assertGreater(len(results), 0)

    @patch("core.sage.hooks._get_client")
    def test_handles_error_gracefully(self, mock_get_client):
        mock_client = MagicMock()

        async def mock_query(text, domain_tag, top_k=5):
            raise ConnectionError("SAGE down")

        mock_client.query = mock_query
        mock_get_client.return_value = mock_client

        from core.sage.hooks import recall_context_for_scan
        results = recall_context_for_scan("/path/to/repo")
        self.assertEqual(results, [])


class TestStoreScanResults(unittest.TestCase):
    """Test post-scan storage hook."""

    @patch("core.sage.hooks._get_client", return_value=None)
    def test_returns_zero_when_unavailable(self, _):
        from core.sage.hooks import store_scan_results
        result = store_scan_results("/repo", [], {})
        self.assertEqual(result, 0)

    @patch("core.sage.hooks._get_client", return_value=None)
    def test_returns_zero_for_empty_findings(self, _):
        from core.sage.hooks import store_scan_results
        result = store_scan_results("/repo", [], {"total_findings": 0})
        self.assertEqual(result, 0)


class TestEnrichAnalysisPrompt(unittest.TestCase):
    """Test prompt enrichment hook."""

    @patch("core.sage.hooks._get_client", return_value=None)
    def test_returns_empty_when_unavailable(self, _):
        from core.sage.hooks import enrich_analysis_prompt
        result = enrich_analysis_prompt("rule-123", "src/app.py", "python")
        self.assertEqual(result, "")

    @patch("core.sage.hooks._get_client")
    def test_returns_context_when_available(self, mock_get_client):
        mock_client = MagicMock()

        async def mock_query(text, domain_tag, top_k=5):
            return [{"content": "SQL injection pattern", "confidence": 0.92, "domain": "raptor-findings"}]

        mock_client.query = mock_query
        mock_get_client.return_value = mock_client

        from core.sage.hooks import enrich_analysis_prompt
        result = enrich_analysis_prompt("sql-injection", "src/db.py", "python")
        self.assertIn("Historical Context from SAGE", result)
        self.assertIn("SQL injection pattern", result)

    @patch("core.sage.hooks._get_client")
    def test_returns_empty_on_no_results(self, mock_get_client):
        mock_client = MagicMock()

        async def mock_query(text, domain_tag, top_k=5):
            return []

        mock_client.query = mock_query
        mock_get_client.return_value = mock_client

        from core.sage.hooks import enrich_analysis_prompt
        result = enrich_analysis_prompt("rule-123", "src/app.py")
        self.assertEqual(result, "")


class TestStoreAnalysisResults(unittest.TestCase):
    """Test analysis results storage."""

    @patch("core.sage.hooks._get_client", return_value=None)
    def test_noop_when_unavailable(self, _):
        from core.sage.hooks import store_analysis_results
        # Should not raise
        store_analysis_results("/repo", {"exploitable": 3})


class TestRecallExploitPrimitives(unittest.TestCase):
    """Test exploit primitive recall."""

    @patch("core.sage.hooks._get_client", return_value=None)
    def test_returns_empty_when_unavailable(self, _):
        from core.sage.hooks import recall_exploit_primitives
        result = recall_exploit_primitives(["buffer_overflow"])
        self.assertEqual(result, [])


if __name__ == "__main__":
    unittest.main()
