#!/usr/bin/env python3
"""Tests for SAGE pipeline hooks."""

import unittest
from unittest.mock import patch, MagicMock


class TestRecallContextForScan(unittest.TestCase):
    """Test pre-scan recall hook."""

    @patch("core.sage.hooks._get_client", return_value=None)
    def test_returns_empty_when_unavailable(self, _):
        from core.sage.hooks import recall_context_for_scan
        self.assertEqual(recall_context_for_scan("/path/to/repo"), [])

    @patch("core.sage.hooks._get_client")
    def test_returns_results_when_available(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.query.return_value = [
            {"content": "test finding", "confidence": 0.9, "domain": "raptor-findings"}
        ]
        mock_get_client.return_value = mock_client

        from core.sage.hooks import recall_context_for_scan
        results = recall_context_for_scan("/path/to/repo", languages=["python"])
        self.assertGreater(len(results), 0)
        # Should have called both findings + methodology queries
        self.assertEqual(mock_client.query.call_count, 2)

    @patch("core.sage.hooks._get_client")
    def test_handles_error_gracefully(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.query.side_effect = ConnectionError("SAGE down")
        mock_get_client.return_value = mock_client

        from core.sage.hooks import recall_context_for_scan
        self.assertEqual(recall_context_for_scan("/path/to/repo"), [])


class TestStoreScanResults(unittest.TestCase):
    """Test post-scan storage hook."""

    @patch("core.sage.hooks._get_client", return_value=None)
    def test_returns_zero_when_unavailable(self, _):
        from core.sage.hooks import store_scan_results
        self.assertEqual(store_scan_results("/repo", [], {}), 0)

    @patch("core.sage.hooks._get_client", return_value=None)
    def test_returns_zero_for_empty_findings(self, _):
        from core.sage.hooks import store_scan_results
        self.assertEqual(store_scan_results("/repo", [], {"total_findings": 0}), 0)

    @patch("core.sage.hooks._throttle")
    @patch("core.sage.hooks._get_client")
    def test_stores_findings_when_available(self, mock_get_client, mock_throttle):
        mock_client = MagicMock()
        mock_client.propose.return_value = True
        mock_get_client.return_value = mock_client

        from core.sage.hooks import store_scan_results
        findings = [
            {"rule_id": "javascript.express.xss", "level": "error",
             "file_path": "a.js", "message": "reflected xss"},
            {"rule_id": "javascript.db.sqli", "level": "warning",
             "file_path": "b.js", "message": "concat'd query"},
        ]
        stored = store_scan_results("/repo", findings, {"total_findings": 2})
        self.assertEqual(stored, 2)
        # Two findings + one summary
        self.assertEqual(mock_client.propose.call_count, 3)
        # One throttle call per finding-propose (not after the summary).
        self.assertEqual(mock_throttle.call_count, 2)


class TestEnrichAnalysisPrompt(unittest.TestCase):
    """Test prompt enrichment hook."""

    @patch("core.sage.hooks._get_client", return_value=None)
    def test_returns_empty_when_unavailable(self, _):
        from core.sage.hooks import enrich_analysis_prompt
        self.assertEqual(enrich_analysis_prompt("rule-123", "src/app.py", "python"), "")

    @patch("core.sage.hooks._get_client")
    def test_returns_context_when_available(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.query.return_value = [
            {"content": "SQL injection pattern", "confidence": 0.92,
             "domain": "raptor-findings"}
        ]
        mock_get_client.return_value = mock_client

        from core.sage.hooks import enrich_analysis_prompt
        result = enrich_analysis_prompt("sql-injection", "src/db.py", "python")
        self.assertIn("Historical Context from SAGE", result)
        self.assertIn("SQL injection pattern", result)

    @patch("core.sage.hooks._get_client")
    def test_returns_empty_on_no_results(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.query.return_value = []
        mock_get_client.return_value = mock_client

        from core.sage.hooks import enrich_analysis_prompt
        self.assertEqual(enrich_analysis_prompt("rule-123", "src/app.py"), "")


class TestStoreAnalysisResults(unittest.TestCase):
    """Test analysis results storage."""

    @patch("core.sage.hooks._get_client", return_value=None)
    def test_noop_when_unavailable(self, _):
        from core.sage.hooks import store_analysis_results
        # Should not raise
        store_analysis_results("/repo", {"exploitable": 3})


class TestThrottle(unittest.TestCase):
    """SAGE_PROPOSE_DELAY_MS behaviour (default 0, no sleep)."""

    @patch.dict("os.environ", {}, clear=False)
    @patch("core.sage.hooks.time.sleep")
    def test_noop_when_env_unset(self, mock_sleep):
        import os
        os.environ.pop("SAGE_PROPOSE_DELAY_MS", None)
        from core.sage.hooks import _throttle
        _throttle()
        mock_sleep.assert_not_called()

    @patch.dict("os.environ", {"SAGE_PROPOSE_DELAY_MS": "0"}, clear=False)
    @patch("core.sage.hooks.time.sleep")
    def test_noop_when_env_zero(self, mock_sleep):
        from core.sage.hooks import _throttle
        _throttle()
        mock_sleep.assert_not_called()

    @patch.dict("os.environ", {"SAGE_PROPOSE_DELAY_MS": "50"}, clear=False)
    @patch("core.sage.hooks.time.sleep")
    def test_sleeps_when_env_set(self, mock_sleep):
        from core.sage.hooks import _throttle
        _throttle()
        mock_sleep.assert_called_once_with(0.05)

    @patch.dict("os.environ", {"SAGE_PROPOSE_DELAY_MS": "not-a-number"}, clear=False)
    @patch("core.sage.hooks.time.sleep")
    def test_invalid_value_is_noop(self, mock_sleep):
        from core.sage.hooks import _throttle
        _throttle()
        mock_sleep.assert_not_called()


if __name__ == "__main__":
    unittest.main()
