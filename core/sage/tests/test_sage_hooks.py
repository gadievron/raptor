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


class TestSageRecallPriors(unittest.TestCase):
    def test_pick_strongest_respects_min_confidence(self):
        from core.sage.hooks import pick_strongest_recall_row

        rows = [
            {"content": "low", "confidence": 0.5},
            {"content": "high", "confidence": 0.9},
        ]
        self.assertIsNone(pick_strongest_recall_row(rows, min_confidence=0.95))
        best = pick_strongest_recall_row(rows, min_confidence=0.85)
        self.assertEqual(best["content"], "high")

    def test_infer_afl_flags_mopt_and_deterministic(self):
        from core.sage.hooks import infer_afl_fuzz_flags_from_sage_recall_row

        self.assertEqual(
            infer_afl_fuzz_flags_from_sage_recall_row(
                {"content": "Prior run: enable MOpt for this target", "confidence": 0.9},
            ),
            ["-L", "0"],
        )
        flags = infer_afl_fuzz_flags_from_sage_recall_row(
            {"content": "Use deterministic fuzzing schedule", "confidence": 0.9},
        )
        self.assertIn("-D", flags)

    def test_infer_afl_flags_power_schedule_explore(self):
        from core.sage.hooks import infer_afl_fuzz_flags_from_sage_recall_row

        flags = infer_afl_fuzz_flags_from_sage_recall_row(
            {
                "content": "Prior campaign: AFL++ power schedule explore worked well",
                "confidence": 0.9,
            },
        )
        self.assertEqual(flags[:2], ["-p", "explore"])


class TestMergeRecallRows(unittest.TestCase):
    def test_dedupes_by_content_preserves_first_list_priority(self):
        from core.sage.hooks import _merge_recall_rows

        a = [{"content": "dup", "k": 1}]
        b = [{"content": "dup", "k": 2}, {"content": "unique-b", "k": 3}]
        merged = _merge_recall_rows(a, b, top_k=5)
        self.assertEqual(len(merged), 2)
        self.assertEqual(merged[0]["k"], 1)
        self.assertEqual(merged[1]["content"], "unique-b")

    def test_top_k_truncates(self):
        from core.sage.hooks import _merge_recall_rows

        merged = _merge_recall_rows(
            [{"content": "a"}, {"content": "b"}],
            [{"content": "c"}],
            top_k=2,
        )
        self.assertEqual(len(merged), 2)
        self.assertEqual({m["content"] for m in merged}, {"a", "b"})


class TestRecallContextForCrashAnalysis(unittest.TestCase):
    @patch("core.sage.hooks._get_client")
    def test_queries_repo_crashes_and_methodology(self, mock_get_client):
        mock_client = MagicMock()
        domains = []

        def _q(**kwargs):
            domains.append(kwargs.get("domain_tag", ""))
            if "crashes" in kwargs.get("domain_tag", ""):
                return [{"content": "heap uaf prior", "confidence": 0.8}]
            return [{"content": "asan triage tip", "confidence": 0.75}]

        mock_client.query.side_effect = _q
        mock_get_client.return_value = mock_client

        from core.sage.hooks import recall_context_for_crash_analysis
        out = recall_context_for_crash_analysis(
            "/path/to/repo", signal="SIGSEGV", function_name="parse",
        )
        self.assertEqual(mock_client.query.call_count, 2)
        self.assertTrue(any("crashes" in d for d in domains))
        self.assertIn("raptor-methodology", domains)
        self.assertEqual(len(out), 2)
        self.assertEqual(out[0]["content"], "heap uaf prior")


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

        def _query_side_effect(**kwargs):
            domain = kwargs.get("domain_tag", "")
            if domain.startswith("raptor-findings"):
                return [
                    {"content": "SQL injection pattern", "confidence": 0.92,
                     "domain": "raptor-findings"}
                ]
            if domain == "raptor-methodology":
                return [
                    {"content": "Check ORM layer", "confidence": 0.81,
                     "domain": "raptor-methodology"}
                ]
            return []

        mock_client.query.side_effect = _query_side_effect
        mock_get_client.return_value = mock_client

        from core.sage.hooks import enrich_analysis_prompt
        result = enrich_analysis_prompt(
            "sql-injection", "src/db.py", "python", repo_path="/path/to/repo"
        )
        self.assertIn("Historical Context from SAGE", result)
        self.assertIn("SQL injection pattern", result)
        self.assertIn("Methodology hints from SAGE", result)
        self.assertIn("Check ORM layer", result)

    @patch("core.sage.hooks._get_client")
    def test_returns_methodology_only_when_findings_empty(self, mock_get_client):
        mock_client = MagicMock()

        def _query_side_effect(**kwargs):
            domain = kwargs.get("domain_tag", "")
            if domain.startswith("raptor-findings"):
                return []
            if domain == "raptor-methodology":
                return [{"content": "Triage hint", "confidence": 0.88}]
            return []

        mock_client.query.side_effect = _query_side_effect
        mock_get_client.return_value = mock_client

        from core.sage.hooks import enrich_analysis_prompt
        result = enrich_analysis_prompt(
            "xss", "src/x.js", "javascript", repo_path="/path/to/repo"
        )
        self.assertIn("Methodology hints from SAGE", result)
        self.assertIn("Triage hint", result)
        self.assertNotIn("Historical Context from SAGE", result)

    @patch("core.sage.hooks._get_client")
    def test_returns_empty_on_no_results(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.query.return_value = []
        mock_get_client.return_value = mock_client

        from core.sage.hooks import enrich_analysis_prompt
        self.assertEqual(
            enrich_analysis_prompt("rule-123", "src/app.py", repo_path="/repo"), ""
        )

    @patch("core.sage.hooks._get_client")
    def test_returns_empty_without_repo_path(self, mock_get_client):
        mock_client = MagicMock()
        mock_get_client.return_value = mock_client

        from core.sage.hooks import enrich_analysis_prompt
        # No repo_path → skip query entirely (unscoped recall would leak
        # cross-repo since same-basename repos now live under distinct domains).
        self.assertEqual(enrich_analysis_prompt("rule-123", "src/app.py"), "")
        mock_client.query.assert_not_called()


class TestStoreAnalysisResults(unittest.TestCase):
    """Test analysis results storage."""

    @patch("core.sage.hooks._get_client", return_value=None)
    def test_noop_when_unavailable(self, _):
        from core.sage.hooks import store_analysis_results
        # Should not raise
        store_analysis_results("/repo", {"exploitable": 3})


class TestAdditionalSageHooks(unittest.TestCase):
    @patch("core.sage.hooks._get_client")
    def test_store_web_payload_effectiveness_redacts_secret_like_text(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.propose.return_value = True
        mock_get_client.return_value = mock_client

        from core.sage.hooks import store_web_payload_effectiveness
        store_web_payload_effectiveness(
            repo_path="https://example.test",
            target_fingerprint="https://example.test/search",
            payload_class="xss",
            evidence_class="reflection",
            effectiveness=0.91,
            attempts=12,
            signals=3,
            notes="auth header Bearer sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDE",
        )

        self.assertTrue(mock_client.propose.called)
        content = mock_client.propose.call_args.kwargs["content"]
        self.assertNotIn("sk-proj-", content)
        self.assertIn("[REDACTED]", content)

    @patch("core.sage.hooks._get_client")
    def test_recall_context_for_codeql_build_returns_results(self, mock_get_client):
        mock_client = MagicMock()

        def _q(**kwargs):
            domain = kwargs.get("domain_tag", "")
            if domain.startswith("raptor-findings"):
                return [{"content": "prior cpp sqli", "confidence": 0.72}]
            return [
                {"content": "build succeeded with autobuild", "confidence": 0.85,
                 "domain": "raptor-methodology"}
            ]

        mock_client.query.side_effect = _q
        mock_get_client.return_value = mock_client

        from core.sage.hooks import recall_context_for_codeql_build
        results = recall_context_for_codeql_build("/repo", ["python"])
        self.assertEqual(len(results), 2)
        self.assertEqual(mock_client.query.call_count, 2)
        self.assertEqual(results[0]["content"], "prior cpp sqli")

    @patch("core.sage.hooks._get_client")
    def test_recall_context_for_fuzzing_strategy_handles_failure(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.query.side_effect = RuntimeError("boom")
        mock_get_client.return_value = mock_client

        from core.sage.hooks import recall_context_for_fuzzing_strategy
        self.assertEqual(
            recall_context_for_fuzzing_strategy("/repo", "abc123", "default"),
            [],
        )


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


class TestGetClientThreadSafety(unittest.TestCase):
    """Singleton init is guarded by _client_lock and _client_initialised.

    The orchestrator dispatches via ThreadPoolExecutor, so two workers can
    call _get_client() before either has finished initialising. Without the
    lock, both would construct SageClient (wasteful) and one could briefly
    see a non-None _client while the other resets it to None.
    """

    def setUp(self):
        import core.sage.hooks as hooks
        # Reset module state so each test starts from a cold singleton.
        hooks._client = None
        hooks._client_initialised = False

    def tearDown(self):
        import core.sage.hooks as hooks
        hooks._client = None
        hooks._client_initialised = False

    @patch("core.sage.hooks.SageClient")
    def test_concurrent_first_call_constructs_client_once(self, mock_cls):
        from concurrent.futures import ThreadPoolExecutor
        import core.sage.hooks as hooks

        mock_instance = MagicMock()
        mock_instance.is_available.return_value = True
        mock_cls.return_value = mock_instance

        with ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(lambda _: hooks._get_client(), range(16)))

        self.assertEqual(mock_cls.call_count, 1)
        self.assertTrue(all(r is mock_instance for r in results))

    @patch("core.sage.hooks.SageClient")
    def test_unavailable_at_init_sticks(self, mock_cls):
        """Once SAGE is decided unavailable, don't re-probe on every call."""
        import core.sage.hooks as hooks

        mock_instance = MagicMock()
        mock_instance.is_available.return_value = False
        mock_cls.return_value = mock_instance

        self.assertIsNone(hooks._get_client())
        self.assertIsNone(hooks._get_client())
        self.assertIsNone(hooks._get_client())

        # SageClient ctor and is_available each ran exactly once across
        # three hook calls — cached init prevents the probe-storm the
        # old code would cause when SAGE is down for the whole run.
        self.assertEqual(mock_cls.call_count, 1)
        self.assertEqual(mock_instance.is_available.call_count, 1)


class TestFormatSageMemoriesForPrompt(unittest.TestCase):
    def test_empty(self):
        from core.sage.hooks import format_sage_memories_for_prompt
        self.assertEqual(format_sage_memories_for_prompt([]), "")

    def test_orders_by_confidence(self):
        from core.sage.hooks import format_sage_memories_for_prompt
        rows = [
            {"content": "low", "confidence": 0.5},
            {"content": "high", "confidence": 0.95, "domain": "raptor-methodology"},
        ]
        out = format_sage_memories_for_prompt(rows, max_items=5)
        self.assertIn("high", out)
        self.assertLess(out.index("high"), out.index("low"))


if __name__ == "__main__":
    unittest.main()
