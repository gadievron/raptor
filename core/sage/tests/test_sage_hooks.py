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


    @patch("core.sage.hooks.SageClient")
    def test_reprobe_after_ttl_expiry(self, mock_cls):
        """When SAGE was unavailable but TTL has elapsed, re-probe."""
        import time
        import core.sage.hooks as hooks

        # First call: SAGE unavailable → _client = None
        mock_instance = MagicMock()
        mock_instance.is_available.return_value = False
        mock_cls.return_value = mock_instance

        self.assertIsNone(hooks._get_client())
        self.assertTrue(hooks._client_initialised)
        self.assertEqual(mock_cls.call_count, 1)

        # Second call within TTL: cached None, no re-probe
        self.assertIsNone(hooks._get_client())
        self.assertEqual(mock_cls.call_count, 1)

        # Expire the TTL
        hooks._client_none_decided_at = time.time() - hooks._CLIENT_NONE_TTL_S - 1

        # Third call: TTL expired → re-probe, now SAGE is available
        mock_instance2 = MagicMock()
        mock_instance2.is_available.return_value = True
        mock_cls.return_value = mock_instance2

        result = hooks._get_client()
        self.assertIs(result, mock_instance2)
        self.assertEqual(mock_cls.call_count, 2)

    @patch("core.sage.hooks.SageConfig")
    def test_init_exception_returns_none(self, mock_config_cls):
        """_get_client() must never propagate exceptions to callers."""
        import core.sage.hooks as hooks
        mock_config_cls.from_env.side_effect = RuntimeError("bad env")
        self.assertIsNone(hooks._get_client())
        self.assertTrue(hooks._client_initialised)


class TestSage11Features(unittest.TestCase):
    """SAGE 11.9.2: tags on propose calls, min_confidence on query calls."""

    @patch("core.sage.hooks._throttle")
    @patch("core.sage.hooks._get_client")
    def test_store_scan_results_passes_tags(self, mock_get_client, _throttle):
        mock_client = MagicMock()
        mock_client.propose.return_value = True
        mock_get_client.return_value = mock_client

        from core.sage.hooks import store_scan_results
        store_scan_results(
            "/repo",
            [{"rule_id": "xss.reflected", "level": "error",
              "file_path": "a.js", "message": "xss"}],
            {"total_findings": 1},
        )
        calls = mock_client.propose.call_args_list
        finding_call = calls[0]
        self.assertEqual(
            finding_call.kwargs["tags"],
            ["scan", "finding", "xss.reflected"],
        )
        summary_call = calls[1]
        self.assertEqual(summary_call.kwargs["tags"], ["scan", "summary"])

    @patch("core.sage.hooks._get_client")
    def test_recall_queries_pass_min_confidence(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.query.return_value = []
        mock_get_client.return_value = mock_client

        from core.sage.hooks import recall_context_for_scan
        recall_context_for_scan("/repo", languages=["python"])

        for call in mock_client.query.call_args_list:
            self.assertEqual(
                call.kwargs.get("min_confidence"), 0.5,
                f"min_confidence missing from query call: {call}",
            )

    @patch("core.sage.hooks._get_client")
    def test_store_crash_pattern_passes_tags(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.propose.return_value = True
        mock_get_client.return_value = mock_client

        from core.sage.hooks import store_crash_analysis_pattern
        store_crash_analysis_pattern(
            repo_path="/repo", binary_path="/bin/test",
            signal="SIGSEGV", function_name="parse",
            crash_type="heap-buffer-overflow",
        )
        kwargs = mock_client.propose.call_args.kwargs
        self.assertEqual(kwargs["tags"], ["crash", "pattern", "heap-buffer-overflow"])

    @patch("core.sage.hooks._get_client")
    def test_store_fuzzing_strategy_passes_tags(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.propose.return_value = True
        mock_get_client.return_value = mock_client

        from core.sage.hooks import store_fuzzing_strategy_outcome
        store_fuzzing_strategy_outcome(
            repo_path="/repo", binary_fingerprint="abc",
            strategy_id="havoc-splice", duration_s=300,
            execs=100000, unique_crashes=2, hangs=0,
            exploitable_crashes=1,
        )
        kwargs = mock_client.propose.call_args.kwargs
        self.assertEqual(kwargs["tags"], ["fuzzing", "strategy", "havoc-splice"])


class TestValidationHooks(unittest.TestCase):
    """Exploitability validation recall and store hooks."""

    @patch("core.sage.hooks._get_client", return_value=None)
    def test_recall_returns_empty_when_unavailable(self, _):
        from core.sage.hooks import recall_context_for_validation
        self.assertEqual(recall_context_for_validation("/repo"), [])

    @patch("core.sage.hooks._get_client")
    def test_recall_queries_validation_and_methodology(self, mock_get_client):
        mock_client = MagicMock()
        domains = []

        def _q(**kwargs):
            domains.append(kwargs.get("domain_tag", ""))
            return [{"content": "prior verdict", "confidence": 0.9}]

        mock_client.query.side_effect = _q
        mock_get_client.return_value = mock_client

        from core.sage.hooks import recall_context_for_validation
        recall_context_for_validation("/repo", vuln_type="sqli", cwe_id="CWE-89")
        self.assertEqual(mock_client.query.call_count, 2)
        self.assertTrue(any("validation" in d for d in domains))
        self.assertIn("raptor-methodology", domains)

    @patch("core.sage.hooks._throttle")
    @patch("core.sage.hooks._get_client")
    def test_store_verdicts_tags_and_counts(self, mock_get_client, _throttle):
        mock_client = MagicMock()
        mock_client.propose.return_value = True
        mock_get_client.return_value = mock_client

        from core.sage.hooks import store_validation_verdicts
        findings = [
            {
                "id": "FIND-0001", "vuln_type": "sql_injection",
                "cwe_id": "CWE-89", "final_status": "exploitable",
                "confidence": "high", "file": "db.py", "function": "query",
                "ruling": {"reason": "unsanitised input", "disqualifier": None},
            },
            {
                "id": "FIND-0002", "vuln_type": "xss",
                "final_status": "ruled_out", "confidence": "high",
                "file": "view.py", "function": "render",
                "ruling": {"reason": "autoescaped", "disqualifier": "D-1"},
            },
        ]
        summary = {"total_input": 5, "confirmed": 1, "ruled_out": 1, "exploitable": 1}
        stored = store_validation_verdicts("/repo", findings, summary)
        self.assertEqual(stored, 2)
        # 2 findings + 1 summary
        self.assertEqual(mock_client.propose.call_count, 3)

        first_call = mock_client.propose.call_args_list[0]
        self.assertIn("CWE-89", first_call.kwargs["tags"])
        self.assertIn("validation", first_call.kwargs["tags"])

    @patch("core.sage.hooks._get_client", return_value=None)
    def test_store_verdicts_noop_when_unavailable(self, _):
        from core.sage.hooks import store_validation_verdicts
        self.assertEqual(store_validation_verdicts("/repo", [{"id": "X"}]), 0)

    @patch("core.sage.hooks._throttle")
    @patch("core.sage.hooks._get_client")
    def test_store_disproven_stores_lessons(self, mock_get_client, _throttle):
        mock_client = MagicMock()
        mock_client.propose.return_value = True
        mock_get_client.return_value = mock_client

        from core.sage.hooks import store_validation_disproven
        store_validation_disproven("/repo", [
            {
                "finding": "FIND-0003",
                "original_claim": "buffer overflow via memcpy",
                "why_wrong": "length is bounded by prior check",
                "lesson": "check callers for bounds before claiming overflow",
            },
        ])
        self.assertEqual(mock_client.propose.call_count, 1)
        kwargs = mock_client.propose.call_args.kwargs
        self.assertEqual(kwargs["tags"], ["validation", "disproven"])
        self.assertEqual(kwargs["memory_type"], "inference")


class TestUnderstandHooks(unittest.TestCase):
    """Code understanding recall and store hooks (map/trace/hunt)."""

    @patch("core.sage.hooks._get_client", return_value=None)
    def test_recall_map_returns_empty_when_unavailable(self, _):
        from core.sage.hooks import recall_context_for_map
        self.assertEqual(recall_context_for_map("/repo"), [])

    @patch("core.sage.hooks._get_client")
    def test_recall_map_queries_understand_and_methodology(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.query.return_value = [
            {"content": "prior entry points", "confidence": 0.8}
        ]
        mock_get_client.return_value = mock_client

        from core.sage.hooks import recall_context_for_map
        out = recall_context_for_map("/repo", languages=["python"])
        self.assertEqual(mock_client.query.call_count, 2)
        self.assertGreater(len(out), 0)

    @patch("core.sage.hooks._get_client")
    def test_recall_trace_accepts_entry_and_sink(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.query.return_value = []
        mock_get_client.return_value = mock_client

        from core.sage.hooks import recall_context_for_trace
        recall_context_for_trace("/repo", entry_point="EP-001", sink="SINK-002")
        call_text = mock_client.query.call_args.kwargs["text"]
        self.assertIn("EP-001", call_text)
        self.assertIn("SINK-002", call_text)

    @patch("core.sage.hooks._get_client")
    def test_recall_hunt_accepts_pattern(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.query.return_value = []
        mock_get_client.return_value = mock_client

        from core.sage.hooks import recall_context_for_hunt
        recall_context_for_hunt("/repo", pattern="format-string")
        call_text = mock_client.query.call_args.kwargs["text"]
        self.assertIn("format-string", call_text)

    @patch("core.sage.hooks._throttle")
    @patch("core.sage.hooks._get_client")
    def test_store_map_stores_summary_and_unchecked_flows(self, mock_get_client, _throttle):
        mock_client = MagicMock()
        mock_client.propose.return_value = True
        mock_get_client.return_value = mock_client

        from core.sage.hooks import store_map_results
        context_map = {
            "meta": {"frameworks": ["express"]},
            "entry_points": [
                {"id": "EP-001", "type": "http_handler"},
                {"id": "EP-002", "type": "http_handler"},
            ],
            "sink_details": [
                {"id": "SINK-001", "type": "sql_query"},
            ],
            "boundary_details": [
                {"id": "TB-001", "type": "auth_check"},
            ],
            "unchecked_flows": [
                {"entry_point": "EP-001", "sink": "SINK-001",
                 "missing_boundary": "input validation"},
            ],
        }
        store_map_results("/repo", context_map)
        # 1 summary + 1 unchecked flow
        self.assertEqual(mock_client.propose.call_count, 2)
        summary_tags = mock_client.propose.call_args_list[0].kwargs["tags"]
        self.assertEqual(summary_tags, ["understand", "map", "summary"])

    @patch("core.sage.hooks._get_client")
    def test_store_trace_stores_flow_summary(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.propose.return_value = True
        mock_get_client.return_value = mock_client

        from core.sage.hooks import store_trace_result
        trace = {
            "id": "TRACE-001", "name": "sqli via search",
            "meta": {"entry_point": "GET /search", "target_sink": "db.execute"},
            "steps": [{"step": 1}, {"step": 2}, {"step": 3}],
            "proximity": 8,
            "blockers": [],
            "attacker_control": {"level": "full"},
            "summary": {"flow_confirmed": True, "verdict": "reachable"},
        }
        store_trace_result("/repo", trace)
        self.assertEqual(mock_client.propose.call_count, 1)
        kwargs = mock_client.propose.call_args.kwargs
        self.assertIn("TRACE-001", kwargs["tags"])
        self.assertIn("proximity 8/10", kwargs["content"])
        self.assertEqual(kwargs["confidence"], 0.85)

    @patch("core.sage.hooks._throttle")
    @patch("core.sage.hooks._get_client")
    def test_store_hunt_stores_summary_and_root_cause_groups(self, mock_get_client, _throttle):
        mock_client = MagicMock()
        mock_client.propose.return_value = True
        mock_get_client.return_value = mock_client

        from core.sage.hooks import store_hunt_results
        variants_data = {
            "meta": {
                "pattern": "format-string",
                "total_matches": 12,
                "confirmed_tainted": 5,
                "likely_tainted": 3,
                "false_positive": 4,
            },
            "root_cause_groups": [
                {"id": "RCG-001", "name": "unchecked-printf",
                 "count": 4, "fix_strategy": "use printf with format literal"},
            ],
        }
        store_hunt_results("/repo", variants_data)
        # 1 summary + 1 root cause group
        self.assertEqual(mock_client.propose.call_count, 2)
        summary_tags = mock_client.propose.call_args_list[0].kwargs["tags"]
        self.assertEqual(summary_tags, ["understand", "hunt", "format-string"])
        group_tags = mock_client.propose.call_args_list[1].kwargs["tags"]
        self.assertIn("root_cause", group_tags)


class TestExploitHooks(unittest.TestCase):
    """Test exploit recall and store hooks."""

    @patch("core.sage.hooks._get_client", return_value=None)
    def test_recall_returns_empty_when_unavailable(self, _):
        from core.sage.hooks import recall_context_for_exploit
        self.assertEqual(recall_context_for_exploit("/repo"), [])

    @patch("core.sage.hooks._get_client")
    def test_recall_queries_exploits_and_methodology(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.query.return_value = [
            {"content": "ROP chain succeeded", "confidence": 0.9}
        ]
        mock_get_client.return_value = mock_client

        from core.sage.hooks import recall_context_for_exploit
        results = recall_context_for_exploit(
            "/repo", vuln_type="buffer_overflow", cwe_id="CWE-120",
            mitigations=["NX", "ASLR"],
        )
        self.assertGreater(len(results), 0)
        self.assertEqual(mock_client.query.call_count, 2)
        exploit_call = mock_client.query.call_args_list[0]
        self.assertIn("buffer_overflow", exploit_call.kwargs["text"])
        self.assertIn("NX", exploit_call.kwargs["text"])
        self.assertIn("raptor-exploits-", exploit_call.kwargs["domain_tag"])

    @patch("core.sage.hooks._get_client")
    def test_recall_handles_error_gracefully(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.query.side_effect = ConnectionError("down")
        mock_get_client.return_value = mock_client

        from core.sage.hooks import recall_context_for_exploit
        self.assertEqual(recall_context_for_exploit("/repo"), [])

    @patch("core.sage.hooks._get_client", return_value=None)
    def test_store_returns_zero_when_unavailable(self, _):
        from core.sage.hooks import store_exploit_outcomes
        self.assertEqual(store_exploit_outcomes("/repo", [{"result": "success"}]), 0)

    @patch("core.sage.hooks._get_client")
    def test_store_writes_outcomes(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.propose.return_value = True
        mock_get_client.return_value = mock_client

        from core.sage.hooks import store_exploit_outcomes
        outcomes = [
            {
                "finding_id": "F1",
                "vuln_type": "heap_overflow",
                "result": "success",
                "technique": "ROP",
                "mitigations_encountered": ["NX", "ASLR"],
                "cwe_id": "CWE-122",
                "file_path": "src/parse.c",
            },
            {
                "finding_id": "F2",
                "vuln_type": "format_string",
                "result": "blocked",
                "file_path": "src/log.c",
            },
        ]
        stored = store_exploit_outcomes("/repo", outcomes)
        self.assertEqual(stored, 2)
        self.assertEqual(mock_client.propose.call_count, 2)

        first_call = mock_client.propose.call_args_list[0]
        self.assertIn("ROP", first_call.kwargs["content"])
        self.assertIn("NX", first_call.kwargs["content"])
        self.assertEqual(first_call.kwargs["memory_type"], "fact")
        self.assertEqual(first_call.kwargs["confidence"], 0.95)
        self.assertIn("success", first_call.kwargs["tags"])
        self.assertIn("ROP", first_call.kwargs["tags"])

        second_call = mock_client.propose.call_args_list[1]
        self.assertEqual(second_call.kwargs["memory_type"], "observation")
        self.assertEqual(second_call.kwargs["confidence"], 0.80)

    @patch("core.sage.hooks._get_client")
    def test_store_infers_success_from_has_exploit(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.propose.return_value = True
        mock_get_client.return_value = mock_client

        from core.sage.hooks import store_exploit_outcomes
        outcomes = [{"finding_id": "F1", "has_exploit": True, "vuln_type": "sqli"}]
        store_exploit_outcomes("/repo", outcomes)
        call = mock_client.propose.call_args_list[0]
        self.assertIn("success", call.kwargs["content"])
        self.assertEqual(call.kwargs["memory_type"], "fact")

    @patch("core.sage.hooks._get_client")
    def test_store_tags_include_exploit_and_result(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.propose.return_value = True
        mock_get_client.return_value = mock_client

        from core.sage.hooks import store_exploit_outcomes
        store_exploit_outcomes("/repo", [{"result": "partial", "technique": "heap_spray"}])
        tags = mock_client.propose.call_args_list[0].kwargs["tags"]
        self.assertEqual(tags, ["exploit", "partial", "heap_spray"])

    @patch("core.sage.hooks._get_client")
    def test_store_caps_at_20(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.propose.return_value = True
        mock_get_client.return_value = mock_client

        from core.sage.hooks import store_exploit_outcomes
        outcomes = [{"finding_id": f"F{i}", "result": "success"} for i in range(30)]
        stored = store_exploit_outcomes("/repo", outcomes)
        self.assertEqual(stored, 20)
        self.assertEqual(mock_client.propose.call_count, 20)


class TestSCAHooks(unittest.TestCase):
    """Test SCA recall and store hooks."""

    @patch("core.sage.hooks._get_client", return_value=None)
    def test_recall_returns_empty_when_unavailable(self, _):
        from core.sage.hooks import recall_context_for_sca
        self.assertEqual(recall_context_for_sca("/repo"), [])

    @patch("core.sage.hooks._get_client")
    def test_recall_queries_sca_and_methodology(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.query.return_value = [
            {"content": "SCA: evil-pkg (PyPI) — malicious_confirmed", "confidence": 0.98}
        ]
        mock_get_client.return_value = mock_client

        from core.sage.hooks import recall_context_for_sca
        results = recall_context_for_sca(
            "/repo",
            ecosystems=["PyPI", "npm"],
            dep_names=["evil-pkg", "suspect-lib"],
        )
        self.assertGreater(len(results), 0)
        self.assertEqual(mock_client.query.call_count, 2)
        sca_call = mock_client.query.call_args_list[0]
        self.assertIn("PyPI", sca_call.kwargs["text"])
        self.assertIn("evil-pkg", sca_call.kwargs["text"])
        self.assertIn("raptor-sca-", sca_call.kwargs["domain_tag"])

    @patch("core.sage.hooks._get_client")
    def test_recall_handles_error_gracefully(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.query.side_effect = ConnectionError("down")
        mock_get_client.return_value = mock_client

        from core.sage.hooks import recall_context_for_sca
        self.assertEqual(recall_context_for_sca("/repo"), [])

    @patch("core.sage.hooks._get_client", return_value=None)
    def test_store_returns_zero_when_unavailable(self, _):
        from core.sage.hooks import store_sca_outcomes
        self.assertEqual(
            store_sca_outcomes("/repo", [{"package_name": "evil"}]), 0
        )

    @patch("core.sage.hooks._get_client")
    def test_store_writes_outcomes(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.propose.return_value = True
        mock_get_client.return_value = mock_client

        from core.sage.hooks import store_sca_outcomes
        outcomes = [
            {
                "package_name": "evil-pkg",
                "ecosystem": "PyPI",
                "version": "0.1.0",
                "kind": "slopsquat_suspect",
                "verdict": "malicious_confirmed",
                "detail": "AI-hallucinated package name",
                "llm_summary": "Package is a slopsquat of real-pkg.",
            },
            {
                "package_name": "legit-dep",
                "ecosystem": "npm",
                "kind": "typosquat_candidate",
                "verdict": "false_positive",
                "detail": "Name collision with unrelated project",
            },
        ]
        stored = store_sca_outcomes("/repo", outcomes)
        self.assertEqual(stored, 2)
        self.assertEqual(mock_client.propose.call_count, 2)

        first_call = mock_client.propose.call_args_list[0]
        self.assertIn("evil-pkg", first_call.kwargs["content"])
        self.assertIn("PyPI", first_call.kwargs["content"])
        self.assertIn("malicious_confirmed", first_call.kwargs["content"])
        self.assertEqual(first_call.kwargs["memory_type"], "fact")
        self.assertEqual(first_call.kwargs["confidence"], 0.98)
        self.assertIn("sca", first_call.kwargs["tags"])
        self.assertIn("PyPI", first_call.kwargs["tags"])

        second_call = mock_client.propose.call_args_list[1]
        self.assertEqual(second_call.kwargs["memory_type"], "fact")
        self.assertEqual(second_call.kwargs["confidence"], 0.92)
        self.assertIn("false_positive", second_call.kwargs["tags"])

    @patch("core.sage.hooks._get_client")
    def test_store_caps_at_30(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.propose.return_value = True
        mock_get_client.return_value = mock_client

        from core.sage.hooks import store_sca_outcomes
        outcomes = [
            {"package_name": f"pkg-{i}", "verdict": "suspect"}
            for i in range(50)
        ]
        stored = store_sca_outcomes("/repo", outcomes)
        self.assertEqual(stored, 30)
        self.assertEqual(mock_client.propose.call_count, 30)

    @patch("core.sage.hooks._get_client")
    def test_store_includes_cve_ids(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.propose.return_value = True
        mock_get_client.return_value = mock_client

        from core.sage.hooks import store_sca_outcomes
        store_sca_outcomes("/repo", [{
            "package_name": "vuln-lib",
            "verdict": "vulnerable",
            "cve_ids": ["CVE-2024-1234", "CVE-2024-5678"],
        }])
        call = mock_client.propose.call_args_list[0]
        self.assertIn("CVE-2024-1234", call.kwargs["content"])

    @patch("core.sage.hooks._get_client")
    def test_store_empty_outcomes_returns_zero(self, mock_get_client):
        mock_client = MagicMock()
        mock_get_client.return_value = mock_client

        from core.sage.hooks import store_sca_outcomes
        self.assertEqual(store_sca_outcomes("/repo", []), 0)
        mock_client.propose.assert_not_called()


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
