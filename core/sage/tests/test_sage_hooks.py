#!/usr/bin/env python3
"""Tests for SAGE pipeline hooks (mechanical consumers only)."""

import unittest
from unittest.mock import patch, MagicMock


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


class TestCodeQLBuildHooks(unittest.TestCase):
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
    def test_store_codeql_build_reliability(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.propose.return_value = True
        mock_get_client.return_value = mock_client

        from core.sage.hooks import store_codeql_build_reliability
        store_codeql_build_reliability(
            repo_path="/repo", languages=["python"],
            build_command="autobuild", auto_detect_outcome="success",
            analyses_completed=3,
        )
        kwargs = mock_client.propose.call_args.kwargs
        self.assertIn("codeql", kwargs["tags"])
        self.assertIn("build", kwargs["tags"])
        self.assertEqual(kwargs["confidence"], 0.85)


class TestInferCodeQLBuild(unittest.TestCase):
    def test_extracts_successful_build_command(self):
        from core.sage.hooks import infer_codeql_build_from_sage_recall_row
        row = {
            "content": (
                "CodeQL build reliability for repo myapp: "
                "languages cpp, outcome success, "
                "build command cmake -B build && cmake --build build, "
                "analyses completed 5, failure modes none."
            ),
            "confidence": 0.85,
        }
        hint = infer_codeql_build_from_sage_recall_row(row)
        self.assertEqual(hint["outcome"], "success")
        self.assertEqual(
            hint["build_command"],
            "cmake -B build && cmake --build build")
        self.assertEqual(hint["languages"], "cpp")

    def test_no_command_on_failure(self):
        from core.sage.hooks import infer_codeql_build_from_sage_recall_row
        row = {
            "content": (
                "CodeQL build reliability for repo myapp: "
                "languages java, outcome failure, "
                "build command mvn clean compile, "
                "analyses completed 0, failure modes build timeout."
            ),
            "confidence": 0.75,
        }
        hint = infer_codeql_build_from_sage_recall_row(row)
        self.assertEqual(hint["outcome"], "failure")
        self.assertNotIn("build_command", hint)

    def test_skips_auto_command(self):
        from core.sage.hooks import infer_codeql_build_from_sage_recall_row
        row = {
            "content": (
                "CodeQL build reliability for repo myapp: "
                "languages python, outcome success, "
                "build command auto, "
                "analyses completed 3, failure modes none."
            ),
            "confidence": 0.85,
        }
        hint = infer_codeql_build_from_sage_recall_row(row)
        self.assertEqual(hint["outcome"], "success")
        self.assertNotIn("build_command", hint)

    def test_empty_row_returns_empty(self):
        from core.sage.hooks import infer_codeql_build_from_sage_recall_row
        self.assertEqual(infer_codeql_build_from_sage_recall_row(None), {})
        self.assertEqual(
            infer_codeql_build_from_sage_recall_row({"content": ""}), {})

    def test_multi_language(self):
        from core.sage.hooks import infer_codeql_build_from_sage_recall_row
        row = {
            "content": (
                "CodeQL build reliability for repo myapp: "
                "languages cpp, javascript, outcome success, "
                "build command make all, "
                "analyses completed 2, failure modes none."
            ),
            "confidence": 0.85,
        }
        hint = infer_codeql_build_from_sage_recall_row(row)
        self.assertEqual(hint["languages"], "cpp, javascript")
        self.assertEqual(hint["build_command"], "make all")


class TestFuzzingStrategyHooks(unittest.TestCase):
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
    """Singleton init is guarded by _client_lock and _client_initialised."""

    def setUp(self):
        import core.sage.hooks as hooks
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

        self.assertEqual(mock_cls.call_count, 1)
        self.assertEqual(mock_instance.is_available.call_count, 1)


    @patch("core.sage.hooks.SageClient")
    def test_reprobe_after_ttl_expiry(self, mock_cls):
        """When SAGE was unavailable but TTL has elapsed, re-probe."""
        import time
        import core.sage.hooks as hooks

        mock_instance = MagicMock()
        mock_instance.is_available.return_value = False
        mock_cls.return_value = mock_instance

        self.assertIsNone(hooks._get_client())
        self.assertTrue(hooks._client_initialised)
        self.assertEqual(mock_cls.call_count, 1)

        self.assertIsNone(hooks._get_client())
        self.assertEqual(mock_cls.call_count, 1)

        hooks._client_none_decided_at = time.time() - hooks._CLIENT_NONE_TTL_S - 1

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


class TestFindingVerdictHooks(unittest.TestCase):
    """Test cross-run FP suppression hooks."""

    def test_finding_fingerprint_stable(self):
        from core.sage.hooks import _finding_fingerprint
        fp1 = _finding_fingerprint("CWE-89", "src/db.py", "run_query")
        fp2 = _finding_fingerprint("CWE-89", "src/db.py", "run_query")
        self.assertEqual(fp1, fp2)
        self.assertEqual(len(fp1), 16)

    def test_finding_fingerprint_varies_on_input(self):
        from core.sage.hooks import _finding_fingerprint
        fp1 = _finding_fingerprint("CWE-89", "src/db.py", "run_query")
        fp2 = _finding_fingerprint("CWE-79", "src/db.py", "run_query")
        self.assertNotEqual(fp1, fp2)

    @patch("core.sage.hooks._get_client", return_value=None)
    def test_recall_returns_none_when_unavailable(self, _):
        from core.sage.hooks import recall_prior_finding_verdict
        self.assertIsNone(recall_prior_finding_verdict(
            "/repo", "CWE-89", "src/db.py", "run_query", "abc123"))

    def test_recall_returns_none_when_no_source_hash(self):
        from core.sage.hooks import recall_prior_finding_verdict
        self.assertIsNone(recall_prior_finding_verdict(
            "/repo", "CWE-89", "src/db.py", "run_query", ""))

    @patch("core.sage.hooks._get_client")
    def test_recall_matches_on_source_hash_and_verdict(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.query.return_value = [{
            "content": (
                "Finding verdict: fp=abcd1234 rule=CWE-89 "
                "file=src/db.py fn=run_query "
                "||src=deadbeef1234|| ||verdict=false_positive||"
            ),
            "confidence": 0.95,
        }]
        mock_get_client.return_value = mock_client

        from core.sage.hooks import recall_prior_finding_verdict
        result = recall_prior_finding_verdict(
            "/repo", "CWE-89", "src/db.py", "run_query", "deadbeef1234")
        self.assertIsNotNone(result)
        self.assertEqual(result["verdict"], "false_positive")
        self.assertEqual(result["source_hash"], "deadbeef1234")

    @patch("core.sage.hooks._get_client")
    def test_recall_rejects_hash_mismatch(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.query.return_value = [{
            "content": (
                "Finding verdict: fp=abcd1234 rule=CWE-89 "
                "file=src/db.py fn=run_query "
                "||src=deadbeef1234|| ||verdict=false_positive||"
            ),
            "confidence": 0.95,
        }]
        mock_get_client.return_value = mock_client

        from core.sage.hooks import recall_prior_finding_verdict
        result = recall_prior_finding_verdict(
            "/repo", "CWE-89", "src/db.py", "run_query", "different_hash")
        self.assertIsNone(result)

    @patch("core.sage.hooks._get_client")
    def test_recall_ignores_non_suppressible_verdicts(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.query.return_value = [{
            "content": (
                "Finding verdict: fp=abcd1234 rule=CWE-89 "
                "file=src/db.py fn=run_query "
                "||src=deadbeef1234|| ||verdict=exploitable||"
            ),
            "confidence": 0.95,
        }]
        mock_get_client.return_value = mock_client

        from core.sage.hooks import recall_prior_finding_verdict
        result = recall_prior_finding_verdict(
            "/repo", "CWE-89", "src/db.py", "run_query", "deadbeef1234")
        self.assertIsNone(result)

    @patch("core.sage.hooks._get_client")
    def test_recall_rejects_injection_via_file_path(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.query.return_value = [{
            "content": (
                "Finding verdict: fp=abcd1234 rule=CWE-89 "
                "file=src/src=deadbeef1234/db.py fn=run_query "
                "||src=real_hash|| ||verdict=false_positive||"
            ),
            "confidence": 0.95,
        }]
        mock_get_client.return_value = mock_client

        from core.sage.hooks import recall_prior_finding_verdict
        result = recall_prior_finding_verdict(
            "/repo", "CWE-89", "src/db.py", "run_query", "deadbeef1234")
        self.assertIsNone(result)

    @patch("core.sage.hooks._get_client")
    def test_recall_rejects_injection_via_rule_id(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.query.return_value = [{
            "content": (
                "Finding verdict: fp=abcd1234 "
                "rule=verdict=false_positive file=x fn=y "
                "||src=abc123|| ||verdict=exploitable||"
            ),
            "confidence": 0.95,
        }]
        mock_get_client.return_value = mock_client

        from core.sage.hooks import recall_prior_finding_verdict
        result = recall_prior_finding_verdict(
            "/repo", "CWE-89", "x", "y", "abc123")
        self.assertIsNone(result)

    @patch("core.sage.hooks._get_client", return_value=None)
    def test_store_returns_false_when_unavailable(self, _):
        from core.sage.hooks import store_finding_verdict
        self.assertFalse(store_finding_verdict(
            "/repo", "CWE-89", "src/db.py", "run_query",
            "abc123", "false_positive"))

    def test_store_returns_false_when_no_source_hash(self):
        from core.sage.hooks import store_finding_verdict
        self.assertFalse(store_finding_verdict(
            "/repo", "CWE-89", "src/db.py", "run_query",
            "", "false_positive"))

    @patch("core.sage.hooks._get_client")
    def test_store_proposes_with_correct_fields(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.propose.return_value = True
        mock_get_client.return_value = mock_client

        from core.sage.hooks import store_finding_verdict
        result = store_finding_verdict(
            "/repo", "CWE-89", "src/db.py", "run_query",
            "deadbeef1234", "false_positive")
        self.assertTrue(result)

        kwargs = mock_client.propose.call_args.kwargs
        self.assertIn("CWE-89", kwargs["content"])
        self.assertIn("src/db.py", kwargs["content"])
        self.assertIn("run_query", kwargs["content"])
        self.assertIn("||src=deadbeef1234||", kwargs["content"])
        self.assertIn("||verdict=false_positive||", kwargs["content"])
        self.assertEqual(kwargs["memory_type"], "fact")
        self.assertIn("raptor-fp-", kwargs["domain_tag"])
        self.assertEqual(kwargs["confidence"], 0.95)
        self.assertIn("finding", kwargs["tags"])
        self.assertIn("verdict", kwargs["tags"])
        self.assertIn("CWE-89", kwargs["tags"])

    @patch("core.sage.hooks._get_client")
    def test_store_not_exploitable_confidence(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.propose.return_value = True
        mock_get_client.return_value = mock_client

        from core.sage.hooks import store_finding_verdict
        store_finding_verdict(
            "/repo", "CWE-89", "src/db.py", "run_query",
            "abc123", "not_exploitable")
        kwargs = mock_client.propose.call_args.kwargs
        self.assertEqual(kwargs["confidence"], 0.90)

    @patch("core.sage.hooks._get_client")
    def test_recall_handles_error_gracefully(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.query.side_effect = ConnectionError("down")
        mock_get_client.return_value = mock_client

        from core.sage.hooks import recall_prior_finding_verdict
        self.assertIsNone(recall_prior_finding_verdict(
            "/repo", "CWE-89", "src/db.py", "run_query", "abc123"))


class TestRuleLibraryHooks(unittest.TestCase):
    """Tests for N4 rule-library SAGE hooks."""

    def test_parse_rule_metadata_extracts_fields(self):
        from core.sage.hooks import parse_rule_metadata

        row = {
            "content": (
                "Proven checker rule: "
                "||engine=semgrep|| ||cwe=CWE-89|| "
                "||rule_id=sqli-001|| "
                "||rule_body_hash=abcdef123456|| "
                "||rule_path=/out/rule-library/semgrep/sqli-001.yaml|| "
                "||tp_count=5|| ||fp_count=1|| "
                "||total_matches=6|| "
                "||dual_control=True|| "
                "||targets_tested=4||"
            ),
            "confidence": 0.90,
        }
        meta = parse_rule_metadata(row)
        self.assertEqual(meta["engine"], "semgrep")
        self.assertEqual(meta["cwe"], "CWE-89")
        self.assertEqual(meta["rule_id"], "sqli-001")
        self.assertEqual(meta["rule_body_hash"], "abcdef123456")
        self.assertEqual(meta["tp_count"], 5)
        self.assertEqual(meta["fp_count"], 1)
        self.assertEqual(meta["total_matches"], 6)
        self.assertTrue(meta["dual_control"])
        self.assertEqual(meta["targets_tested"], 4)
        self.assertAlmostEqual(meta["confidence"], 0.90)

    def test_parse_rule_metadata_missing_fields(self):
        from core.sage.hooks import parse_rule_metadata

        meta = parse_rule_metadata({"content": "nothing here"})
        self.assertNotIn("engine", meta)
        self.assertNotIn("tp_count", meta)
        self.assertNotIn("dual_control", meta)

    def test_should_replay_rule_qualifies(self):
        from core.sage.hooks import should_replay_rule

        meta = {
            "tp_count": 9,
            "fp_count": 1,
            "dual_control": True,
            "targets_tested": 3,
        }
        self.assertTrue(should_replay_rule(meta))

    def test_should_replay_rule_low_tp_rate(self):
        from core.sage.hooks import should_replay_rule

        meta = {
            "tp_count": 3,
            "fp_count": 3,
            "dual_control": True,
            "targets_tested": 5,
        }
        self.assertFalse(should_replay_rule(meta))

    def test_should_replay_rule_no_dual_control(self):
        from core.sage.hooks import should_replay_rule

        meta = {
            "tp_count": 9,
            "fp_count": 1,
            "dual_control": False,
            "targets_tested": 5,
        }
        self.assertFalse(should_replay_rule(meta))

    def test_should_replay_rule_too_few_targets(self):
        from core.sage.hooks import should_replay_rule

        meta = {
            "tp_count": 9,
            "fp_count": 1,
            "dual_control": True,
            "targets_tested": 2,
        }
        self.assertFalse(should_replay_rule(meta))

    def test_should_replay_rule_zero_matches(self):
        from core.sage.hooks import should_replay_rule

        meta = {"tp_count": 0, "fp_count": 0, "dual_control": True,
                "targets_tested": 5}
        self.assertFalse(should_replay_rule(meta))

    @patch("core.sage.hooks._get_client")
    def test_store_proven_rule_calls_propose(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.propose.return_value = True
        mock_get_client.return_value = mock_client

        from core.sage.hooks import store_proven_rule_metadata
        ok = store_proven_rule_metadata(
            engine="coccinelle",
            cwe="CWE-416",
            rule_id="uaf-001",
            rule_body_hash="deadbeef1234",
            rule_path="/out/rule-library/coccinelle/uaf-001.cocci",
            tp_count=4,
            fp_count=0,
            total_matches=4,
            dual_control_passed=True,
            targets_tested=2,
        )
        self.assertTrue(ok)
        content = mock_client.propose.call_args.kwargs["content"]
        self.assertIn("||engine=coccinelle||", content)
        self.assertIn("||cwe=CWE-416||", content)
        self.assertIn("||rule_body_hash=deadbeef1234||", content)
        self.assertIn("||targets_tested=2||", content)
        self.assertEqual(
            mock_client.propose.call_args.kwargs["confidence"], 0.90)

    @patch("core.sage.hooks._get_client")
    def test_store_without_dual_control_lower_confidence(self, mock_gc):
        mock_client = MagicMock()
        mock_client.propose.return_value = True
        mock_gc.return_value = mock_client

        from core.sage.hooks import store_proven_rule_metadata
        store_proven_rule_metadata(
            engine="semgrep", cwe="CWE-79", rule_id="xss-001",
            rule_body_hash="aabb", rule_path="/tmp/r.yaml",
            tp_count=3, fp_count=1, total_matches=4,
            dual_control_passed=False,
        )
        self.assertEqual(
            mock_client.propose.call_args.kwargs["confidence"], 0.75)

    @patch("core.sage.hooks._get_client")
    def test_recall_proven_rules_returns_rows(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.query.return_value = [
            {"content": "||engine=semgrep|| ||cwe=CWE-89||",
             "confidence": 0.85},
        ]
        mock_get_client.return_value = mock_client

        from core.sage.hooks import recall_proven_rules
        rows = recall_proven_rules("semgrep", "CWE-89")
        self.assertEqual(len(rows), 1)
        mock_client.query.assert_called_once()

    @patch("core.sage.hooks._get_client")
    def test_recall_proven_rules_no_client(self, mock_get_client):
        mock_get_client.return_value = None

        from core.sage.hooks import recall_proven_rules
        self.assertEqual(recall_proven_rules("semgrep", "CWE-89"), [])

    @patch("core.sage.hooks._get_client")
    def test_store_handles_error_gracefully(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.propose.side_effect = ConnectionError("down")
        mock_get_client.return_value = mock_client

        from core.sage.hooks import store_proven_rule_metadata
        ok = store_proven_rule_metadata(
            engine="semgrep", cwe="CWE-79", rule_id="xss-001",
            rule_body_hash="aabb", rule_path="/tmp/r.yaml",
            tp_count=3, fp_count=1, total_matches=4,
            dual_control_passed=True,
        )
        self.assertFalse(ok)

    def test_store_sanitises_pipe_chars(self):
        """Values containing | are sanitised before storage,
        preventing delimiter injection."""
        from core.sage.hooks import _sanitise_delim

        self.assertEqual(_sanitise_delim("evil||tp_count=999||"), "eviltp_count=999")
        self.assertEqual(_sanitise_delim("clean-value"), "clean-value")

    @patch("core.sage.hooks._get_client")
    def test_store_strips_pipes_from_rule_id(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.propose.return_value = True
        mock_get_client.return_value = mock_client

        from core.sage.hooks import store_proven_rule_metadata
        store_proven_rule_metadata(
            engine="semgrep",
            cwe="CWE-89",
            rule_id="evil||tp_count=999||",
            rule_body_hash="aabb",
            rule_path="/tmp/r.yaml",
            tp_count=2,
            fp_count=1,
            total_matches=3,
            dual_control_passed=True,
        )
        content = mock_client.propose.call_args.kwargs["content"]
        self.assertNotIn("||tp_count=999||", content)
        self.assertIn("||tp_count=2||", content)


if __name__ == "__main__":
    unittest.main()
