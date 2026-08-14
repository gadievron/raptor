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
        self._gpu_patch = patch("core.sage.hooks._ollama_gpu_available", return_value=True)
        self._gpu_patch.start()

    def tearDown(self):
        self._gpu_patch.stop()
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


class TestStoreStudyConcepts(unittest.TestCase):
    """Tests for store_study_concepts (N1 study → SAGE)."""

    @patch("core.sage.hooks._get_client", return_value=None)
    def test_returns_zero_when_unavailable(self, _):
        from core.sage.hooks import store_study_concepts
        model = self._make_model()
        self.assertEqual(store_study_concepts("/repo", model), 0)

    @patch("core.sage.hooks._throttle")
    @patch("core.sage.hooks._propose_redacted", return_value=True)
    @patch("core.sage.hooks._get_client")
    def test_stores_concepts_above_inferred(self, mock_gc, mock_pr, _):
        mock_gc.return_value = MagicMock()
        from core.sage.hooks import store_study_concepts
        model = self._make_model()
        stored = store_study_concepts("/repo", model, study_scope="crypto/")
        self.assertEqual(stored, 2)
        self.assertEqual(mock_pr.call_count, 2)

    @patch("core.sage.hooks._throttle")
    @patch("core.sage.hooks._propose_redacted", return_value=True)
    @patch("core.sage.hooks._get_client")
    def test_skips_inferred_concepts(self, mock_gc, mock_pr, _):
        mock_gc.return_value = MagicMock()
        from core.sage.hooks import store_study_concepts
        model = self._make_model(only_inferred=True)
        stored = store_study_concepts("/repo", model)
        self.assertEqual(stored, 0)
        mock_pr.assert_not_called()

    @patch("core.sage.hooks._throttle")
    @patch("core.sage.hooks._propose_redacted", return_value=True)
    @patch("core.sage.hooks._get_client")
    def test_inlines_invariants_and_contracts(self, mock_gc, mock_pr, _):
        mock_gc.return_value = MagicMock()
        from core.sage.hooks import store_study_concepts
        model = self._make_model()
        store_study_concepts("/repo", model)
        content = mock_pr.call_args_list[0][1]["content"]
        self.assertIn("Invariant", content)
        self.assertIn("Contract", content)

    @patch("core.sage.hooks._throttle")
    @patch("core.sage.hooks._propose_redacted", side_effect=Exception("boom"))
    @patch("core.sage.hooks._get_client")
    def test_handles_propose_error(self, mock_gc, mock_pr, _):
        mock_gc.return_value = MagicMock()
        from core.sage.hooks import store_study_concepts
        model = self._make_model()
        stored = store_study_concepts("/repo", model)
        self.assertEqual(stored, 0)

    @staticmethod
    def _make_model(only_inferred=False):
        from dataclasses import dataclass, field

        @dataclass
        class FakeEvidence:
            type: str = "code_path"
            file: str = "auth.c"
            observation: str = "refcount incremented"
            line: int = 42
            item: str = "get_page"
            hash: str = ""

        @dataclass
        class FakeConcept:
            id: str = "page_ownership"
            description: str = "Pages are owned by the SGL"
            evidence: list = field(default_factory=lambda: [FakeEvidence()])
            confidence: str = "inferred" if only_inferred else "traced"
            state: str = "proposed"

        @dataclass
        class FakeInvariant:
            id: str = "inv_refcount"
            concept: str = "page_ownership"
            statement: str = "Every page has exactly one owner"
            negation: str = "Double-free or leak"
            relevant_cwes: list = field(default_factory=lambda: ["CWE-415"])
            mechanism_tags: list = field(default_factory=lambda: ["refcount"])
            mechanism_keywords: list = field(default_factory=list)
            confidence: str = "traced"

        @dataclass
        class FakeContract:
            function: str = "get_page"
            file: str = "auth.c"
            when: str = "before use"
            ownership_transfer: str = "caller to callee"
            input_semantics: str = ""
            output_semantics: str = ""
            implication: str = ""
            hash: str = ""

        @dataclass
        class FakeModel:
            concepts: list = field(default_factory=list)
            invariants: list = field(default_factory=list)
            contracts: list = field(default_factory=list)

        if only_inferred:
            return FakeModel(
                concepts=[FakeConcept(), FakeConcept(id="c2")],
                invariants=[],
                contracts=[],
            )
        return FakeModel(
            concepts=[
                FakeConcept(),
                FakeConcept(id="page_transfer", description="TX→RX"),
            ],
            invariants=[FakeInvariant()],
            contracts=[FakeContract()],
        )


class TestRecallConceptsForTeach(unittest.TestCase):
    """Tests for recall_concepts_for_teach (N1 teach ← SAGE)."""

    @patch("core.sage.hooks._get_client", return_value=None)
    def test_returns_empty_when_unavailable(self, _):
        from core.sage.hooks import recall_concepts_for_teach
        self.assertEqual(
            recall_concepts_for_teach("/repo", "struct page"), []
        )

    @patch("core.sage.hooks._get_client")
    def test_queries_both_domains(self, mock_gc):
        mock_client = MagicMock()
        mock_client.query.return_value = [
            {"content": "Concept [page_ownership]", "confidence": 0.85}
        ]
        mock_gc.return_value = mock_client

        from core.sage.hooks import recall_concepts_for_teach
        results = recall_concepts_for_teach("/repo", "struct page")
        self.assertEqual(mock_client.query.call_count, 2)
        self.assertGreater(len(results), 0)

    @patch("core.sage.hooks._get_client")
    def test_handles_error_gracefully(self, mock_gc):
        mock_client = MagicMock()
        mock_client.query.side_effect = ConnectionError("SAGE down")
        mock_gc.return_value = mock_client

        from core.sage.hooks import recall_concepts_for_teach
        self.assertEqual(
            recall_concepts_for_teach("/repo", "struct page"), []
        )

    @patch("core.sage.hooks._get_client")
    def test_respects_min_confidence(self, mock_gc):
        mock_client = MagicMock()
        mock_gc.return_value = mock_client
        mock_client.query.return_value = []

        from core.sage.hooks import recall_concepts_for_teach
        recall_concepts_for_teach("/repo", "page", min_confidence=0.90)
        call_kwargs = mock_client.query.call_args_list[0][1]
        self.assertEqual(call_kwargs["min_confidence"], 0.90)


class TestRecallConceptsForStudy(unittest.TestCase):
    """Tests for recall_concepts_for_study (N1 study ← SAGE)."""

    @patch("core.sage.hooks._get_client", return_value=None)
    def test_returns_empty_when_unavailable(self, _):
        from core.sage.hooks import recall_concepts_for_study
        self.assertEqual(
            recall_concepts_for_study("/repo", ["get_page", "put_page"]), {}
        )

    @patch("core.sage.hooks._get_client")
    def test_returns_per_identifier(self, mock_gc):
        mock_client = MagicMock()
        mock_client.query.side_effect = [
            [{"content": "get_page concept", "confidence": 0.8}],
            [],
        ]
        mock_gc.return_value = mock_client

        from core.sage.hooks import recall_concepts_for_study
        result = recall_concepts_for_study("/repo", ["get_page", "put_page"])
        self.assertIn("get_page", result)
        self.assertNotIn("put_page", result)

    @patch("core.sage.hooks._get_client")
    def test_handles_partial_errors(self, mock_gc):
        mock_client = MagicMock()
        mock_client.query.side_effect = [
            ConnectionError("boom"),
            [{"content": "put_page concept", "confidence": 0.8}],
        ]
        mock_gc.return_value = mock_client

        from core.sage.hooks import recall_concepts_for_study
        result = recall_concepts_for_study("/repo", ["get_page", "put_page"])
        self.assertNotIn("get_page", result)
        self.assertIn("put_page", result)


class TestApplyRelevanceGate(unittest.TestCase):
    """Tests for _apply_relevance_gate (N1 relevance scoring)."""

    def test_drops_below_threshold(self):
        from core.sage.hooks import _apply_relevance_gate
        rows = [{"content": "unrelated stuff", "confidence": 0.1}]
        scored = _apply_relevance_gate(rows)
        self.assertEqual(scored, [])

    def test_file_overlap_boosts_score(self):
        from core.sage.hooks import _apply_relevance_gate
        rows = [
            {"content": "Evidence files: auth.c, crypto.c", "confidence": 0.7}
        ]
        no_overlap = _apply_relevance_gate(rows, evidence_files=["unrelated.c"])
        with_overlap = _apply_relevance_gate(rows, evidence_files=["auth.c"])
        self.assertGreater(
            with_overlap[0]["relevance_score"],
            no_overlap[0]["relevance_score"] if no_overlap else 0,
        )

    def test_function_overlap_boosts_score(self):
        from core.sage.hooks import _apply_relevance_gate
        rows = [
            {"content": "Contract [get_page] when: before use", "confidence": 0.7}
        ]
        with_fn = _apply_relevance_gate(
            rows, inventory_functions=["get_page"]
        )
        without_fn = _apply_relevance_gate(
            rows, inventory_functions=["unrelated_fn"]
        )
        self.assertGreater(
            with_fn[0]["relevance_score"],
            without_fn[0]["relevance_score"] if without_fn else 0,
        )

    def test_broader_scope_boosts_score(self):
        from core.sage.hooks import _apply_relevance_gate
        broad = [{"content": "Study scope: linux\nOther content", "confidence": 0.7}]
        narrow = [{"content": "Study scope: net/crypto/af_alg/impl\nOther content", "confidence": 0.7}]
        broad_scored = _apply_relevance_gate(broad)
        narrow_scored = _apply_relevance_gate(narrow)
        if broad_scored and narrow_scored:
            self.assertGreater(
                broad_scored[0]["relevance_score"],
                narrow_scored[0]["relevance_score"],
            )

    def test_no_context_still_scores(self):
        from core.sage.hooks import _apply_relevance_gate
        rows = [{"content": "Concept [page_ownership]", "confidence": 0.8}]
        scored = _apply_relevance_gate(rows)
        self.assertEqual(len(scored), 1)
        self.assertGreater(scored[0]["relevance_score"], 0.3)


class TestAuditHypothesisVerdict(unittest.TestCase):
    """Tests for store/recall audit hypothesis verdicts."""

    @patch("core.sage.hooks._get_client", return_value=None)
    def test_store_returns_false_when_unavailable(self, _):
        from core.sage.hooks import store_audit_hypothesis_verdict
        self.assertFalse(store_audit_hypothesis_verdict(
            repo_path="/repo", file_path="ipc/msg.c", function="do_msgsnd",
            hypothesis="unchecked copy_from_user return",
            status="clean", evidence_tool="semgrep", source_hash="abc123",
        ))

    def test_store_rejects_empty_hash(self):
        from core.sage.hooks import store_audit_hypothesis_verdict
        self.assertFalse(store_audit_hypothesis_verdict(
            repo_path="/repo", file_path="ipc/msg.c", function="do_msgsnd",
            hypothesis="test", status="clean", evidence_tool="",
            source_hash="",
        ))

    def test_store_rejects_empty_hypothesis(self):
        from core.sage.hooks import store_audit_hypothesis_verdict
        self.assertFalse(store_audit_hypothesis_verdict(
            repo_path="/repo", file_path="ipc/msg.c", function="do_msgsnd",
            hypothesis="", status="clean", evidence_tool="",
            source_hash="abc123",
        ))

    @patch("core.sage.hooks._propose_redacted", return_value=True)
    @patch("core.sage.hooks._get_client")
    def test_store_succeeds(self, mock_gc, mock_pr):
        mock_gc.return_value = MagicMock()
        from core.sage.hooks import store_audit_hypothesis_verdict
        ok = store_audit_hypothesis_verdict(
            repo_path="/repo", file_path="ipc/msg.c", function="do_msgsnd",
            hypothesis="unchecked copy_from_user return",
            status="finding", evidence_tool="semgrep",
            source_hash="abc123def456",
        )
        self.assertTrue(ok)
        content = mock_pr.call_args[1]["content"]
        self.assertIn("||src=abc123def456||", content)
        self.assertIn("||status=finding||", content)
        self.assertIn("||tool=semgrep||", content)
        self.assertIn("unchecked copy_from_user", content)

    @patch("core.sage.hooks._propose_redacted", return_value=True)
    @patch("core.sage.hooks._get_client")
    def test_tool_confirmed_gets_high_confidence(self, mock_gc, mock_pr):
        mock_gc.return_value = MagicMock()
        from core.sage.hooks import store_audit_hypothesis_verdict
        store_audit_hypothesis_verdict(
            repo_path="/repo", file_path="f.c", function="fn",
            hypothesis="test", status="clean", evidence_tool="semgrep",
            source_hash="h",
        )
        self.assertEqual(mock_pr.call_args[1]["confidence"], 0.90)

    @patch("core.sage.hooks._propose_redacted", return_value=True)
    @patch("core.sage.hooks._get_client")
    def test_no_tool_gets_lower_confidence(self, mock_gc, mock_pr):
        mock_gc.return_value = MagicMock()
        from core.sage.hooks import store_audit_hypothesis_verdict
        store_audit_hypothesis_verdict(
            repo_path="/repo", file_path="f.c", function="fn",
            hypothesis="test", status="suspicious", evidence_tool="",
            source_hash="h",
        )
        self.assertEqual(mock_pr.call_args[1]["confidence"], 0.75)

    @patch("core.sage.hooks._get_client", return_value=None)
    def test_recall_returns_none_when_unavailable(self, _):
        from core.sage.hooks import recall_audit_hypothesis_verdict
        self.assertIsNone(recall_audit_hypothesis_verdict(
            repo_path="/repo", file_path="f.c", function="fn",
            hypothesis="test", source_hash="h",
        ))

    @patch("core.sage.hooks._get_client")
    def test_recall_matches_clean_verdict(self, mock_gc):
        from core.sage.hooks import recall_audit_hypothesis_verdict
        from core.hash import sha256_string
        hyp = "unchecked return value"
        hyp_hash = sha256_string(hyp)[:16]
        mock_client = MagicMock()
        mock_client.query.return_value = [{
            "content": (
                f"Audit hypothesis verdict: "
                f"||file=ipc/msg.c|| ||fn=do_msgsnd|| "
                f"||hyp={hyp_hash}|| ||src=abc123|| "
                f"||status=clean|| ||tool=semgrep||"
            ),
            "confidence": 0.90,
        }]
        mock_gc.return_value = mock_client
        result = recall_audit_hypothesis_verdict(
            repo_path="/repo", file_path="ipc/msg.c", function="do_msgsnd",
            hypothesis=hyp, source_hash="abc123",
        )
        self.assertIsNotNone(result)
        self.assertEqual(result["status"], "clean")
        self.assertEqual(result["tool"], "semgrep")

    @patch("core.sage.hooks._get_client")
    def test_recall_rejects_finding_verdict(self, mock_gc):
        from core.sage.hooks import recall_audit_hypothesis_verdict
        from core.hash import sha256_string
        hyp = "test hypothesis"
        hyp_hash = sha256_string(hyp)[:16]
        mock_client = MagicMock()
        mock_client.query.return_value = [{
            "content": (
                f"Audit hypothesis verdict: "
                f"||hyp={hyp_hash}|| ||src=abc123|| "
                f"||status=finding|| ||tool=semgrep||"
            ),
            "confidence": 0.90,
        }]
        mock_gc.return_value = mock_client
        result = recall_audit_hypothesis_verdict(
            repo_path="/repo", file_path="f.c", function="fn",
            hypothesis=hyp, source_hash="abc123",
        )
        self.assertIsNone(result)

    @patch("core.sage.hooks._get_client")
    def test_recall_rejects_stale_hash(self, mock_gc):
        from core.sage.hooks import recall_audit_hypothesis_verdict
        from core.hash import sha256_string
        hyp = "test"
        hyp_hash = sha256_string(hyp)[:16]
        mock_client = MagicMock()
        mock_client.query.return_value = [{
            "content": (
                f"Audit hypothesis verdict: "
                f"||hyp={hyp_hash}|| ||src=old_hash|| "
                f"||status=clean|| ||tool=semgrep||"
            ),
            "confidence": 0.90,
        }]
        mock_gc.return_value = mock_client
        result = recall_audit_hypothesis_verdict(
            repo_path="/repo", file_path="f.c", function="fn",
            hypothesis=hyp, source_hash="new_hash",
        )
        self.assertIsNone(result)

    @patch("core.sage.hooks._get_client")
    def test_recall_matches_dormant_verdict(self, mock_gc):
        from core.sage.hooks import recall_audit_hypothesis_verdict
        from core.hash import sha256_string
        hyp = "dead code path"
        hyp_hash = sha256_string(hyp)[:16]
        mock_client = MagicMock()
        mock_client.query.return_value = [{
            "content": (
                f"Audit hypothesis verdict: "
                f"||hyp={hyp_hash}|| ||src=h1|| "
                f"||status=dormant|| ||tool=||"
            ),
            "confidence": 0.85,
        }]
        mock_gc.return_value = mock_client
        result = recall_audit_hypothesis_verdict(
            repo_path="/repo", file_path="f.c", function="fn",
            hypothesis=hyp, source_hash="h1",
        )
        self.assertIsNotNone(result)
        self.assertEqual(result["status"], "dormant")

    @patch("core.sage.hooks._get_client")
    def test_recall_without_hypothesis_matches(self, mock_gc):
        """Pre-review recall (no hypothesis) matches on src hash alone."""
        from core.sage.hooks import recall_audit_hypothesis_verdict
        mock_client = MagicMock()
        mock_client.query.return_value = [{
            "content": (
                "Audit hypothesis verdict: "
                "||file=f.c|| ||fn=fn|| "
                "||hyp=abcd1234|| ||src=h1|| "
                "||status=clean|| ||tool=semgrep:test||"
            ),
            "confidence": 0.90,
        }]
        mock_gc.return_value = mock_client
        result = recall_audit_hypothesis_verdict(
            repo_path="/repo", file_path="f.c", function="fn",
            source_hash="h1",
        )
        self.assertIsNotNone(result)
        self.assertEqual(result["status"], "clean")

    @patch("core.sage.hooks._get_client")
    def test_recall_without_hypothesis_rejects_stale(self, mock_gc):
        """Pre-review recall (no hypothesis) rejects stale hash."""
        from core.sage.hooks import recall_audit_hypothesis_verdict
        mock_client = MagicMock()
        mock_client.query.return_value = [{
            "content": (
                "Audit hypothesis verdict: "
                "||hyp=abcd|| ||src=old|| "
                "||status=clean|| ||tool=||"
            ),
            "confidence": 0.90,
        }]
        mock_gc.return_value = mock_client
        result = recall_audit_hypothesis_verdict(
            repo_path="/repo", file_path="f.c", function="fn",
            source_hash="new",
        )
        self.assertIsNone(result)


class TestAuditObservation(unittest.TestCase):
    """Tests for store/recall audit observations."""

    @patch("core.sage.hooks._get_client", return_value=None)
    def test_store_returns_false_when_unavailable(self, _):
        from core.sage.hooks import store_audit_observation
        self.assertFalse(store_audit_observation(
            repo_path="/repo",
            observation="semgrep confirmed unchecked return",
            kind="tool_confirmation",
            source_function="ipc/msg.c:do_msgsnd",
        ))

    def test_store_rejects_llm_observation(self):
        from core.sage.hooks import store_audit_observation
        self.assertFalse(store_audit_observation(
            repo_path="/repo",
            observation="this looks suspicious because of the pattern",
            kind="llm_observation",
            source_function="f.c:fn",
        ))

    def test_store_rejects_short_text(self):
        from core.sage.hooks import store_audit_observation
        self.assertFalse(store_audit_observation(
            repo_path="/repo", observation="short",
            kind="tool_confirmation", source_function="f.c:fn",
        ))

    @patch("core.sage.hooks._propose_redacted", return_value=True)
    @patch("core.sage.hooks._get_client")
    def test_store_confirmation(self, mock_gc, mock_pr):
        mock_gc.return_value = MagicMock()
        from core.sage.hooks import store_audit_observation
        ok = store_audit_observation(
            repo_path="/repo",
            observation="[tool-confirmed] semgrep confirmed: unchecked copy_from_user return",
            kind="tool_confirmation",
            source_function="ipc/msg.c:do_msgsnd",
        )
        self.assertTrue(ok)
        self.assertEqual(mock_pr.call_args[1]["domain_tag"], "raptor-methodology")
        self.assertEqual(mock_pr.call_args[1]["confidence"], 0.85)

    @patch("core.sage.hooks._propose_redacted", return_value=True)
    @patch("core.sage.hooks._get_client")
    def test_store_refutation(self, mock_gc, mock_pr):
        mock_gc.return_value = MagicMock()
        from core.sage.hooks import store_audit_observation
        ok = store_audit_observation(
            repo_path="/repo",
            observation="[tool-refuted] hypothesis 'buffer overflow' was not confirmed",
            kind="tool_refutation",
            source_function="f.c:fn",
        )
        self.assertTrue(ok)
        self.assertEqual(mock_pr.call_args[1]["confidence"], 0.75)

    @patch("core.sage.hooks._get_client", return_value=None)
    def test_recall_returns_empty_when_unavailable(self, _):
        from core.sage.hooks import recall_audit_observations
        self.assertEqual(recall_audit_observations("unchecked return"), [])

    @patch("core.sage.hooks._get_client")
    def test_recall_filters_to_audit_observations(self, mock_gc):
        mock_client = MagicMock()
        mock_client.query.return_value = [
            {"content": "Audit observation (tool_confirmation): semgrep confirmed X",
             "confidence": 0.85},
            {"content": "Unrelated SAGE memory about something else",
             "confidence": 0.80},
        ]
        mock_gc.return_value = mock_client
        from core.sage.hooks import recall_audit_observations
        results = recall_audit_observations("unchecked return")
        self.assertEqual(len(results), 1)
        self.assertIn("Audit observation", results[0]["content"])


class TestAuditSageIntegration(unittest.TestCase):
    """Combined tests: store then recall in the same flow."""

    @patch("core.sage.hooks._get_client")
    def test_roundtrip_hypothesis_clean(self, mock_gc):
        """Store clean verdict, recall it with same hash — should match."""
        from core.sage.hooks import (
            store_audit_hypothesis_verdict,
            recall_audit_hypothesis_verdict,
        )
        from core.hash import sha256_string

        stored_content = {}

        def fake_propose(**kwargs):
            stored_content["content"] = kwargs["content"]
            return True

        hyp = "return value not checked after ioctl"
        hyp_hash = sha256_string(hyp)[:16]

        mock_client = MagicMock()
        mock_gc.return_value = mock_client

        with patch("core.sage.hooks._propose_redacted", side_effect=fake_propose):
            store_audit_hypothesis_verdict(
                repo_path="/repo", file_path="drivers/net/foo.c",
                function="foo_ioctl", hypothesis=hyp,
                status="clean", evidence_tool="semgrep",
                source_hash="hashA",
            )

        self.assertIn("||status=clean||", stored_content["content"])
        self.assertIn(f"||hyp={hyp_hash}||", stored_content["content"])

        mock_client.query.return_value = [{
            "content": stored_content["content"],
            "confidence": 0.90,
        }]

        result = recall_audit_hypothesis_verdict(
            repo_path="/repo", file_path="drivers/net/foo.c",
            function="foo_ioctl", hypothesis=hyp,
            source_hash="hashA",
        )
        self.assertIsNotNone(result)
        self.assertEqual(result["status"], "clean")

    @patch("core.sage.hooks._get_client")
    def test_roundtrip_hypothesis_stale_after_edit(self, mock_gc):
        """Store clean verdict, recall with different hash — should not match."""
        from core.sage.hooks import (
            store_audit_hypothesis_verdict,
            recall_audit_hypothesis_verdict,
        )
        stored_content = {}

        def fake_propose(**kwargs):
            stored_content["content"] = kwargs["content"]
            return True

        hyp = "integer overflow in size calculation"
        mock_client = MagicMock()
        mock_gc.return_value = mock_client

        with patch("core.sage.hooks._propose_redacted", side_effect=fake_propose):
            store_audit_hypothesis_verdict(
                repo_path="/repo", file_path="mm/slab.c",
                function="kmalloc", hypothesis=hyp,
                status="clean", evidence_tool="smt",
                source_hash="original_hash",
            )

        mock_client.query.return_value = [{
            "content": stored_content["content"],
            "confidence": 0.90,
        }]

        result = recall_audit_hypothesis_verdict(
            repo_path="/repo", file_path="mm/slab.c",
            function="kmalloc", hypothesis=hyp,
            source_hash="edited_hash",
        )
        self.assertIsNone(result)

    @patch("core.sage.hooks._get_client")
    def test_observation_and_hypothesis_different_domains(self, mock_gc):
        """Observations go to methodology, hypotheses to audit-{key}."""
        from core.sage.hooks import (
            store_audit_hypothesis_verdict,
            store_audit_observation,
        )

        domains_seen = []

        def capture_propose(**kwargs):
            domains_seen.append(kwargs["domain_tag"])
            return True

        mock_gc.return_value = MagicMock()

        with patch("core.sage.hooks._propose_redacted", side_effect=capture_propose):
            store_audit_hypothesis_verdict(
                repo_path="/repo", file_path="f.c", function="fn",
                hypothesis="test hyp", status="clean",
                evidence_tool="", source_hash="h",
            )
            store_audit_observation(
                repo_path="/repo",
                observation="[tool-confirmed] semgrep confirmed: unchecked return value pattern",
                kind="tool_confirmation",
                source_function="f.c:fn",
            )

        self.assertEqual(len(domains_seen), 2)
        self.assertTrue(domains_seen[0].startswith("raptor-audit-"))
        self.assertEqual(domains_seen[1], "raptor-methodology")


if __name__ == "__main__":
    unittest.main()
