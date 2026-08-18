"""Tests for core.audit.checker_synthesis — mid-loop checker amplification.

Tests the delegation to ``packages.checker_synthesis`` via the
``synthesize_and_sweep`` adapter, the ``_seed_from_outcome`` builder,
and the ``SynthesisResult`` dataclass.
"""

from unittest.mock import patch

import pytest

from core.audit.checker_synthesis import (
    SynthesisResult,
    _build_llm_callable,
    _seed_from_outcome,
    synthesize_and_sweep,
)


class TestSynthesisResult:
    def test_basic(self):
        r = SynthesisResult(
            rule_id="synth-cwe-120-parse_header",
            tool="semgrep",
            content="rules:\n  - id: test",
            cwe="CWE-120",
            origin_file="parser.c",
            origin_function="parse_header",
            hits=[{"file": "other.c", "function": "process", "line": 42}],
        )
        assert r.rule_id == "synth-cwe-120-parse_header"
        assert len(r.hits) == 1

    def test_empty_hits(self):
        r = SynthesisResult(
            rule_id="r", tool="semgrep", content="c",
            cwe="CWE-120", origin_file="a.c", origin_function="f",
        )
        assert r.hits == []


# ---------------------------------------------------------------------------
# _seed_from_outcome
# ---------------------------------------------------------------------------


class _StubOutcome:
    """Minimal ReviewOutcome-shaped object for tests."""
    def __init__(self, **kwargs):
        self.file = kwargs.get("file", "src/auth.c")
        self.function = kwargs.get("function", "check_pw")
        self.line = kwargs.get("line", 42)
        self.hypothesis = kwargs.get("hypothesis", "")
        self.status = kwargs.get("status", "finding")
        self.evidence_tool = kwargs.get("evidence_tool", "semgrep")
        self.review_result = kwargs.get("review_result", {
            "hypothesis": "missing bounds check on len",
            "cwe_class": "CWE-120",
            "source_snippet": "memcpy(dst, buf, len);",
        })


class _StubConfig:
    def __init__(self, **kwargs):
        self.target_path = kwargs.get("target_path", "/tmp/target")
        self.out_dir = kwargs.get("out_dir", "/tmp/out")
        self.codeql_db_path = kwargs.get("codeql_db_path", None)


class TestSeedFromOutcome:
    def test_builds_seed_from_outcome(self):
        o = _StubOutcome()
        seed = _seed_from_outcome(o)
        assert seed is not None
        assert seed.file == "src/auth.c"
        assert seed.function == "check_pw"
        assert seed.cwe == "CWE-120"
        assert "bounds check" in seed.reasoning

    def test_returns_none_without_hypothesis(self):
        o = _StubOutcome(review_result={"cwe_class": "CWE-120"})
        assert _seed_from_outcome(o) is None

    def test_returns_none_without_cwe(self):
        o = _StubOutcome(review_result={"hypothesis": "test"})
        assert _seed_from_outcome(o) is None

    def test_returns_none_without_file(self):
        o = _StubOutcome(file="")
        assert _seed_from_outcome(o) is None

    def test_returns_none_without_function(self):
        o = _StubOutcome(function="")
        assert _seed_from_outcome(o) is None

    def test_falls_back_to_outcome_hypothesis(self):
        o = _StubOutcome(
            hypothesis="fallback hypothesis",
            review_result={"cwe_class": "CWE-89"},
        )
        seed = _seed_from_outcome(o)
        assert seed is not None
        assert seed.reasoning == "fallback hypothesis"

    def test_uses_source_snippet(self):
        o = _StubOutcome()
        seed = _seed_from_outcome(o)
        assert seed is not None
        assert seed.snippet == "memcpy(dst, buf, len);"

    def test_line_mapped_to_start_and_end(self):
        o = _StubOutcome(line=99)
        seed = _seed_from_outcome(o)
        assert seed is not None
        assert seed.line_start == 99
        assert seed.line_end == 99


# ---------------------------------------------------------------------------
# _build_llm_callable
# ---------------------------------------------------------------------------


class _BareClient:
    """LLM client without generate_structured."""


class TestBuildLLMCallable:
    @pytest.mark.slow
    def test_returns_none_without_generate_structured(self):
        with patch("core.llm.client.LLMClient", return_value=_BareClient()):
            assert _build_llm_callable(_StubConfig()) is None

    def test_returns_callable_with_generate_structured(self):
        class _FullClient:
            total_cost = 0.0

            def generate_structured(self, **kw):
                return {"result": True}, {}

        with patch("core.llm.client.LLMClient", return_value=_FullClient()):
            result = _build_llm_callable(_StubConfig())
            assert result is not None
            fn, _client = result
            assert callable(fn)

    def test_call_passes_synthesis_timeout(self):
        """Synthesis is the heaviest structured call class — the
        callable must pass its own per-call timeout so the claudecode
        provider's 600s default doesn't kill it mid-generation."""
        from core.audit.checker_synthesis import SYNTHESIS_TIMEOUT_S

        class _CapturingClient:
            total_cost = 0.0
            captured = None

            def generate_structured(self, **kw):
                _CapturingClient.captured = kw
                return {"result": True}, {}

        with patch("core.llm.client.LLMClient",
                   return_value=_CapturingClient()):
            fn, _client = _build_llm_callable(_StubConfig())
            out = fn("prompt", {"type": "object"}, "system")
            assert out == {"result": True}
            assert (_CapturingClient.captured["timeout_s"]
                    == SYNTHESIS_TIMEOUT_S)
            assert SYNTHESIS_TIMEOUT_S > 600


# ---------------------------------------------------------------------------
# synthesize_and_sweep — delegation to packages.checker_synthesis
# ---------------------------------------------------------------------------


class TestSynthesizeAndSweepDelegation:
    def test_cap_reached_returns_none(self):
        o = _StubOutcome()
        assert synthesize_and_sweep(
            o, _StubConfig(), set(), synthesis_count=5, max_per_run=5,
        ) is None

    def test_no_hypothesis_returns_none(self):
        o = _StubOutcome(review_result={})
        assert synthesize_and_sweep(o, _StubConfig(), set()) is None

    def test_no_target_path_returns_none(self):
        o = _StubOutcome()
        c = _StubConfig(target_path=None)

        class _FakeClient:
            total_cost = 0.0

        with patch(
            "core.audit.checker_synthesis._build_llm_callable",
            return_value=(lambda p, s, sp: None, _FakeClient()),
        ):
            assert synthesize_and_sweep(o, c, set()) is None

    def test_delegates_to_synthesise_with_refinement(self, tmp_path):
        from packages.checker_synthesis import (
            CheckerSynthesisResult,
            Match,
            SynthesisedRule,
        )

        captured = {}

        def _fake_refinement(seed, *, repo_root, out_dir, llm, **kw):
            captured["seed"] = seed
            captured["repo_root"] = repo_root
            return CheckerSynthesisResult(
                seed=seed,
                rule=SynthesisedRule(
                    engine="semgrep", rule_id="synth.0", body="rules: ...",
                ),
                matches=[
                    Match(file="src/other.c", line=10, snippet="bad()"),
                    Match(file="src/auth.c", line=42, snippet="same"),
                ],
                positive_control=True,
            )

        def _fake_llm_callable(_config):
            class _FakeClient:
                total_cost = 0.0
            return lambda p, s, sp: {"rule": "r"}, _FakeClient()

        o = _StubOutcome()
        c = _StubConfig(target_path=str(tmp_path), out_dir=str(tmp_path))

        with patch(
            "core.audit.checker_synthesis._build_llm_callable",
            side_effect=_fake_llm_callable,
        ), patch(
            "packages.checker_synthesis.synthesise_with_refinement",
            side_effect=_fake_refinement,
        ):
            result = synthesize_and_sweep(o, c, set())

        assert result is not None
        assert result.rule_id == "synth.0"
        assert result.tool == "semgrep"
        assert result.cwe == "CWE-120"
        assert result.origin_file == "src/auth.c"
        # Both matches are emitted; the seed's own function is excluded
        # downstream by function identity, not here by line.
        assert [h["file"] for h in result.hits] == ["src/other.c", "src/auth.c"]
        assert all(h["origin_function"] == "check_pw" for h in result.hits)

    def _sweep_with_matches(self, tmp_path, matches, seen=None):
        from packages.checker_synthesis import (
            CheckerSynthesisResult,
            SynthesisedRule,
        )

        def _fake_refinement(seed, **kw):
            return CheckerSynthesisResult(
                seed=seed,
                rule=SynthesisedRule(
                    engine="semgrep", rule_id="synth.1", body="r",
                ),
                matches=list(matches),
                positive_control=True,
            )

        def _fake_llm_callable(_config):
            class _FakeClient:
                total_cost = 0.0
            return lambda p, s, sp: {"rule": "r"}, _FakeClient()

        o = _StubOutcome()
        c = _StubConfig(target_path=str(tmp_path), out_dir=str(tmp_path))

        with patch(
            "core.audit.checker_synthesis._build_llm_callable",
            side_effect=_fake_llm_callable,
        ), patch(
            "packages.checker_synthesis.synthesise_with_refinement",
            side_effect=_fake_refinement,
        ):
            return synthesize_and_sweep(o, c, seen if seen is not None else set())

    def test_sites_survive_a_prior_run_key(self, tmp_path):
        """A site is not suppressed by `<file>:<seed function>`.

        The old key paired the *matched* file with the *seed's* function
        name, which identifies nothing, and `seen_keys` spans prior runs
        — so a real variant could be dropped by coincidence. Sites are
        function-less; dedup belongs downstream once each is resolved.
        """
        from packages.checker_synthesis import Match

        result = self._sweep_with_matches(
            tmp_path,
            [Match(file="src/already_seen.c", line=5)],
            seen={"src/already_seen.c:check_pw"},
        )
        assert result is not None
        assert [h["file"] for h in result.hits] == ["src/already_seen.c"]

    def test_same_file_sibling_is_kept(self, tmp_path):
        """A second vulnerable function in the seed's own file counts.

        `m.file != file_path` used to discard every same-file match.
        """
        from packages.checker_synthesis import Match

        result = self._sweep_with_matches(
            tmp_path, [Match(file="src/auth.c", line=99)],
        )
        assert [(h["file"], h["line"]) for h in result.hits] == [
            ("src/auth.c", 99),
        ]

    def test_origin_is_attached_to_every_hit(self, tmp_path):
        """Downstream excludes the seed by function identity, so each hit
        must say which finding it came from."""
        from packages.checker_synthesis import Match

        result = self._sweep_with_matches(
            tmp_path,
            [Match(file="src/auth.c", line=42),
             Match(file="src/other.c", line=99)],
        )
        assert [(h["origin_file"], h["origin_function"]) for h in result.hits] == [
            ("src/auth.c", "check_pw"), ("src/auth.c", "check_pw"),
        ]

    def test_synthesis_failure_returns_none(self, tmp_path):
        from packages.checker_synthesis import CheckerSynthesisResult

        def _fake_refinement(seed, **kw):
            return CheckerSynthesisResult(seed=seed, rule=None)

        def _fake_llm_callable(_config):
            class _FakeClient:
                total_cost = 0.0
            return lambda p, s, sp: {"rule": "r"}, _FakeClient()

        o = _StubOutcome()
        c = _StubConfig(target_path=str(tmp_path), out_dir=str(tmp_path))

        with patch(
            "core.audit.checker_synthesis._build_llm_callable",
            side_effect=_fake_llm_callable,
        ), patch(
            "packages.checker_synthesis.synthesise_with_refinement",
            side_effect=_fake_refinement,
        ):
            assert synthesize_and_sweep(o, c, set()) is None

    def test_exception_in_substrate_returns_none(self, tmp_path):
        def _fake_llm_callable(_config):
            class _FakeClient:
                total_cost = 0.0
            return lambda p, s, sp: {"rule": "r"}, _FakeClient()

        o = _StubOutcome()
        c = _StubConfig(target_path=str(tmp_path), out_dir=str(tmp_path))

        with patch(
            "core.audit.checker_synthesis._build_llm_callable",
            side_effect=_fake_llm_callable,
        ), patch(
            "packages.checker_synthesis.synthesise_with_refinement",
            side_effect=RuntimeError("substrate boom"),
        ):
            assert synthesize_and_sweep(o, c, set()) is None


# ---------------------------------------------------------------------------
# _sage_replay_rule — SAGE-recalled proven rules join sweeps (P33)
# ---------------------------------------------------------------------------


class TestSageReplayRule:
    def _seed(self):
        from packages.checker_synthesis import SeedBug

        return SeedBug(
            file="src/auth.c", function="check_pw",
            line_start=42, line_end=42,
            cwe="CWE-89", reasoning="sql injection",
        )

    def _meta(self, rule_path, body, **kw):
        import hashlib

        meta = {
            "engine": "semgrep",
            "cwe": "CWE-89",
            "rule_id": "sqli-001",
            "rule_body_hash": hashlib.sha256(
                body.encode("utf-8")).hexdigest()[:16],
            "rule_path": str(rule_path),
            "tp_count": 9,
            "fp_count": 1,
            "total_matches": 10,
            "dual_control": True,
            "targets_tested": 4,
            "verified": True,
        }
        meta.update(kw)
        return meta

    def test_replays_verified_rule_with_sage_provenance(self, tmp_path):
        from core.audit.checker_synthesis import _sage_replay_rule
        from packages.checker_synthesis import Match

        body = "rules:\n  - id: sqli-001\n"
        rule_file = tmp_path / "sqli-001.yaml"
        rule_file.write_text(body)

        with patch(
            "core.sage.recall_verified_proven_rules",
            return_value=[self._meta(rule_file, body)],
        ), patch(
            "packages.checker_synthesis.synthesise._run_engine",
            return_value=(
                [Match(file="src/other.c", line=7, snippet="q()")], [],
            ),
        ):
            replay = _sage_replay_rule(
                "semgrep", "CWE-89", self._seed(), tmp_path,
            )

        assert replay is not None
        cs_result, provenance = replay
        assert provenance == "sage:sqli-001"
        assert cs_result.rule.rule_id == "sqli-001"
        assert cs_result.rule_tier == "library"
        assert cs_result.dual_control is True
        assert [m.file for m in cs_result.matches] == ["src/other.c"]

    def test_body_hash_mismatch_skipped(self, tmp_path):
        from core.audit.checker_synthesis import _sage_replay_rule

        rule_file = tmp_path / "sqli-001.yaml"
        rule_file.write_text("rules:\n  - id: TAMPERED\n")
        meta = self._meta(rule_file, "rules:\n  - id: sqli-001\n")

        with patch(
            "core.sage.recall_verified_proven_rules", return_value=[meta],
        ):
            assert _sage_replay_rule(
                "semgrep", "CWE-89", self._seed(), tmp_path,
            ) is None

    def test_missing_rule_file_skipped(self, tmp_path):
        from core.audit.checker_synthesis import _sage_replay_rule

        meta = self._meta(tmp_path / "gone.yaml", "body")
        with patch(
            "core.sage.recall_verified_proven_rules", return_value=[meta],
        ):
            assert _sage_replay_rule(
                "semgrep", "CWE-89", self._seed(), tmp_path,
            ) is None

    def test_no_verified_rows_returns_none(self, tmp_path):
        from core.audit.checker_synthesis import _sage_replay_rule

        with patch(
            "core.sage.recall_verified_proven_rules", return_value=[],
        ):
            assert _sage_replay_rule(
                "semgrep", "CWE-89", self._seed(), tmp_path,
            ) is None

    def test_sweep_hits_carry_sage_provenance(self, tmp_path):
        """synthesize_and_sweep stamps sage: provenance on hits when
        the rule came from SAGE replay."""
        from packages.checker_synthesis import (
            CheckerSynthesisResult,
            Match,
            SynthesisedRule,
        )

        def _fake_llm_callable(_config):
            class _FakeClient:
                total_cost = 0.0

            return lambda p, s, sp: {"rule": "r"}, _FakeClient()

        def _fake_sage_replay(engine, cwe, seed, target_path):
            cs = CheckerSynthesisResult(
                seed=seed,
                rule=SynthesisedRule(
                    engine="semgrep", rule_id="sqli-001", body="r",
                ),
                matches=[Match(file="src/other.c", line=7, snippet="q()")],
            )
            cs.rule_tier = "library"
            return cs, "sage:sqli-001"

        class _NoReplayLib:
            def find_replayable(self, cwe, engine):
                return []

        o = _StubOutcome()
        c = _StubConfig(target_path=str(tmp_path), out_dir=str(tmp_path))

        with patch(
            "core.audit.checker_synthesis._build_llm_callable",
            side_effect=_fake_llm_callable,
        ), patch(
            "packages.checker_synthesis.RuleLibrary",
            return_value=_NoReplayLib(),
        ), patch(
            "core.audit.checker_synthesis._sage_replay_rule",
            side_effect=_fake_sage_replay,
        ):
            result = synthesize_and_sweep(o, c, set())

        assert result is not None
        assert result.rule_id == "sqli-001"
        assert all(h["provenance"] == "sage:sqli-001" for h in result.hits)
