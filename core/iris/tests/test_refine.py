"""Tests for core.iris.refine — iterative spec refinement loop."""

import json

from core.evidence import EvidenceTier
from core.iris.assumptions import (
    AssumptionCategory,
    BypassFinding,
    SafetyAssumption,
)
from core.iris.refine import (
    RefinementFeedback,
    _build_outcomes,
    _demote_refuted,
    _inject_bypass_candidates,
    _promote_confirmed,
    refine_loop,
)
from core.iris.specs import CandidateFunction, TaintSpec
from core.iris.store import RoundRecord, _spec_key
from core.iris.synthesise import _ASSUMPTION_SYSTEM_PROMPT


def _cand(fn="check_input", file="src/auth.py", **kw):
    return CandidateFunction(function=fn, file=file, **kw)


def _spec(fn="check_input", file="src/auth.py", role="sanitiser", **kw):
    return TaintSpec(function=fn, file=file, role=role, **kw)


class TestRefinementFeedback:
    def test_tp_rate_all_confirmed(self):
        fb = RefinementFeedback(confirmed_keys=["a", "b", "c"])
        assert fb.tp_rate == 1.0

    def test_tp_rate_mixed(self):
        fb = RefinementFeedback(
            confirmed_keys=["a", "b"],
            refuted_keys=["c"],
        )
        assert abs(fb.tp_rate - 2 / 3) < 0.01

    def test_tp_rate_none(self):
        fb = RefinementFeedback()
        assert fb.tp_rate == 0.0

    def test_to_dict(self):
        fb = RefinementFeedback(
            confirmed_keys=["a"],
            refuted_keys=["b"],
            tool_errors=["c"],
        )
        d = fb.to_dict()
        assert d["confirmed_keys"] == ["a"]
        assert d["refuted_keys"] == ["b"]
        assert d["tool_errors"] == ["c"]


class TestPromoteConfirmed:
    def test_promotes_matching(self):
        specs = [_spec(evidence_tier=EvidenceTier.HEURISTIC)]
        key = _spec_key(specs[0])
        fb = RefinementFeedback(confirmed_keys=[key])
        result = _promote_confirmed(specs, fb)
        assert result[0].evidence_tier == EvidenceTier.XREF_BACKED

    def test_no_change_when_already_higher(self):
        specs = [_spec(evidence_tier=EvidenceTier.SMT_PROVED)]
        key = _spec_key(specs[0])
        fb = RefinementFeedback(confirmed_keys=[key])
        result = _promote_confirmed(specs, fb)
        assert result[0].evidence_tier == EvidenceTier.SMT_PROVED

    def test_no_confirmed(self):
        specs = [_spec()]
        result = _promote_confirmed(specs, RefinementFeedback())
        assert len(result) == 1


class TestDemoteRefuted:
    def test_removes_heuristic(self):
        specs = [_spec(evidence_tier=EvidenceTier.HEURISTIC)]
        key = _spec_key(specs[0])
        fb = RefinementFeedback(refuted_keys=[key])
        result = _demote_refuted(specs, fb)
        assert len(result) == 0

    def test_keeps_confirmed(self):
        specs = [_spec(evidence_tier=EvidenceTier.XREF_BACKED)]
        key = _spec_key(specs[0])
        fb = RefinementFeedback(refuted_keys=[key])
        result = _demote_refuted(specs, fb)
        assert len(result) == 1

    def test_no_refuted(self):
        specs = [_spec()]
        result = _demote_refuted(specs, RefinementFeedback())
        assert len(result) == 1


class TestRefineLoop:
    def test_single_round_heuristic(self):
        """No LLM, single tool round."""
        def tool_runner(specs):
            return RefinementFeedback(
                confirmed_keys=[_spec_key(s) for s in specs],
            )

        cands = [_cand(fn="sanitize_html")]
        specs, history, *_ = refine_loop(
            cands, None, tool_runner, max_rounds=1,
        )
        assert len(specs) >= 1
        assert len(history) == 1
        assert history[0].n_confirmed >= 1
        confirmed = [s for s in specs if s.evidence_tier == EvidenceTier.XREF_BACKED]
        assert len(confirmed) >= 1

    def test_convergence_stops_early(self):
        round_count = []

        def tool_runner(specs):
            round_count.append(1)
            return RefinementFeedback(
                confirmed_keys=[_spec_key(s) for s in specs],
            )

        cands = [_cand(fn="sanitize_html")]
        specs, history, *_ = refine_loop(
            cands, None, tool_runner,
            max_rounds=5, convergence_threshold=0.5,
        )
        assert len(round_count) == 1  # converged at round 0

    def test_fixpoint_stops(self):
        round_count = []

        def tool_runner(specs):
            round_count.append(1)
            return RefinementFeedback()

        cands = [_cand(fn="sanitize_html")]
        specs, history, *_ = refine_loop(
            cands, None, tool_runner,
            max_rounds=5, convergence_threshold=0.99,
        )
        # Empty feedback has tp_rate=0.0, so convergence doesn't trigger.
        # Fixpoint detection stops at round 1 (specs unchanged).
        assert len(round_count) == 2

    def test_max_rounds_respected(self):
        round_count = []

        def tool_runner(specs):
            round_count.append(1)
            return RefinementFeedback(
                confirmed_keys=[_spec_key(specs[0])] if specs else [],
                refuted_keys=[_spec_key(specs[1])] if len(specs) > 1 else [],
            )

        cands = [
            _cand(fn="sanitize_html"),
            _cand(fn="exec_cmd"),
            _cand(fn="read_input"),
        ]
        specs, history, *_ = refine_loop(
            cands, None, tool_runner,
            max_rounds=2, convergence_threshold=0.99,
        )
        assert len(round_count) <= 2

    def test_tool_failure_graceful(self):
        def failing_runner(specs):
            raise RuntimeError("joern crashed")

        cands = [_cand(fn="sanitize_html")]
        specs, history, *_ = refine_loop(
            cands, None, failing_runner, max_rounds=1,
        )
        assert len(specs) >= 1
        assert len(history) == 1
        assert history[0].n_errors >= 1

    def test_empty_candidates(self):
        def tool_runner(specs):
            return RefinementFeedback()

        specs, history, *_ = refine_loop([], None, tool_runner, max_rounds=1)
        assert specs == []
        assert history == []

    def test_prior_specs_merged(self):
        prior = [_spec(fn="known_sink", role="sink",
                       evidence_tier=EvidenceTier.XREF_BACKED)]

        def tool_runner(specs):
            return RefinementFeedback(
                confirmed_keys=[_spec_key(s) for s in specs],
            )

        cands = [_cand(fn="new_sanitiser")]
        specs, history, *_ = refine_loop(
            cands, None, tool_runner,
            prior_specs=prior, max_rounds=1,
        )
        funcs = {s.function for s in specs}
        assert "known_sink" in funcs
        assert "new_sanitiser" in funcs

    def test_no_tool_runner_synthesis_only(self):
        """Without a tool runner, synthesis runs but no refinement rounds."""
        cands = [_cand(fn="sanitize_html"), _cand(fn="exec_cmd")]
        specs, history, *_ = refine_loop(
            cands, None, None,
            max_rounds=3,
        )
        assert len(specs) >= 2
        assert history == []
        for s in specs:
            assert s.evidence_tier == EvidenceTier.HEURISTIC

    def test_no_tool_runner_merges_prior(self):
        """Synthesis-only mode still merges prior specs."""
        prior = [_spec(fn="known_sink", role="sink",
                       evidence_tier=EvidenceTier.XREF_BACKED)]
        cands = [_cand(fn="sanitize_html")]
        specs, history, *_ = refine_loop(
            cands, None, None,
            prior_specs=prior, max_rounds=2,
        )
        funcs = {s.function for s in specs}
        assert "known_sink" in funcs
        assert "sanitize_html" in funcs
        assert history == []
        known = [s for s in specs if s.function == "known_sink"]
        assert known[0].evidence_tier == EvidenceTier.XREF_BACKED

    def test_with_mock_llm_refinement(self):
        """Two rounds with LLM producing refined specs."""
        call_count = []

        def mock_llm(system, user):
            call_count.append(1)
            return json.dumps([{
                "function": "check_input",
                "file": "src/auth.py",
                "role": "sanitiser",
                "confidence": 0.9,
            }])

        def tool_runner(specs):
            return RefinementFeedback(
                confirmed_keys=[_spec_key(s) for s in specs[:1]],
                refuted_keys=[_spec_key(s) for s in specs[1:2]],
            )

        cands = [_cand(fn="check_input"), _cand(fn="bad_guess")]
        specs, history, *_ = refine_loop(
            cands, mock_llm, tool_runner,
            max_rounds=2, convergence_threshold=0.99,
        )
        assert len(history) >= 1
        assert len(call_count) >= 1

    def test_scorecard_recording(self):
        """When a scorecard is provided, outcomes are recorded."""
        from unittest.mock import MagicMock

        sc = MagicMock()

        def tool_runner(specs):
            keys = [_spec_key(s) for s in specs]
            return RefinementFeedback(
                confirmed_keys=keys[:1],
                refuted_keys=keys[1:2],
            )

        cands = [_cand(fn="exec_cmd"), _cand(fn="bad_guess")]
        specs, history, *_ = refine_loop(
            cands, None, tool_runner,
            max_rounds=1, scorecard=sc, model="test-model",
        )
        assert sc.record_event.call_count >= 1
        calls = sc.record_event.call_args_list
        decision_classes = [c[0][0] for c in calls]
        assert all(dc == "iris_spec_quality" for dc in decision_classes)

    def test_scorecard_none_no_error(self):
        """scorecard=None must not raise."""
        def tool_runner(specs):
            return RefinementFeedback(
                confirmed_keys=[_spec_key(s) for s in specs],
            )

        cands = [_cand(fn="exec_cmd")]
        specs, history, *_ = refine_loop(
            cands, None, tool_runner,
            max_rounds=1, scorecard=None, model="m",
        )
        assert len(history) == 1


class TestToolCrashDoesNotConverge:
    """H1 fix: tool crash should not masquerade as convergence."""

    def test_crash_populates_tool_errors(self):
        def crashing_runner(specs):
            raise RuntimeError("joern segfault")

        cands = [_cand(fn="exec_cmd"), _cand(fn="sanitize_html")]
        specs, history, *_ = refine_loop(
            cands, None, crashing_runner, max_rounds=2,
        )
        assert len(history) >= 1
        assert history[0].n_errors >= 1

    def test_crash_does_not_stop_loop_early(self):
        round_count = []

        def crashing_then_ok(specs):
            round_count.append(1)
            if len(round_count) == 1:
                raise RuntimeError("first round crash")
            return RefinementFeedback(
                confirmed_keys=[_spec_key(s) for s in specs],
            )

        cands = [_cand(fn="exec_cmd")]
        specs, history, *_ = refine_loop(
            cands, None, crashing_then_ok,
            max_rounds=2, convergence_threshold=0.5,
        )
        assert len(round_count) == 2


class TestFixpointDetection:
    """Verify actual fixpoint detection (prev_keys == current_keys)."""

    def test_fixpoint_stops_when_specs_unchanged(self):
        round_count = []

        def no_change_runner(specs):
            round_count.append(1)
            return RefinementFeedback(
                confirmed_keys=[_spec_key(specs[0])],
                refuted_keys=[],
            )

        cands = [_cand(fn="exec_cmd")]
        specs, history, *_ = refine_loop(
            cands, None, no_change_runner,
            max_rounds=5, convergence_threshold=0.99,
        )
        assert len(round_count) <= 3


class TestBuildOutcomes:
    def test_confirmed_and_refuted(self):
        specs = [
            _spec(fn="exec_cmd", role="sink", taint_classes=["cmd"]),
            _spec(fn="read_input", role="source", taint_classes=["sql"]),
            _spec(fn="untested", role="sink"),
        ]
        feedback = RefinementFeedback(
            confirmed_keys=[_spec_key(specs[0])],
            refuted_keys=[_spec_key(specs[1])],
        )
        outcomes = _build_outcomes(specs, feedback)
        assert len(outcomes) == 2
        confirmed = [o for o in outcomes if o.confirmed is True]
        refuted = [o for o in outcomes if o.confirmed is False]
        assert len(confirmed) == 1
        assert confirmed[0].function == "exec_cmd"
        assert len(refuted) == 1
        assert refuted[0].function == "read_input"

    def test_untested_excluded(self):
        specs = [_spec(fn="some_fn", role="sink")]
        feedback = RefinementFeedback()
        outcomes = _build_outcomes(specs, feedback)
        assert len(outcomes) == 0


# ── Phase B: bypass integration ─────────────────────────────────────


def _assumption(target="sink", enforced_by=None, **kw):
    return SafetyAssumption(
        target=target,
        file=kw.pop("file", "src/db.c"),
        assumption=f"{target} requires enforcer",
        category=kw.pop("category", AssumptionCategory.ORDERING),
        enforced_by=enforced_by or ["guard"],
        **kw,
    )


def _bypass(target="sink", caller="bad_caller", via=None, **kw):
    return BypassFinding(
        assumption=_assumption(target),
        caller_file=kw.pop("caller_file", "src/handler.c"),
        caller_function=caller,
        missing_enforcer="guard",
        via_intermediate=via,
        is_transitive=via is not None,
        **kw,
    )


class TestInjectBypassCandidates:
    def test_no_bypass_findings_returns_original(self):
        cands = [_cand(fn="exec_cmd")]
        result = _inject_bypass_candidates(cands, [])
        assert result is cands

    def test_adds_intermediate(self):
        cands = [_cand(fn="exec_cmd")]
        bf = _bypass(via="do_work")
        result = _inject_bypass_candidates(cands, [bf])
        funcs = {c.function for c in result}
        assert "do_work" in funcs
        assert "exec_cmd" in funcs

    def test_no_duplicate_injection(self):
        cands = [_cand(fn="do_work", file="src/handler.c")]
        bf = _bypass(via="do_work")
        result = _inject_bypass_candidates(cands, [bf])
        assert len(result) == 1

    def test_no_injection_without_intermediate(self):
        cands = [_cand(fn="exec_cmd")]
        bf = _bypass(via=None)
        result = _inject_bypass_candidates(cands, [bf])
        assert len(result) == 1

    def test_reason_set(self):
        cands = [_cand(fn="exec_cmd")]
        bf = _bypass(via="do_work")
        result = _inject_bypass_candidates(cands, [bf])
        new = [c for c in result if c.function == "do_work"]
        assert "bypass intermediate" in new[0].reason


class TestRoundRecordBypass:
    def test_n_bypass_recorded(self):
        rec = RoundRecord(round=0, n_specs=5, n_bypass=3)
        assert rec.n_bypass == 3

    def test_n_bypass_default_zero(self):
        rec = RoundRecord(round=0, n_specs=5)
        assert rec.n_bypass == 0

    def test_feedback_to_dict_has_no_bypass(self):
        fb = RefinementFeedback(confirmed_keys=["a"])
        d = fb.to_dict()
        assert "bypass_count" not in d
        assert "bypass_findings" not in d


class TestRefineLoopBypass:
    @staticmethod
    def _dual_llm(system, user):
        """Return spec or assumption JSON depending on the system prompt."""
        if system == _ASSUMPTION_SYSTEM_PROMPT:
            return json.dumps([{
                "target": "exec_cmd",
                "file": "src/auth.py",
                "assumption": "must validate input",
                "category": "validation",
                "enforced_by": ["validate_input"],
                "confidence": 0.9,
            }])
        return json.dumps([{
            "function": "exec_cmd",
            "file": "src/auth.py",
            "role": "sink",
            "confidence": 0.9,
        }])

    def test_bypass_runner_called(self):
        calls = []

        def bypass_runner(assumptions):
            calls.append(assumptions)
            return [_bypass(via="intermediate")]

        cands = [_cand(fn="exec_cmd")]
        specs, history, assumptions, bypass_findings = refine_loop(
            cands, self._dual_llm, None,
            bypass_runner=bypass_runner,
            max_rounds=1,
        )
        assert len(calls) >= 1
        assert len(bypass_findings) >= 1

    def test_bypass_findings_returned(self):
        def bypass_runner(assumptions):
            return [_bypass(via="intermediate")]

        cands = [_cand(fn="exec_cmd")]
        specs, history, assumptions, bypass_findings = refine_loop(
            cands, self._dual_llm, None,
            bypass_runner=bypass_runner,
        )
        assert len(bypass_findings) == 1
        assert bypass_findings[0].via_intermediate == "intermediate"

    def test_no_bypass_runner_no_findings(self):
        cands = [_cand(fn="sanitize_html")]
        specs, history, assumptions, bypass_findings = refine_loop(
            cands, None, None,
        )
        assert bypass_findings == []
        assert assumptions == []

    def test_prior_assumptions_returned(self):
        prior_a = [_assumption(target="exec_cmd")]
        cands = [_cand(fn="sanitize_html")]
        specs, history, assumptions, bypass_findings = refine_loop(
            cands, None, None,
            prior_assumptions=prior_a,
        )
        assert len(assumptions) >= 1
        assert assumptions[0].target == "exec_cmd"

    def test_bypass_runner_failure_graceful(self):
        def bad_runner(assumptions):
            raise RuntimeError("graph unavailable")

        cands = [_cand(fn="exec_cmd")]
        specs, history, assumptions, bypass_findings = refine_loop(
            cands, self._dual_llm, None,
            bypass_runner=bad_runner,
        )
        assert bypass_findings == []

    def test_bypass_in_refinement_round(self):
        """Bypass runner fires during refinement rounds too."""
        round_calls = []

        def bypass_runner(assumptions):
            round_calls.append(1)
            return [_bypass(via="mid")]

        def tool_runner(specs):
            return RefinementFeedback()

        cands = [_cand(fn="exec_cmd"), _cand(fn="read_input")]
        specs, history, assumptions, bypass_findings = refine_loop(
            cands, self._dual_llm, tool_runner,
            bypass_runner=bypass_runner,
            max_rounds=3,
            convergence_threshold=0.99,
        )
        assert len(round_calls) >= 2


class TestRefineTierCarriedThroughSavePath:
    """End-to-end tier flow: refine loop → persist → gated reader.

    The precondition the baseline-reduction note documented: refined
    SANITISER specs must not flow into suppression-direction readers
    untiered. A tool-confirmed sanitiser (promoted to XREF_BACKED in
    the loop) reaches ``get_project_sanitisers``; an unconfirmed
    heuristic one persists as hint-only and does not.
    """

    def test_confirmed_suppresses_heuristic_does_not(self, tmp_path):
        from core.iris.api import get_project_sanitisers, load_project_specs
        from core.iris.store import load_specs, persist_refined_specs

        confirmed = _spec(fn="real_sanitiser", role="sanitiser")
        unconfirmed = _spec(fn="llm_guess", file="src/b.py",
                            role="sanitiser")
        confirmed_key = _spec_key(confirmed)

        def tool_runner(specs):
            return RefinementFeedback(
                confirmed_keys=[
                    k for k in (_spec_key(s) for s in specs)
                    if k == confirmed_key
                ],
            )

        refined, history, assumptions, _bypass = refine_loop(
            [_cand(fn="sanitize_extra", file="src/c.py")],
            llm_client=None, tool_runner=tool_runner,
            prior_specs=[confirmed, unconfirmed], max_rounds=1,
        )

        by_fn = {s.function: s for s in refined}
        assert by_fn["real_sanitiser"].evidence_tier == EvidenceTier.XREF_BACKED
        assert by_fn["llm_guess"].evidence_tier == EvidenceTier.HEURISTIC

        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        persist_refined_specs(run_dir, refined, history=[])

        stored = {s.function: s for s in load_specs(run_dir)}
        assert stored["real_sanitiser"].evidence_tier == EvidenceTier.XREF_BACKED
        assert stored["llm_guess"].evidence_tier == EvidenceTier.HEURISTIC

        # Suppression-direction reader: only the corroborated one.
        assert get_project_sanitisers(out_dir=run_dir) == {"real_sanitiser"}
        # Prompt-direction: both visible as context.
        assert {
            s.function
            for s in load_project_specs(out_dir=run_dir, roles={"sanitiser"})
        } == {"real_sanitiser", "llm_guess", "sanitize_extra"}
