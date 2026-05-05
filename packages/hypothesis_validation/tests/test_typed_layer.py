"""Plain-dataclass tests for the typed-plan layer.

Four areas, in the order the design doc lists them:

  1. Structured hypothesis fields: optional, additive, round-trippable.
  2. Evidence provenance: refers_to + stable hash_hypothesis.
  3. Verdict ladder: verdict_from preserves the runner's downgrade rules.
  4. Iteration guard: must_progress raises iff progress isn't strict.

The runner-behavior assertions in section 3 are the load-bearing ones —
they pin down that pulling the downgrade rules out of `runner._evaluate`
into `verdict_from` left the runner's behaviour unchanged.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from packages.hypothesis_validation import (
    Evidence,
    FlowStep,
    Hypothesis,
    IterationStalled,
    IterationStep,
    ProvenanceMismatch,
    SinkLocation,
    SourceLocation,
    aggregate,
    ensure_same_provenance,
    hash_hypothesis,
    must_progress,
    uncertainty,
    verdict_from,
)
from packages.hypothesis_validation.adapters.base import ToolEvidence


# 1. Structured hypothesis fields ---------------------------------------------


class TestStructuredFields:
    """Optional structured fields are additive — no breaking changes."""

    def test_minimal_hypothesis_has_no_structure(self):
        h = Hypothesis(claim="x", target=Path("/src"))
        assert h.source is None
        assert h.sink is None
        assert h.flow_steps == []
        assert h.sanitizers == []
        assert h.smt_constraints == []

    def test_to_dict_omits_unset_structured_fields(self):
        h = Hypothesis(claim="x", target=Path("/src"))
        d = h.to_dict()
        # Legacy serialised shape — none of the new keys are present
        # when the caller didn't set them.
        for key in ("source", "sink", "flow_steps", "sanitizers", "smt_constraints"):
            assert key not in d

    def test_round_trip_with_structured_fields(self):
        h = Hypothesis(
            claim="cmd injection in handler",
            target=Path("src/handler.c"),
            cwe="CWE-78",
            source=SourceLocation(kind="network", function="recv_request", line=42),
            sink=SinkLocation(kind="exec", function="run_cmd", line=170),
            flow_steps=[
                FlowStep(file="src/handler.c", function="recv_request", line=50,
                         description="copy into buf"),
                FlowStep(file="src/handler.c", function="run_cmd", line=170,
                         description="passed to system()"),
            ],
            sanitizers=["shell_quote", "validate_arg"],
            smt_constraints=["len(buf) > 0", "buf[0] != '/'"],
        )
        h2 = Hypothesis.from_dict(h.to_dict())
        assert h2.source == h.source
        assert h2.sink == h.sink
        assert h2.flow_steps == h.flow_steps
        assert h2.sanitizers == h.sanitizers
        assert h2.smt_constraints == h.smt_constraints

    def test_partial_structure_is_allowed(self):
        # Only sink set — adapters should handle the partial case.
        h = Hypothesis(
            claim="x",
            target=Path("/src"),
            sink=SinkLocation(kind="deref", line=10),
        )
        d = h.to_dict()
        assert d["sink"] == {"kind": "deref", "file": "", "function": "", "line": 10}
        assert "source" not in d
        assert "flow_steps" not in d


# 2. Evidence provenance ------------------------------------------------------


class TestEvidenceRefersTo:
    def test_refers_to_defaults_to_empty(self):
        e = Evidence(tool="t", rule="r", summary="s")
        assert e.refers_to == ""

    def test_refers_to_round_trips_when_set(self):
        e = Evidence(tool="t", rule="r", summary="s", refers_to="abc")
        assert e.to_dict()["refers_to"] == "abc"

    def test_to_dict_omits_refers_to_when_empty(self):
        e = Evidence(tool="t", rule="r", summary="s")
        # Legacy shape preserved — `refers_to` only appears when set.
        assert "refers_to" not in e.to_dict()


class TestHashHypothesis:
    def test_hash_is_64_hex(self):
        h = Hypothesis(claim="x", target=Path("/src"))
        out = hash_hypothesis(h)
        assert len(out) == 64
        int(out, 16)  # parses as hex

    def test_hash_is_stable(self):
        h = Hypothesis(claim="x", target=Path("/src"), cwe="CWE-78")
        assert hash_hypothesis(h) == hash_hypothesis(h)

    def test_hash_distinguishes_content(self):
        a = Hypothesis(claim="a", target=Path("/src"))
        b = Hypothesis(claim="b", target=Path("/src"))
        assert hash_hypothesis(a) != hash_hypothesis(b)

    def test_hash_normalises_whitespace(self):
        # The hash spec says: collapse runs of whitespace, strip ends.
        # "foo bar" and "foo   bar" must hash the same.
        a = Hypothesis(claim="foo bar", target=Path("/src"))
        b = Hypothesis(claim="foo   bar", target=Path("/src"))
        c = Hypothesis(claim="foo\n\tbar", target=Path("/src"))
        d = Hypothesis(claim="  foo bar  ", target=Path("/src"))
        assert hash_hypothesis(a) == hash_hypothesis(b)
        assert hash_hypothesis(a) == hash_hypothesis(c)
        assert hash_hypothesis(a) == hash_hypothesis(d)

    def test_hash_distinguishes_non_whitespace_changes(self):
        a = Hypothesis(claim="foo bar", target=Path("/src"))
        b = Hypothesis(claim="foo  bar!", target=Path("/src"))  # added '!'
        assert hash_hypothesis(a) != hash_hypothesis(b)

    def test_hash_independent_of_field_order(self):
        # to_dict + sort_keys means dict-order doesn't matter; reconstruct
        # via from_dict to confirm (Python preserves insertion order, so
        # the only way order would matter is if sort_keys weren't applied).
        h = Hypothesis(
            claim="x", target=Path("/src"), cwe="CWE-1",
            suggested_tools=["a", "b"], context="ctx",
        )
        h2 = Hypothesis.from_dict(h.to_dict())
        assert hash_hypothesis(h) == hash_hypothesis(h2)

    def test_hash_includes_structured_fields(self):
        # Structured fields must contribute to the hash — otherwise an
        # iteration that only refines source/sink would look identical.
        bare = Hypothesis(claim="x", target=Path("/src"))
        with_source = Hypothesis(
            claim="x", target=Path("/src"),
            source=SourceLocation(kind="network"),
        )
        assert hash_hypothesis(bare) != hash_hypothesis(with_source)


class TestEnsureSameProvenance:
    def test_empty_returns_empty_string(self):
        assert ensure_same_provenance([]) == ""

    def test_single_hash_passes(self):
        e1 = Evidence(tool="t", rule="r", summary="s", refers_to="abc")
        e2 = Evidence(tool="u", rule="r", summary="s", refers_to="abc")
        assert ensure_same_provenance([e1, e2]) == "abc"

    def test_mismatch_raises(self):
        e1 = Evidence(tool="t", rule="r", summary="s", refers_to="abc")
        e2 = Evidence(tool="u", rule="r", summary="s", refers_to="xyz")
        with pytest.raises(ProvenanceMismatch):
            ensure_same_provenance([e1, e2])

    def test_unset_refers_to_is_skipped_not_treated_as_match(self):
        e1 = Evidence(tool="t", rule="r", summary="s")  # refers_to=""
        e2 = Evidence(tool="u", rule="r", summary="s", refers_to="abc")
        assert ensure_same_provenance([e1, e2]) == "abc"

    def test_all_unset_returns_empty(self):
        e1 = Evidence(tool="t", rule="r", summary="s")
        e2 = Evidence(tool="u", rule="r", summary="s")
        assert ensure_same_provenance([e1, e2]) == ""


# 3. Verdict ladder -----------------------------------------------------------


class TestVerdictFrom:
    """Mirrors the runner's three downgrade rules exactly."""

    def _ev(self, success=True, matches=None, error=""):
        return ToolEvidence(
            tool="t", rule="r",
            success=success,
            matches=matches or [],
            error=error,
        )

    # Rule 1: tool failure → inconclusive
    def test_tool_failure_inconclusive_regardless_of_claim(self):
        ev = self._ev(success=False, error="boom")
        for claim in ("confirmed", "refuted", "inconclusive"):
            assert verdict_from(ev, claim) == "inconclusive"

    # Rule 2: confirmed without matches → refuted
    def test_confirmed_without_matches_downgrades_to_refuted(self):
        ev = self._ev(success=True, matches=[])
        assert verdict_from(ev, "confirmed") == "refuted"

    # Rule 3: refuted with matches → inconclusive
    def test_refuted_with_matches_downgrades_to_inconclusive(self):
        ev = self._ev(success=True, matches=[{"file": "x", "line": 1}])
        assert verdict_from(ev, "refuted") == "inconclusive"

    # Pass-through cases
    def test_confirmed_with_matches_passes_through(self):
        ev = self._ev(success=True, matches=[{"file": "x", "line": 1}])
        assert verdict_from(ev, "confirmed") == "confirmed"

    def test_refuted_without_matches_passes_through(self):
        ev = self._ev(success=True, matches=[])
        assert verdict_from(ev, "refuted") == "refuted"

    def test_inconclusive_passes_through(self):
        ev_a = self._ev(success=True, matches=[])
        ev_b = self._ev(success=True, matches=[{"file": "x", "line": 1}])
        assert verdict_from(ev_a, "inconclusive") == "inconclusive"
        assert verdict_from(ev_b, "inconclusive") == "inconclusive"

    def test_unknown_claim_coerced_to_inconclusive(self):
        ev = self._ev(success=True, matches=[])
        assert verdict_from(ev, "garbage") == "inconclusive"

    def test_default_claim_is_inconclusive(self):
        ev = self._ev(success=True, matches=[])
        assert verdict_from(ev) == "inconclusive"


class TestAggregate:
    def _ev(self, success=True, matches=None, error=""):
        return ToolEvidence(
            tool="t", rule="r",
            success=success,
            matches=matches or [],
            error=error,
        )

    def test_empty_is_inconclusive(self):
        assert aggregate([], "confirmed") == "inconclusive"

    def test_all_agree_confirmed(self):
        evs = [
            self._ev(matches=[{"file": "a", "line": 1}]),
            self._ev(matches=[{"file": "b", "line": 2}]),
        ]
        assert aggregate(evs, "confirmed") == "confirmed"

    def test_one_failure_collapses_aggregate(self):
        evs = [
            self._ev(matches=[{"file": "a", "line": 1}]),
            self._ev(success=False, error="oops"),
        ]
        assert aggregate(evs, "confirmed") == "inconclusive"

    def test_disagreement_collapses(self):
        # First adapter: matches → claim "confirmed" passes through.
        # Second adapter: no matches → "confirmed" downgrades to "refuted".
        # Two distinct verdicts → meet collapses to inconclusive.
        evs = [
            self._ev(matches=[{"file": "a", "line": 1}]),
            self._ev(matches=[]),
        ]
        assert aggregate(evs, "confirmed") == "inconclusive"


class TestRunnerStillUsesDowngrades:
    """Behaviour-preservation: refactor must not change runner output."""

    def _setup(self):
        from unittest.mock import MagicMock
        from packages.hypothesis_validation.runner import _evaluate
        return _evaluate, MagicMock

    def test_runner_downgrades_confirmed_without_matches(self):
        _evaluate, MagicMock = self._setup()
        client = MagicMock()
        client.generate_structured.return_value = {
            "verdict": "confirmed", "reasoning": "tried"
        }
        ev = ToolEvidence(tool="t", rule="r", success=True, matches=[])
        h = Hypothesis(claim="x", target=Path("/src"))
        verdict, _ = _evaluate(h, ev, client, task_type="audit")
        assert verdict == "refuted"

    def test_runner_downgrades_refuted_with_matches(self):
        _evaluate, MagicMock = self._setup()
        client = MagicMock()
        client.generate_structured.return_value = {
            "verdict": "refuted", "reasoning": "spurious"
        }
        ev = ToolEvidence(
            tool="t", rule="r", success=True,
            matches=[{"file": "x", "line": 1}],
        )
        h = Hypothesis(claim="x", target=Path("/src"))
        verdict, _ = _evaluate(h, ev, client, task_type="audit")
        assert verdict == "inconclusive"

    def test_runner_passes_confirmed_with_matches(self):
        _evaluate, MagicMock = self._setup()
        client = MagicMock()
        client.generate_structured.return_value = {
            "verdict": "confirmed", "reasoning": "ok"
        }
        ev = ToolEvidence(
            tool="t", rule="r", success=True,
            matches=[{"file": "x", "line": 1}],
        )
        h = Hypothesis(claim="x", target=Path("/src"))
        verdict, _ = _evaluate(h, ev, client, task_type="audit")
        assert verdict == "confirmed"

    def test_runner_tool_failure_inconclusive(self):
        _evaluate, MagicMock = self._setup()
        client = MagicMock()
        ev = ToolEvidence(tool="t", rule="r", success=False, error="boom")
        h = Hypothesis(claim="x", target=Path("/src"))
        verdict, _ = _evaluate(h, ev, client, task_type="audit")
        assert verdict == "inconclusive"
        # LLM never called when the tool failed.
        client.generate_structured.assert_not_called()


# 4. Iteration guard ----------------------------------------------------------


class TestUncertainty:
    def test_zero_when_all_resolved(self):
        h = Hypothesis(claim="x", target=Path("/src"))
        evs = [
            Evidence(tool="t", rule="r", summary="s",
                     matches=[{"file": "a", "line": 1}], success=True),
            Evidence(tool="u", rule="r", summary="s",
                     matches=[{"file": "b", "line": 2}], success=True),
        ]
        assert uncertainty(IterationStep(hypothesis=h, evidence=evs)) == 0

    def test_counts_failures(self):
        h = Hypothesis(claim="x", target=Path("/src"))
        evs = [Evidence(tool="t", rule="r", summary="s", success=False, error="e")]
        assert uncertainty(IterationStep(hypothesis=h, evidence=evs)) == 1

    def test_counts_no_match_results(self):
        h = Hypothesis(claim="x", target=Path("/src"))
        evs = [Evidence(tool="t", rule="r", summary="s", matches=[], success=True)]
        assert uncertainty(IterationStep(hypothesis=h, evidence=evs)) == 1


class TestMustProgress:
    def _ev(self, matches=None, success=True):
        return Evidence(
            tool="t", rule="r", summary="s",
            matches=matches or [], success=success,
        )

    def test_strict_progress_passes(self):
        h1 = Hypothesis(claim="a", target=Path("/src"))
        h2 = Hypothesis(claim="b", target=Path("/src"))
        prev = IterationStep(hypothesis=h1, evidence=[self._ev(success=False)])
        # New hypothesis + new resolved evidence → uncertainty 0 < 1.
        curr = IterationStep(
            hypothesis=h2,
            evidence=[self._ev(matches=[{"file": "x", "line": 1}])],
        )
        must_progress(prev, curr)  # does not raise

    def test_same_hypothesis_raises(self):
        h = Hypothesis(claim="a", target=Path("/src"))
        prev = IterationStep(hypothesis=h, evidence=[self._ev(success=False)])
        curr = IterationStep(
            hypothesis=h,
            evidence=[self._ev(matches=[{"file": "x", "line": 1}])],
        )
        with pytest.raises(IterationStalled, match="identical hypothesis"):
            must_progress(prev, curr)

    def test_no_uncertainty_decrease_raises(self):
        h1 = Hypothesis(claim="a", target=Path("/src"))
        h2 = Hypothesis(claim="b", target=Path("/src"))
        prev = IterationStep(hypothesis=h1, evidence=[self._ev(success=False)])
        # New hypothesis but the new evidence is also unresolved → not strict.
        curr = IterationStep(hypothesis=h2, evidence=[self._ev(success=False)])
        with pytest.raises(IterationStalled, match="strictly decrease"):
            must_progress(prev, curr)

    def test_equal_uncertainty_raises_not_just_increase(self):
        # Strict means strictly less; equal still counts as stalled.
        h1 = Hypothesis(claim="a", target=Path("/src"))
        h2 = Hypothesis(claim="b", target=Path("/src"))
        prev = IterationStep(
            hypothesis=h1,
            evidence=[self._ev(matches=[{"file": "x", "line": 1}])],
        )
        curr = IterationStep(
            hypothesis=h2,
            evidence=[self._ev(matches=[{"file": "y", "line": 2}])],
        )
        # Both have uncertainty 0; equal is not strictly less.
        with pytest.raises(IterationStalled):
            must_progress(prev, curr)
