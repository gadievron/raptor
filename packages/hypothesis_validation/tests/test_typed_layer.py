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

import hashlib
import json
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
    Posterior,
    ProvenanceMismatch,
    SinkLocation,
    SourceLocation,
    UNIFORM_PRIOR,
    aggregate,
    ensure_same_provenance,
    hash_hypothesis,
    must_progress,
    posterior_from,
    posterior_update,
    uncertainty,
    verdict_from,
    verdict_from_posterior,
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

    def test_hash_normalises_target_path(self):
        # `./foo.c`, `src/./foo.c`, and `src/../src/foo.c` are the same
        # path under os.path.normpath; the hash must agree.
        a = Hypothesis(claim="x", target=Path("/src/foo.c"))
        b = Hypothesis(claim="x", target=Path("/src/./foo.c"))
        c = Hypothesis(claim="x", target=Path("/src/../src/foo.c"))
        assert hash_hypothesis(a) == hash_hypothesis(b)
        assert hash_hypothesis(a) == hash_hypothesis(c)

    def test_hash_normalises_nested_file_paths(self):
        # Nested location/flow-step `file` fields go through the same
        # normalisation as the top-level target.
        a = Hypothesis(
            claim="x",
            target=Path("/src"),
            source=SourceLocation(file="src/foo.c", line=1),
        )
        b = Hypothesis(
            claim="x",
            target=Path("/src"),
            source=SourceLocation(file="src/./foo.c", line=1),
        )
        assert hash_hypothesis(a) == hash_hypothesis(b)

    def test_hash_keeps_abs_and_rel_distinct(self):
        # normpath cannot canonicalise abs vs rel without a cwd, and
        # using cwd would make the hash process-dependent. Document by
        # asserting they remain distinct.
        a = Hypothesis(claim="x", target=Path("foo.c"))
        b = Hypothesis(claim="x", target=Path("/src/foo.c"))
        assert hash_hypothesis(a) != hash_hypothesis(b)

    def test_hash_preserves_empty_path_strings(self):
        # `os.path.normpath("")` returns ".", which would conflate
        # "no path set" with "current directory" in the hash. A guard
        # in `_normalise_string` skips normpath on empty input. This
        # test exercises the guard via a SourceLocation whose `file`
        # is unset (empty string).
        a = Hypothesis(
            claim="x", target=Path("/src"),
            source=SourceLocation(kind="network"),  # file=""
        )
        b = Hypothesis(
            claim="x", target=Path("/src"),
            source=SourceLocation(kind="network", file="."),
        )
        assert hash_hypothesis(a) != hash_hypothesis(b)

    def test_hash_distinguishes_none_from_empty_source(self):
        # `to_dict` skips structured fields when None but emits them
        # with default values when set. So `source=None` and
        # `source=SourceLocation()` are meaningfully different inputs
        # and must hash differently. This test pins that sharp edge so
        # any future "always emit defaults" change to to_dict surfaces
        # as a test failure rather than a silent stored-hash invalidation.
        h1 = Hypothesis(claim="x", target=Path("/x"))
        h2 = Hypothesis(
            claim="x", target=Path("/x"),
            source=SourceLocation(),
        )
        assert hash_hypothesis(h1) != hash_hypothesis(h2)
        # Same property for sink and flow_steps.
        h3 = Hypothesis(claim="x", target=Path("/x"), sink=SinkLocation())
        assert hash_hypothesis(h1) != hash_hypothesis(h3)
        h4 = Hypothesis(claim="x", target=Path("/x"), flow_steps=[FlowStep()])
        assert hash_hypothesis(h1) != hash_hypothesis(h4)

    def test_hash_path_normalisation_is_platform_independent(self):
        """The hash of a forward-slash path must not depend on host OS.

        os.path.normpath converts to backslashes on Windows; posixpath
        .normpath does not. Hashes are stored cross-machine, so
        platform-dependent normalisation breaks Evidence.refers_to
        lookups. Pinning this property prevents a regression to
        os.path.normpath.
        """
        # Two paths that normalise to the same canonical form. On any
        # POSIX or Windows host, posixpath.normpath collapses both to
        # "src/foo.c" with forward slashes intact.
        h_dotted = Hypothesis(claim="x", target=Path("src/./foo.c"))
        h_clean = Hypothesis(claim="x", target=Path("src/foo.c"))
        assert hash_hypothesis(h_dotted) == hash_hypothesis(h_clean)

        # Stronger guarantee: the canonical form encoded in the hash
        # input contains forward slashes. We re-derive the expected
        # digest with an explicit forward-slash payload; if the
        # implementation ever swaps in a backslash separator the hash
        # will no longer match.
        expected_payload = {
            "claim": "x",
            "target": "src/foo.c",  # forward slashes, regardless of host
            "target_function": "",
            "cwe": "",
            "suggested_tools": [],
            "context": "",
        }
        expected = hashlib.sha256(
            json.dumps(
                expected_payload, sort_keys=True, separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        assert hash_hypothesis(h_clean) == expected

    def test_hash_is_byte_stable(self):
        """Pin the hash for a fixed hypothesis. Changes to to_dict,
        _normalise, the JSON encoding contract, or the hash algorithm
        will fail this test. If you trip it, every persisted
        Evidence.refers_to in the wild becomes invalid — bump a hash
        version explicitly and write a migration, rather than silently
        breaking the contract.
        """
        h = Hypothesis(claim="foo bar", target=Path("/x"), cwe="CWE-129")
        assert hash_hypothesis(h) == (
            "066b6bcb035ac80f53209d417bb66bcf"
            "155d5a869305c50b3c92eb1f236a3e93"
        )

    def test_hash_stable_across_field_addition_when_omitted(self):
        # Adding optional structured fields without populating them must
        # NOT change the hash of an existing hypothesis. This protects
        # any persisted `Evidence.refers_to` against accidental changes
        # to `to_dict` (e.g. "always emit source even when None") that
        # would silently invalidate every stored hash.
        h = Hypothesis(claim="x", target=Path("/x"))
        expected_payload = {
            "claim": "x",
            "target": "/x",
            "target_function": "",
            "cwe": "",
            "suggested_tools": [],
            "context": "",
        }
        expected = hashlib.sha256(
            json.dumps(
                expected_payload, sort_keys=True, separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        assert hash_hypothesis(h) == expected


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


# 5. Bayesian posterior aggregation -------------------------------------------


def _ev(success=True, matches=None, error=""):
    return ToolEvidence(
        tool="t", rule="r",
        success=success,
        matches=matches or [],
        error=error,
    )


class TestPosterior:
    """Beta-Bernoulli arithmetic and basic invariants."""

    def test_uniform_prior_mean_is_half(self):
        assert UNIFORM_PRIOR.mean == 0.5
        assert UNIFORM_PRIOR.strength == 2.0

    def test_mean_handles_degenerate_strength_zero(self):
        # Defensive: a caller that constructs (0, 0) should not get
        # ZeroDivisionError. The default-constructor path can't reach
        # this state, but explicit construction can.
        p = Posterior(alpha=0.0, beta=0.0)
        assert p.mean == 0.5

    def test_update_confirming_increments_alpha(self):
        p = posterior_update(UNIFORM_PRIOR, confirms=True)
        assert p.alpha == 2.0
        assert p.beta == 1.0
        assert p.mean > 0.5

    def test_update_refuting_increments_beta(self):
        p = posterior_update(UNIFORM_PRIOR, confirms=False)
        assert p.alpha == 1.0
        assert p.beta == 2.0
        assert p.mean < 0.5

    def test_posterior_is_frozen(self):
        # Mutating updates would alias-bug iteration loops.
        p = Posterior(1.0, 1.0)
        with pytest.raises(Exception):
            p.alpha = 99.0  # type: ignore[misc]

    def test_weight_scales_update(self):
        p1 = posterior_update(UNIFORM_PRIOR, confirms=True, weight=1.0)
        p3 = posterior_update(UNIFORM_PRIOR, confirms=True, weight=3.0)
        assert p3.alpha == p1.alpha + 2.0
        assert p3.mean > p1.mean


class TestPosteriorFrom:
    """Aggregating evidence lists into a posterior."""

    def test_empty_evidence_returns_prior(self):
        assert posterior_from([]) == UNIFORM_PRIOR

    def test_all_confirming_concentrates_above_half(self):
        evs = [_ev(matches=[{"file": "a", "line": 1}]) for _ in range(5)]
        p = posterior_from(evs)
        assert p.mean > 0.8
        assert p.strength == UNIFORM_PRIOR.strength + 5

    def test_all_refuting_concentrates_below_half(self):
        evs = [_ev(matches=[]) for _ in range(5)]
        p = posterior_from(evs)
        assert p.mean < 0.2

    def test_mixed_evidence_reflects_ratio(self):
        # 3 confirms, 1 refute → posterior mean should sit near 4/6 ≈ 0.67.
        evs = (
            [_ev(matches=[{"file": "a", "line": 1}]) for _ in range(3)] +
            [_ev(matches=[]) for _ in range(1)]
        )
        p = posterior_from(evs)
        # Beta(4, 2) mean = 4/6 = 0.667
        assert abs(p.mean - 4.0 / 6.0) < 1e-9

    def test_tool_failure_does_not_update(self):
        # Failed tool runs are no-ops — they don't shift alpha or beta.
        evs = [_ev(success=False, error="boom"), _ev(success=False, error="boom")]
        p = posterior_from(evs)
        assert p == UNIFORM_PRIOR

    def test_strength_increases_monotonically(self):
        # Each non-failure observation adds 1 to strength.
        p0 = posterior_from([])
        p1 = posterior_from([_ev(matches=[{"file": "a", "line": 1}])])
        p2 = posterior_from([
            _ev(matches=[{"file": "a", "line": 1}]),
            _ev(matches=[]),
        ])
        assert p1.strength > p0.strength
        assert p2.strength > p1.strength

    def test_custom_prior_is_respected(self):
        # Strong prior shifts the posterior even with one observation.
        strong = Posterior(alpha=10.0, beta=1.0)  # mean ≈ 0.91
        evs = [_ev(matches=[])]  # one refute
        p = posterior_from(evs, prior=strong)
        # Beta(10, 2) mean = 10/12 ≈ 0.833 — still high despite refute.
        assert p.mean > 0.8

    def test_accepts_evidence_dataclass_too(self):
        # `Evidence` (from result.py) has the same .success/.matches
        # surface as ToolEvidence; posterior_from should accept either.
        evs = [
            Evidence(tool="t", rule="r", summary="s",
                     matches=[{"file": "a", "line": 1}], success=True),
            Evidence(tool="u", rule="r", summary="s",
                     matches=[], success=True),
        ]
        p = posterior_from(evs)
        # Beta(2, 2) mean = 0.5
        assert p.mean == 0.5


class TestVerdictFromPosterior:
    """Threshold projection from continuous posterior to 3-valued verdict."""

    def test_high_mean_confirms(self):
        p = Posterior(alpha=10.0, beta=1.0)  # mean ≈ 0.91
        assert verdict_from_posterior(p) == "confirmed"

    def test_low_mean_refutes(self):
        p = Posterior(alpha=1.0, beta=10.0)  # mean ≈ 0.09
        assert verdict_from_posterior(p) == "refuted"

    def test_middling_is_inconclusive(self):
        # Uniform prior with no evidence → mean = 0.5 → inconclusive.
        assert verdict_from_posterior(UNIFORM_PRIOR) == "inconclusive"
        # One observation either way is also still inconclusive at
        # default thresholds — guards against a single false positive.
        p_one = posterior_update(UNIFORM_PRIOR, confirms=True)
        assert verdict_from_posterior(p_one) == "inconclusive"

    def test_three_confirms_tips_to_confirmed_at_default(self):
        # Beta(4, 1) mean = 0.8 — exactly at the threshold; > 0.8 wins.
        # We need 4 confirms to clear it.
        p = UNIFORM_PRIOR
        for _ in range(4):
            p = posterior_update(p, confirms=True)
        assert verdict_from_posterior(p) == "confirmed"

    def test_thresholds_are_tunable(self):
        # Looser thresholds let a single observation tip the verdict.
        p = posterior_update(UNIFORM_PRIOR, confirms=True)  # mean ≈ 0.667
        assert verdict_from_posterior(p, confirm_threshold=0.6) == "confirmed"

    def test_invalid_thresholds_raise(self):
        with pytest.raises(ValueError):
            verdict_from_posterior(UNIFORM_PRIOR, confirm_threshold=0.3,
                                    refute_threshold=0.5)
        with pytest.raises(ValueError):
            verdict_from_posterior(UNIFORM_PRIOR, confirm_threshold=1.5)
        with pytest.raises(ValueError):
            verdict_from_posterior(UNIFORM_PRIOR, refute_threshold=-0.1)


class TestPosteriorPreservesSignal:
    """The headline property: posterior aggregation does NOT collapse
    multi-evidence signal the way the 3-valued lattice does."""

    def test_three_confirms_one_refute_distinguishable_from_one_each(self):
        # The verdict lattice would call both of these "inconclusive"
        # (any disagreement collapses). The posterior keeps them apart.
        many_signal = (
            [_ev(matches=[{"file": "a", "line": 1}]) for _ in range(3)] +
            [_ev(matches=[])]
        )
        balanced = [_ev(matches=[{"file": "a", "line": 1}]), _ev(matches=[])]

        p_many = posterior_from(many_signal)
        p_bal = posterior_from(balanced)

        # Both means are above 0.5 (more confirms than refutes), but
        # `many_signal` is meaningfully more confident.
        assert p_many.mean > p_bal.mean
        # Strength reflects how much evidence informed the answer.
        assert p_many.strength > p_bal.strength

    def test_aggregate_collapses_where_posterior_does_not(self):
        # Pin the contrast against the legacy meet-based aggregator.
        evs = (
            [_ev(matches=[{"file": "a", "line": 1}]) for _ in range(3)] +
            [_ev(matches=[])]
        )
        # Under the lattice: 3 "confirmed" and 1 "refuted" → meet → inconclusive.
        legacy = aggregate(evs, "confirmed")
        assert legacy == "inconclusive"

        # Under the posterior: 3 confirms vs 1 refute → mean > 0.5,
        # quantified rather than collapsed.
        p = posterior_from(evs)
        assert p.mean > 0.5
        # The threshold readout still says inconclusive at strict
        # defaults, but the underlying signal is preserved for callers
        # that read p.mean directly (i.e. ranking-based triage).
        assert 0.5 < p.mean < 0.8
