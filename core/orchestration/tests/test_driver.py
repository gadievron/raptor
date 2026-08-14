"""Tests for the generate-and-verify loop driver."""

from __future__ import annotations

from core.orchestration.driver import (
    DriverConfig,
    DriverResult,
    Verdict,
    oracle_from_fn,
    proposer_from_fn,
    run,
)


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _pass_oracle(candidate, context):
    return Verdict(passed=True, evidence={"value": candidate})


def _fail_oracle(candidate, context):
    return Verdict(passed=False, feedback="not good enough")


def _always_propose(context, feedback, *, prior_verdict=None):
    return "candidate"


def _counting_proposer():
    """Proposer that returns call count and records feedback received."""
    state = {"calls": 0, "feedbacks": []}

    def propose(context, feedback, *, prior_verdict=None):
        state["calls"] += 1
        state["feedbacks"].append(feedback)
        return state["calls"]

    return proposer_from_fn(propose), state


# ------------------------------------------------------------------
# Basic success / failure
# ------------------------------------------------------------------

class TestBasicLoop:
    def test_success_first_attempt(self):
        result = run(
            proposer_from_fn(_always_propose),
            oracle_from_fn(_pass_oracle),
            context={},
        )
        assert result.success
        assert result.candidate == "candidate"
        assert result.verdict.passed
        assert result.attempts == 1
        assert result.refine_cycles == 0
        assert result.errors == []

    def test_all_attempts_fail_oracle(self):
        result = run(
            proposer_from_fn(_always_propose),
            oracle_from_fn(_fail_oracle),
            context={},
            config=DriverConfig(max_attempts=3),
        )
        assert not result.success
        assert result.candidate == "candidate"
        assert result.verdict.passed is False
        assert result.attempts == 3
        assert len(result.errors) == 3

    def test_no_candidate_when_proposer_always_raises(self):
        def bad_proposer(ctx, fb, *, prior_verdict=None):
            raise ValueError("broken")

        result = run(
            proposer_from_fn(bad_proposer),
            oracle_from_fn(_pass_oracle),
            context={},
            config=DriverConfig(max_attempts=2),
        )
        assert not result.success
        assert result.candidate is None
        assert result.verdict is None
        assert result.attempts == 2
        assert all("propose:" in e for e in result.errors)

    def test_no_candidate_when_oracle_always_raises(self):
        def bad_oracle(candidate, ctx):
            raise RuntimeError("boom")

        result = run(
            proposer_from_fn(_always_propose),
            oracle_from_fn(bad_oracle),
            context={},
            config=DriverConfig(max_attempts=2),
        )
        assert not result.success
        assert result.candidate is None
        assert result.attempts == 2
        assert all("oracle:" in e for e in result.errors)


# ------------------------------------------------------------------
# Retry with feedback
# ------------------------------------------------------------------

class TestRetryFeedback:
    def test_feedback_threaded_to_proposer(self):
        proposer, state = _counting_proposer()

        def oracle_fail_then_pass(candidate, ctx):
            if candidate < 3:
                return Verdict(passed=False, feedback=f"try harder ({candidate})")
            return Verdict(passed=True)

        result = run(
            proposer,
            oracle_from_fn(oracle_fail_then_pass),
            context={},
            config=DriverConfig(max_attempts=5),
        )
        assert result.success
        assert result.attempts == 3
        assert state["feedbacks"][0] == ""
        assert "try harder" in state["feedbacks"][1]
        assert "try harder" in state["feedbacks"][2]

    def test_propose_error_becomes_feedback(self):
        call_count = {"n": 0}

        def flaky_proposer(ctx, fb, *, prior_verdict=None):
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise ValueError("parse error")
            return "fixed"

        result = run(
            proposer_from_fn(flaky_proposer),
            oracle_from_fn(_pass_oracle),
            context={},
            config=DriverConfig(max_attempts=3),
        )
        assert result.success
        assert result.attempts == 2

    def test_oracle_error_becomes_feedback(self):
        call_count = {"n": 0}

        def flaky_oracle(candidate, ctx):
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise RuntimeError("timeout")
            return Verdict(passed=True)

        result = run(
            proposer_from_fn(_always_propose),
            oracle_from_fn(flaky_oracle),
            context={},
            config=DriverConfig(max_attempts=3),
        )
        assert result.success
        assert result.attempts == 2
        assert any("oracle:" in e for e in result.errors)


# ------------------------------------------------------------------
# Refinement cycles
# ------------------------------------------------------------------

class TestRefinement:
    def test_refinement_cycle_on_non_passing_verdict(self):
        cycle = {"n": 0}

        def refining_oracle(candidate, ctx):
            cycle["n"] += 1
            if cycle["n"] < 3:
                return Verdict(
                    passed=False,
                    feedback="not sound",
                    evidence={"cycle": cycle["n"]},
                )
            return Verdict(passed=True)

        result = run(
            proposer_from_fn(_always_propose),
            oracle_from_fn(refining_oracle),
            context={},
            config=DriverConfig(max_attempts=1, max_refine_cycles=5),
        )
        assert result.success
        assert result.refine_cycles == 2

    def test_refinement_budget_exhausted(self):
        result = run(
            proposer_from_fn(_always_propose),
            oracle_from_fn(_fail_oracle),
            context={},
            config=DriverConfig(max_attempts=1, max_refine_cycles=2),
        )
        assert not result.success
        assert result.refine_cycles == 2
        assert result.candidate == "candidate"

    def test_prior_verdict_threaded_to_proposer(self):
        verdicts_seen = []

        def tracking_proposer(ctx, fb, *, prior_verdict=None):
            verdicts_seen.append(prior_verdict)
            return "x"

        cycle = {"n": 0}

        def staged_oracle(candidate, ctx):
            cycle["n"] += 1
            if cycle["n"] <= 2:
                return Verdict(
                    passed=False,
                    feedback="refine",
                    evidence={"stage": cycle["n"]},
                )
            return Verdict(passed=True)

        result = run(
            proposer_from_fn(tracking_proposer),
            oracle_from_fn(staged_oracle),
            context={},
            config=DriverConfig(max_attempts=1, max_refine_cycles=3),
        )
        assert result.success
        assert verdicts_seen[0] is None
        assert verdicts_seen[1] is not None
        assert verdicts_seen[1].evidence["stage"] == 1
        assert verdicts_seen[2].evidence["stage"] == 2

    def test_compile_budget_resets_per_cycle(self):
        """Each refinement cycle gets a fresh max_attempts budget."""
        attempt_counts = []
        cycle = {"n": 0}

        def counting_proposer(ctx, fb, *, prior_verdict=None):
            return f"c{cycle['n']}"

        def oracle_needs_refinement(candidate, ctx):
            cycle["n"] += 1
            attempt_counts.append(cycle["n"])
            if cycle["n"] <= 2:
                return Verdict(passed=False, feedback="refine more")
            return Verdict(passed=True)

        result = run(
            proposer_from_fn(counting_proposer),
            oracle_from_fn(oracle_needs_refinement),
            context={},
            config=DriverConfig(max_attempts=1, max_refine_cycles=5),
        )
        assert result.success
        assert result.attempts == 3

    def test_retry_on_failure_false_breaks_on_verdict(self):
        """retry_on_failure=False exits inner loop on any verdict."""
        call_count = {"n": 0}

        def oracle_always_fails(candidate, ctx):
            call_count["n"] += 1
            return Verdict(passed=False, feedback="not sound")

        result = run(
            proposer_from_fn(_always_propose),
            oracle_from_fn(oracle_always_fails),
            context={},
            config=DriverConfig(max_attempts=5, max_refine_cycles=0,
                                retry_on_failure=False),
        )
        assert not result.success
        assert call_count["n"] == 1
        assert result.attempts == 1

    def test_retry_on_failure_false_still_retries_exceptions(self):
        """retry_on_failure=False still retries on oracle exceptions."""
        call_count = {"n": 0}

        def flaky_oracle(candidate, ctx):
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise RuntimeError("compile error")
            return Verdict(passed=True)

        result = run(
            proposer_from_fn(_always_propose),
            oracle_from_fn(flaky_oracle),
            context={},
            config=DriverConfig(max_attempts=3, retry_on_failure=False),
        )
        assert result.success
        assert call_count["n"] == 2

    def test_retry_on_failure_false_with_refinement(self):
        """retry_on_failure=False + max_refine_cycles: verdicts go to refinement."""
        cycle = {"n": 0}

        def oracle_refine_then_pass(candidate, ctx):
            cycle["n"] += 1
            if cycle["n"] <= 2:
                return Verdict(passed=False, feedback="not sound",
                               evidence={"stage": cycle["n"]})
            return Verdict(passed=True)

        result = run(
            proposer_from_fn(_always_propose),
            oracle_from_fn(oracle_refine_then_pass),
            context={},
            config=DriverConfig(max_attempts=1, max_refine_cycles=5,
                                retry_on_failure=False),
        )
        assert result.success
        assert result.refine_cycles == 2
        assert result.attempts == 3


# ------------------------------------------------------------------
# Context threading
# ------------------------------------------------------------------

class TestContext:
    def test_context_passed_to_both(self):
        seen_ctx = {"proposer": None, "oracle": None}

        def p(ctx, fb, *, prior_verdict=None):
            seen_ctx["proposer"] = ctx
            return "x"

        def o(candidate, ctx):
            seen_ctx["oracle"] = ctx
            return Verdict(passed=True)

        run(proposer_from_fn(p), oracle_from_fn(o), context={"key": 42})
        assert seen_ctx["proposer"] == {"key": 42}
        assert seen_ctx["oracle"] == {"key": 42}


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

class TestHelpers:
    def test_oracle_from_fn_carries_reliability_class(self):
        o = oracle_from_fn(_pass_oracle, reliability_class="judgement")
        assert o.reliability_class == "judgement"
        v = o.judge("x", {})
        assert v.passed

    def test_oracle_from_fn_defaults_decisive(self):
        o = oracle_from_fn(_pass_oracle)
        assert o.reliability_class == "decisive"

    def test_proposer_from_fn(self):
        p = proposer_from_fn(_always_propose)
        assert p.propose({}, "") == "candidate"

    def test_driver_result_success_property(self):
        assert not DriverResult().success
        assert not DriverResult(verdict=Verdict(passed=False)).success
        assert DriverResult(verdict=Verdict(passed=True)).success
