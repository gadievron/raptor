"""Tests for ``synthesise_with_refinement`` — iterative FP-elimination.

Each iteration runs the full synthesis pipeline; the wrapper carries
forward false-positive matches as negative examples in subsequent
prompts. Convergence: triage FP rate ≤ threshold.

Stub LLM + stub engine adapters keep tests deterministic.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

import pytest

from packages.checker_synthesis import (
    Match,
    SeedBug,
    SynthesisedRule,
    synthesise_with_refinement,
)
from packages.checker_synthesis import synthesise as synth_mod


def _seed(tmp_path: Path) -> SeedBug:
    src_dir = tmp_path / "src"
    src_dir.mkdir(exist_ok=True)
    (src_dir / "auth.py").write_text(
        "def login(req):\n    return cursor.execute(f'x={req.q}')\n"
    )
    return SeedBug(
        file="src/auth.py", function="login",
        line_start=1, line_end=2,
        cwe="CWE-89", reasoning="tainted f-string into execute",
    )


def _stub_llm(responses):
    queue = list(responses)

    def llm(prompt, schema, system_prompt):
        if not queue:
            raise AssertionError("stub LLM out of responses")
        item = queue.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item
    llm._queue = queue
    return llm


def _stub_engines_per_iteration(monkeypatch, iterations):
    """``iterations`` is a list of (probe_matches, scan_matches) per
    iteration. Each ``synthesise_and_run`` call consumes one entry's
    pair (positive control + codebase scan)."""
    state = {"iter": 0, "call_in_iter": 0}

    def fake_run(rule, rule_path, target):
        i = state["iter"]
        c = state["call_in_iter"]
        if i >= len(iterations):
            return [], []
        probe, scan = iterations[i]
        if c == 0:
            # Positive control on seed file.
            state["call_in_iter"] = 1
            return list(probe), []
        # Codebase scan; advance to next iteration.
        state["iter"] += 1
        state["call_in_iter"] = 0
        return list(scan), []

    monkeypatch.setattr(synth_mod, "_run_engine", fake_run)


# ---------------------------------------------------------------------------
# Convergence behaviour
# ---------------------------------------------------------------------------


class TestConvergence:
    def test_converges_when_fp_rate_below_threshold(self, tmp_path, monkeypatch):
        """First iteration's triage shows 1 variant + 0 FPs → fp_rate=0.0,
        below default 0.2 threshold → converged on iteration 1."""
        seed = _seed(tmp_path)
        seed_match = Match(file="src/auth.py", line=2)
        variant = Match(file="src/admin.py", line=42)
        _stub_engines_per_iteration(monkeypatch, [
            ([seed_match], [seed_match, variant]),
        ])
        llm = _stub_llm([
            # Iteration 1 synthesis
            {"rule_body": "rules: tight", "rationale": "x"},
            # Iteration 1 triage (one variant)
            {"status": "variant", "reasoning": "same shape"},
        ])
        result = synthesise_with_refinement(
            seed, tmp_path, tmp_path / "out", llm,
            max_iterations=5,
        )
        assert result.rule is not None
        assert result.positive_control is True
        assert len(result.matches) == 1

    def test_iterates_when_fp_rate_above_threshold(self, tmp_path, monkeypatch):
        """First iteration: 1 variant + 4 FPs (rate 0.8). Second
        iteration: 1 variant + 0 FPs (rate 0.0). Converges on
        iteration 2."""
        seed = _seed(tmp_path)
        seed_m = Match(file="src/auth.py", line=2)
        variant = Match(file="src/admin.py", line=42)
        fps = [Match(file=f"src/fp{i}.py", line=1) for i in range(4)]
        _stub_engines_per_iteration(monkeypatch, [
            # Iteration 1: noisy rule
            ([seed_m], [seed_m, variant, *fps]),
            # Iteration 2: tight rule (FPs gone)
            ([seed_m], [seed_m, variant]),
        ])
        llm = _stub_llm([
            # Iter 1 synthesis
            {"rule_body": "rules: noisy", "rationale": "loose"},
            # Iter 1 triage: 1 variant, 4 FPs
            {"status": "variant", "reasoning": "tp"},
            {"status": "false_positive", "reasoning": "fp1"},
            {"status": "false_positive", "reasoning": "fp2"},
            {"status": "false_positive", "reasoning": "fp3"},
            {"status": "false_positive", "reasoning": "fp4"},
            # Iter 2 synthesis (FP context appended)
            {"rule_body": "rules: tight", "rationale": "refined"},
            # Iter 2 triage: 1 variant, 0 FPs → converged
            {"status": "variant", "reasoning": "tp"},
        ])
        result = synthesise_with_refinement(
            seed, tmp_path, tmp_path / "out", llm,
            max_iterations=5,
        )
        # Final result is the converged (iter 2) one — only 1 variant.
        assert len(result.matches) == 1
        # Convergence message NOT logged (we did converge).
        assert not any("did not converge" in e for e in result.errors)

    def test_returns_best_result_when_no_iteration_converges(
        self, tmp_path, monkeypatch,
    ):
        """All iterations have FP rate above threshold; wrapper
        returns the best (lowest-rate) one and logs the no-converge."""
        seed = _seed(tmp_path)
        seed_m = Match(file="src/auth.py", line=2)
        # 3 iterations, each produces 1 variant + N FPs
        _stub_engines_per_iteration(monkeypatch, [
            # Iter 1: 1 variant + 5 FPs (rate 5/6 ≈ 0.83)
            ([seed_m], [seed_m, Match(file="src/v.py", line=1)]
                + [Match(file=f"src/fp1_{i}.py", line=1)
                   for i in range(5)]),
            # Iter 2: 1 variant + 2 FPs (rate 2/3 ≈ 0.67) ← best
            ([seed_m], [seed_m, Match(file="src/v.py", line=1)]
                + [Match(file=f"src/fp2_{i}.py", line=1)
                   for i in range(2)]),
            # Iter 3: 1 variant + 4 FPs (rate 0.8)
            ([seed_m], [seed_m, Match(file="src/v.py", line=1)]
                + [Match(file=f"src/fp3_{i}.py", line=1)
                   for i in range(4)]),
        ])
        # 3 syntheses + (6 + 3 + 5) triages = 17 LLM calls
        responses = []
        for i in range(3):
            responses.append({"rule_body": f"rules: r{i}",
                              "rationale": f"iter{i}"})
            n_triage = [6, 3, 5][i]
            responses.append({"status": "variant", "reasoning": "tp"})
            for _ in range(n_triage - 1):
                responses.append(
                    {"status": "false_positive", "reasoning": "fp"}
                )
        llm = _stub_llm(responses)
        result = synthesise_with_refinement(
            seed, tmp_path, tmp_path / "out", llm,
            max_iterations=3,
            max_acceptable_fp_rate=0.1,  # tighter than any iteration
        )
        # The wrapper returned a result, and explicitly logged the
        # no-convergence case.
        assert result.rule is not None
        assert any("did not converge" in e for e in result.errors)


# ---------------------------------------------------------------------------
# FP context propagation
# ---------------------------------------------------------------------------


class TestFpContextPropagation:
    def test_synthesis_prompt_includes_prior_fps_on_iter_2(
        self, tmp_path, monkeypatch,
    ):
        """The second iteration's synthesis prompt should mention
        the false positives the first iteration found."""
        seed = _seed(tmp_path)
        seed_m = Match(file="src/auth.py", line=2)
        fp1 = Match(file="src/sparse.py", line=10,
                    snippet="db.exec_some_other_thing()")
        # Iter 1: produces FP. Iter 2: clean.
        _stub_engines_per_iteration(monkeypatch, [
            ([seed_m], [seed_m, fp1]),
            ([seed_m], [seed_m]),
        ])

        # Capture prompts the LLM sees.
        captured_prompts: List[str] = []

        def llm(prompt, schema, system_prompt):
            captured_prompts.append(prompt)
            # Iteration 1 synthesis → loose rule, then triage 1 FP.
            # Iteration 2 synthesis → tight rule, then no triage
            # needed (no extra matches).
            if len(captured_prompts) == 1:
                return {"rule_body": "rules: r1", "rationale": "loose"}
            if len(captured_prompts) == 2:
                # Triage of fp1
                return {"status": "false_positive",
                        "reasoning": "different sink"}
            if len(captured_prompts) == 3:
                # Iter 2 synthesis — should see FP context.
                return {"rule_body": "rules: r2",
                        "rationale": "tightened"}
            raise AssertionError("unexpected extra LLM call")

        result = synthesise_with_refinement(
            seed, tmp_path, tmp_path / "out", llm,
            max_iterations=3,
        )
        # Iter 2's synthesis prompt (index 2, 0-indexed) should
        # include the FP feedback section.
        assert "PRIOR FALSE POSITIVES" in captured_prompts[2]
        assert "src/sparse.py:10" in captured_prompts[2]
        # Iter 1's synthesis prompt should NOT have FP context (no
        # prior iterations).
        assert "PRIOR FALSE POSITIVES" not in captured_prompts[0]


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_max_iterations_zero_returns_error(self, tmp_path):
        seed = _seed(tmp_path)
        llm = _stub_llm([])
        result = synthesise_with_refinement(
            seed, tmp_path, tmp_path / "out", llm,
            max_iterations=0,
        )
        assert result.rule is None
        assert any("max_iterations" in e for e in result.errors)

    def test_no_triage_verdicts_returns_immediately(
        self, tmp_path, monkeypatch,
    ):
        """If a synthesis produces zero matches (and therefore zero
        triage verdicts), refinement has nothing to learn from. Return
        the result without iterating."""
        seed = _seed(tmp_path)
        seed_m = Match(file="src/auth.py", line=2)
        _stub_engines_per_iteration(monkeypatch, [
            # Probe matches seed (positive control passes), but
            # codebase scan finds only the seed (no variants).
            ([seed_m], [seed_m]),
        ])
        llm = _stub_llm([
            {"rule_body": "rules: tight", "rationale": "x"},
            # No triage calls expected — zero variants.
        ])
        result = synthesise_with_refinement(
            seed, tmp_path, tmp_path / "out", llm,
            max_iterations=5,
        )
        # Returned cleanly after iter 1.
        assert result.rule is not None
        assert any("nothing to learn" in e for e in result.errors)

    def test_synthesis_failure_in_iter_1_returns_with_errors(
        self, tmp_path, monkeypatch,
    ):
        """If the first iteration's positive control fails on both
        the initial attempt and the retry, no rule is produced.
        Wrapper should still return — not crash, not loop forever."""
        seed = _seed(tmp_path)
        # Probe never matches.
        _stub_engines_per_iteration(monkeypatch, [
            ([], []),
            ([], []),
            ([], []),
        ])
        llm = _stub_llm([
            # Iter 1: 2 synthesis attempts (max_retries=1), both miss.
            {"rule_body": "rules: bad1", "rationale": "x"},
            {"rule_body": "rules: bad2", "rationale": "y"},
            # Iter 2: 2 more attempts, also miss.
            {"rule_body": "rules: bad3", "rationale": "x"},
            {"rule_body": "rules: bad4", "rationale": "y"},
            # Iter 3: 2 more.
            {"rule_body": "rules: bad5", "rationale": "x"},
            {"rule_body": "rules: bad6", "rationale": "y"},
        ])
        result = synthesise_with_refinement(
            seed, tmp_path, tmp_path / "out", llm,
            max_iterations=3,
        )
        # No rule, but no crash.
        assert result.rule is None
        assert any("no rule produced" in e for e in result.errors)


# ---------------------------------------------------------------------------
# FP dedup across iterations
# ---------------------------------------------------------------------------


class TestFpDedup:
    def test_duplicate_fp_locations_not_double_counted(
        self, tmp_path, monkeypatch,
    ):
        """The same (file, line) showing up as FP in iter 1 and iter 2
        should appear once in the accumulated context."""
        seed = _seed(tmp_path)
        seed_m = Match(file="src/auth.py", line=2)
        repeated_fp = Match(file="src/repeat.py", line=10)
        _stub_engines_per_iteration(monkeypatch, [
            ([seed_m], [seed_m, repeated_fp]),
            ([seed_m], [seed_m, repeated_fp]),
            ([seed_m], [seed_m]),
        ])
        captured: List[str] = []

        def llm(prompt, schema, system_prompt):
            captured.append(prompt)
            if "rule_body" in schema.get("required", []):
                return {"rule_body": "rules: r", "rationale": "x"}
            return {"status": "false_positive", "reasoning": "fp"}

        result = synthesise_with_refinement(
            seed, tmp_path, tmp_path / "out", llm,
            max_iterations=3,
        )
        # Iter 3 synthesis prompt should reference the FP only once,
        # not twice. Find iter 3's synthesis prompt: it's the one
        # following the second triage.
        synthesis_prompts = [p for p in captured if "PRIOR FALSE" in p]
        # Both iter 2 and iter 3 should include FP context.
        for p in synthesis_prompts:
            count = p.count("src/repeat.py:10")
            assert count == 1, (
                f"FP location should appear exactly once per prompt; "
                f"saw {count} occurrences"
            )
