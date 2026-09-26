"""Tests for ``apply_producer_fair_share`` — the per-producer
interleave applied at the analysis agent's prioritisation point when
``max_findings`` binds.

The dataflow-first prioritisation fronts EVERY dataflow-carrying
finding before the cap; a producer whose findings all carry dataflow
(the cross-file taint engine) could displace every other producer
wholesale. The interleave gives each producer a fair share of the
cap window while preserving each producer's own internal priority
order — and stays byte-identical (same list object) whenever there is
no contention or no taint producer in the set.
"""

from __future__ import annotations

import sys
from pathlib import Path

# packages/llm_analysis/tests/... -> repo root
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from packages.llm_analysis.agent import (  # noqa: E402
    _TAINT_PRODUCER,
    apply_producer_fair_share,
)

AGENT_PY = Path(__file__).resolve().parents[1] / "agent.py"


def _f(tool: str, n: int, **kw):
    return {"finding_id": f"{tool}-{n}", "tool": tool, **kw}


def _mixed_set(taint: int, semgrep: int, codeql: int) -> list[dict]:
    """Dataflow-fronted shape: every taint finding carries dataflow
    (so the pre-interleave order fronts them all), scanners follow."""
    findings = [
        _f(_TAINT_PRODUCER, i, has_dataflow=True) for i in range(taint)
    ]
    findings += [_f("semgrep", i) for i in range(semgrep)]
    findings += [_f("codeql", i) for i in range(codeql)]
    return findings


class TestConservativeDefaults:
    """No contention / no taint producer → the input list object."""

    def test_cap_not_binding_returns_same_object(self):
        findings = _mixed_set(taint=2, semgrep=2, codeql=2)
        result, deferred = apply_producer_fair_share(findings, 10)
        assert result is findings
        assert deferred is None

    def test_cap_equal_to_len_returns_same_object(self):
        findings = _mixed_set(taint=2, semgrep=2, codeql=2)
        result, deferred = apply_producer_fair_share(findings, 6)
        assert result is findings
        assert deferred is None

    def test_zero_cap_returns_same_object(self):
        # max_findings <= 0 means "no cap" on this path — nothing to
        # fair-share against.
        findings = _mixed_set(taint=5, semgrep=5, codeql=0)
        result, deferred = apply_producer_fair_share(findings, 0)
        assert result is findings
        assert deferred is None

    def test_no_taint_producer_is_byte_identical(self):
        # The no-taint differential: scanner-only contention keeps the
        # existing fronting-then-truncate prioritisation untouched.
        findings = [_f("semgrep", i, has_dataflow=True) for i in range(8)]
        findings += [_f("codeql", i) for i in range(8)]
        result, deferred = apply_producer_fair_share(findings, 4)
        assert result is findings
        assert deferred is None

    def test_single_producer_taint_only_unchanged(self):
        findings = [
            _f(_TAINT_PRODUCER, i, has_dataflow=True) for i in range(8)
        ]
        result, deferred = apply_producer_fair_share(findings, 3)
        assert result is findings
        assert deferred is None


class TestFairShareInterleave:
    def test_three_producer_merge_every_producer_retains_share(self):
        # 12 taint findings front-run 4 semgrep + 4 codeql at cap 6.
        # Pre-interleave truncation would keep taint findings ONLY.
        findings = _mixed_set(taint=12, semgrep=4, codeql=4)
        result, deferred = apply_producer_fair_share(findings, 6)
        window = result[:6]
        by_tool = {}
        for f in window:
            by_tool[f["tool"]] = by_tool.get(f["tool"], 0) + 1
        assert by_tool[_TAINT_PRODUCER] == 2
        assert by_tool["semgrep"] == 2
        assert by_tool["codeql"] == 2
        # Deferred counts cover exactly the beyond-cap tail.
        assert deferred == {_TAINT_PRODUCER: 10, "semgrep": 2, "codeql": 2}
        assert sum(deferred.values()) == len(findings) - 6

    def test_within_producer_order_preserved(self):
        findings = _mixed_set(taint=6, semgrep=3, codeql=0)
        result, _ = apply_producer_fair_share(findings, 4)
        taint_ids = [f["finding_id"] for f in result
                     if f["tool"] == _TAINT_PRODUCER]
        semgrep_ids = [f["finding_id"] for f in result
                       if f["tool"] == "semgrep"]
        assert taint_ids == [f"{_TAINT_PRODUCER}-{i}" for i in range(6)]
        assert semgrep_ids == [f"semgrep-{i}" for i in range(3)]

    def test_no_finding_dropped_only_reordered(self):
        findings = _mixed_set(taint=5, semgrep=3, codeql=2)
        result, _ = apply_producer_fair_share(findings, 4)
        assert sorted(f["finding_id"] for f in result) == sorted(
            f["finding_id"] for f in findings
        )

    def test_exhausted_producer_slack_absorbed(self):
        # semgrep has one finding; round-robin lets the others absorb
        # the slack instead of leaving cap slots empty.
        findings = _mixed_set(taint=6, semgrep=1, codeql=6)
        result, _ = apply_producer_fair_share(findings, 7)
        window_tools = [f["tool"] for f in result[:7]]
        assert window_tools.count("semgrep") == 1
        assert window_tools.count(_TAINT_PRODUCER) == 3
        assert window_tools.count("codeql") == 3

    def test_deterministic_across_calls(self):
        findings = _mixed_set(taint=7, semgrep=5, codeql=3)
        first, first_deferred = apply_producer_fair_share(list(findings), 5)
        second, second_deferred = apply_producer_fair_share(list(findings), 5)
        assert [f["finding_id"] for f in first] == [
            f["finding_id"] for f in second
        ]
        assert first_deferred == second_deferred

    def test_producer_order_is_first_appearance(self):
        # codeql appears before taint in the input → codeql leads each
        # round-robin cycle (deterministic, input-order-derived).
        findings = [_f("codeql", 0), _f(_TAINT_PRODUCER, 0),
                    _f("codeql", 1), _f(_TAINT_PRODUCER, 1),
                    _f(_TAINT_PRODUCER, 2)]
        result, _ = apply_producer_fair_share(findings, 2)
        assert result[0]["tool"] == "codeql"
        assert result[1]["tool"] == _TAINT_PRODUCER

    def test_non_string_tool_bucketed_as_unknown(self):
        findings = [
            _f(_TAINT_PRODUCER, 0), _f(_TAINT_PRODUCER, 1),
            {"finding_id": "junk-0", "tool": 42},
            {"finding_id": "junk-1"},
        ]
        result, deferred = apply_producer_fair_share(findings, 2)
        assert len(result) == 4
        assert deferred is not None
        # Both junk rows share the "unknown" producer bucket.
        assert result[1]["finding_id"] == "junk-0"


class TestVocabularyPin:
    def test_producer_constant_matches_emission(self):
        from core.taint.emission import PRODUCER
        assert _TAINT_PRODUCER == PRODUCER


class TestProcessFindingsWiring:
    """Static-wiring sanity (same pattern as the journal-emit tests):
    the interleave is applied at the prioritisation point, between the
    prefer-glob ordering and the sequential-mode cap."""

    def test_call_present_in_process_findings(self):
        text = AGENT_PY.read_text(encoding="utf-8")
        assert (
            "fair_share_deferred = apply_producer_fair_share(" in text
        )

    def test_call_is_between_prefer_globs_and_cap(self):
        text = AGENT_PY.read_text(encoding="utf-8")
        prefer_idx = text.index("prioritized_findings = apply_prefer_globs(")
        fair_idx = text.index(
            "fair_share_deferred = apply_producer_fair_share("
        )
        cap_idx = text.index("prioritized_findings[:max_findings]")
        assert prefer_idx < fair_idx < cap_idx
