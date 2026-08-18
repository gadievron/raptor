"""Tests for pipelined ensemble (#10), file-level dampening (#4),
and callee-contract propagation (#6).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from core.audit.pipeline import (
    _apply_counter_hypothesis_veto,
    _apply_speculative_race_gate,
    _counter_hypothesis_vetoes,
    _dampen_file_pileup,
    _extract_bug_class,
    _is_speculative_race,
    _merge_outcomes,
    _needs_second_pass,
)


@dataclass
class _MockOutcome:
    file: str = "a.c"
    function: str = "foo"
    status: str = "clean"
    body: str = ""
    hypothesis: str = ""
    evidence_tool: str = ""
    cost_usd: float = 0.01
    model: str = "test"
    duration_s: float = 1.0
    review_result: dict[str, Any] | None = None
    line: int = 0
    hypotheses: list | None = None
    verification_tier: str = "speculative"
    tools_dispatched: set | None = field(default=None, repr=False)
    _propagated: bool = field(default=False, repr=False)
    error_class: str = ""


# ── #10: _needs_second_pass ──────────────────────────────────────────


class TestNeedsSecondPass:
    def test_clean_no_evidence_no_counter_skips(self):
        o = _MockOutcome(status="clean")
        assert not _needs_second_pass(o)

    def test_finding_always_needs_pass2(self):
        o = _MockOutcome(status="finding")
        assert _needs_second_pass(o)

    def test_suspicious_always_needs_pass2(self):
        o = _MockOutcome(status="suspicious")
        assert _needs_second_pass(o)

    def test_clean_with_evidence_needs_pass2(self):
        o = _MockOutcome(status="clean", evidence_tool="semgrep:rule1")
        assert _needs_second_pass(o)

    def test_clean_without_evidence_skips(self):
        o = _MockOutcome(
            status="clean",
            review_result={
                "counter_hypothesis": (
                    "An attacker could trigger an integer overflow in "
                    "the size calculation leading to a heap buffer overflow"
                ),
            },
        )
        assert not _needs_second_pass(o)


# ── #4: file-level dampening ────────────────────────────────────────


class TestFilePileupDampening:
    def test_no_dampening_below_threshold(self):
        outcomes = [
            _MockOutcome(
                file="a.c", function=f"f{i}",
                status="finding",
                hypothesis="integer overflow in size",
            )
            for i in range(2)
        ]
        assert _dampen_file_pileup(outcomes) == 0

    def test_three_same_class_dampened(self):
        outcomes = [
            _MockOutcome(
                file="a.c", function=f"f{i}",
                status="finding",
                hypothesis="integer overflow in calculation",
            )
            for i in range(3)
        ]
        dampened = _dampen_file_pileup(outcomes)
        assert dampened == 2
        finding_count = sum(1 for o in outcomes if o.status == "finding")
        assert finding_count == 1

    def test_mixed_classes_not_dampened(self):
        outcomes = [
            _MockOutcome(
                file="a.c", function="f1",
                status="finding",
                hypothesis="integer overflow",
            ),
            _MockOutcome(
                file="a.c", function="f2",
                status="finding",
                hypothesis="null pointer dereference",
            ),
            _MockOutcome(
                file="a.c", function="f3",
                status="finding",
                hypothesis="race condition in mutex",
            ),
        ]
        assert _dampen_file_pileup(outcomes) == 0

    def test_evidence_backed_not_dampened(self):
        outcomes = [
            _MockOutcome(
                file="a.c", function=f"f{i}",
                status="finding",
                hypothesis="integer overflow",
                evidence_tool="semgrep:rule1",
            )
            for i in range(4)
        ]
        assert _dampen_file_pileup(outcomes) == 0

    def test_different_files_independent(self):
        outcomes = []
        for f in ("a.c", "b.c"):
            for i in range(3):
                outcomes.append(_MockOutcome(
                    file=f, function=f"f{i}",
                    status="finding",
                    hypothesis="integer overflow",
                ))
        dampened = _dampen_file_pileup(outcomes)
        assert dampened == 4  # 2 from a.c + 2 from b.c

    def test_strongest_kept(self):
        outcomes = [
            _MockOutcome(
                file="a.c", function="f1",
                status="finding",
                hypothesis="integer overflow in the size calculation",
            ),
            _MockOutcome(
                file="a.c", function="f2",
                status="finding",
                hypothesis="integer overflow in size calculation",
            ),
            _MockOutcome(
                file="a.c", function="f3",
                status="suspicious",
                hypothesis="integer overflow in size calculation maybe",
            ),
        ]
        _dampen_file_pileup(outcomes)
        # f1 has most-specific hypothesis + finding status → kept
        assert outcomes[0].status == "finding"
        # f2 demoted finding→suspicious; f3 collapsed but NEVER
        # demoted to clean (softened dampening)
        assert outcomes[1].status == "suspicious"
        assert outcomes[2].status == "suspicious"


# ── #4: bug class extraction ────────────────────────────────────────


class TestExtractBugClass:
    def test_from_review_result(self):
        o = _MockOutcome(review_result={"bug_class": "arithmetic"})
        assert _extract_bug_class(o) == "arithmetic"

    def test_from_hypothesis_overflow(self):
        o = _MockOutcome(hypothesis="integer overflow in size calculation")
        assert _extract_bug_class(o) == "arithmetic"

    def test_from_hypothesis_null(self):
        o = _MockOutcome(hypothesis="null pointer dereference when buf is empty")
        assert _extract_bug_class(o) == "null_deref"

    def test_from_hypothesis_race(self):
        o = _MockOutcome(hypothesis="TOCTOU race between check and use")
        assert _extract_bug_class(o) == "concurrency"

    def test_fallback_other(self):
        o = _MockOutcome(hypothesis="unclear issue with the code")
        assert _extract_bug_class(o) == "other"


# ── #6: relies_on schema ────────────────────────────────────────────


class TestReliesOnSchema:
    def test_relies_on_in_schema(self):
        from core.audit.llm_review import REVIEW_SCHEMA

        assert "relies_on" in REVIEW_SCHEMA["properties"]
        ro = REVIEW_SCHEMA["properties"]["relies_on"]
        assert ro["type"] == "array"
        item_props = ro["items"]["properties"]
        assert "callee" in item_props
        assert "assumption" in item_props

    def test_relies_on_not_required(self):
        from core.audit.llm_review import REVIEW_SCHEMA

        assert "relies_on" not in REVIEW_SCHEMA["required"]


# ── #6: callee_contract_violation in prompt ─────────────────────────


class TestCalleeContractPrompt:
    def test_violation_appears_in_prompt(self):
        from core.audit.context import format_context_for_prompt

        ctx = {
            "file": "a.c",
            "function": "foo",
            "line_start": 1,
            "line_end": 10,
            "source": "void foo() {}",
            "callee_contract_violation": {
                "callee": "validate_input",
                "assumption": "validates input length",
                "callee_status": "finding",
                "callee_hypothesis": "missing bounds check on user input",
            },
        }
        prompt = format_context_for_prompt(ctx)
        assert "validate_input" in prompt
        assert "validates input length" in prompt
        assert "missing bounds check" in prompt

    def test_no_violation_no_section(self):
        from core.audit.context import format_context_for_prompt

        ctx = {
            "file": "a.c",
            "function": "foo",
            "line_start": 1,
            "line_end": 10,
            "source": "void foo() {}",
        }
        prompt = format_context_for_prompt(ctx)
        assert "Callee-contract" not in prompt


# ── #10: pipelined merge ────────────────────────────────────────────


class TestPipelinedMerge:
    def test_single_pass_clean_returns_unchanged(self):
        """When pass 1 is clean with no counter, pass 2 is skipped."""
        o = _MockOutcome(status="clean")
        assert not _needs_second_pass(o)

    def test_merge_demotes_without_evidence(self):
        """Disagree without evidence: conservative merge picks lower result."""
        sec = _MockOutcome(status="clean", file="a.c", function="foo")
        bf = _MockOutcome(
            status="finding", file="a.c", function="foo",
            hypothesis="buffer overflow",
        )
        merged = _merge_outcomes([sec], [bf])
        assert len(merged) == 1
        assert merged[0].status == "clean"

    def test_merge_keeps_finding_with_evidence(self):
        sec = _MockOutcome(status="clean", file="a.c", function="foo")
        bf = _MockOutcome(
            status="finding", file="a.c", function="foo",
            hypothesis="buffer overflow",
            evidence_tool="semgrep:rule1",
        )
        merged = _merge_outcomes([sec], [bf])
        assert len(merged) == 1
        assert merged[0].status == "finding"

    def test_merge_sums_cost(self):
        sec = _MockOutcome(
            status="finding", file="a.c", function="foo",
            cost_usd=0.05, evidence_tool="semgrep:rule1",
        )
        bf = _MockOutcome(
            status="finding", file="a.c", function="foo",
            cost_usd=0.03, evidence_tool="joern:flow1",
        )
        merged = _merge_outcomes([sec], [bf])
        assert merged[0].cost_usd == pytest.approx(0.08)

    def test_merge_demotes_detection_only_evidence(self):
        """Detection-role evidence is not verification — conservative merge picks lower."""
        sec = _MockOutcome(
            status="suspicious", file="a.c", function="foo",
            hypothesis="lock issue",
            evidence_tool="smt:check-lock-domain",
        )
        bf = _MockOutcome(status="clean", file="a.c", function="foo")
        merged = _merge_outcomes([sec], [bf])
        assert merged[0].status == "clean"

    def test_merge_demotes_llm_claimed_evidence(self):
        """llm-claimed evidence is not verification — conservative merge picks lower."""
        sec = _MockOutcome(
            status="suspicious", file="a.c", function="foo",
            hypothesis="lock issue",
            evidence_tool="llm-claimed:smt:check-lock-domain",
        )
        bf = _MockOutcome(status="clean", file="a.c", function="foo")
        merged = _merge_outcomes([sec], [bf])
        assert merged[0].status == "clean"


# ── Fix B: counter-hypothesis veto ─────────────────────────────────


class TestCounterHypothesisVeto:
    def _make_finding_with_counter(self, counter, *, evidence="", hypothesis=""):
        hyp = hypothesis or "integer overflow in size calculation"
        return _MockOutcome(
            status="finding",
            hypothesis=hyp,
            evidence_tool=evidence,
            review_result={"counter_hypothesis": counter},
        )

    def test_vetoes_with_protection_keyword(self):
        o = self._make_finding_with_counter(
            "This overflow is prevented by the bounds check on line 42 "
            "which validates size < MAX_SIZE before the multiplication",
        )
        assert _counter_hypothesis_vetoes(o) is True

    def test_no_veto_with_mechanical_evidence(self):
        o = self._make_finding_with_counter(
            "This overflow is prevented by the bounds check on line 42 "
            "which validates size < MAX_SIZE before the multiplication",
            evidence="semgrep:rule1",
        )
        assert _counter_hypothesis_vetoes(o) is False

    def test_no_veto_short_counter(self):
        o = self._make_finding_with_counter("prevented by check")
        assert _counter_hypothesis_vetoes(o) is False

    def test_no_veto_no_protection_keyword(self):
        o = self._make_finding_with_counter(
            "The overflow might happen but is unlikely because the values "
            "are typically small in practice and rarely exceed 1000",
        )
        assert _counter_hypothesis_vetoes(o) is False

    def test_no_veto_counter_too_short_relative_to_hypothesis(self):
        long_hyp = "x" * 200
        o = self._make_finding_with_counter(
            "prevented by bounds check on x",
            hypothesis=long_hyp,
        )
        # counter < 0.6 * hypothesis → no veto
        assert _counter_hypothesis_vetoes(o) is False

    def test_refuting_counter_vetoes(self):
        """A counter asserting the hypothesis was refuted argues in the
        clean direction exactly like a named protection mechanism —
        the veto must fire even without a protection keyword (live
        corpus case: llm-claimed SMT signal evaluated and refuted,
        verdict stayed suspicious)."""
        o = self._make_finding_with_counter(
            "The use-after-free claim was refuted with specific "
            "lock/refcount evidence: the claimed free site has no "
            "deallocation semantics and the pin/put lifecycle "
            "surrounds every use. Not a vulnerability.",
            evidence="llm-claimed:smt:check-early-release signal "
                     "evaluated and refuted",
        )
        assert _counter_hypothesis_vetoes(o) is True

    def test_refuting_counter_no_veto_with_mechanical_evidence(self):
        o = self._make_finding_with_counter(
            "The use-after-free claim was refuted with specific "
            "lock/refcount evidence: the pin/put lifecycle surrounds "
            "every use of the object. Not a vulnerability.",
            evidence="smt:check-early-release",
        )
        assert _counter_hypothesis_vetoes(o) is False

    def test_prefilter_evidence_still_vetoes(self):
        o = self._make_finding_with_counter(
            "This overflow is prevented by the bounds check on line 42 "
            "which validates size < MAX_SIZE before the multiplication",
            evidence="prefilter:sink",
        )
        assert _counter_hypothesis_vetoes(o) is True

    def test_apply_demotes_to_clean(self):
        outcomes = [
            self._make_finding_with_counter(
                "This overflow is prevented by the bounds check on line 42 "
                "which validates size < MAX_SIZE before the multiplication",
            ),
            _MockOutcome(status="finding", evidence_tool="semgrep:rule1"),
            _MockOutcome(status="clean"),
        ]
        vetoed = _apply_counter_hypothesis_veto(outcomes)
        assert vetoed == 1
        assert outcomes[0].status == "clean"
        assert outcomes[1].status == "finding"
        assert outcomes[2].status == "clean"


# ── Fix C: class-agnostic file dampening ───────────────────────────


class TestClassAgnosticDampening:
    def test_four_mixed_class_dampened_to_two(self):
        """≥4 evidence-free findings in one file → keep top 2."""
        outcomes = [
            _MockOutcome(
                file="a.c", function="f1", status="finding",
                hypothesis="integer overflow in size calculation path",
            ),
            _MockOutcome(
                file="a.c", function="f2", status="finding",
                hypothesis="null pointer dereference",
            ),
            _MockOutcome(
                file="a.c", function="f3", status="finding",
                hypothesis="race condition in handler",
            ),
            _MockOutcome(
                file="a.c", function="f4", status="finding",
                hypothesis="use-after-free",
            ),
        ]
        dampened = _dampen_file_pileup(outcomes)
        assert dampened == 2
        finding_count = sum(1 for o in outcomes if o.status == "finding")
        assert finding_count == 2

    def test_three_mixed_class_not_dampened(self):
        """3 mixed-class findings stay below class-agnostic threshold."""
        outcomes = [
            _MockOutcome(
                file="a.c", function="f1", status="finding",
                hypothesis="integer overflow",
            ),
            _MockOutcome(
                file="a.c", function="f2", status="finding",
                hypothesis="null dereference",
            ),
            _MockOutcome(
                file="a.c", function="f3", status="finding",
                hypothesis="race condition",
            ),
        ]
        assert _dampen_file_pileup(outcomes) == 0

    def test_same_class_and_agnostic_no_double_count(self):
        """Same-class dampening + class-agnostic don't double-demote."""
        outcomes = [
            _MockOutcome(
                file="a.c", function=f"f{i}", status="finding",
                hypothesis="integer overflow in calc",
            )
            for i in range(5)
        ]
        dampened = _dampen_file_pileup(outcomes)
        # Near-duplicate collapse fires first: 5 identical hypotheses →
        # keep 1, demote 4 finding→suspicious; the file cap must not
        # demote the same outcomes again.
        assert dampened == 4
        finding_count = sum(1 for o in outcomes if o.status == "finding")
        assert finding_count == 1
        assert all(o.status != "clean" for o in outcomes)

    def test_agnostic_preserves_evidence_backed(self):
        """Evidence-backed findings are never touched by agnostic tier."""
        outcomes = [
            _MockOutcome(
                file="a.c", function=f"f{i}", status="finding",
                hypothesis=f"bug type {i}",
                evidence_tool="semgrep:rule1",
            )
            for i in range(6)
        ]
        assert _dampen_file_pileup(outcomes) == 0


# ── Heavy pile-up (tier 3) ──────────────────────────────────────────


class TestHeavyPileupDampening:
    def test_six_findings_heavy_keeps_one(self):
        """>=6 evidence-free in one file → heavy tier, keep 1."""
        outcomes = [
            _MockOutcome(
                file="big.c", function=f"f{i}", status="finding",
                hypothesis=f"bug type {i} some details here",
            )
            for i in range(6)
        ]
        dampened = _dampen_file_pileup(outcomes)
        finding_count = sum(1 for o in outcomes if o.status == "finding")
        assert finding_count <= 1
        assert dampened >= 5

    def test_suspicious_pile_never_demoted_to_clean(self):
        """Suspicious pile-ups are collapsed/marked but NEVER silenced.

        Vulnerability density is heavy-tailed — the legacy file with
        many genuine issues is where audits earn their keep, so the
        softened dampener never demotes suspicious outcomes to clean.
        """
        outcomes = [
            _MockOutcome(
                file="big.c", function=f"f{i}", status="suspicious",
                hypothesis=f"suspicious thing {i} in the code path",
            )
            for i in range(7)
        ]
        _dampen_file_pileup(outcomes)
        assert all(o.status == "suspicious" for o in outcomes)

    def test_evidence_backed_survives_heavy(self):
        """Tool-backed findings survive even in heavy pile-up."""
        outcomes = [
            _MockOutcome(
                file="big.c", function=f"f{i}", status="finding",
                hypothesis=f"bug {i}",
                evidence_tool="semgrep:rule1" if i == 0 else "",
            )
            for i in range(8)
        ]
        _dampen_file_pileup(outcomes)
        # f0 has evidence → never touched
        assert outcomes[0].status == "finding"


# ── P29: softened dampening + audit trail ───────────────────────────


class TestSoftenedDampening:
    def test_same_class_distinct_hypotheses_not_collapsed(self):
        """Three DIFFERENT real overflows no longer collapse to one.

        The old coarse keyword-class grouping demoted two of these;
        near-duplicate collapse keeps all three distinct hypotheses.
        """
        outcomes = [
            _MockOutcome(
                file="a.c", function="f1", status="finding",
                hypothesis="integer overflow in width * height multiplication",
            ),
            _MockOutcome(
                file="a.c", function="f2", status="finding",
                hypothesis="unchecked length allows heap buffer overflow via memcpy",
            ),
            _MockOutcome(
                file="a.c", function="f3", status="finding",
                hypothesis="refcount wraparound after repeated acquire calls",
            ),
        ]
        assert _dampen_file_pileup(outcomes) == 0
        assert all(o.status == "finding" for o in outcomes)

    def test_heavy_pileup_never_demotes_to_clean(self):
        """>=6 evidence-free findings demote at most one step."""
        outcomes = [
            _MockOutcome(
                file="big.c", function=f"f{i}", status="finding",
                hypothesis=f"completely distinct bug shape number{i} "
                           f"variant{i * 7} path{i * 13}",
            )
            for i in range(8)
        ]
        dampened = _dampen_file_pileup(outcomes)
        assert dampened >= 5
        assert all(o.status in ("finding", "suspicious") for o in outcomes)
        assert any(o.status == "finding" for o in outcomes)

    def test_marker_and_record_stamped(self):
        from core.audit.pipeline import DAMPENING_MARKER, dampen_file_pileup

        outcomes = [
            _MockOutcome(
                file="a.c", function=f"f{i}", status="finding",
                hypothesis="integer overflow in size calculation",
            )
            for i in range(3)
        ]
        records: list = []
        dampened = dampen_file_pileup(outcomes, records=records)
        assert dampened == 2
        assert len(records) == 2
        rec = records[0]
        assert rec["file"] == "a.c"
        assert rec["tier"] == "near_duplicate"
        assert rec["from_status"] == "finding"
        assert rec["to_status"] == "suspicious"
        assert rec["group_size"] == 3
        assert rec["kept_function"]
        demoted = [o for o in outcomes if o.status == "suspicious"]
        assert len(demoted) == 2
        for o in demoted:
            assert DAMPENING_MARKER in o.hypothesis
            assert o.review_result["file_dampening"]["tier"] == "near_duplicate"

    def test_suspicious_collapse_marked_not_demoted(self):
        from core.audit.pipeline import DAMPENING_MARKER, dampen_file_pileup

        outcomes = [
            _MockOutcome(
                file="a.c", function=f"f{i}", status="suspicious",
                hypothesis="race condition on shared counter increment",
            )
            for i in range(3)
        ]
        records: list = []
        dampened = dampen_file_pileup(outcomes, records=records)
        # No status change — but the collapse is recorded and marked.
        assert dampened == 0
        assert len(records) == 2
        assert all(o.status == "suspicious" for o in outcomes)
        assert sum(DAMPENING_MARKER in o.hypothesis for o in outcomes) == 2

    def test_file_cap_records_tier(self):
        from core.audit.pipeline import dampen_file_pileup

        outcomes = [
            _MockOutcome(
                file="a.c", function=f"f{i}", status="finding",
                hypothesis=f"distinct issue kind{i} in area{i * 11} "
                           f"mechanism{i * 3}",
            )
            for i in range(4)
        ]
        records: list = []
        dampened = dampen_file_pileup(outcomes, records=records)
        assert dampened == 2
        assert all(r["tier"] == "file_cap" for r in records)


class TestDampenPreExportHook:
    def _result(self, outcomes):
        class _R:
            pass

        r = _R()
        r.outcomes = outcomes
        r.findings = sum(1 for o in outcomes if o.status == "finding")
        r.suspicious = sum(1 for o in outcomes if o.status == "suspicious")
        return r

    def _config(self, out_dir):
        class _C:
            pass

        c = _C()
        c.out_dir = out_dir
        return c

    def test_hook_writes_audit_log_and_recounts(self, tmp_path):
        import json

        from core.audit.pipeline import DAMPENING_LOG, dampen_pileup_pre_export

        outcomes = [
            _MockOutcome(
                file="a.c", function=f"f{i}", status="finding",
                hypothesis="integer overflow in size calculation",
            )
            for i in range(3)
        ]
        result = self._result(outcomes)
        config = self._config(tmp_path)

        dampen_pileup_pre_export(result, config)

        assert result.findings == 1
        assert result.suspicious == 2
        log = tmp_path / DAMPENING_LOG
        assert log.is_file()
        rows = [json.loads(line) for line in log.read_text().splitlines()]
        assert len(rows) == 2
        assert all(r["tier"] == "near_duplicate" for r in rows)

    def test_hook_noop_without_pileup(self, tmp_path):
        from core.audit.pipeline import DAMPENING_LOG, dampen_pileup_pre_export

        outcomes = [
            _MockOutcome(file="a.c", function="f1", status="finding",
                         hypothesis="single real bug"),
        ]
        result = self._result(outcomes)
        config = self._config(tmp_path)
        dampen_pileup_pre_export(result, config)
        assert result.findings == 1
        assert not (tmp_path / DAMPENING_LOG).exists()

    def test_ensemble_wires_hook_into_config(self, monkeypatch, tmp_path):
        """run_ensemble_pipeline registers the dampener as a pre-export
        hook instead of dampening post-hoc (after the export ran)."""
        import core.audit.llm_review as llm_review_mod
        import core.audit.orchestrator as orch_mod
        import core.audit.pipeline as pipeline_mod
        from core.audit.pipeline import AuditPipelineOpts, run_ensemble_pipeline

        captured = {}

        def _fake_run_orchestrator(config, review_fn, on_progress=None,
                                   prep_cache=None):
            captured["config"] = config

            class _R:
                def __init__(self):
                    self.outcomes = []
                    self.findings = 0
                    self.suspicious = 0
                    self.total_duration_s = 0.0

            return _R()

        monkeypatch.setattr(
            pipeline_mod, "_make_llm_client",
            lambda opts: (object(), ["default"], None),
        )
        monkeypatch.setattr(
            llm_review_mod, "make_review_fn",
            lambda *a, **k: (lambda ctx, config: None),
        )
        monkeypatch.setattr(
            orch_mod, "run_orchestrator", _fake_run_orchestrator,
        )

        opts = AuditPipelineOpts(target_path=tmp_path, out_dir=tmp_path)
        run_ensemble_pipeline(opts)

        hooks = captured["config"].pre_export_hooks
        assert hooks == [pipeline_mod.dampen_pileup_pre_export]

    def test_orchestrator_runs_hooks_before_export(self):
        """Ordering regression guard: the pre-export hook loop sits
        before the journal correction pass and the graded export."""
        import inspect

        import core.audit.orchestrator as orch_mod

        src = inspect.getsource(orch_mod)
        hook_pos = src.index("config.pre_export_hooks or ()")
        rejournal_pos = src.index("_rejournal_final_statuses(result, config)")
        export_pos = src.index("graded = export_findings(")
        assert hook_pos < rejournal_pos < export_pos


# ── Speculative-race gate ──────────────────────────────────────────


class TestSpeculativeRaceGate:
    def test_race_hypothesis_no_evidence_is_speculative(self):
        o = _MockOutcome(
            status="finding",
            hypothesis="A race condition between thread A and thread B",
        )
        assert _is_speculative_race(o) is True

    def test_toctou_hypothesis_is_speculative(self):
        o = _MockOutcome(
            status="suspicious",
            hypothesis="A TOCTOU vulnerability in the check-then-use pattern",
        )
        assert _is_speculative_race(o) is True

    def test_race_with_smt_evidence_not_speculative(self):
        o = _MockOutcome(
            status="finding",
            hypothesis="A race condition in the lock acquisition",
            evidence_tool="smt:check-lock-discipline",
        )
        assert _is_speculative_race(o) is False

    def test_race_with_coccinelle_evidence_not_speculative(self):
        o = _MockOutcome(
            status="finding",
            hypothesis="A race condition after unlock",
            evidence_tool="coccinelle:use_after_unlock",
        )
        assert _is_speculative_race(o) is False

    def test_non_race_hypothesis_not_gated(self):
        o = _MockOutcome(
            status="finding",
            hypothesis="An integer overflow in size * count",
        )
        assert _is_speculative_race(o) is False

    def test_clean_not_gated(self):
        """Gate only applies to finding/suspicious."""
        outcomes = [
            _MockOutcome(
                status="clean",
                hypothesis="A race condition but the code is safe",
            ),
        ]
        gated = _apply_speculative_race_gate(outcomes)
        assert gated == 0

    def test_gate_demotes_finding_to_suspicious(self):
        outcomes = [
            _MockOutcome(
                status="suspicious",
                hypothesis="A TOCTOU race condition between check and use",
            ),
            _MockOutcome(
                status="finding",
                hypothesis="A data race on the shared counter",
            ),
            _MockOutcome(
                status="finding",
                hypothesis="Integer overflow in multiplication",
            ),
        ]
        gated = _apply_speculative_race_gate(outcomes)
        assert gated == 1
        assert outcomes[0].status == "suspicious"   # suspicious stays
        assert outcomes[1].status == "suspicious"   # finding → suspicious
        assert outcomes[2].status == "finding"      # non-race, untouched

    def test_gate_works_on_dicts(self):
        from core.audit.pipeline import apply_speculative_race_gate

        results = [
            {"actual": "finding", "function_id": "a.c:f1",
             "hypothesis": "A race condition on shared state",
             "evidence_tool": ""},
        ]
        gated = apply_speculative_race_gate(results)
        assert gated == 1
        assert results[0]["actual"] == "suspicious"  # finding → suspicious

    def test_concurrent_keyword_gated(self):
        o = _MockOutcome(
            status="suspicious",
            hypothesis="Two threads concurrently access the buffer",
        )
        assert _is_speculative_race(o) is True

    def test_prefilter_lock_evidence_not_gated(self):
        o = _MockOutcome(
            status="finding",
            hypothesis="A race condition in the lock path",
            evidence_tool="prefilter:lock-imbalance",
        )
        assert _is_speculative_race(o) is False


# ── Fix D: _status_matches (corpus scoring) ───────────────────────


class TestStatusMatches:
    def test_finding_matches_suspicious(self):
        from core.audit.corpus.run_corpus import _status_matches

        assert _status_matches("finding", "suspicious") is True

    def test_finding_matches_finding(self):
        from core.audit.corpus.run_corpus import _status_matches

        assert _status_matches("finding", "finding") is True

    def test_finding_does_not_match_clean(self):
        from core.audit.corpus.run_corpus import _status_matches

        assert _status_matches("finding", "clean") is False

    def test_clean_matches_clean(self):
        from core.audit.corpus.run_corpus import _status_matches

        assert _status_matches("clean", "clean") is True

    def test_clean_matches_dormant(self):
        from core.audit.corpus.run_corpus import _status_matches

        assert _status_matches("clean", "dormant") is True

    def test_clean_does_not_match_finding(self):
        from core.audit.corpus.run_corpus import _status_matches

        assert _status_matches("clean", "finding") is False


# ── Fix E: concurrency deep check in system prompt ────────────────


class TestConcurrencyDeepCheck:
    def test_prompt_contains_concurrency_deep_check(self):
        from core.audit.llm_review import _SYSTEM_PROMPT_TEMPLATE

        assert "CONCURRENCY DEEP CHECK" in _SYSTEM_PROMPT_TEMPLATE

    def test_prompt_contains_lock_domain_mismatch(self):
        from core.audit.llm_review import _SYSTEM_PROMPT_TEMPLATE

        assert "Lock-domain mismatch" in _SYSTEM_PROMPT_TEMPLATE

    def test_prompt_contains_early_lock_release(self):
        from core.audit.llm_review import _SYSTEM_PROMPT_TEMPLATE

        assert "Early lock release" in _SYSTEM_PROMPT_TEMPLATE

    def test_prompt_contains_callback_wakeup_races(self):
        from core.audit.llm_review import _SYSTEM_PROMPT_TEMPLATE

        assert "Callback/wakeup races" in _SYSTEM_PROMPT_TEMPLATE


# ── Fix F: SMT hypothesis disproof ────────────────────────────────


class TestHypothesisDisproof:
    def test_import_and_dataclass(self):
        from core.audit.condition_smt import HypothesisDisproofResult

        r = HypothesisDisproofResult(
            hypothesis_class="integer_overflow",
            disproved=True,
            reasoning="test",
        )
        assert r.disproved is True
        d = r.to_dict()
        assert d["disproved"] is True
        assert d["hypothesis_class"] == "integer_overflow"

    def test_no_z3_returns_error(self):
        import importlib
        import sys

        z3_mod = sys.modules.get("z3")
        sys.modules["z3"] = None
        try:
            importlib.invalidate_caches()
            from core.audit.condition_smt import disprove_integer_overflow

            r = disprove_integer_overflow(
                "integer overflow in the multiplication of a * b",
                "uint32_t a; uint32_t b;",
            )
            assert r.error == "z3 not installed"
            assert r.disproved is None
        finally:
            if z3_mod is not None:
                sys.modules["z3"] = z3_mod
            else:
                sys.modules.pop("z3", None)

    def test_no_expression_returns_inconclusive(self):
        z3_available = True
        try:
            import z3  # noqa: F401
        except ImportError:
            z3_available = False

        if not z3_available:
            pytest.skip("z3 not installed")

        from core.audit.condition_smt import disprove_integer_overflow

        r = disprove_integer_overflow(
            "the function has problems with edge cases",
            "int x; int y;",
        )
        assert r.disproved is None
        assert "could not extract" in r.reasoning

    def test_type_widths_present(self):
        from core.audit.condition_smt import _TYPE_WIDTHS

        assert _TYPE_WIDTHS["int"] == 32
        assert _TYPE_WIDTHS["uint64_t"] == 64
        assert _TYPE_WIDTHS["size_t"] == 64
        assert _TYPE_WIDTHS["uint8_t"] == 8

    def test_regex_extracts_expression(self):
        from core.audit.condition_smt import _INT_HYPO_RE

        m = _INT_HYPO_RE.search(
            "integer overflow in the calculation `count * element_size`"
        )
        assert m is not None
        assert "count" in m.group(1)


# ── Fix A: callee-contract evidence gate (orchestrator) ────────────


class TestCalleeContractEvidenceGate:
    """The callee-contract requeue should skip callees with no evidence."""

    def test_gate_concept(self):
        """Verify the evidence-gate logic independently.

        The actual function _callee_contract_requeue has heavy
        dependencies (OrchestratorResult, review_fn, etc.) so we test
        the gating logic pattern in isolation.
        """
        _NON_MECHANICAL = ("prefilter:", "llm-claimed:")

        def _should_propagate(co_evidence: str) -> bool:
            return bool(co_evidence) and not co_evidence.startswith(_NON_MECHANICAL)

        assert _should_propagate("semgrep:rule1") is True
        assert _should_propagate("joern:flow1") is True
        assert _should_propagate("codeql:query1") is True
        assert _should_propagate("") is False
        assert _should_propagate("prefilter:sink") is False
        assert _should_propagate("llm-claimed:overflow") is False


# ── Bug fixes (P0) ────────────────────────────────────────────────


class TestBugFixes:
    def test_type_widths_not_shadowed(self):
        """_TYPE_WIDTHS should include kernel-style types (u32, s64, etc.)."""
        from core.audit.condition_smt import _TYPE_WIDTHS

        assert _TYPE_WIDTHS["u32"] == 32
        assert _TYPE_WIDTHS["s64"] == 64
        assert _TYPE_WIDTHS["__u16"] == 16
        assert _TYPE_WIDTHS["loff_t"] == 64
        assert _TYPE_WIDTHS["uintptr_t"] == 64

    def test_disproof_type_widths_is_comprehensive(self):
        """_DISPROOF_TYPE_WIDTHS should be the same as _TYPE_WIDTHS."""
        from core.audit.condition_smt import (
            _DISPROOF_TYPE_WIDTHS,
            _TYPE_WIDTHS,
        )

        assert _DISPROOF_TYPE_WIDTHS is _TYPE_WIDTHS

    def test_sweep_result_has_details_field(self):
        from core.audit.sweep import SweepResult

        r = SweepResult(
            tool="smt", file_path="a.c", function_name="foo",
            outcome="confirmed", details={"key": "val"},
        )
        assert r.details == {"key": "val"}

    def test_status_rank_aligned(self):
        """_STATUS_RANK should agree between pipeline.py and run_corpus.py."""
        from core.audit.corpus.run_corpus import _STATUS_RANK as corpus_rank
        from core.audit.pipeline import _STATUS_RANK as pipeline_rank

        assert pipeline_rank == corpus_rank


# ── P2: CWE dispatch wiring ──────────────────────────────────────


class TestCweDispatchWiring:
    def test_concurrency_has_smt_verb(self):
        from core.audit.cwe_dispatch import smt_verb_for_cwe

        assert smt_verb_for_cwe("CWE-362") == "check-lock-domain"
        assert smt_verb_for_cwe("CWE-667") == "check-lock-discipline"

    def test_auth_has_smt_verb(self):
        from core.audit.cwe_dispatch import smt_verb_for_cwe

        assert smt_verb_for_cwe("CWE-287") == "check-auth-bypass"
        assert smt_verb_for_cwe("CWE-862") == "check-auth-bypass"

    def test_null_has_smt_verb(self):
        from core.audit.cwe_dispatch import smt_verb_for_cwe

        assert smt_verb_for_cwe("CWE-476") == "check-null-propagation"

    def test_resource_leak_has_smt_verb(self):
        from core.audit.cwe_dispatch import smt_verb_for_cwe

        assert smt_verb_for_cwe("CWE-401") == "check-resource-leak"

    def test_integer_narrowing_has_smt_verb(self):
        from core.audit.cwe_dispatch import smt_verb_for_cwe

        assert smt_verb_for_cwe("CWE-681") == "check-integer-narrowing"


# ── Phase 2: New mechanical verifiers ─────────────────────────────


class TestEarlyRelease:
    def test_go_early_release_detected(self):
        from core.audit.condition_smt import check_early_release

        source = '''\
func (r *Reader) Read() string {
    r.mu.RLock()
    val := r.data.Value
    r.mu.RUnlock()
    return fmt.Sprintf("%s", val)
}
'''
        result = check_early_release(source)
        assert result.early_release_found is True
        assert "val" in result.variable
        assert "race window" in result.reasoning

    def test_go_defer_not_flagged(self):
        from core.audit.condition_smt import check_early_release

        source = '''\
func (r *Reader) Read() string {
    r.mu.RLock()
    defer r.mu.RUnlock()
    val := r.data.Value
    return fmt.Sprintf("%s", val)
}
'''
        result = check_early_release(source)
        assert result.early_release_found is False

    def test_c_early_release_detected(self):
        from core.audit.condition_smt import check_early_release

        source = '''\
void read_state(struct ctx *c) {
    spin_lock(&c->lock);
    struct node *n = c->head;
    spin_unlock(&c->lock);
    process(n->data);
}
'''
        result = check_early_release(source)
        assert result.early_release_found is True
        assert "n" in result.variable

    def test_c_no_use_after_unlock(self):
        from core.audit.condition_smt import check_early_release

        source = '''\
void read_state(struct ctx *c) {
    spin_lock(&c->lock);
    c->counter++;
    spin_unlock(&c->lock);
    return;
}
'''
        result = check_early_release(source)
        assert result.early_release_found is False


class TestLockDomain:
    def test_c_cross_domain_detected(self):
        from core.audit.condition_smt import check_lock_domain

        source = '''\
void check_creds(struct task *t) {
    spin_lock(&t->cred_lock);
    uid = t->cred->uid;
    spin_unlock(&t->cred_lock);

    mutex_lock(&t->group_lock);
    gid = t->cred->gid;
    mutex_unlock(&t->group_lock);
}
'''
        result = check_lock_domain(source)
        assert result.mismatch_found is True
        assert "cred" in result.field

    def test_c_same_lock_not_flagged(self):
        from core.audit.condition_smt import check_lock_domain

        source = '''\
void check_creds(struct task *t) {
    spin_lock(&t->cred_lock);
    uid = t->cred->uid;
    gid = t->cred->gid;
    spin_unlock(&t->cred_lock);
}
'''
        result = check_lock_domain(source)
        assert result.mismatch_found is False

    def test_go_cross_domain_detected(self):
        from core.audit.condition_smt import check_lock_domain

        source = '''\
func (s *Server) HandleRequest() {
    s.authMu.Lock()
    user := s.state.User
    s.authMu.Unlock()

    s.dataMu.Lock()
    role := s.state.Role
    s.dataMu.Unlock()
}
'''
        result = check_lock_domain(source)
        assert result.mismatch_found is True
        assert "state" in result.field


class TestTocTou:
    def test_c_stat_then_open(self):
        from core.audit.condition_smt import check_toctou

        source = '''\
int check_and_open(const char *path) {
    struct stat st;
    if (stat(path, &st) < 0) return -1;
    if (!S_ISREG(st.st_mode)) return -1;
    int fd = open(path, O_RDONLY);
    return fd;
}
'''
        result = check_toctou(source)
        assert result.toctou_found is True
        assert result.check_call == "stat"
        assert result.use_call == "open"
        assert "path" in result.variable

    def test_c_no_toctou_safe(self):
        from core.audit.condition_smt import check_toctou

        source = '''\
int safe_open(const char *path) {
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return -1;
    struct stat st;
    fstat(fd, &st);
    return fd;
}
'''
        result = check_toctou(source)
        assert result.toctou_found is False

    def test_go_stat_then_open(self):
        from core.audit.condition_smt import check_toctou

        source = '''\
package main

import "os"

func readIfExists(path string) ([]byte, error) {
    _, err := os.Stat(path)
    if err != nil {
        return nil, err
    }
    f, err := os.Open(path)
    if err != nil {
        return nil, err
    }
    defer f.Close()
    return io.ReadAll(f)
}
'''
        result = check_toctou(source)
        assert result.toctou_found is True
        assert result.check_call == "os.Stat"
        assert result.use_call == "os.Open"

    def test_py_exists_then_open(self):
        from core.audit.condition_smt import check_toctou

        source = '''\
import os

def read_config(path):
    if os.path.exists(path):
        with open(path) as f:
            return f.read()
    return None
'''
        result = check_toctou(source)
        assert result.toctou_found is True
        assert "os.path.exists" in result.check_call
        assert result.use_call == "open"

    def test_double_fetch(self):
        from core.audit.condition_smt import check_toctou

        source = '''\
int handle_cmd(struct cmd __user *ucmd) {
    struct cmd kcmd;
    if (copy_from_user(&kcmd, ucmd, sizeof(kcmd)))
        return -EFAULT;
    char *buf = kmalloc(kcmd.len, GFP_KERNEL);
    if (copy_from_user(buf, ucmd, kcmd.len))
        goto err;
    return process(buf, kcmd.len);
err:
    kfree(buf);
    return -EFAULT;
}
'''
        result = check_toctou(source)
        assert result.toctou_found is True
        assert "double fetch" in result.reasoning

    def test_sweep_dispatch(self):
        from core.audit.sweep import _SMT_VERBS
        assert "check-toctou" in _SMT_VERBS


# ── W8: Dual code path unification ──────────────────────────────────


class TestW8Unification:
    def test_status_rank_imported_not_duplicated(self):
        from core.audit.corpus.run_corpus import _STATUS_RANK
        from core.audit.pipeline import STATUS_RANK

        assert _STATUS_RANK is STATUS_RANK

    def test_dampen_works_on_dicts(self):
        from core.audit.pipeline import dampen_file_pileup

        results = [
            {"actual": "finding", "function_id": "a.c:f1",
             "hypothesis": "integer overflow on x", "evidence_tool": ""},
            {"actual": "finding", "function_id": "a.c:f2",
             "hypothesis": "integer overflow on y", "evidence_tool": ""},
            {"actual": "finding", "function_id": "a.c:f3",
             "hypothesis": "integer overflow on z", "evidence_tool": ""},
        ]
        dampened = dampen_file_pileup(results)
        assert dampened >= 2
        statuses = [r["actual"] for r in results]
        assert "finding" in statuses  # strongest kept

    def test_veto_works_on_dicts(self):
        from core.audit.pipeline import apply_counter_hypothesis_veto

        results = [
            {
                "actual": "finding",
                "hypothesis": "integer overflow in x * y",
                "evidence_tool": "",
                "counter_hypothesis": (
                    "This overflow is prevented by the bounds check on line 42 "
                    "which validates that x < MAX_SIZE before the multiplication"
                ),
            },
        ]
        vetoed = apply_counter_hypothesis_veto(results)
        assert vetoed == 1
        assert results[0]["actual"] == "clean"

    def test_dampen_works_on_objects(self):
        from core.audit.pipeline import dampen_file_pileup

        outcomes = [
            _MockOutcome(file="b.c", function=f"f{i}", status="finding",
                         hypothesis="integer overflow cond", evidence_tool="")
            for i in range(4)
        ]
        dampened = dampen_file_pileup(outcomes)
        assert dampened >= 2
        statuses = [o.status for o in outcomes]
        assert "finding" in statuses  # strongest kept


class TestRuleRole:
    """Tests for coccinelle rule role metadata."""

    def test_get_rule_role_verification(self, tmp_path):
        rule = tmp_path / "double_free.cocci"
        rule.write_text("// double_free.cocci\n// @role: verification\n@@\n")
        from core.audit.sweep import get_rule_role
        assert get_rule_role(str(rule)) == "verification"

    def test_get_rule_role_detection(self, tmp_path):
        rule = tmp_path / "resource_leak_err.cocci"
        rule.write_text("// resource_leak\n// @role: detection\n@@\n")
        from core.audit.sweep import get_rule_role
        assert get_rule_role(str(rule)) == "detection"

    def test_get_rule_role_missing_defaults_detection(self, tmp_path):
        rule = tmp_path / "unknown.cocci"
        rule.write_text("// no role annotation\n@@\n")
        from core.audit.sweep import get_rule_role
        assert get_rule_role(str(rule)) == "detection"

    def test_get_rule_role_nonexistent_file(self):
        from core.audit.sweep import get_rule_role
        assert get_rule_role("/nonexistent/path.cocci") == "detection"

    def test_real_resource_leak_is_detection(self):
        import os

        from core.audit.sweep import get_rule_role
        rule = os.path.join(
            os.environ.get("RAPTOR_DIR", "."),
            "engine", "coccinelle", "rules", "resource_leak_err.cocci",
        )
        assert get_rule_role(rule) == "detection"

    def test_real_use_after_free_is_verification(self):
        import os

        from core.audit.sweep import get_rule_role
        rule = os.path.join(
            os.environ.get("RAPTOR_DIR", "."),
            "engine", "coccinelle", "rules", "use_after_free.cocci",
        )
        assert get_rule_role(rule) == "verification"


class TestBuildOrchestratorConfig:
    """Both pipeline entry points build their OrchestratorConfig via
    the shared _build_orchestrator_config helper."""

    def test_threads_opts_fields(self, tmp_path):
        from core.audit.pipeline import (
            AuditPipelineOpts,
            ReviewMode,
            _build_orchestrator_config,
        )

        opts = AuditPipelineOpts(
            target_path=tmp_path,
            out_dir=tmp_path / "out",
            models=["m1", "m2"],
            max_cost_usd=5.0,
            batch_sloc_threshold=42,
            schedule="priority",
            adversarial=True,
            max_workers=3,
        )
        client = object()
        cfg = _build_orchestrator_config(
            opts, client, ["m1", "m2"], ReviewMode.SECURITY,
        )
        assert cfg.target_path == tmp_path
        assert cfg.models == ["m1", "m2"]
        assert cfg.multi_model is True
        assert cfg.adversarial is True
        assert cfg.max_cost_usd == 5.0
        assert cfg.batch_sloc_threshold == 42
        assert cfg.schedule == "priority"
        assert cfg.max_workers == 3
        assert cfg.mode is ReviewMode.SECURITY
        assert cfg.llm_client is client
        assert cfg.llm_budget_client is client

    def test_batch_sloc_default_preserved(self, tmp_path):
        from core.audit.orchestrator import OrchestratorConfig
        from core.audit.pipeline import (
            AuditPipelineOpts,
            ReviewMode,
            _build_orchestrator_config,
        )

        opts = AuditPipelineOpts(target_path=tmp_path, out_dir=tmp_path)
        cfg = _build_orchestrator_config(
            opts, object(), ["default"], ReviewMode.ENSEMBLE,
        )
        assert cfg.batch_sloc_threshold == (
            OrchestratorConfig(
                target_path=tmp_path, out_dir=tmp_path,
            ).batch_sloc_threshold
        )
        assert cfg.multi_model is False
