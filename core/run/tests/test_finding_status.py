"""Tests for ``core.run.finding_status`` — the unified per-finding
status enum + helpers (QoL #19)."""

from __future__ import annotations

import pytest

from core.run.finding_status import (
    ALL_STATUSES,
    ANALYSED,
    ANALYSIS_INCONSISTENT,
    ERROR,
    SKIPPED,
    SKIPPED_DEAD_CODE,
    SKIPPED_DUPLICATE,
    SKIPPED_FILTERED,
    SKIPPED_OVER_BUDGET,
    SKIPPED_TOOL_ABSENT,
    derive_status,
    get_status,
    is_actionable,
    is_errored,
    is_skipped,
    is_terminal,
    needs_review,
    set_status,
)


class TestDeriveStatus:
    """Backwards-compat path: status inferred from existing finding
    fields when no explicit ``status`` was stamped."""

    def test_error_field_gives_error(self):
        assert derive_status({"error": "timeout"}) == ERROR

    def test_missing_verdict_gives_skipped(self):
        # No is_true_positive → not analysed → generic skipped (the
        # caller didn't record a specific skip reason; #19's whole
        # point is to start recording one explicitly).
        assert derive_status({"file_path": "x.c"}) == SKIPPED

    def test_self_contradictory_exploitable_gives_inconsistent(self):
        finding = {
            "is_true_positive": True,
            "is_exploitable": True,
            "self_contradictory": True,
        }
        assert derive_status(finding) == ANALYSIS_INCONSISTENT

    def test_judge_resolved_contradiction_gives_analysed(self):
        # JudgeTask (commit 727300fc) clears self_contradictory and
        # sets contradiction_resolved_by_judge. The derived status
        # should be ``analysed`` — the contradiction WAS resolved.
        finding = {
            "is_true_positive": True,
            "is_exploitable": True,
            "self_contradictory": False,
            "contradiction_resolved_by_judge": True,
        }
        assert derive_status(finding) == ANALYSED

    def test_clean_exploitable_gives_analysed(self):
        finding = {
            "is_true_positive": True,
            "is_exploitable": True,
        }
        assert derive_status(finding) == ANALYSED

    def test_clean_false_positive_gives_analysed(self):
        # A false-positive verdict IS an analysis result — still
        # "analysed". The verdict's value (TP vs FP) is orthogonal
        # to whether analysis happened.
        finding = {
            "is_true_positive": False,
            "is_exploitable": False,
        }
        assert derive_status(finding) == ANALYSED


class TestSetStatus:
    def test_stamps_status_and_skip_reason(self):
        finding = {"file_path": "x.c"}
        set_status(finding, SKIPPED_OVER_BUDGET,
                   skip_reason="cap reached after 8 findings")
        assert finding["status"] == SKIPPED_OVER_BUDGET
        assert finding["skip_reason"] == "cap reached after 8 findings"

    def test_skip_reason_optional(self):
        finding = {"file_path": "x.c"}
        set_status(finding, ANALYSED)
        assert finding["status"] == ANALYSED
        assert "skip_reason" not in finding

    def test_unknown_status_raises(self):
        # Deliberate — typos would silently break the audit trail
        # otherwise.
        with pytest.raises(ValueError) as exc:
            set_status({}, "skipped_silently")
        assert "unknown status" in str(exc.value).lower()

    def test_overwrites_existing_status(self):
        # Lifecycle: a finding might transition from ``analysed`` to
        # something else (rare but possible — e.g. ``error`` on a
        # late-stage retry). Don't fight it.
        finding = {"status": ANALYSED}
        set_status(finding, ERROR)
        assert finding["status"] == ERROR


class TestGetStatus:
    def test_prefers_explicit_status(self):
        # Even when derive would say something else, explicit wins.
        finding = {
            "status": SKIPPED_DUPLICATE,  # explicit
            "is_true_positive": True,     # derive would say ANALYSED
            "is_exploitable": True,
        }
        assert get_status(finding) == SKIPPED_DUPLICATE

    def test_falls_back_to_derive_when_status_missing(self):
        finding = {"error": "boom"}
        assert get_status(finding) == ERROR

    def test_unknown_explicit_status_falls_back_to_derive(self):
        # Defensive: if a finding carries an unknown status string
        # (perhaps written by an older codebase variant), the
        # derive fallback still produces a meaningful classification
        # from the other fields.
        finding = {
            "status": "made_up_value",
            "is_true_positive": True,
        }
        assert get_status(finding) == ANALYSED  # derived


class TestPredicates:
    """is_actionable / needs_review / is_skipped / is_errored
    surface the four orthogonal questions consumers actually ask."""

    def test_is_actionable_only_analysed(self):
        assert is_actionable({"status": ANALYSED}) is True
        assert is_actionable({"status": ANALYSIS_INCONSISTENT}) is False
        assert is_actionable({"status": SKIPPED_OVER_BUDGET}) is False
        assert is_actionable({"status": ERROR}) is False

    def test_needs_review_only_analysis_inconsistent(self):
        assert needs_review({"status": ANALYSIS_INCONSISTENT}) is True
        assert needs_review({"status": ANALYSED}) is False
        assert needs_review({"status": ERROR}) is False

    def test_is_skipped_covers_all_skip_variants(self):
        for s in [SKIPPED, SKIPPED_OVER_BUDGET, SKIPPED_DUPLICATE,
                  SKIPPED_DEAD_CODE, SKIPPED_FILTERED, SKIPPED_TOOL_ABSENT]:
            assert is_skipped({"status": s}) is True, f"missed {s}"
        assert is_skipped({"status": ANALYSED}) is False
        assert is_skipped({"status": ERROR}) is False

    def test_is_errored_only_error(self):
        assert is_errored({"status": ERROR}) is True
        assert is_errored({"status": SKIPPED_OVER_BUDGET}) is False

    def test_is_terminal_true_for_all_known_statuses(self):
        for s in ALL_STATUSES:
            assert is_terminal({"status": s}) is True


class TestPredicatesWithDerivedStatus:
    """Predicates work against the derive fallback too — pre-#19
    emit paths get correct classification without explicit
    ``status`` stamping."""

    def test_actionable_from_legacy_shape(self):
        # Legacy finding (no status field, just is_true_positive).
        finding = {"is_true_positive": True, "is_exploitable": False}
        assert is_actionable(finding) is True

    def test_needs_review_from_legacy_contradictory_shape(self):
        finding = {
            "is_true_positive": True, "is_exploitable": True,
            "self_contradictory": True,
        }
        assert needs_review(finding) is True

    def test_skipped_from_legacy_missing_verdict(self):
        # No is_true_positive key → derived as skipped (generic).
        assert is_skipped({"file_path": "x.c"}) is True


class TestExportSurface:
    def test_all_statuses_match_module_constants(self):
        # ALL_STATUSES should match the union of every exported
        # status constant — catches the case where a new status is
        # added but ALL_STATUSES isn't updated, which would break
        # ``set_status``'s validation.
        from core.run import finding_status as fs
        constants = {
            v for k, v in vars(fs).items()
            if not k.startswith("_") and k.isupper()
            and isinstance(v, str) and v in fs.ALL_STATUSES
        }
        assert constants == set(fs.ALL_STATUSES)
