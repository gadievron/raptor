"""Tests for ``_finalize_results_for_emit`` — the orchestrator's
emit-side finaliser that strips operator-internal fields + stamps
the explicit status enum (QoL #10 / #11-11e / #19) on each result
before save_json hits disk."""

from __future__ import annotations

from packages.llm_analysis.orchestrator import _finalize_results_for_emit


class TestRepoPathStripping:
    """Operator-internal ``repo_path`` was carried per-finding for
    SAGE enrichment scoping (orchestrate ~line 303); must be gone
    from the on-disk record so filesystem layout doesn't leak to
    anyone the report is shared with."""

    def test_repo_path_removed(self):
        results = [{
            "finding_id": "F1",
            "repo_path": "/home/alice/projects/secret-target",
            "is_true_positive": True,
            "is_exploitable": True,
        }]
        _finalize_results_for_emit(results)
        assert "repo_path" not in results[0]

    def test_missing_repo_path_is_noop(self):
        results = [{"finding_id": "F1", "is_true_positive": True}]
        # Findings that never had repo_path stamped (e.g. CC-prep
        # path) don't crash.
        _finalize_results_for_emit(results)
        assert "repo_path" not in results[0]


class TestStatusStamping:
    """Explicit status field per the QoL #19 enum lands on every
    result so downstream readers (raptor_agentic summary, report
    renderers, automation) skip null-field detection."""

    def test_analysed_finding_gets_analysed_status(self):
        results = [{
            "finding_id": "F1",
            "is_true_positive": True,
            "is_exploitable": True,
        }]
        _finalize_results_for_emit(results)
        assert results[0]["status"] == "analysed"

    def test_self_contradictory_gets_analysis_inconsistent_status(self):
        results = [{
            "finding_id": "F1",
            "is_true_positive": True,
            "is_exploitable": True,
            "self_contradictory": True,
        }]
        _finalize_results_for_emit(results)
        assert results[0]["status"] == "analysis_inconsistent"

    def test_judge_resolved_contradiction_lands_in_analysed(self):
        # Composes with the QoL #11-11d judge-resolution shipped in
        # the previous batch: a finding that WAS self_contradictory
        # but the judge resolved it lands in ``analysed`` (not
        # ``analysis_inconsistent``), so the headline counts drop
        # the false-positive review load.
        results = [{
            "finding_id": "F1",
            "is_true_positive": True,
            "is_exploitable": True,
            "self_contradictory": False,
            "contradiction_resolved_by_judge": True,
        }]
        _finalize_results_for_emit(results)
        assert results[0]["status"] == "analysed"

    def test_error_finding_gets_error_status(self):
        results = [{
            "finding_id": "F1",
            "error": "timeout after 600s",
        }]
        _finalize_results_for_emit(results)
        assert results[0]["status"] == "error"

    def test_missing_verdict_gets_skipped_status(self):
        # No is_true_positive key → derived as generic skipped.
        # Producers that know the specific reason (budget cap,
        # dedup, binary-oracle) stamp ``skipped_*`` explicitly;
        # this fallback covers the case where SOMETHING decided
        # to drop the finding without recording the reason.
        results = [{"finding_id": "F1", "file_path": "x.c"}]
        _finalize_results_for_emit(results)
        assert results[0]["status"] == "skipped"


class TestExplicitStatusPreserved:
    """When a producer already stamped an explicit ``status`` value
    (skipped_over_budget, skipped_duplicate, skipped_dead_code),
    the finaliser MUST NOT clobber it — those values carry more
    information than the generic ``skipped`` derivation."""

    def test_explicit_skipped_over_budget_preserved(self):
        # Producer (budget cap) stamped specific reason; finaliser
        # leaves it alone.
        results = [{
            "finding_id": "F1",
            "status": "skipped_over_budget",
            "skip_reason": "cap reached after 8 findings",
        }]
        _finalize_results_for_emit(results)
        assert results[0]["status"] == "skipped_over_budget"
        assert results[0]["skip_reason"] == "cap reached after 8 findings"

    def test_explicit_skipped_dead_code_preserved(self):
        # binary-oracle stamped status; preserved.
        results = [{
            "finding_id": "F1",
            "status": "skipped_dead_code",
            "is_true_positive": True,  # would normally derive to analysed
            "is_exploitable": True,
        }]
        _finalize_results_for_emit(results)
        assert results[0]["status"] == "skipped_dead_code"

    def test_unknown_explicit_status_overwritten_by_derive(self):
        # Defensive: a malformed status string (typo, older
        # codebase variant) falls back to derive so the on-disk
        # value is always one of ALL_STATUSES.
        results = [{
            "finding_id": "F1",
            "status": "made_up_value",
            "is_true_positive": True,
        }]
        _finalize_results_for_emit(results)
        assert results[0]["status"] == "analysed"


class TestNonDictResultsTolerated:
    """Defensive: the loop must not crash on malformed records
    (None, list, string) that shouldn't be there but might creep
    in via test fixtures / corrupted JSON / sub-task dispatch
    errors writing the wrong shape."""

    def test_none_entry_skipped(self):
        results = [None, {"finding_id": "F1", "is_true_positive": True}]
        _finalize_results_for_emit(results)
        # The dict entry got its status; the None was left alone.
        assert results[0] is None
        assert results[1]["status"] == "analysed"

    def test_list_entry_skipped(self):
        results = [[], {"finding_id": "F1", "is_true_positive": True}]
        _finalize_results_for_emit(results)
        assert results[1]["status"] == "analysed"

    def test_empty_results_is_noop(self):
        results: list = []
        _finalize_results_for_emit(results)  # no crash
        assert results == []
