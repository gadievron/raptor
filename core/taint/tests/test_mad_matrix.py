"""Emissibility-matrix pins: barrier/summary rows require
operator-grade provenance, python and javascript exclude barriers
identically (checked against the emitter's actual layout tables), and
every non-emitted kind is a counted refusal."""

from __future__ import annotations

import pytest

from core.dataflow.extension_pack import (
    ROLE_BARRIER,
    _LANGUAGE_LAYOUTS,
    _MAD_PROVENANCE,
)
from core.taint.mad_matrix import (
    BARRIERLESS_MAD_LANGUAGES,
    OPERATOR_GRADE_PROVENANCE,
    Emissibility,
    emissibility_report,
    mad_emissibility,
)
from core.taint.packs import default_pack_names, load_packs


def cell(**kwargs) -> Emissibility:
    defaults = {
        "language": "python", "role": "sink", "kind": "dotted_callee",
        "provenance": "framework_catalog",
    }
    defaults.update(kwargs)
    return mad_emissibility(**defaults)


# ── emissible kinds ──────────────────────────────────────────────────


def test_python_source_and_sink_rows_emissible():
    assert cell(role="source", kind="module_attribute") == Emissibility(
        True, predicate="sourceModel",
    )
    assert cell(role="source", kind="call_return").predicate == "sourceModel"
    assert cell(role="sink", kind="dotted_callee").predicate == "sinkModel"


def test_python_summary_rows_emissible_for_operator_grade():
    result = cell(role="propagator", kind="dotted_callee")
    assert result.emissible and result.predicate == "summaryModel"


# ── pinned invariant: barrier/summary need operator-grade provenance ─


def test_learned_provenance_cannot_emit_summary_rows():
    result = cell(role="propagator", kind="dotted_callee",
                  provenance="iris_refined")
    assert not result.emissible
    assert "operator-grade" in result.reason


def test_learned_provenance_cannot_emit_barrier_rows_anywhere():
    # cpp DOES have a barrier predicate — the provenance rule must
    # refuse independently of the layout.
    result = cell(language="cpp", role="sanitizer", kind="dotted_callee",
                  provenance="iris_refined")
    assert not result.emissible
    assert "operator-grade" in result.reason


def test_operator_grade_barrier_emissible_where_layout_has_it():
    result = cell(language="cpp", role="sanitizer", kind="dotted_callee",
                  provenance="operator")
    assert result.emissible and result.predicate == "barrierModel"


def test_learned_provenance_may_emit_source_and_sink_rows():
    assert cell(role="source", kind="call_return",
                provenance="iris_refined").emissible
    assert cell(role="sink", kind="dotted_callee",
                provenance="iris_refined").emissible


def test_operator_grade_set_matches_emitter_manual_set():
    assert OPERATOR_GRADE_PROVENANCE == frozenset(_MAD_PROVENANCE)


# ── pinned invariant: python/javascript barrier exclusion ────────────


def test_python_layout_really_has_no_barrier_predicate():
    assert ROLE_BARRIER not in _LANGUAGE_LAYOUTS["python"]


def test_barrier_exclusion_covers_python_and_javascript():
    assert {"python", "javascript"} <= BARRIERLESS_MAD_LANGUAGES


@pytest.mark.parametrize("language", ["python", "javascript"])
def test_no_barrier_rows_even_operator_grade(language):
    result = cell(language=language, role="sanitizer",
                  kind="dotted_callee", provenance="operator")
    assert not result.emissible
    assert "barrier" in result.reason


def test_javascript_layout_if_added_must_exclude_barriers():
    """Forward pin: whenever a javascript layout lands in the emitter,
    it must exclude barrierModel exactly like python's does — and this
    matrix keeps refusing regardless (the previous test)."""
    for language in ("python", "javascript"):
        layout = _LANGUAGE_LAYOUTS.get(language)
        if layout is not None:
            assert ROLE_BARRIER not in layout


# ── per-kind refusals are loud ───────────────────────────────────────


@pytest.mark.parametrize("role,kind,fragment", [
    ("source", "route_param", "route-model"),
    ("source", "stored_read", "reserved"),
    ("sink", "stored_write", "reserved"),
    ("sink", "method_name", "same-named"),
])
def test_inexpressible_kinds_refused_with_reason(role, kind, fragment):
    result = cell(role=role, kind=kind)
    assert not result.emissible
    assert fragment in result.reason


def test_unknown_language_refused_loudly():
    result = cell(language="ruby")
    assert not result.emissible
    assert "no verified models-as-data layout" in result.reason


def test_unknown_role_and_kind_refused():
    assert not cell(role="mystery").emissible
    assert not cell(role="sink", kind="mystery").emissible


# ── the counting report ──────────────────────────────────────────────


def test_report_accounts_for_every_entry():
    ps = load_packs(default_pack_names("python"))
    report = emissibility_report(ps, language="python")
    total = (len(ps.sources) + len(ps.sinks)
             + len(ps.sanitizers) + len(ps.propagators))
    assert report.emissible_rows + len(report.rejected) == total
    assert report.emissible_rows > 0
    # python emits no barrier rows: every sanitizer is a counted refusal
    sanitizer_rejects = [r for r in report.rejected
                         if r.row.startswith("sanitizer:")]
    assert len(sanitizer_rejects) == len(ps.sanitizers)
    counts = dict(report.counts)
    assert set(counts) <= {"sourceModel", "sinkModel", "summaryModel"}
    as_dict = report.to_dict()
    assert as_dict["emissible_rows"] == report.emissible_rows
    assert len(as_dict["rejected"]) == len(report.rejected)


def test_report_rejections_carry_reasons():
    ps = load_packs(["python/frameworks-flask"])
    report = emissibility_report(ps, language="python")
    assert all(r.reason for r in report.rejected)
    route_rejects = [r for r in report.rejected if "route_param" in r.row]
    assert route_rejects, "route_param refusal must be visible, not silent"
