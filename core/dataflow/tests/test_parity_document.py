"""Captured parity output keeps native decisions and measurement limits."""
from copy import deepcopy
from dataclasses import replace

from core.dataflow import sanitizer_cut_parity_report as baseline
from core.dataflow.parity_document import build_parity_document
from core.dataflow.sanitizer_cut_parity import aggregate_parity, render_parity_report
from core.dataflow.tests.test_sanitizer_cut_parity import _rec
from core.reporting.document import ReportDocument
from core.reporting.renderers import render_document


def test_empty_population_keeps_native_placeholder_but_displays_unavailable():
    summary = aggregate_parity([])
    document = build_parity_document(summary)
    assert document.summary["Native Phase 16 gate"] is False
    rates = next(block for block in document.blocks if block.title.startswith("Suppression rates"))
    assert all(row[2:4] == [0, 0] and row[4:] == [None, None, None] for row in rates.rows)
    assert all(row["available"] is False and row["rate"] == 0.0 for row in document.extensions["raptor.native_rates"])
    assert summary.lexical.noise_suppression.rate == 0.0
    assert "Records in window: **0**" in render_parity_report(summary)


def test_captured_baseline_formats_do_not_execute_fixtures_or_change_flags(monkeypatch):
    summary = aggregate_parity([_rec(fid="safe", lexical=True, verdict="no_suppress", label="should_suppress"),
                                _rec(fid="real", lexical=False, verdict="no_suppress", label="should_not_suppress")])
    before = deepcopy(summary)
    monkeypatch.setenv("RAPTOR_SANITIZER_CUT", "0")
    def refuse():
        raise AssertionError("rendering repeated fixture execution")
    monkeypatch.setattr(baseline, "build_baseline_summary", refuse)
    for format in ("markdown", "json", "xml"):
        result = baseline.render_baseline_report(summary, format=format)
        assert "Baseline, not the gating window." in result
        assert "synthetic-baseline" in result
        assert "Safe to remove lexical (Phase 16 gate): NO" in result
    import os
    assert os.environ["RAPTOR_SANITIZER_CUT"] == "0"
    assert summary == before
    document = build_parity_document(summary)
    assert document.summary["No lexical regression"] is False
    assert document.blocks[2].rows[0][2:5] == [1, 1, 1.0]
    assert ReportDocument.from_dict(document.to_dict()).to_dict() == document.to_dict()


def test_proposal_labels_are_inert_bounded_and_do_not_merge_counts():
    original = aggregate_parity([])
    counts = {"both_suppress": 1, "lexical_only": 2, "value_bound_only": 3, "neither": 4}
    summary = replace(original, by_kind={"|\n<script>x</script>\x1b[2J": dict(counts),
                                        **{f"kind-{i}" + "x" * 3000: dict(counts) for i in range(1001)}})
    before = deepcopy(summary)
    document = build_parity_document(summary, title="<script>title</script>\x1b[2J")
    table = next(block for block in document.blocks if block.title == "By proposal kind")
    assert len(table.rows) == 1000 and table.rows[0][2:] == [1, 2, 3, 4]
    assert document.extensions["raptor.proposal_kind_rows_omitted"] == 2
    assert document.extensions["raptor.capture_limited"] is True
    assert sum(len(row[1]) for row in table.rows) <= 200_000
    for format in ("markdown", "json", "xml"):
        result = render_document(document, format).content.decode()
        assert "\x1b" not in result
        if format != "json":
            assert "<script>" not in result
    assert summary == before


def test_native_positive_gate_is_preserved_as_measurement_only():
    from core.dataflow.sanitizer_cut_parity import VERDICT_SUPPRESS, VERDICT_NO_SUPPRESS, parity_criterion_met

    summary = aggregate_parity([
        _rec(fid="safe", lexical=True, verdict=VERDICT_SUPPRESS, label="should_suppress"),
        _rec(fid="real", lexical=False, verdict=VERDICT_NO_SUPPRESS, label="should_not_suppress"),
    ])
    assert parity_criterion_met(summary) is True
    document = build_parity_document(summary)
    assert document.summary["Native Phase 16 gate"] is True
    assert "Safe to remove lexical (Phase 16 gate): YES" in render_parity_report(summary)
    assert "authorisation" in " ".join(document.diagnostics)
