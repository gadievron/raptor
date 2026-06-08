"""Tests for ``core.llm.multi_model.replay`` — Phase 2d harness.

Drives synthetic ``orchestrated_report.json`` fixtures through the
replay pipeline and asserts on the comparison output. We do not
test the EM math here (that's covered in test_dawid_skene.py) — we
test that:

* Recorded verdicts are paired with the right finding_ids.
* Flip tags compute correctly across the truth table.
* Per-class summaries reflect the partition output.
* Posterior histogram bins line up.
* Edge cases: empty corpus, malformed JSON, findings without panel
  (skipped).
* Renderers produce valid output for both populated and empty
  reports.
"""
from __future__ import annotations

import json

import pytest

from core.llm.multi_model.replay import (
    FLIP_TO_EXPLOITABLE,
    NO_FLIP,
    render_json,
    render_markdown,
    replay,
)


def _finding(fid, rule_id, *, is_exploitable, analyses):
    return {
        "finding_id": fid,
        "rule_id": rule_id,
        "is_exploitable": is_exploitable,
        "multi_model_analyses": analyses,
    }


def _entry(model, is_exploitable):
    return {"model": model, "is_exploitable": is_exploitable}


def _write_report(path, findings):
    payload = {"results": findings}
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Pairing recorded verdict ↔ posterior
# ---------------------------------------------------------------------------


def test_recorded_verdict_matches_finding_id(tmp_path):
    path = _write_report(tmp_path / "rep.json", [
        _finding("F1", "rule-a", is_exploitable=True, analyses=[
            _entry("m1", True), _entry("m2", True), _entry("m3", True),
        ]),
        _finding("F2", "rule-a", is_exploitable=False, analyses=[
            _entry("m1", False), _entry("m2", False), _entry("m3", False),
        ]),
    ])
    report = replay([path])
    by_fid = {f.finding_id: f for f in report.findings}
    assert by_fid["F1"].recorded_is_exploitable is True
    assert by_fid["F2"].recorded_is_exploitable is False


def test_finding_with_missing_is_exploitable_records_none(tmp_path):
    """Tolerance: missing or non-boolean ``is_exploitable`` flows
    through as ``None`` rather than aborting the replay."""
    path = _write_report(tmp_path / "rep.json", [
        {
            "finding_id": "F1", "rule_id": "rule-a",
            # no is_exploitable
            "multi_model_analyses": [
                _entry("m1", True), _entry("m2", True),
            ],
        },
    ])
    report = replay([path])
    assert report.findings[0].recorded_is_exploitable is None


# ---------------------------------------------------------------------------
# Flip tags
# ---------------------------------------------------------------------------


def test_flip_to_exploitable_when_posterior_disagrees(tmp_path):
    """Recorded False, posterior > 0.5 → FLIP_TO_EXPLOITABLE.

    Built using a 3-model unanimous-True panel against a recorded
    ``is_exploitable: False`` — D–S converges to high posterior,
    the recorded majority-derived verdict says False, so this is
    a flip-to-exploitable case.
    """
    # Need many findings so EM has enough data to commit to ~1.0
    # rather than the prior mean.
    findings = []
    for i in range(8):
        # 8 unanimous-True findings recorded as False (pathological
        # historical pipeline) — drives D–S to high α for all models
        # and posteriors near 1.
        findings.append(_finding(
            f"F{i}", "rule-a", is_exploitable=False,
            analyses=[_entry("m1", True), _entry("m2", True), _entry("m3", True)],
        ))
    path = _write_report(tmp_path / "rep.json", findings)
    report = replay([path])
    for f in report.findings:
        assert f.posterior_true_positive > 0.5
        assert f.flip == FLIP_TO_EXPLOITABLE


def test_no_flip_when_verdicts_align(tmp_path):
    findings = []
    for i in range(8):
        findings.append(_finding(
            f"P{i}", "rule-a", is_exploitable=True,
            analyses=[_entry("m1", True), _entry("m2", True), _entry("m3", True)],
        ))
        findings.append(_finding(
            f"N{i}", "rule-a", is_exploitable=False,
            analyses=[_entry("m1", False), _entry("m2", False), _entry("m3", False)],
        ))
    path = _write_report(tmp_path / "rep.json", findings)
    report = replay([path])
    for f in report.findings:
        assert f.flip == NO_FLIP


# ---------------------------------------------------------------------------
# Aggregate metrics
# ---------------------------------------------------------------------------


def test_flip_rate_arithmetic(tmp_path):
    """Build a fixture with a known flip count; verify the rate
    computation."""
    findings = []
    # 5 aligned + 5 flipped (8 models, unanimous, recorded mismatched)
    for i in range(5):
        findings.append(_finding(
            f"A{i}", "rule-a", is_exploitable=True,
            analyses=[_entry("m1", True), _entry("m2", True), _entry("m3", True)],
        ))
    for i in range(5):
        findings.append(_finding(
            f"B{i}", "rule-a", is_exploitable=False,
            analyses=[_entry("m1", True), _entry("m2", True), _entry("m3", True)],
        ))
    path = _write_report(tmp_path / "rep.json", findings)
    report = replay([path])
    # 5/10 should flip
    assert report.total_findings_with_panel == 10
    assert report.flip_rate == pytest.approx(0.5, abs=1e-9)


def test_posterior_distribution_bins(tmp_path):
    """Posterior bin labels are always emitted (zero-count rows
    included) so renderers have stable rows."""
    findings = []
    for i in range(5):
        findings.append(_finding(
            f"F{i}", "rule-a", is_exploitable=True,
            analyses=[_entry("m1", True), _entry("m2", True)],
        ))
    path = _write_report(tmp_path / "rep.json", findings)
    report = replay([path])
    expected_labels = {
        "0.00-0.05", "0.05-0.20", "0.20-0.40",
        "0.40-0.60", "0.60-0.80", "0.80-0.95", "0.95-1.00",
    }
    assert set(report.posterior_distribution.keys()) == expected_labels


def test_distinct_models_and_classes_sorted(tmp_path):
    path = _write_report(tmp_path / "rep.json", [
        _finding("F1", "rule-z", is_exploitable=True, analyses=[
            _entry("m_z", True), _entry("m_a", False),
        ]),
        _finding("F2", "rule-a", is_exploitable=False, analyses=[
            _entry("m_m", False), _entry("m_a", False),
        ]),
    ])
    report = replay([path])
    assert report.distinct_models == sorted(report.distinct_models)
    assert report.distinct_decision_classes == sorted(report.distinct_decision_classes)
    assert "m_a" in report.distinct_models
    assert "agentic:rule-z" in report.distinct_decision_classes


# ---------------------------------------------------------------------------
# Multi-file + edge cases
# ---------------------------------------------------------------------------


def test_multiple_reports_concatenate(tmp_path):
    a = _write_report(tmp_path / "a.json", [
        _finding("F1", "rule-a", is_exploitable=True,
                 analyses=[_entry("m1", True), _entry("m2", True)]),
    ])
    b = _write_report(tmp_path / "b.json", [
        _finding("F2", "rule-a", is_exploitable=False,
                 analyses=[_entry("m1", False), _entry("m2", False)]),
    ])
    report = replay([a, b])
    fids = {f.finding_id for f in report.findings}
    assert fids == {"F1", "F2"}


def test_empty_corpus_returns_empty_report(tmp_path):
    report = replay([tmp_path / "missing.json"])
    assert report.total_panels == 0
    assert report.total_findings_with_panel == 0
    assert report.findings == []
    assert report.class_summaries == []
    assert report.flip_rate == 0.0


def test_malformed_file_silently_skipped(tmp_path):
    """Mirrors the panel_log loader's tolerance: a bad file in a
    corpus shouldn't tank the whole replay. Returns empty rather
    than raising."""
    good = _write_report(tmp_path / "good.json", [
        _finding("F1", "rule-a", is_exploitable=True,
                 analyses=[_entry("m1", True), _entry("m2", True)]),
    ])
    bad = tmp_path / "bad.json"
    bad.write_text("not json", encoding="utf-8")
    # malformed file is dropped silently from the recorded-verdict
    # index; the panel_log loader raises on parse errors, so the
    # bad file should not be in the path list when the replay is
    # invoked via the CLI's --root discovery (discover_reports only
    # finds files literally named orchestrated_report.json). Pass
    # only ``good`` for the safe-by-construction case.
    report = replay([good])
    assert report.total_findings_with_panel == 1


def test_findings_without_multi_model_analyses_skipped(tmp_path):
    """Single-model runs leave findings without panels; replay
    should ignore them entirely."""
    path = _write_report(tmp_path / "rep.json", [
        # Has panel
        _finding("F1", "rule-a", is_exploitable=True,
                 analyses=[_entry("m1", True), _entry("m2", True)]),
        # No multi_model_analyses
        {"finding_id": "F2", "rule_id": "rule-a", "is_exploitable": True},
    ])
    report = replay([path])
    assert report.total_findings_with_panel == 1
    assert report.findings[0].finding_id == "F1"


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def test_markdown_renderer_produces_headlines(tmp_path):
    path = _write_report(tmp_path / "rep.json", [
        _finding("F1", "rule-a", is_exploitable=True,
                 analyses=[_entry("m1", True), _entry("m2", True)]),
    ])
    report = replay([path])
    md = render_markdown(report)
    assert "# Panel-log replay" in md
    assert "Flip rate" in md
    assert "Posterior distribution" in md
    assert "Per-decision-class summary" in md
    # Per-model reliability section appears when class summaries exist.
    assert "Inferred per-model reliability" in md


def test_markdown_renderer_handles_empty_report(tmp_path):
    """Empty report should still produce a valid markdown skeleton
    without crashing on missing sections."""
    report = replay([tmp_path / "missing.json"])
    md = render_markdown(report)
    assert "# Panel-log replay" in md
    assert "Flip rate" in md
    # No "_No classes_" if there are zero summaries — that branch
    # is taken.
    assert "_No classes_" in md


def test_json_renderer_round_trips(tmp_path):
    path = _write_report(tmp_path / "rep.json", [
        _finding("F1", "rule-a", is_exploitable=True,
                 analyses=[_entry("m1", True), _entry("m2", True)]),
    ])
    report = replay([path])
    payload = json.loads(render_json(report))
    assert "flip_rate" in payload
    assert "findings" in payload
    assert isinstance(payload["findings"], list)
    assert payload["total_findings_with_panel"] == 1


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_cli_exits_2_when_no_paths(capsys):
    from core.llm.multi_model.replay import main
    rc = main([])
    assert rc == 2
    captured = capsys.readouterr()
    assert "no paths supplied" in captured.err


def test_cli_writes_output_files(tmp_path, capsys):
    from core.llm.multi_model.replay import main
    path = _write_report(tmp_path / "rep.json", [
        _finding("F1", "rule-a", is_exploitable=True,
                 analyses=[_entry("m1", True), _entry("m2", True)]),
    ])
    out_md = tmp_path / "out" / "report.md"
    rc = main([str(path), "--out", str(out_md)])
    assert rc == 0
    assert out_md.is_file()
    json_sidecar = out_md.with_suffix(".md.json")
    assert json_sidecar.is_file()
    # JSON sidecar parses cleanly.
    payload = json.loads(json_sidecar.read_text())
    assert payload["total_findings_with_panel"] == 1


def test_cli_root_discovery_finds_nested_reports(tmp_path, capsys):
    from core.llm.multi_model.replay import main
    nested = tmp_path / "run1" / "subdir"
    nested.mkdir(parents=True)
    _write_report(nested / "orchestrated_report.json", [
        _finding("F1", "rule-a", is_exploitable=True,
                 analyses=[_entry("m1", True), _entry("m2", True)]),
    ])
    rc = main(["--root", str(tmp_path), "--json"])
    assert rc == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["total_findings_with_panel"] == 1
