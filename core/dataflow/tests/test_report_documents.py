"""Portable trust views preserve corpus units, missing rates and input data."""
from copy import deepcopy
from types import SimpleNamespace

from core.dataflow import trust_corpus_report as corpus
from core.dataflow.report_documents import build_corpus_document, build_trust_document
from core.dataflow.trust_report import TrustReport, render
from core.dataflow.tests.test_trust_corpus_report import _make_db, _row
from core.reporting.document import ReportDocument
from core.reporting.renderers import render_document


def test_vacuous_controls_are_unavailable_rates_not_zero_or_sound():
    report = TrustReport(0, 0, 0, 0, 0, 0, 0, 0)
    document = build_trust_document(report)
    assert document.summary["Native corpus sound"] is False
    table = document.blocks[0]
    assert all(row[3] is None for row in table.rows)
    assert "vacuous" in document.blocks[1].text
    assert "coverage:" in render(report)  # native plain-text compatibility
    for format in ("markdown", "json", "xml"):
        assert render(report, format=format) == render_document(document, format).content.decode()
    assert ReportDocument.from_dict(document.to_dict()).to_dict() == document.to_dict()


def test_false_suppression_measurement_is_not_promoted_by_rendering():
    report = TrustReport(4, 2, 2, 1, 1, 2, 2, 1)
    document = build_trust_document(report)
    assert document.summary["Native corpus sound"] is False
    assert document.blocks[0].rows[1] == ["false-suppression", 1, 2, 0.5]
    assert "UNSOUND" in render(report) and "UNSOUND" in render(report, format="markdown")
    assert report.false_suppression_n == 1 and report.coverage == 0.5


def test_corpus_views_freeze_all_backend_axes_without_another_query(tmp_path, monkeypatch):
    source = tmp_path / "corpus.db"
    hostile = "CWE-78\x1b[2J"
    _make_db(source, [
        _row("f1", hostile, "CVE-1", "Python", "sound", "smt"),
        _row("f2", hostile, "CVE-2", "Python", "sound", "library"),
        _row("f3", hostile, "CVE-3", "Python", "sound", "codeql"),
        _row("f4", hostile, "CVE-4", "Python", "sound", "future_backend"),
        _row("f5", hostile, "CVE-5", "Python", "not_sound", "codeql", "preserve_tp_failed"),
        _row("f6", hostile, "CVE-6", "Python", "no_barrier", ""),
        _row("f7", hostile, "CVE-7", "Python", "future_pipeline_error", ""),
    ])
    report = corpus.analyze(source)
    before = deepcopy(report)
    source.unlink()
    def refuse(*args, **kwargs):
        raise AssertionError("presentation must not query or rerun corpus analysis")
    monkeypatch.setattr(corpus, "analyze", refuse)
    monkeypatch.setattr(corpus, "sqlite3", SimpleNamespace(connect=refuse))
    document = build_corpus_document(report)
    assert document.summary["Processed outcomes"] == 6
    assert document.summary["Pipeline-error rows (separate)"] == 1
    assert document.summary["Suppression rate"] == 4 / 5
    assert document.summary["Estimated Tier 0 attempts saved"] == 3
    assert ReportDocument.from_dict(document.to_dict()).to_dict() == document.to_dict()
    assert "\x1b" not in corpus.render_text(report)
    for format in ("markdown", "json", "xml"):
        result = corpus.render_text(report, format=format)
        assert "future_backend" in result and "future_pipeline_error" in result
        assert "not measured tokens" in result
    assert report == before
    assert not any(block.kind == "legacy_markdown" for block in document.blocks)


def test_empty_corpus_view_does_not_claim_complete_or_zero_rate():
    report = corpus.CorpusReport()
    document = build_corpus_document(report)
    assert document.summary["Suppression rate"] is None
    assert document.summary["Tier 0 share of sound"] is None
    assert any("unavailable database/query" in note for note in document.diagnostics)
