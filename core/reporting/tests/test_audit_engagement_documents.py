"""Detailed domain reports share capture, rendering, and publication."""
from copy import deepcopy
import json

import pytest

from core.reporting.options import ReportOptions
from core.reporting.renderers import render_document
from core.reporting.writer import load_committed_report, regenerate


def audit_report():
    return {"stats": {"reviewed": 3, "clean": 1, "finding": 1, "dark": 1}, "gaps_remaining": 2,
            "completeness": {"partial": True, "run_status": "failed", "resumable": True,
                             "missing": ["validation receipts"], "channel_loss": [{"channel": "fixture", "skipped_dispatches": 2, "reason": "backend unavailable"}]},
            "not_attempted": {"reason": "budget", "count": 2},
            "findings": [{"id": "F1", "title": "Recorded finding", "file": "src/a.c", "line": 1, "depth": "L2",
                          "evidence_tier": "observed_runtime", "severity": "high", "provisional": True,
                          "tool_evidence": [{"tool": "fixture", "details": "frozen receipt"}]}],
            "dark_findings": [{"id": "D1", "title": "Unverified hypothesis", "file": "a.c", "line": 2}],
            "unverified_residue": {"suspicious": {"count": 1, "detail": "findings-graded.json", "browse": "raptor-audit report"}},
            "analysis_gaps": {"count": 1, "reasons": {"parser budget exceeded": 1}},
            "decomp_sweep": {"rules_run": 2, "findings_total": 3, "mapped": 2, "unmapped": 1,
                             "conformance": {"parsed_rate": None, "quarantine_total": 1}}}


def engagement_report():
    return {"generated_at": "2026-11-06T00:00:00Z", "target_root": "/target", "counts": {"rows": 1, "by_class": {"elf": 1}},
            "policy": {"engagement_parked": True, "amendment_count": 1}, "attestation_totals": {"non_attesting": 1},
            "verdict_table": [{"artifact_id": "sha256-fixture", "class": "elf", "policy_depth": "T3", "reached_depth": "T1",
                               "degradation_reasons": [{"stage": "audit", "reason": "partial receipt"}],
                               "format_capability_tier_at_run_time": "core", "attestation": "non_attesting",
                               "wording": "no findings within core capability — catalogs pending"}],
            "coverage": {"earned_journal_rows_total": {"clean": 2}, "at_verdict_time_rows_total": {"clean": 1},
                         "per_artifact": [{"artifact_id": "sha256-fixture", "journal_verdict_rows": {"clean": 2},
                                           "journal_load_complete": False, "journal_rows_absent_since_verdict": True,
                                           "overlay": {"consumed": True, "checklist_items": 10, "reviewed_analysed_depth": 2,
                                                       "no_lane_residual": 8, "advisory_llm_extent_including_reads": 10}}]},
            "survivors": {"total": 1, "listed": [{"artifact_id": "sha256-fixture", "file": "a.c", "function": "parse", "run": "audit"}],
                          "note": "survivors await operator-run /validate; nothing here promotes a finding"},
            "verified_outcomes": {"consumed": False, "reason": "unavailable"},
            "residual_map": {"ledger_residuals_total": 1, "ledger_residuals": [{"kind": "partial", "message": "retained residual"}],
                             "scored_low_unverified": ["sha256-fixture"], "verified_low_exposure": []}}


def publish(kind, payload, directory, options=None):
    sink = []
    if kind == "audit":
        from core.audit.report import write_markdown_report, write_report
        write_report(payload, directory)
        path = write_markdown_report(payload, directory, report_options=options, reporting_sink=sink,
                                     model="fixture-model", duration_minutes=2, cost_usd=1.5,
                                     capabilities={"fixture": True}, suppressions_count=1)
    else:
        from core.engagement.report import write_report
        _, path = write_report(directory, payload, report_options=options, reporting_sink=sink)
    return sink[0], path


@pytest.mark.parametrize("kind,factory", [("audit", audit_report), ("engagement", engagement_report)])
def test_detailed_report_is_portable_frozen_and_preserves_domain_json(tmp_path, kind, factory):
    payload = factory()
    before = deepcopy(payload)
    result, _ = publish(kind, payload, tmp_path, ReportOptions(formats=("markdown", "html", "json", "xml")))
    assert not result.errors and payload == before
    domain_path = tmp_path / f"{kind}-report.json"
    canonical = json.loads(domain_path.read_text())
    assert canonical == payload
    assert (tmp_path / f"{kind}-summary.json").is_file()
    context, document, manifest = load_committed_report(tmp_path)
    assert context.extensions[f"raptor.{kind}"] == payload
    assert f"{kind}-summary.json" in manifest["files"]
    def blocks(values):
        for block in values:
            yield block
            yield from blocks(block.children)
    assert not any(b.kind == "legacy_markdown" for b in blocks(document.blocks))
    expected = b"frozen receipt" if kind == "audit" else b"no findings within core capability"
    for format in ("markdown", "html", "json", "xml"):
        assert expected in render_document(document, format).content
    html = (tmp_path / f"{kind}-report.html").read_bytes()
    domain_path.unlink()
    regenerate(tmp_path, tmp_path / "offline.html", format="html")
    assert (tmp_path / "offline.html").read_bytes() == html
    if kind == "audit":
        assert len(context.findings) == 1  # dark hypotheses are a separate population
        assert b"Partial run" in html and b"parse rate unavailable" in html
        assert document.extensions["raptor.references"]["F00001"] == context.findings[0]["occurrence_ref"]
        assert b"Report ref" in html and b"F00001" in html
    else:
        assert context.extensions["raptor.findings_available"] is False
        assert b"Non Attesting" in html and b"rows absent since verdict" in html
        assert b"advisory stratum" in html and b"Scored Low (unverified" in html


@pytest.mark.parametrize("kind,factory", [("audit", audit_report), ("engagement", engagement_report)])
def test_format_failure_keeps_other_outputs_and_canonical_data(tmp_path, monkeypatch, kind, factory):
    import core.reporting.writer as writer
    real = writer.render_document
    def fail(document, format="markdown"):
        if format == "html":
            raise ValueError("optional format failed")
        return real(document, format)
    monkeypatch.setattr(writer, "render_document", fail)
    result, _ = publish(kind, factory(), tmp_path, ReportOptions(formats=("markdown", "html", "json")))
    assert result.errors == ["html"]
    assert result.publication.committed and (tmp_path / f"{kind}-report.md").exists()
    assert json.loads((tmp_path / f"{kind}-report.json").read_text()) == factory()


@pytest.mark.parametrize("kind,factory", [("audit", audit_report), ("engagement", engagement_report)])
def test_explicit_html_does_not_rewrite_stale_markdown(tmp_path, kind, factory):
    old = tmp_path / f"{kind}-report.md"
    old.write_text("historical report")
    result, _ = publish(kind, factory(), tmp_path, ReportOptions(formats=("html",)))
    assert not result.errors
    assert old.read_text() == "historical report"
    assert result.publication.outputs == {"html": str(tmp_path / f"{kind}-report.html")}


@pytest.mark.parametrize("kind,factory", [("audit", audit_report), ("engagement", engagement_report)])
def test_no_report_keeps_summary_and_domain_state(tmp_path, kind, factory):
    result, _ = publish(kind, factory(), tmp_path, ReportOptions(enabled=False))
    assert not result.errors and (tmp_path / "summary.md").is_file()
    assert not (tmp_path / f"{kind}-report.md").exists()
    assert not (tmp_path / f"{kind}-summary.json").exists()
    assert json.loads((tmp_path / f"{kind}-report.json").read_text()) == factory()


@pytest.mark.parametrize("filename", ["../native.json", "sub/native.json", "native.md"])
def test_filename_overrides_are_validated(filename):
    with pytest.raises(ValueError, match="filename override"):
        ReportOptions(filenames=(("json", filename),)).validate()


@pytest.mark.parametrize("kind,factory", [("audit", audit_report), ("engagement", engagement_report)])
def test_capture_failure_refreshes_summary_instead_of_showing_stale_success(tmp_path, monkeypatch, caplog, kind, factory):
    publish(kind, factory(), tmp_path)
    old = (tmp_path / f"{kind}-report.md").read_bytes()
    def fail(*args, **kwargs):
        raise ValueError("uncapturable domain detail")
    if kind == "audit":
        import core.audit.report_document as builder
        monkeypatch.setattr(builder, "build_audit_document", fail)
    else:
        import core.engagement.report as builder
        monkeypatch.setattr(builder, "build_engagement_document", fail)
    result, _ = publish(kind, factory(), tmp_path)
    assert result.errors
    summary = json.loads((tmp_path / "summary.json").read_text())
    assert summary["state"] == "partial" and summary["findings_available"] is False
    assert any("capture failed" in note for note in summary["diagnostics"])
    assert "capture failed" in caplog.text
    assert (tmp_path / f"{kind}-report.md").read_bytes() == old


def test_user_filename_overrides_survive_domain_defaults(tmp_path):
    result, _ = publish("audit", audit_report(), tmp_path,
                         ReportOptions(formats=("markdown", "json"), filenames=(("markdown", "custom.md"), ("json", "custom.json"))))
    assert not result.errors
    assert result.publication.outputs == {"markdown": str(tmp_path / "custom.md"), "json": str(tmp_path / "custom.json")}
    _, _, manifest = load_committed_report(tmp_path)
    assert {"custom.md", "custom.json"} <= manifest["files"].keys()


def test_renderer_extension_collision_cannot_silently_drop_a_format(tmp_path, monkeypatch):
    import core.reporting.renderers as renderers
    from core.reporting.document import ReportContext
    from core.reporting.builders import build_document
    from core.reporting.writer import publish_report
    monkeypatch.setitem(renderers._RENDERERS, "other_md", renderers.Renderer("other_md", ".md", "text/markdown", lambda d: render_document(d)))
    context = ReportContext("inspection", "fixture")
    with pytest.raises(ValueError, match="same destination"):
        publish_report(context, build_document(context), tmp_path, options=ReportOptions(formats=("markdown", "other_md")))
    assert not list(tmp_path.iterdir())
