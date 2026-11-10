"""One native diagram render feeds protected files and frozen typed blocks."""
import argparse
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

from core.reporting.options import ReportOptions
from core.reporting.renderers import render_document
from core.reporting.writer import load_committed_report
from core.testing.module_bindings import patch_module_attribute
from core.testing.standalone_cli import run_standalone_cli
from packages.diagram import cli, cli_reporting, renderer
from packages.diagram.reporting import directory_blocks_from_rendered


def _seed(out):
    path = out / "context-map.json"
    path.write_text(json.dumps({"entry_points": [{"id": "EP-1", "name": "before", "type": "function", "file": "app.py", "line": 1}],
                                "sink_details": [], "unchecked_flows": []}))
    (out / "findings.json").write_text(json.dumps({"findings": [{"id": "a", "vuln_type": "x", "is_true_positive": False},
                                                                   {"id": "b", "vuln_type": "y", "is_true_positive": False}]}))
    return path


def test_portable_capture_reuses_native_render_and_freezes_diagrams(tmp_path, monkeypatch, capsys):
    path = _seed(tmp_path)
    actual = renderer.render_directory
    calls = []
    def render(*args, **kwargs):
        calls.append(kwargs)
        return actual(*args, **kwargs)
    monkeypatch.setattr(renderer, "render_directory", render)
    assert cli.main([str(tmp_path), "--report-format", "json"]) == 0
    assert len(calls) == 1 and calls[0]["source_observer"] is not None
    native = (tmp_path / "diagrams.md").read_text()
    context, document, _ = load_committed_report(tmp_path)
    diagrams = [block for block in document.blocks if block.kind == "diagram"]
    assert len(diagrams) == native.count("```mermaid") == context.extensions["raptor.result"]["captured_diagrams"]
    assert any(block.title.startswith("Findings Summary") for block in diagrams)
    assert all(block.source_refs == [context.snapshot_id] and block.extensions["input_snapshot_id"] == context.snapshot_id for block in diagrams)
    assert str(path.resolve()) in [artifact["path"] for artifact in context.artifacts]
    path.write_text("changed after capture")
    rendered = render_document(document, "markdown").content.decode()
    assert "before" in rendered and "changed after capture" not in rendered
    assert "Diagrams:" in capsys.readouterr().out


def test_diagram_export_cannot_replace_consumed_source(tmp_path, capsys):
    source = _seed(tmp_path)
    original = source.read_bytes()
    assert cli.main([str(tmp_path), "--stdout", "--report-format", "json", "--report-output", str(source)]) == 0
    streams = capsys.readouterr()
    assert source.read_bytes() == original and not (tmp_path / "diagrams.md").exists()
    assert "# Security Diagrams" in streams.out and "Report persistence failed" in streams.err


def test_diagram_capture_limit_is_structured_and_disclosed(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli_reporting, "_MAX_CAPTURE_CHARS", 1)
    args = argparse.Namespace(_report_options=ReportOptions(("json",)), report_format=["json"], report_output=None)
    result = cli_reporting.complete_diagram_report(args, "## large captured output", tmp_path, None, [])
    assert result is not None and not result.errors
    context, _, _ = load_committed_report(tmp_path)
    assert context.state == "partial"
    assert context.extensions["raptor.result"] == {"captured_diagrams": 0, "capture_complete": False, "secrets_redacted": False}
    assert "size limit" in capsys.readouterr().err


def test_native_render_target_uses_shared_inline_sanitisation(tmp_path, capsys):
    _seed(tmp_path)
    assert cli.main([str(tmp_path), "--stdout", "--target", "evil`name\x1b![x](https://example.invalid/image)"]) == 0
    text = capsys.readouterr().out
    assert "\x1b" not in text and "![x](" not in text


def test_standalone_extraction_can_retain_native_summary_pies():
    content = "## Findings Summary\nNative population.\n```mermaid\npie\n  \"recorded\" : 2\n```\n"
    assert not directory_blocks_from_rendered(content)
    blocks = directory_blocks_from_rendered(content, include_findings_summary=True)
    assert len(blocks) == 1 and blocks[0].extensions["mermaid"].startswith("pie")


def test_graph_fallback_source_is_observed_without_another_render(tmp_path, monkeypatch):
    from packages.diagram.tests.test_renderer_graph_fallback import _write_understand_artifacts, _ingest_and_strip, _seal_target
    target, out = tmp_path / "codebase", tmp_path / "run"
    _write_understand_artifacts(out, target)
    _ingest_and_strip(out, target, monkeypatch)
    _seal_target(out, target)
    sources = []
    rendered = renderer.render_directory(out, source_observer=sources.append)
    assert "Context Map from Graph Memory" in rendered and out / "graph" / "raptor.graph.sqlite" in sources


def test_binary_diagram_real_child_exports_without_clobbering_preview(tmp_path):
    _seed(tmp_path)
    handedit = tmp_path / "diagrams.md"
    handedit.write_text("owned operator notes")
    env = dict(os.environ, _RAPTOR_TRUSTED="1")
    result = run_standalone_cli([sys.executable, str(Path(__file__).resolve().parents[3] / "libexec" / "raptor-binary"),
                                 "diagram", str(tmp_path), "--stdout", "--report-format", "json"],
                                env=env, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert handedit.read_text() == "owned operator notes" and "# Security Diagrams" in result.stdout
    assert (tmp_path / "diagram-report.json").is_file() and "Diagrams captured" in result.stderr


def test_binary_diagram_disable_keeps_one_child_and_status(tmp_path, monkeypatch):
    from packages.binary_analysis import cli as binary_cli
    commands = []
    patch_module_attribute(monkeypatch, binary_cli, "subprocess", "run", lambda command, **kw: commands.append(command) or SimpleNamespace(returncode=7))
    assert binary_cli.main(["diagram", str(tmp_path), "--stdout", "--no-report"]) == 7
    assert len(commands) == 1 and commands[0][-2:] == ["--stdout", "--no-report"]


def test_portable_export_does_not_bypass_native_overwrite_refusal(tmp_path, monkeypatch, capsys):
    _seed(tmp_path)
    native = tmp_path / "diagrams.md"
    native.write_text("owned hand-edit")
    monkeypatch.setattr(renderer, "render_directory", lambda *a, **kw: pytest.fail("overwrite refusal must precede rendering"))
    assert cli.main([str(tmp_path), "--report-format", "json"]) == 1
    assert native.read_text() == "owned hand-edit" and not (tmp_path / "diagram-report.json").exists()
    assert "already exists" in capsys.readouterr().err


def test_portable_diagram_content_redacts_recognised_secrets_before_capture(tmp_path):
    secret = "owner-secret-" + "a" * 32
    content = '## Context Map\nNative source.\n```mermaid\nflowchart LR\n A["https://example.test/?api_key=' + secret + '"]\n```\n'
    args = argparse.Namespace(_report_options=ReportOptions(("json",)), report_format=["json"], report_output=None)
    result = cli_reporting.complete_diagram_report(args, content, tmp_path, None, [])
    assert result is not None and not result.errors
    text = (tmp_path / "report-context.json").read_text()
    context = json.loads(text)
    assert secret not in text and context["extensions"]["raptor.result"]["secrets_redacted"] is True


@pytest.mark.parametrize("flags", [[], ["--no-report"]])
def test_native_diagram_quick_view_survives_without_portable_exports(tmp_path, flags, capsys):
    _seed(tmp_path)
    marker = tmp_path / "reporting-manifest.json"
    if flags:
        marker.write_text("previous portable receipt; do not parse")
    assert cli.main([str(tmp_path), *flags]) == 0
    streams = capsys.readouterr()
    assert "Diagrams rendered: 3" in streams.err
    assert (tmp_path / "diagrams.md").read_text().count("```mermaid") == 3
    assert not (tmp_path / "diagram-report.md").exists() and not (tmp_path / "report-context.json").exists()
    if flags:
        assert marker.read_text() == "previous portable receipt; do not parse"
        assert "prior report artifacts were not refreshed" in streams.err
    else:
        assert not marker.exists()


def test_source_reference_limit_declines_export_without_false_snapshot(tmp_path, monkeypatch, capsys):
    _seed(tmp_path)
    marker = tmp_path / "reporting-manifest.json"
    marker.write_text("previous receipt; do not amend")
    monkeypatch.setattr(cli, "_MAX_CAPTURE_SOURCES", 1)
    assert cli.main([str(tmp_path), "--report-format", "json"]) == 0
    streams = capsys.readouterr()
    assert "source reference limit exceeded" in streams.err and "Diagrams rendered: 3" in streams.err
    assert marker.read_text() == "previous receipt; do not amend"
    assert not (tmp_path / "report-context.json").exists() and not (tmp_path / ".reporting").exists()
    assert (tmp_path / "diagrams.md").read_text().count("```mermaid") == 3


def test_repeated_source_references_do_not_exhaust_unique_source_budget(tmp_path, monkeypatch):
    source = tmp_path / "source.json"
    source.write_text('{"name": "owned"}')
    reads = []
    def repeated(*args, **kwargs):
        for _ in range(3):
            data = json.loads(source.read_text())
            reads.append(data)
            kwargs["source_observer"](source)
        return '## Context Map\nNative source.\n```mermaid\nflowchart LR\n A["' + data["name"] + '"]\n```\n'
    monkeypatch.setattr(cli, "_MAX_CAPTURE_SOURCES", 1)
    monkeypatch.setattr(renderer, "render_directory", repeated)
    assert cli.main([str(tmp_path), "--report-format", "json"]) == 0
    context, _, _ = load_committed_report(tmp_path)
    assert len(reads) == 3 and context.extensions["raptor.result"]["capture_complete"] is True
    assert [a["path"] for a in context.artifacts].count(str(source.resolve())) == 1
