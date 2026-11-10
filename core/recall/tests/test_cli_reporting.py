"""Recall exports consume one captured measurement and preserve native output."""
from __future__ import annotations

import json

import pytest

from core.recall import cli


def _manifest(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({
        "schema_version": 1, "name": "report-fixture",
        "target": {"repo_url": "https://example.invalid/repo", "pinned_sha": "a" * 40,
                   "local_path": str(target)}, "language": "java", "profile": "scan",
        "expected": [{"id": "e1", "file": "A.java", "cwe": "CWE-89",
                      "provenance": {"kind": "benchmark", "suite": "fixture", "case": "1"}}],
        "clean_regions": [],
    }))
    return manifest, target


@pytest.mark.parametrize("flags,exported,native_markdown", [
    (["--report-format", "json"], True, True), ([], False, True), (["--no-report"], False, False),
])
def test_one_pipeline_native_measurement_and_export_policy(tmp_path, monkeypatch, capsys, flags, exported, native_markdown):
    manifest, target = _manifest(tmp_path)
    calls = []
    out = tmp_path / "run"
    pipeline = out / "pipeline"
    def run(*args, **kwargs):
        calls.append(args)
        pipeline.mkdir(parents=True)
        return pipeline
    monkeypatch.setattr(cli, "verify_pinned_clone", lambda *args: target)
    monkeypatch.setattr(cli, "run_pipeline", run)
    monkeypatch.setattr(cli, "collect_findings", lambda *args, **kwargs: [])
    monkeypatch.setattr(cli, "collect_toolchain", lambda: {"detector": "fixture"})
    assert cli.main(["run", "--manifest", str(manifest), "--out", str(out), *flags]) == 0
    assert len(calls) == 1
    native = json.loads((out / "report.json").read_text())
    assert native["expected_total"] == 1
    assert native["found_total"] == 0
    assert native["recall"] == 0.0
    assert native["label_class"] == "recall-ground-truth"
    assert native["missed"][0]["id"] == "e1"
    assert (out / "report.md").exists() is native_markdown
    assert (out / "portable-reports" / "recall-report.json").exists() is exported
    assert "0.0% (0/1)" in capsys.readouterr().out
    if exported:
        context = json.loads((out / "portable-reports" / "report-context.json").read_text())
        assert context["extensions"]["raptor.measurement_role"] == native["label_class"]
        assert context["extensions"]["raptor.metrics"]["Expected findings"] == 1


@pytest.mark.parametrize("destination", ["target", "native", "manifest"])
def test_destination_refusal_before_clone_or_pipeline(tmp_path, monkeypatch, destination):
    manifest, target = _manifest(tmp_path)
    out = tmp_path / "run"
    path = target / "receipt.json" if destination == "target" else out / "report.json" if destination == "native" else manifest
    before = manifest.read_bytes()
    monkeypatch.setattr(cli, "verify_pinned_clone", lambda *args: pytest.fail("must refuse before clone"))
    monkeypatch.setattr(cli, "run_pipeline", lambda *args, **kwargs: pytest.fail("must refuse before detector"))
    assert cli.main(["run", "--manifest", str(manifest), "--out", str(out),
                     "--report-format", "json", "--report-output", str(path)]) == 2
    assert manifest.read_bytes() == before
    assert not out.exists()


def test_conflicting_flags_refused_before_manifest_load(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "load_manifest", lambda *args: pytest.fail("invalid flags must not start work"))
    with pytest.raises(SystemExit) as exc:
        cli.main(["run", "--manifest", str(tmp_path / "absent"), "--no-report", "--report-format", "json"])
    assert exc.value.code == 2


def test_native_warm_measurement_omission_is_visible(tmp_path):
    from argparse import Namespace
    from core.recall.reporting import complete_recall_report
    from core.recall.score import RecallReport
    report = RecallReport("fixture", "java", "scan", "sha")
    args = Namespace(report_format=["json"], report_output=None, no_report=False, manifest=tmp_path / "manifest.json")
    out = tmp_path / "run"
    result = complete_recall_report(args, report, out, warm_present=True)
    assert not result.errors
    document = json.loads((out / "portable-reports" / "report-document.json").read_text())
    assert any("mechanical-warm" in note and "raw recall only" in note for note in document["diagnostics"])
    context = json.loads((out / "portable-reports" / "report-context.json").read_text())
    assert context["extensions"]["raptor.warm_measurements_not_projected"] is True
