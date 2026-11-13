"""Offline delta inputs remain source artifacts during report publication."""
from copy import deepcopy
import json

import pytest

from core.reporting.__main__ import main
from core.reporting.adapters import native_findings
from core.reporting.document import ReportContext
from core.reporting.writer import load_committed_report


def _inputs(directory, summary_role=None):
    directory.mkdir(exist_ok=True)
    before = ReportContext("fixture", "before", target="owned", state="unknown",
                           findings=native_findings([{"id": "one", "title": "saved observation"}],
                                                    run_id="before", producer="fixture", triage=True))
    after = deepcopy(before)
    after.run_id = "after"
    after.findings[0]["severity"] = "high"
    values = {"baseline": before.to_dict(), "candidate": after.to_dict(), "lineage": {}}
    paths = {}
    for role, value in values.items():
        path = directory / ("summary.json" if role == summary_role else role + ".json")
        path.write_text(json.dumps(value))
        paths[role] = path
    return paths


@pytest.mark.parametrize("role", ["baseline", "candidate", "lineage"])
def test_delta_export_cannot_replace_concrete_input(tmp_path, capsys, role):
    paths = _inputs(tmp_path)
    original = {key: path.read_bytes() for key, path in paths.items()}
    output = tmp_path / "output"
    argv = ["delta", str(paths["baseline"]), str(paths["candidate"]), "--lineage", str(paths["lineage"]),
            "--out", str(output), "--report-format", "json", "--report-output", str(paths[role])]
    assert main(argv) == 1
    assert {key: path.read_bytes() for key, path in paths.items()} == original
    assert not (output / "reporting-manifest.json").exists()
    assert "Report persistence failed (ValueError)" in capsys.readouterr().out


@pytest.mark.parametrize("role", ["baseline", "candidate", "lineage"])
def test_disabled_delta_summary_cannot_replace_concrete_input(tmp_path, role):
    paths = _inputs(tmp_path, summary_role=role)
    original = {key: path.read_bytes() for key, path in paths.items()}
    assert main(["delta", str(paths["baseline"]), str(paths["candidate"]), "--lineage", str(paths["lineage"]),
                 "--out", str(tmp_path), "--no-report"]) == 1
    assert {key: path.read_bytes() for key, path in paths.items()} == original
    assert not (tmp_path / "summary.md").exists()
    assert not (tmp_path / "reporting-manifest.json").exists()


@pytest.mark.parametrize("with_lineage", [False, True], ids=["parents", "parents-and-lineage"])
def test_separate_delta_output_captures_input_paths_before_document(tmp_path, with_lineage):
    paths = _inputs(tmp_path)
    original = {key: path.read_bytes() for key, path in paths.items()}
    output = tmp_path / "output"
    argv = ["delta", str(paths["baseline"]), str(paths["candidate"]), "--out", str(output),
            "--report-format", "json", "--report-format", "markdown"]
    if with_lineage:
        argv += ["--lineage", str(paths["lineage"])]
    assert main(argv) == 0
    context, document, _ = load_committed_report(output)
    expected = [{"path": str(paths[role].resolve())} for role in
                (["baseline", "candidate", "lineage"] if with_lineage else ["baseline", "candidate"])]
    assert context.artifacts == document.extensions["raptor.artifacts"] == expected
    assert document.snapshot_id == context.snapshot_id
    assert document.extensions["raptor.summary"]["snapshot_id"] == context.snapshot_id
    assert context.extensions["raptor.delta"]["finding_changes"][0]["dimension"] == "severity"
    assert {key: path.read_bytes() for key, path in paths.items()} == original
