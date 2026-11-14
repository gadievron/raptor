"""Explicit offline lineage maps must be admitted before replacing a report."""
from io import StringIO
import json

import pytest

from core.reporting.__main__ import main
from core.reporting.adapters import native_findings
from core.reporting.document import ReportContext, digest
from core.reporting.options import ReportOptions
from core.reporting.service import complete_reporting
from core.reporting.writer import load_committed_report


def _tree(directory):
    return {str(p.relative_to(directory)): p.read_bytes() for p in directory.rglob("*") if p.is_file()}


@pytest.mark.parametrize("case", ["array", "non-string-value", "outside-candidate", "outside-baseline", "valid"])
def test_external_lineage_admission_preserves_sources_and_prior_report(tmp_path, capsys, case):
    parents = []
    paths = []
    for label, severity in (("before", "low"), ("after", "high")):
        context = ReportContext("fixture", label, target="owned", state="unknown",
                                findings=native_findings([{"id": "one", "file": "a.c", "line": 1, "severity": severity}],
                                                         run_id=label, producer="fixture", triage=True))
        path = tmp_path / (label + ".json")
        path.write_text(json.dumps(context.to_dict()))
        parents.append(context)
        paths.append(path)
    oldref, newref = (p.findings[0]["occurrence_ref"] for p in parents)
    assert oldref != newref
    mappings = {"array": [], "non-string-value": {newref: False},
                "outside-candidate": {"outside": oldref}, "outside-baseline": {newref: "outside"},
                "valid": {newref: oldref}}
    lineage = tmp_path / "lineage.json"
    lineage.write_text(json.dumps(mappings[case]))
    output = tmp_path / "output"
    initial = complete_reporting(parents[0], output, options=ReportOptions(formats=("json", "markdown")), stream=StringIO())
    assert not initial.errors and initial.publication.committed
    previous = load_committed_report(output)
    prior_tree = _tree(output)
    raw_sources = {p: p.read_bytes() for p in [*paths, lineage]}
    code = main(["delta", *(str(p) for p in paths), "--lineage", str(lineage), "--out", str(output),
                 "--report-format", "json", "--report-format", "markdown"])
    captured = capsys.readouterr()
    assert {p: p.read_bytes() for p in raw_sources} == raw_sources
    if case != "valid":
        assert code == 1
        expected = "Lineage must map" if case in {"array", "non-string-value"} else "outside the selected snapshots"
        assert expected in captured.err
        assert "wrote" not in captured.out.lower()
        assert _tree(output) == prior_tree
        restored = load_committed_report(output)
        assert restored[0].to_dict() == previous[0].to_dict()
        assert restored[1].to_dict() == previous[1].to_dict()
        assert restored[2] == previous[2]
    else:
        assert code == 0
        context, document, manifest = load_committed_report(output)
        record = context.extensions["raptor.delta"]
        assert record["lineage"] == {newref: oldref}
        assert record["changes"] == [[newref, "changed: severity, recorded evidence", "Unconfirmed", "Unconfirmed"]]
        details = record["finding_changes"]
        assert details[0] == {"occurrence": newref, "dimension": "severity", "before": "low", "after": "high"}
        assert len(details) == 2 and details[1]["dimension"] == "native"
        assert details[1]["before"]["sha256"] == digest(parents[0].findings[0]["native"])
        assert details[1]["after"]["sha256"] == digest(parents[1].findings[0]["native"])
        assert context.parents == [p.snapshot_id for p in parents]
        generation = output / ".reporting" / manifest["generation"]
        assert json.loads((generation / "report.json").read_bytes()) == document.to_dict()
        assert "does not establish a fix or disproof" in (generation / "report.md").read_text()
