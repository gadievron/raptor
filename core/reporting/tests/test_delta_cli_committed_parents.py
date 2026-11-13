"""Offline delta CLI compares explicit committed parents without rewriting them."""
from copy import deepcopy
from io import StringIO
import json

import pytest

from core.reporting.__main__ import main
from core.reporting.adapters import native_findings
from core.reporting.document import ReportContext
from core.reporting.options import ReportOptions
from core.reporting.service import complete_reporting
from core.reporting.writer import load_committed_report


@pytest.mark.parametrize("directories", [False, True], ids=["context-files", "committed-directories"])
def test_delta_cli_reads_committed_parent_identities_and_preserves_captures(tmp_path, directories):
    before = ReportContext("fixture", "before", target="owned", state="unknown",
                           findings=native_findings([{"id": "one", "title": "saved observation", "severity": "low"}],
                                                    run_id="before", producer="fixture", triage=True))
    after = deepcopy(before)
    after.run_id = "after"
    after.findings[0]["severity"] = "high"
    parents = []
    locations = []
    options = ReportOptions(("json", "markdown"))
    for label, context in (("before", before), ("after", after)):
        directory = tmp_path / label
        result = complete_reporting(context, directory, options=options, stream=StringIO())
        assert not result.errors and result.publication and result.publication.committed
        parents.append(load_committed_report(directory)[0])
        locations.append(directory if directories else directory / "report-context.json")
    original_parents = [parent.to_dict() for parent in parents]
    protected = {str(path.relative_to(tmp_path)): path.read_bytes() for label in ("before", "after")
                 for path in (tmp_path / label).rglob("*") if path.is_file()}
    output = tmp_path / "delta"
    assert main(["delta", *(str(path) for path in locations), "--out", str(output),
                 "--report-format", "json", "--report-format", "markdown"]) == 0
    context, document, manifest = load_committed_report(output)
    assert context.parents == [parent.snapshot_id for parent in parents]
    record = context.extensions["raptor.delta"]
    assert record["baseline"] == parents[0].snapshot_id and record["candidate"] == parents[1].snapshot_id
    assert record["changes"] == [[before.findings[0]["occurrence_ref"], "changed: severity", "Unconfirmed", "Unconfirmed"]]
    assert record["finding_changes"] == [{"occurrence": before.findings[0]["occurrence_ref"],
                                          "dimension": "severity", "before": "low", "after": "high"}]
    assert document.metadata["Baseline"] == parents[0].snapshot_id
    assert document.metadata["Candidate"] == parents[1].snapshot_id
    generation = output / ".reporting" / manifest["generation"]
    assert json.loads((generation / "report.json").read_bytes()) == document.to_dict()
    markdown = (generation / "report.md").read_text()
    assert "changed: severity" in markdown and "does not establish a fix or disproof" in markdown
    assert (output / "report.md").read_text() == markdown
    assert [load_committed_report(tmp_path / label)[0].to_dict() for label in ("before", "after")] == original_parents
    assert {str(path.relative_to(tmp_path)): path.read_bytes() for label in ("before", "after")
            for path in (tmp_path / label).rglob("*") if path.is_file()} == protected
