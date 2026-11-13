"""Unsupported selection records cannot alter a saved finding population."""
from copy import deepcopy
from io import StringIO
import json

import pytest

from core.reporting.adapters import native_findings
from core.reporting.document import ReportContext
from core.reporting.lifecycle import apply_input_selection
from core.reporting.options import ReportOptions
from core.reporting.service import complete_reporting
from core.reporting.writer import load_committed_report


@pytest.mark.parametrize("failure", ["malformed-json", "boolean-version", "future-version", "unknown-policy"])
def test_refused_sidecar_keeps_findings_and_no_lineage_in_committed_capture(tmp_path, failure):
    directory = tmp_path / "input"
    directory.mkdir()
    source = directory / "native.json"
    source.write_text(json.dumps({"findings": [{"id": "F", "file": "a.c", "line": 1}]}), encoding="utf-8")
    source_bytes = source.read_bytes()
    payload = json.loads(source_bytes)
    context = ReportContext("fixture", "saved", state="unknown",
                            findings=native_findings(payload["findings"], run_id="saved", producer="fixture", triage=True),
                            artifacts=[{"path": str(source)}], extensions={"fixture.raw": payload})
    original_findings = deepcopy(context.findings)
    record = {"schema_version": 1, "mode": "selected-findings", "owner": None,
              "identity_policy": "exact-input-content-and-recorded-occurrence/v1",
              "source_snapshot": context.snapshot_id, "input_rows": 1,
              "selection": [{"id": "F", "file": "a.c", "line": 1,
                             "source": {"snapshot_id": context.snapshot_id,
                                        "occurrence_ref": context.findings[0]["occurrence_ref"]}}]}
    if failure == "boolean-version":
        record["schema_version"] = True
    elif failure == "future-version":
        record["schema_version"] = 2
    elif failure == "unknown-policy":
        record["identity_policy"] = "unsupported-fixture-policy"
    sidecar = directory / "reporting-input.json"
    original_sidecar = b"{" if failure == "malformed-json" else json.dumps(record).encode()
    sidecar.write_bytes(original_sidecar)
    apply_input_selection(context, directory)
    expected_notes = ["Invalid input-selection record ignored; finding lineage is unknown"] if failure == "malformed-json" else []
    assert context.diagnostics == expected_notes
    assert context.findings == original_findings and context.parents == []
    assert all(key not in context.extensions for key in ("raptor.scope", "raptor.input_selection", "raptor.lineage"))
    captured = context.to_dict()
    console = StringIO()
    output = tmp_path / "report"
    result = complete_reporting(context, output, options=ReportOptions(formats=("json", "markdown")), stream=console)
    assert not result.errors and result.publication.committed
    restored, document, manifest = load_committed_report(output)
    assert restored.to_dict() == captured == context.to_dict()
    assert restored.findings == original_findings and restored.parents == []
    assert restored.extensions["fixture.raw"] == payload
    assert result.summary.total == 1 and result.summary.counts == {"Unconfirmed": 1}
    assert result.summary.state == "unknown"
    generation = output / ".reporting" / manifest["generation"]
    assert json.loads((generation / "report.json").read_bytes()) == document.to_dict()
    markdown = (generation / "report.md").read_text(encoding="utf-8")
    assert "Unconfirmed" in markdown and "Captured findings: 1" in console.getvalue()
    assert ("Invalid input-selection record ignored" in markdown) is (failure == "malformed-json")
    assert sidecar.read_bytes() == original_sidecar and source.read_bytes() == source_bytes
