"""Explicit selected-input lineage preserves supported numeric producer IDs."""
from copy import deepcopy
import hashlib
import json

import pytest

from core.json import save_json
from core.reporting.adapters import native_findings
from core.reporting.delta import build_delta
from core.reporting.document import ReportContext
from core.reporting.lifecycle import (
    apply_input_selection, bind_native_input, find_input_snapshot, input_digest, write_input_selection,
)
from core.reporting.options import ReportOptions
from core.reporting.service import complete_reporting
from core.reporting.writer import load_committed_report
from core.run.report_identity import fresh_identity


@pytest.mark.parametrize("identifiers,linked", [
    ([0], [0]), ([0, False, "0"], [0, 2]), (["F1"], [0]), ([0, 0], []),
], ids=["zero", "typed-neighbors", "legacy-string", "duplicate-numeric"])
def test_saved_native_selection_keeps_exact_supported_id_lineage(tmp_path, identifiers, linked):
    origin = tmp_path / "origin"
    origin.mkdir()
    payload = {"findings": [{"id": identifier, "file": f"unit-{index}.c", "line": 1}
                            for index, identifier in enumerate(identifiers)]}
    source = origin / "findings.json"
    source.write_text(json.dumps(payload), encoding="utf-8")
    original_bytes = source.read_bytes()
    baseline = ReportContext("imported", "origin", findings=native_findings(
        payload["findings"], run_id="origin", producer="fixture", triage=True),
        artifacts=[{"path": str(source), "digest": hashlib.sha256(original_bytes).hexdigest(),
                    "canonical_digest": input_digest(payload)}])
    published = complete_reporting(baseline, origin, options=ReportOptions(formats=("json",)))
    assert not published.errors and published.publication.committed
    binding = find_input_snapshot(source, payload)
    assert binding is not None and binding["snapshot_id"] == baseline.snapshot_id
    selected = deepcopy(payload)
    bind_native_input(selected, binding)
    for index, finding in enumerate(selected["findings"]):
        assert finding["_reporting_source"] == {
            "snapshot_id": baseline.snapshot_id, "occurrence_ref": baseline.findings[index]["occurrence_ref"],
        }

    output = tmp_path / "selected"
    output.mkdir()
    identity = fresh_identity()
    save_json(output / ".raptor-run.json", {"command": "validate", "reporting_identity": identity})
    record = write_input_selection(output, selected, binding, source_path=source)
    assert record["owner"] == {key: identity[key] for key in ("run_id", "pass_id", "attempt_id")}
    record_path = output / "reporting-input.json"
    original_record = record_path.read_bytes()
    candidate = ReportContext("validate", identity["run_id"], pass_id=identity["pass_id"],
                              attempt_id=identity["attempt_id"], findings=native_findings(
                                  selected["findings"], run_id=identity["run_id"], producer="fixture", triage=True),
                              artifacts=[{"path": str(source)}])
    apply_input_selection(candidate, output)
    expected = {candidate.findings[index]["occurrence_ref"]: {
        "snapshot_id": baseline.snapshot_id, "occurrence_ref": baseline.findings[index]["occurrence_ref"],
        "policy": "exact-input-content-and-recorded-occurrence/v1",
    } for index in linked}
    assert candidate.extensions["raptor.lineage"] == expected
    published = complete_reporting(candidate, output, options=ReportOptions(formats=("json", "markdown")))
    assert not published.errors and published.publication.committed
    restored, _, _ = load_committed_report(output)
    assert restored.extensions["raptor.lineage"] == expected
    assert len(restored.findings) == len(payload["findings"])
    assert all(finding["status"] == "Unconfirmed" for finding in restored.findings)
    delta, _ = build_delta(baseline, restored)
    changes = delta.extensions["raptor.delta"]["changes"]
    for index in linked:
        assert not any(row[0] == restored.findings[index]["occurrence_ref"]
                       and row[1].startswith("newly observed") for row in changes)
        assert not any(row[0] == baseline.findings[index]["occurrence_ref"]
                       and row[1].startswith("not observed") for row in changes)
    assert source.read_bytes() == original_bytes and record_path.read_bytes() == original_record
