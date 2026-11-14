"""Saved native rows must be unique by content before lineage is attached."""
from copy import deepcopy
import hashlib
from io import StringIO
import json

import pytest

from core.reporting.adapters import native_findings
from core.reporting.document import ReportContext
from core.reporting.lifecycle import bind_native_input, input_digest
from core.reporting.options import ReportOptions
from core.reporting.service import complete_reporting
from core.reporting.writer import load_context


@pytest.mark.parametrize("annotated", [False, True], ids=["identical", "annotation-only"])
def test_saved_native_rebinding_withholds_ambiguous_rows_without_losing_selection(tmp_path, annotated):
    duplicate = {"id": "D", "file": "duplicate.c", "line": 2, "message": "recorded claim"}
    unique = {"id": "U", "file": "unique.c", "line": 3, "message": "unique claim"}
    payload = {"findings": [deepcopy(duplicate), deepcopy(duplicate), deepcopy(unique)]}
    if annotated:
        for index, row in enumerate(payload["findings"][:2]):
            row["_reporting_source"] = {"snapshot_id": f"untrusted-{index}", "occurrence_ref": "old"}
    source = tmp_path / "findings.json"
    raw = json.dumps(payload).encode()
    source.write_bytes(raw)
    context = ReportContext("imported", "saved", findings=native_findings(
        payload["findings"], run_id="saved", producer="fixture"), artifacts=[{
            "path": str(source), "digest": hashlib.sha256(raw).hexdigest(),
            "canonical_digest": input_digest(payload),
        }])
    publication = complete_reporting(context, tmp_path, options=ReportOptions(formats=("json",)),
                                     stream=StringIO())
    assert not publication.errors and publication.publication.committed
    saved = load_context(tmp_path / "report-context.json")
    assert saved.snapshot_id == context.snapshot_id
    binding = {"snapshot_id": saved.snapshot_id, "context": saved}
    captured_before = binding["context"].to_dict()
    altered = {**duplicate, "message": "different claim"}
    expected = [duplicate, unique, altered]
    selected = {"findings": [{**row, "_reporting_source": {
        "snapshot_id": "forged", "occurrence_ref": "forged",
    }} for row in expected]}

    bind_native_input(selected, binding)

    assert selected["findings"][0] == duplicate
    assert selected["findings"][1] == {**unique, "_reporting_source": {
        "snapshot_id": context.snapshot_id,
        "occurrence_ref": binding["context"].findings[2]["occurrence_ref"],
    }}
    assert selected["findings"][2] == altered
    assert len(selected["findings"]) == 3
    assert binding["context"].to_dict() == captured_before
    assert source.read_bytes() == raw
