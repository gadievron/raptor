"""Captured native continuation preserves a valid zero-valued producer ID."""
from copy import deepcopy
from io import StringIO

import pytest

from core.reporting.adapters import native_findings
from core.reporting.document import ReportContext
from core.reporting.lifecycle import _link_same_attempt

from core.reporting.delta import build_delta
from core.reporting.results import NativeResult, complete_native_result
from core.reporting.writer import load_committed_report
from core.run.report_identity import checkpoint, fresh_identity


def test_zero_id_retains_same_attempt_continuation_and_changed_verdict(tmp_path):
    identity = fresh_identity()
    metadata = {"command": "validate", "reporting_identity": identity}
    row = {"finding_id": 0, "id": "secondary", "file": "a.c", "line": 2,
           "status": "not_disproven", "title": "captured finding"}
    first = NativeResult("validate", "src", "placeholder", {}, findings=[row],
                         lifecycle_dir=tmp_path, lifecycle_metadata=metadata)
    publication = complete_native_result(first, tmp_path, stem="validation", stream=StringIO())
    assert not publication.errors and publication.publication.committed
    previous, _, _ = load_committed_report(tmp_path)
    continuation = checkpoint(tmp_path, identity)
    assert continuation and continuation["snapshot_id"] == previous.snapshot_id
    resumed = deepcopy(metadata)
    resumed["reporting_identity"].update(segment=2, continuation=continuation)
    current, _ = NativeResult("validate", "src", "placeholder", {},
                              findings=[{**row, "status": "confirmed"}], lifecycle_dir=tmp_path,
                              lifecycle_metadata=resumed).build()
    assert current.attempt_id == previous.attempt_id
    assert type(current.findings[0]["source_id"]) is int and current.findings[0]["source_id"] == 0
    old_ref, new_ref = previous.findings[0]["occurrence_ref"], current.findings[0]["occurrence_ref"]
    assert old_ref != new_ref
    assert current.extensions["raptor.continuation_lineage"] == {
        new_ref: {"snapshot_id": previous.snapshot_id, "occurrence_ref": old_ref,
                  "policy": "same-attempt-stable-producer-id-and-site/v1"}}
    delta, _ = build_delta(previous, current)
    changes = delta.extensions["raptor.delta"]["changes"]
    assert len(changes) == 1 and changes[0][1].startswith("changed:")


@pytest.mark.parametrize("source_id,old_count,new_count,expected", [
    (0, 1, 1, True), (1, 1, 1, True), ("FIND-1", 1, 1, True),
    (None, 1, 1, False), ("", 1, 1, False), (False, 1, 1, False),
    (0, 2, 1, False), (0, 1, 2, False),
])
def test_continuation_requires_available_id_and_unique_site(source_id, old_count, new_count, expected):
    row = {"finding_id": source_id, "file": "a.c", "line": 2, "title": "captured"}
    old = ReportContext("validate", "owned", findings=native_findings([row] * old_count, producer="validate", run_id="owned"))
    current = ReportContext("validate", "owned", findings=native_findings(
        [{**row, "status": "confirmed"}] * new_count, producer="validate", run_id="owned"))
    _link_same_attempt(current, old)
    links = current.extensions["raptor.continuation_lineage"]
    assert bool(links) is expected
    if expected:
        assert links[current.findings[0]["occurrence_ref"]]["occurrence_ref"] == old.findings[0]["occurrence_ref"]
