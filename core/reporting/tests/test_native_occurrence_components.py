"""Native occurrence components remain distinct without rewriting older captures."""
from copy import deepcopy
import io

import pytest

from core.reporting.adapters import native_findings
from core.reporting.builders import build_document
from core.reporting.delta import build_delta
from core.reporting.document import ReportContext, digest
from core.reporting.options import ReportOptions
from core.reporting.results import NativeResult
from core.reporting.service import complete_reporting
from core.reporting.writer import load_committed_report
from core.run.report_identity import fresh_identity


ROWS = [{"id": "F", "file": "a.c", "line": 1, "message": "saved observation"}]


def _legacy():
    return f"native:fixture:a:b:c:same:{digest(ROWS)}:0"


def test_delimiter_components_separate_and_keep_raw_labels(tmp_path):
    contexts = []
    for name, run, pass_id in (("first", "a:b", "c"), ("second", "a", "b:c")):
        payload = deepcopy(ROWS)
        context, document = NativeResult("fixture", "owned", run, payload, findings=payload,
                                         pass_id=pass_id, attempt_id="same").build()
        completed = complete_reporting(context, tmp_path / name, document=document,
                                       options=ReportOptions(formats=("json", "markdown")), stream=io.StringIO())
        assert not completed.errors
        saved, saved_document, _ = load_committed_report(tmp_path / name)
        assert (saved.run_id, saved.pass_id, saved.attempt_id) == (run, pass_id, "same")
        assert saved.findings[0]["native"] == ROWS[0]
        assert saved.extensions["raptor.result"] == ROWS
        assert saved_document.extensions["raptor.references"]["F00001"] == saved.findings[0]["occurrence_ref"]
        repeated, _ = NativeResult("fixture", "owned", run, payload, findings=payload,
                                   pass_id=pass_id, attempt_id="same").build()
        assert repeated.findings == saved.findings
        assert payload == ROWS
        contexts.append(saved)
    assert contexts[0].findings[0]["occurrence_ref"] != contexts[1].findings[0]["occurrence_ref"]
    assert all(c.findings[0]["occurrence_ref"].startswith("native:v2:") for c in contexts)


@pytest.mark.parametrize("explicit", [False, True])
def test_legacy_readback_and_delta_require_existing_explicit_alias(tmp_path, explicit):
    current = ReportContext("fixture", "a:b", pass_id="c", attempt_id="same",
                            findings=native_findings(ROWS, producer="fixture", run_id="a:b", pass_id="c", attempt_id="same"))
    current.findings[0]["severity"] = "high"
    old = deepcopy(current)
    old.findings[0]["severity"] = "low"
    old.findings[0]["occurrence_ref"] = _legacy()
    complete = complete_reporting(old, tmp_path / "legacy", document=build_document(old),
                                  options=ReportOptions(formats=("json",)), stream=io.StringIO())
    assert not complete.errors
    baseline, document, _ = load_committed_report(tmp_path / "legacy")
    assert baseline.findings[0]["occurrence_ref"] == _legacy()
    assert document.extensions["raptor.references"]["F00001"] == _legacy()
    mapping = {current.findings[0]["occurrence_ref"]: _legacy()} if explicit else None
    delta, _ = build_delta(baseline, current, lineage=mapping)
    changes = delta.extensions["raptor.delta"]["changes"]
    if explicit:
        assert len(changes) == 1 and changes[0][1] == "changed: severity"
    else:
        assert len(changes) == 2
        assert any(row[1] == "newly observed / unmatched" for row in changes)
        assert not delta.extensions["raptor.delta"]["finding_changes"]


@pytest.mark.parametrize("available", [False, True])
def test_lifecycle_requested_refs_preserve_legacy_source_and_occurrence(tmp_path, available):
    identity = fresh_identity()
    metadata = {"command": "fixture", "reporting_identity": identity} if available else {}
    context, _ = NativeResult("fixture", "owned", "a:b", ROWS, findings=ROWS, pass_id="c", attempt_id="same",
                              lifecycle_dir=tmp_path, lifecycle_producer="fixture", lifecycle_metadata=metadata).build()
    if available:
        assert context.findings[0]["source_occurrence_ref"] == _legacy()
        expected = "occurrence:" + digest({"run": identity["run_id"], "pass": identity["pass_id"],
                                           "attempt": identity["attempt_id"], "source": _legacy()})
        assert context.findings[0]["occurrence_ref"] == expected
    else:
        assert context.findings[0]["occurrence_ref"] == _legacy()
