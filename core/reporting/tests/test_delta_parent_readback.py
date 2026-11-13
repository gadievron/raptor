"""Delta previews remain traceable to exact, independently saved parents."""
from copy import deepcopy
from io import StringIO
import json

import pytest

from core.reporting.adapters import native_findings
from core.reporting.delta import build_delta
from core.reporting.document import ReportContext, digest
from core.reporting.options import ReportOptions
from core.reporting.service import complete_reporting
from core.reporting.writer import load_committed_report


@pytest.mark.parametrize("large", [False, True])
def test_published_delta_previews_reference_readable_parent_captures(tmp_path, large):
    before = ReportContext("fixture", "saved", target="owned", state="completed",
                           findings=native_findings([{"id": "F", "file": "a.c", "line": 1}],
                                                    run_id="saved", producer="fixture", triage=True),
                           extensions={"raptor.scope": {"files": ["a.c"]}})
    after = deepcopy(before)
    old_value = "before-tail" + "x" * 600 if large else "before"
    new_value = "after-tail" + "y" * 600 if large else "after"
    before.findings[0]["message"] = old_value
    after.findings[0]["message"] = new_value
    originals = [before.to_dict(), after.to_dict()]
    options = ReportOptions(formats=("json", "markdown"))
    parents = []
    for label, context in (("before", before), ("after", after)):
        result = complete_reporting(context, tmp_path / label, options=options, stream=StringIO())
        assert not result.errors and result.publication.committed
        parents.append(load_committed_report(tmp_path / label)[0])
    delta, document = build_delta(*parents)
    result = complete_reporting(delta, tmp_path / "delta", document=document,
                                options=options, stream=StringIO())
    assert not result.errors and result.publication.committed
    restored, saved_document, manifest = load_committed_report(tmp_path / "delta")
    assert restored.parents == [parent.snapshot_id for parent in parents]
    record = restored.extensions["raptor.delta"]
    assert record["changes"][0][2:] == ["Unconfirmed", "Unconfirmed"]
    change = next(row for row in record["finding_changes"] if row["dimension"] == "message")
    for side, value in (("before", old_value), ("after", new_value)):
        if large:
            assert change[side] == {"sha256": digest(value), "kind": "str",
                                    "entries_or_characters": len(value), "preview": value[:500],
                                    "note": "Full before/after data is referenced by the parent snapshots"}
        else:
            assert change[side] == value
    generation = tmp_path / "delta" / ".reporting" / manifest["generation"]
    assert json.loads((generation / "report.json").read_bytes()) == saved_document.to_dict()
    markdown = (generation / "report.md").read_text(encoding="utf-8")
    assert "does not establish a fix or disproof" in markdown
    assert ("Full before/after data" in markdown) is large
    assert [load_committed_report(tmp_path / label)[0].to_dict()
            for label in ("before", "after")] == originals
    assert [before.to_dict(), after.to_dict()] == originals
