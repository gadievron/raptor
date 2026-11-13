"""Saved ambiguous lineage never becomes a verdict comparison or absence."""
from copy import deepcopy
from io import StringIO
import json

import pytest

from core.reporting.adapters import native_findings
from core.reporting.delta import build_delta
from core.reporting.document import ReportContext
from core.reporting.options import ReportOptions
from core.reporting.service import complete_reporting
from core.reporting.writer import load_committed_report


@pytest.mark.parametrize("alias_first", [False, True], ids=["exact-first", "alias-first"])
def test_saved_alias_and_exact_match_remain_ambiguous(tmp_path, alias_first):
    before = ReportContext("fixture", "before", target="owned", state="completed",
                           findings=native_findings([{"id": "one", "title": "saved observation", "severity": "low"}],
                                                    run_id="before", producer="fixture", triage=True),
                           extensions={"raptor.scope": {"files": ["a.c"]}})
    original = before.findings[0]
    alias = {**deepcopy(original), "occurrence_ref": "fixture-alias", "severity": "high"}
    pair = [alias, deepcopy(original)] if alias_first else [deepcopy(original), alias]
    candidate = ReportContext("fixture", "after", target="owned", state="completed", findings=pair,
                              extensions={"raptor.scope": {"files": ["a.c"]}, "raptor.lineage": {
                                  "fixture-alias": {"snapshot_id": before.snapshot_id,
                                                    "occurrence_ref": original["occurrence_ref"]}}})
    originals = [before.to_dict(), candidate.to_dict()]
    options = ReportOptions(("json", "markdown"))
    parents = []
    for label, context in (("before", before), ("candidate", candidate)):
        result = complete_reporting(context, tmp_path / label, options=options, stream=StringIO())
        assert not result.errors and result.publication and result.publication.committed
        parents.append(load_committed_report(tmp_path / label)[0])
    protected = {str(p.relative_to(tmp_path)): p.read_bytes() for label in ("before", "candidate")
                 for p in (tmp_path / label).rglob("*") if p.is_file()}
    delta, document = build_delta(*parents)
    result = complete_reporting(delta, tmp_path / "delta", document=document, options=options, stream=StringIO())
    assert not result.errors and result.publication and result.publication.committed
    restored, saved_document, manifest = load_committed_report(tmp_path / "delta")
    record = restored.extensions["raptor.delta"]
    refs = [finding["occurrence_ref"] for finding in candidate.findings]
    assert record["changes"] == [[ref, "uncertain match", "", ""] for ref in refs]
    assert record["finding_changes"] == []
    assert record["lineage"] == {"fixture-alias": original["occurrence_ref"]}
    assert restored.parents == [parent.snapshot_id for parent in parents]
    for ref in refs:
        assert f"Ambiguous lineage for {ref}; no verdict comparison made" in restored.diagnostics
    assert all(note in saved_document.diagnostics for note in restored.diagnostics)
    generation = tmp_path / "delta" / ".reporting" / manifest["generation"]
    assert json.loads((generation / "report.json").read_text()) == saved_document.to_dict()
    markdown = (generation / "report.md").read_text()
    assert markdown.count("uncertain match") == 2
    assert "does not establish a fix or disproof" in markdown
    assert "not observed / outside comparable scope" not in markdown
    assert [load_committed_report(tmp_path / label)[0].to_dict() for label in ("before", "candidate")] == originals
    assert [before.to_dict(), candidate.to_dict()] == originals
    assert {str(p.relative_to(tmp_path)): p.read_bytes() for label in ("before", "candidate")
            for p in (tmp_path / label).rglob("*") if p.is_file()} == protected
