"""Audit presentation grouping keeps original occurrence-reference aliases."""
from copy import deepcopy
import json

import pytest

from core.audit.report import write_markdown_report
from core.reporting.options import ReportOptions
from core.reporting.writer import load_committed_report


def _walk(blocks):
    for block in blocks:
        yield block
        yield from _walk(block.children)


@pytest.mark.parametrize("reverse", [False, True], ids=["production-last", "production-first"])
def test_grouped_audit_references_keep_original_positions_after_readback(tmp_path, reverse):
    findings = [
        {"id": "F-vendor", "file": "vendor.c", "tree_class": "vendored-compat"},
        {"id": "F-test", "file": "test.c", "tree_class": "test-harness"},
        {"id": "F-production", "file": "production.c", "tree_class": "production"},
    ]
    for finding in findings:
        finding.update(title="Captured hypothesis", line=1, severity="medium", evidence_tier="heuristic")
    if reverse:
        findings.reverse()
    report = {"stats": {}, "findings": findings, "gaps_remaining": 0}
    source = tmp_path / "audit-report.json"
    source.write_text(json.dumps(report), encoding="utf-8")
    source_bytes = source.read_bytes()
    captured = json.loads(source_bytes)
    original = deepcopy(captured)
    sink = []
    path = write_markdown_report(captured, tmp_path, report_options=ReportOptions(formats=("markdown", "json")),
                                 reporting_sink=sink)
    assert len(sink) == 1 and not sink[0].errors and sink[0].publication.committed
    context, document, manifest = load_committed_report(tmp_path)
    assert context.extensions["raptor.audit"] == original == captured
    assert [finding["native"] for finding in context.findings] == original["findings"]
    assert context.completion_state == "unknown" and sink[0].summary.total == 3
    expected = {finding["source_id"]: (f"F{index:05d}", finding["occurrence_ref"])
                for index, finding in enumerate(context.findings, 1)}
    assert len(expected) == 3
    assert document.extensions["raptor.references"] == {alias: ref for alias, ref in expected.values()}
    section = next(block for block in document.blocks if block.title == "Findings")
    presented = [block for block in _walk(section.children) if block.source_refs]
    assert [block.title.split(":", 1)[0] for block in presented] == ["F-production", "F-vendor", "F-test"]
    assert len(presented) == len(context.findings) == 3
    for block in presented:
        alias, occurrence = expected[block.title.split(":", 1)[0]]
        assert block.source_refs == [occurrence]
        assert block.children[0].rows[0] == ["Report ref", alias]
    assert len({block.source_refs[0] for block in presented}) == 3
    generation = tmp_path / ".reporting" / manifest["generation"]
    assert json.loads((generation / "audit-summary.json").read_bytes()) == document.to_dict()
    assert path.read_bytes() == (generation / "audit-report.md").read_bytes()
    assert source.read_bytes() == source_bytes
