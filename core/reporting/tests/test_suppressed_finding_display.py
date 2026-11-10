"""Full reports retain suppressed findings and identify them per occurrence."""
from copy import deepcopy

import pytest

from core.reporting.adapters import native_findings
from core.reporting.builders import build_document
from core.reporting.document import ReportContext
from core.reporting.renderers import render_document
from core.reporting.summary import build_operator_summary


def test_full_finding_table_marks_suppression_without_changing_verdicts():
    captured = [{"id": "active", "suppressed": False, "title": "same observation"},
                {"id": "suppressed", "suppressed": True, "title": "same observation"}]
    findings = native_findings(captured, run_id="captured", producer="fixture", triage=True)
    context = ReportContext("scan", "captured", findings=findings)
    original = deepcopy(context.to_dict())
    summary = build_operator_summary(context)
    document = build_document(context)
    table = next(block for block in document.blocks if block.title == "Findings")
    assert len(table.rows) == 2 and summary.total == 2 and len(summary.rows) == 1
    assert "Suppressed" in table.columns
    column = table.columns.index("Suppressed")
    assert [row[column] for row in table.rows] == [False, True]
    assert [row[table.columns.index("Status")] for row in table.rows] == ["Unconfirmed", "Unconfirmed"]
    assert context.to_dict() == original


@pytest.mark.parametrize("format", ["markdown", "json", "xml"])
def test_suppression_indicator_is_portable_and_both_rows_remain(format):
    findings = native_findings([{"id": "active"}, {"id": "suppressed", "suppressed": True}],
                               run_id="captured", producer="fixture", triage=True)
    document = build_document(ReportContext("scan", "captured", findings=findings))
    rendered = render_document(document, format).content
    assert b"Suppressed" in rendered and b"F00001" in rendered and b"F00002" in rendered
    assert b"Unconfirmed" in rendered
