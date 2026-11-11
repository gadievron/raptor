"""Coverage-table limits stay visible independently of verdict-table limits."""
from copy import deepcopy

import pytest

from core.engagement.report import build_engagement_document
from core.reporting.tests.test_audit_engagement_documents import engagement_report


@pytest.mark.parametrize("count", [1, 200, 201], ids=["within-cap", "exact-cap", "over-cap"])
def test_captured_coverage_table_declares_its_own_omitted_rows(count):
    report = engagement_report()
    verdict = report["verdict_table"][0]
    coverage = report["coverage"]["per_artifact"][0]
    report["verdict_table"] = []
    report["coverage"]["per_artifact"] = []
    for index in range(count):
        identity = "sha256-fixture" if index == 0 else f"sha256-fixture-{index}"
        report["verdict_table"].append(dict(deepcopy(verdict), artifact_id=identity))
        report["coverage"]["per_artifact"].append(dict(deepcopy(coverage), artifact_id=identity))
    report["counts"] = {"rows": count, "by_class": {"elf": count}}
    report["attestation_totals"] = {"non_attesting": count}
    report["coverage"]["earned_journal_rows_total"] = {"clean": count * 2}
    report["coverage"]["at_verdict_time_rows_total"] = {"clean": count}
    before = deepcopy(report)
    context, document = build_engagement_document(report)
    section = next(block for block in document.blocks if block.title == "Coverage Synthesis")
    table = next(block for block in section.children if block.kind == "table")
    text = "\n".join(block.text + "".join(part.text for part in block.inline) for block in section.children)
    assert len(table.rows) == min(count, 200)
    if count > 200:
        assert "1 more coverage row(s)" in text
    else:
        assert "more coverage row(s)" not in text
    assert "partial load" in str(table.rows) and "rows absent since verdict" in str(table.rows)
    assert "never count as earned coverage" in text
    assert context.extensions["raptor.engagement"] == before and report == before
