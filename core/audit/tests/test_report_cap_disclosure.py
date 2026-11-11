"""Detailed audit views display the same finding-cap notice as quick views."""
from copy import deepcopy

import pytest

from core.audit import report_document as builder
from core.reporting.document import MAX_FINDINGS
from core.reporting.renderers import render_document
from core.reporting.tests.test_audit_engagement_documents import audit_report


@pytest.mark.parametrize("count", [1, 2], ids=["within-cap", "over-cap"])
def test_captured_audit_cap_notice_reaches_detailed_markdown(tmp_path, monkeypatch, count):
    # Lower only this consumer binding to exercise the production cap branch
    # with a small captured fixture; the shared reporting budget stays intact.
    monkeypatch.setattr(builder, "MAX_FINDINGS", 1)
    report = audit_report()
    report["unverified_residue"] = {"llm_suspicious": report["unverified_residue"]["suspicious"]}
    finding = report["findings"][0]
    report["findings"] = [dict(deepcopy(finding), id=f"F{index}") for index in range(count)]
    report["stats"].update(finding=count, reviewed=count + 2)
    before = deepcopy(report)
    context, document = builder.build_audit_document(report, tmp_path)
    text = render_document(document, "markdown").content.decode()
    notice = "Finding presentation truncated to 1 of 2"
    assert (notice in text) == (count > 1)
    assert any(notice in note for note in context.diagnostics) == (count > 1)
    assert len(context.findings) == 1
    assert context.extensions["raptor.audit"] == before and report == before
    assert document.extensions["raptor.references"]["F00001"] == context.findings[0]["occurrence_ref"]
    assert text.count("Partial run") == 1
    assert "Provisional at time of writing" in text and "Unverified residue" in text
    assert "Dark hypotheses are not confirmed findings or refutations" in text
    assert MAX_FINDINGS == 10_000
