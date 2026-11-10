"""Failure views remain recorded analysis outcomes across portable formats."""
from __future__ import annotations

import json
from xml.etree import ElementTree

from cve_diff.report.failure_document import build_failure_document
from cve_diff.report.markdown import render_failure
from core.reporting.document import ReportDocument
from core.reporting.renderers import get_renderer


def test_failure_formats_retain_classification_and_rationale():
    document = build_failure_document("CVE-fixture", "no_evidence", "DiscoveryError: CVE-fixture: agent surrendered (no_evidence): no public reference")
    assert document.metadata == {"Outcome": "No public commit reference", "Class": "no_evidence"}
    assert document.blocks[0].text == "no public reference"
    assert document.kind == "cve-diff-failure"
    assert all(block.kind != "legacy_markdown" for block in document.blocks)
    captured = json.loads(get_renderer("json").render(document).content)
    assert ReportDocument.from_dict(captured).to_dict() == document.to_dict()
    xml = ElementTree.fromstring(get_renderer("xml").render(document).content)
    assert "no public reference" in " ".join(xml.itertext())
    assert "Why no fix was extracted" in render_failure("CVE-fixture", "no_evidence", "no public reference")


def test_unknown_failure_does_not_become_an_absence_verdict():
    document = build_failure_document("CVE-fixture", "FutureClass", "not available")
    assert document.metadata["Outcome"] == "Other (FutureClass)"
    assert any("does not establish" in note and "safe" in note for note in document.diagnostics)
    assert not document.summary


def test_original_reason_and_identifier_caps_are_disclosed():
    document = build_failure_document("CVE-" + "a" * 500, "b" * 500, "reason " * 1000)
    assert len(document.title) == 300
    assert len(document.metadata["Class"]) == 300
    assert len(document.blocks[0].text) == 4000
    assert set(document.extensions["raptor.truncated_fields"]) == {"CVE identifier", "Outcome label", "Failure class", "Rationale"}
    assert any("not retained in this portable document" in note for note in document.diagnostics)


def test_captured_json_redacts_secrets_and_markdown_defangs_structure():
    secret = "private-" + "a" * 24
    reason = "https://example.test/?api_key=" + secret + "\n```html\n<script>bad</script>\n\x1b[31m"
    document = build_failure_document("CVE-fixture\n# forged", "Odd|Class", reason)
    assert secret not in json.dumps(document.to_dict())
    markdown = get_renderer("markdown").render(document).content.decode()
    assert "\n# forged" not in markdown
    assert "```html" not in markdown
    assert "<script>" not in markdown
    assert "\x1b" not in markdown
    assert "Odd|Class" not in markdown
