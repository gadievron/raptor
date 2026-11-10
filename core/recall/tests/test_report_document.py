"""Portable recall presentation preserves measurement and segregation semantics."""
from __future__ import annotations

import json
from xml.etree import ElementTree

from core.recall.score import CweRow, LABEL_CLASS, RecallReport, build_recall_document, render_markdown
from core.reporting.document import ReportDocument
from core.reporting.renderers import get_renderer


def _report():
    return RecallReport(
        manifest_name="benchmark", language="java", profile="scan-codeql", pinned_sha="abc123",
        expected_total=3, found_total=2, per_cwe=[CweRow("CWE-78", 2, 1), CweRow("CWE-89", 1, 1)],
        tool_attribution={"semgrep": 2, "codeql": 1},
        missed=[{"id": "miss-1", "cwe": "CWE-78", "file": "src/A.java", "line_start": 12}],
        clean_region_fp_count=1, clean_region_total=8, label_digest="labels",
        toolchain={"semgrep": "version"}, run_output_dir="out/pipeline",
    )


def test_portable_formats_retain_measurement_content_and_native_json():
    report = _report()
    before = report.to_dict()
    document = build_recall_document(report)
    assert document.kind == "recall-evaluation"
    assert document.metadata["label class"] == LABEL_CLASS
    assert document.summary["overall recall"] == "66.7% (2/3)"
    assert document.summary["findings on labelled-clean regions"] == 1
    assert document.summary["labelled-clean regions"] == 8
    rows = next(b.rows for b in document.blocks if b.title == "Recall by CWE")
    assert rows == [["CWE-78", 2, 1, "50.0%"], ["CWE-89", 1, 1, "100.0%"]]
    assert all(b.kind != "legacy_markdown" for b in document.blocks)
    markdown = render_markdown(report)
    assert all(text in markdown for text in ["miss-1", "src/A.java:12", "Tool attribution", "semgrep", "never feed"])
    captured = json.loads(get_renderer("json").render(document).content)
    assert ReportDocument.from_dict(captured).to_dict() == document.to_dict()
    xml = ElementTree.fromstring(get_renderer("xml").render(document).content)
    assert "miss-1" in " ".join(xml.itertext())
    assert report.to_dict() == before


def test_missed_cap_is_explicit_and_native_measurement_keeps_all_records():
    report = _report()
    report.missed = [{"id": str(i), "cwe": "CWE-78", "file": "A.java"} for i in range(53)]
    document = build_recall_document(report)
    misses = next(b for b in document.blocks if b.title.startswith("Missed"))
    assert len(misses.rows) == 50
    assert document.extensions["raptor.missed_total"] == 53
    assert document.extensions["raptor.missed_displayed"] == 50
    assert "3 more in report.json" in render_markdown(report)
    assert len(report.to_dict()["missed"]) == 53


def test_empty_population_is_unavailable_recall():
    report = RecallReport("empty", "java", "scan", "sha")
    document = build_recall_document(report)
    assert document.summary["overall recall"] == "n/a (0/0)"
    assert document.extensions["raptor.measurement_role"] == LABEL_CLASS
    assert not any(b.title.startswith("Missed") for b in document.blocks)


def test_hostile_labels_cannot_add_markdown_structure():
    report = _report()
    report.manifest_name = "fixture\n# forged"
    report.per_cwe[0].cwe = "CWE-78 | injected\n```html\n<script>bad</script>"
    report.missed[0]["file"] = "A.java\n![fetch](https://example.invalid/x)"
    markdown = render_markdown(report)
    assert "\n# forged" not in markdown
    assert "```html" not in markdown
    assert "<script>" not in markdown
    assert "![fetch]" not in markdown
    assert "REDACTED-AUTOFETCH-MARKUP" in markdown
