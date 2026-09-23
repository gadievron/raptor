"""Analysis-gap surfacing in the audit report."""

from __future__ import annotations

import pytest

from core.audit.report import generate_report, write_markdown_report
from core.run import gaps


@pytest.fixture(autouse=True)
def _fresh_gap_state(monkeypatch):
    monkeypatch.setattr(gaps, "_gap_count", 0)
    monkeypatch.setattr(gaps, "_pending", [])


def test_report_counts_gap_records(tmp_path):
    for reason in (
        "parser budget exceeded", "parser budget exceeded", "parse_error",
    ):
        gaps.record_analysis_gap(
            tmp_path, file_path="src/x.js", reason=reason,
            tool="tree-sitter",
        )
    report = generate_report(tmp_path)
    block = report["analysis_gaps"]
    assert block["count"] == 3
    assert block["reasons"]["parser budget exceeded"] == 2
    assert block["reasons"]["parse_error"] == 1


def test_report_omits_key_without_gaps(tmp_path):
    report = generate_report(tmp_path)
    assert "analysis_gaps" not in report


def test_markdown_section_lists_reasons(tmp_path):
    gaps.record_analysis_gap(
        tmp_path, file_path="src/x.js",
        reason="parser budget exceeded", tool="tree-sitter",
    )
    report = generate_report(tmp_path)
    md_path = write_markdown_report(report, tmp_path)
    text = md_path.read_text()
    assert "## Analysis Gaps" in text
    assert "parser budget exceeded" in text
    assert "analysis-gaps.jsonl" in text


def test_markdown_no_section_without_gaps(tmp_path):
    report = generate_report(tmp_path)
    md_path = write_markdown_report(report, tmp_path)
    assert "## Analysis Gaps" not in md_path.read_text()
