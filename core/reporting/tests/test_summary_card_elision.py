"""Terminal card elision must remain visible without changing saved findings."""
import io
import json

from core.reporting.adapters import native_findings
from core.reporting.document import ReportContext
from core.reporting.options import ReportOptions
from core.reporting.service import complete_reporting
from core.reporting.summary import render_operator_summary


def test_long_cards_disclose_elision_and_keep_full_saved_values(tmp_path):
    context = ReportContext("validate", "captured", state="completed")
    context.findings = native_findings(
        [{"id": "one", "file": "src/" + "nested/" * 20 + "a.c", "line": 17,
          "rule_id": "rule-" + "x" * 180, "final_status": "confirmed"}],
        run_id=context.run_id, producer="validate",
    )
    before = context.to_dict()
    result = complete_reporting(context, tmp_path, options=ReportOptions(enabled=False), stream=io.StringIO())
    saved = json.loads((tmp_path / "summary.json").read_text())
    assert saved["rows"] == result.summary.rows
    assert saved["counts"] == {"Confirmed": 1}
    for width in (40, 80):
        cards = [line for line in render_operator_summary(result.summary, width=width).splitlines()
                 if line.startswith("  ")]
        assert len(cards) == 2
        assert all(len(line) <= width and line.endswith("…") for line in cards)
    markdown = (tmp_path / "summary.md").read_text()
    assert result.summary.rows[0]["location"] in markdown
    assert result.summary.rows[0]["rule"] in markdown
    assert context.to_dict() == before


def test_short_cards_are_not_marked_as_elided():
    context = ReportContext("validate", "captured", state="completed")
    context.findings = native_findings(
        [{"id": "one", "file": "a.c", "line": 2, "rule_id": "r", "final_status": "confirmed"}],
        run_id=context.run_id, producer="validate",
    )
    from core.reporting.summary import build_operator_summary

    summary = build_operator_summary(context)
    cards = [line for line in render_operator_summary(summary, width=40).splitlines() if line.startswith("  ")]
    assert cards == [f"  {summary.rows[0]['tool']} / r", "  a.c:2"]
