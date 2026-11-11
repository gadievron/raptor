"""Unknown function ends cannot turn a fallback window into negative coverage."""
from core.audit.sweep import SweepResult, scope_coccinelle_result


def test_late_row_is_not_refuted_when_function_end_is_unknown(tmp_path):
    source = tmp_path / "long.c"
    source.write_text("void long_function(void) {\n" + "    tick();\n" * 100 + "}\n")
    original = SweepResult(
        tool="coccinelle", file_path="long.c", function_name="",
        outcome="confirmed", rule_id="owned.cocci",
        matches=[{"file": str(source), "line": 90, "column": 1}],
    )
    unknown = scope_coccinelle_result(
        original, target_path=tmp_path, function_name="long_function",
        line_start=1, line_end=None, language="c",
    )
    assert unknown.outcome == "inconclusive"
    assert unknown.matches == []
    assert "end" in unknown.details["reason"]
    known = scope_coccinelle_result(
        original, target_path=tmp_path, function_name="long_function",
        line_start=1, line_end=102, language="c",
    )
    assert known.outcome == "confirmed"
    assert len(known.matches) == 1
    assert original.outcome == "confirmed" and len(original.matches) == 1


def test_empty_file_result_retains_negative_coverage_without_end(tmp_path):
    original = SweepResult(
        tool="coccinelle", file_path="empty.c", function_name="",
        outcome="refuted", rule_id="owned.cocci", matches=[],
    )
    result = scope_coccinelle_result(
        original, target_path=tmp_path, function_name="f",
        line_start=1, line_end=None, language="c",
    )
    assert result.outcome == "refuted"


def test_known_end_can_exclude_a_row_from_another_function(tmp_path):
    original = SweepResult(
        tool="coccinelle", file_path="other.c", function_name="",
        outcome="confirmed", rule_id="owned.cocci",
        matches=[{"file": "other.c", "line": 90, "column": 1}],
    )
    result = scope_coccinelle_result(
        original, target_path=tmp_path, function_name="f",
        line_start=1, line_end=10, language="c",
    )
    assert result.outcome == "refuted" and result.matches == []
