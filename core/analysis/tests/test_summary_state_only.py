"""State-only summaries retain their security context."""
from core.analysis.summaries import build_summary_from_query_outputs


def test_state_only_summary_reaches_context():
    summary = build_summary_from_query_outputs(
        "release", "owned.c", state_transitions=["allocated -> freed"],
    )
    assert not summary.is_empty()
    rendered = summary.format_for_context("full")
    assert "**State transitions:**" in rendered
    assert "allocated -> freed" in rendered
    assert "no CPG-derived security signals" not in summary.format_for_context("oneline")


def test_no_security_signals_remains_empty():
    summary = build_summary_from_query_outputs("utility", "owned.c")
    assert summary.is_empty()
    assert summary.format_for_context("full") == ""
