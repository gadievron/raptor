"""Quick-view metric bounds are explicit without dropping captured metrics."""
import pytest

from core.reporting.document import ReportContext
from core.reporting.summary import build_operator_summary, render_operator_summary


def test_overflow_metrics_are_disclosed_and_retained():
    captured = {f"metric_{index:02d}": index for index in range(22)}
    context = ReportContext("fixture", "captured", extensions={"raptor.metrics": captured})
    summary = build_operator_summary(context)
    rendered = render_operator_summary(summary)
    assert "metric_19: 19" in rendered and "metric_20: 20" not in rendered
    assert "2 additional metrics omitted from quick view" in rendered
    assert summary.metrics == captured and summary.to_dict()["metrics"] == captured


@pytest.mark.parametrize("count", [0, 20])
def test_metrics_within_limit_keep_full_view(count):
    captured = {f"metric_{index:02d}": index for index in range(count)}
    summary = build_operator_summary(ReportContext("fixture", "captured", extensions={"raptor.metrics": captured}))
    rendered = render_operator_summary(summary)
    assert "additional metrics" not in rendered
    assert all(f"{key}: {value}" in rendered for key, value in captured.items())
    assert summary.metrics == captured


def test_markdown_overflow_disclosure_does_not_promise_a_written_artifact():
    captured = {f"metric{index}": index for index in range(22)}
    summary = build_operator_summary(ReportContext("fixture", "captured", extensions={"raptor.metrics": captured}))
    rendered = render_operator_summary(summary, markdown=True)
    assert "2 additional metrics omitted from quick view" in rendered
    assert "metric19: 19" in rendered and "metric20: 20" not in rendered
    assert "summary.json" not in rendered
    assert summary.to_dict()["metrics"] == captured
