"""Unusable optional metadata must not erase a valid captured finding view."""
import io

import pytest

from core.reporting.adapters import native_findings
from core.reporting.document import ReportContext, encode
from core.reporting.options import ReportOptions
from core.reporting.service import complete_reporting
from core.reporting.writer import load_committed_report, load_context


def _publish(tmp_path, extensions):
    context = ReportContext("scan", "captured", extensions=extensions,
                            findings=native_findings([{"id": "F1", "file": "a.c", "line": 1}],
                                                     run_id="captured", producer="fixture", triage=True))
    source = tmp_path / "input.json"
    source.write_bytes(encode(context.to_dict()))
    original = source.read_bytes()
    captured = load_context(source)
    before = captured.to_dict()
    stream = io.StringIO()
    output = tmp_path / "report"
    result = complete_reporting(captured, output, options=ReportOptions(formats=("json",)), stream=stream)
    assert result.publication is not None and result.publication.committed
    restored, document, _ = load_committed_report(output)
    assert restored.to_dict() == before == captured.to_dict()
    assert source.read_bytes() == original
    assert result.summary.total == 1 and result.summary.counts == {"Unconfirmed": 1}
    assert len(result.summary.rows) == 1 and result.summary.rows[0]["status"] == "Unconfirmed"
    assert restored.completion_state == captured.completion_state
    return result.summary, document, stream.getvalue()


@pytest.mark.parametrize("namespace,value,label", [
    pytest.param("raptor.metrics", [{"count": 1}], "metrics", id="metrics-list"),
    pytest.param("raptor.metrics", None, "metrics", id="metrics-null"),
    pytest.param("raptor.accounting", [1], "accounting", id="accounting-list"),
    pytest.param("raptor.accounting", "unavailable", "accounting", id="accounting-string"),
])
def test_nonobject_metadata_keeps_findings_and_declares_unavailable(tmp_path, namespace, value, label):
    summary, document, console = _publish(tmp_path, {namespace: value})
    assert getattr(summary, label) == {}
    expected = f"Captured {label} unavailable"
    assert expected in console
    assert sum(expected in note for note in document.diagnostics) == 1


def test_both_unavailable_metadata_channels_remain_separate(tmp_path):
    summary, document, console = _publish(tmp_path, {"raptor.metrics": [], "raptor.accounting": False})
    assert summary.metrics == {} and summary.accounting == {}
    for label in ("metrics", "accounting"):
        expected = f"Captured {label} unavailable"
        assert expected in console and any(expected in note for note in document.diagnostics)


def test_valid_metadata_keeps_zero_false_unknown_and_scalar_projection(tmp_path):
    metrics = {"count": 0, "enabled": False, "rate": None, "nested": {"count": 1}}
    accounting = {"tokens": 0, "cost": None}
    summary, document, _ = _publish(tmp_path, {"raptor.metrics": metrics, "raptor.accounting": accounting})
    assert summary.metrics == {"count": 0, "enabled": False, "rate": None}
    assert summary.accounting == accounting
    assert not any("Captured metrics unavailable" in note or "Captured accounting unavailable" in note
                   for note in document.diagnostics)


def test_legacy_absent_metadata_adds_no_unavailability_claim(tmp_path):
    summary, document, _ = _publish(tmp_path, {})
    assert summary.metrics == {} and summary.accounting == {}
    assert not any("Captured metrics unavailable" in note or "Captured accounting unavailable" in note
                   for note in document.diagnostics)
