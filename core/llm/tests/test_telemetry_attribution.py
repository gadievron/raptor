"""Source attribution is additive telemetry, never a budget-class change."""

import json

import pytest

from core.llm import telemetry


@pytest.fixture(autouse=True)
def clean_sink():
    telemetry.set_sink(None)
    yield
    telemetry.set_sink(None)


def test_application_caller_recorded_without_transport_frames(tmp_path):
    path = tmp_path / "telemetry.jsonl"
    sink = telemetry.TelemetrySink(path)
    telemetry.set_sink(sink)
    transport = {"__name__": "core.llm.fake_transport", "emit": telemetry.emit}
    exec('def transport():\n emit(event="call", call_class="unclassified", cost_usd=0.5)\n', transport)
    app = {"__name__": "core.audit.example", "transport": transport["transport"]}
    exec('def originate():\n transport()\n', app)
    app["originate"]()
    row = json.loads(path.read_text())
    assert row["call_class"] == "unclassified"
    assert row["caller_chain"][0] == {
        "module": "core.audit.example", "function": "originate", "line": 2,
    }
    assert all(not r["module"].startswith("core.llm.") for r in row["caller_chain"])
    assert sink.class_costs() == {"unclassified": (1, 0.5)}


def test_attribution_is_bounded_and_does_not_read_locals(tmp_path):
    path = tmp_path / "telemetry.jsonl"
    telemetry.set_sink(telemetry.TelemetrySink(path))
    app = {"__name__": "packages.example", "emit": telemetry.emit}
    exec('def nested(depth):\n secret="DO_NOT_RECORD"\n if depth: return nested(depth-1)\n emit(event="attempt_failed", call_class="review")\n', app)
    app["nested"](20)
    row = json.loads(path.read_text())
    assert len(row["caller_chain"]) == 4
    assert "DO_NOT_RECORD" not in path.read_text()


def test_no_sink_does_not_inspect_stack(monkeypatch):
    monkeypatch.setattr(telemetry, "_caller_chain", lambda: pytest.fail("stack inspected"))
    telemetry.emit(event="call")


def test_attribution_failure_still_records_original_event(tmp_path, monkeypatch):
    path = tmp_path / "telemetry.jsonl"
    telemetry.set_sink(telemetry.TelemetrySink(path))

    def fail():
        raise RuntimeError("stack unavailable")

    monkeypatch.setattr(telemetry, "_caller_chain", fail)
    telemetry.emit(event="call", call_class="review", cost_usd=1.0)
    row = json.loads(path.read_text())
    assert row["call_class"] == "review"
    assert row["cost_usd"] == 1.0


def test_explicit_attribution_is_preserved(tmp_path, monkeypatch):
    path = tmp_path / "telemetry.jsonl"
    telemetry.set_sink(telemetry.TelemetrySink(path))
    monkeypatch.setattr(telemetry, "_caller_chain", lambda: pytest.fail("stack inspected"))
    telemetry.emit(event="call", caller_chain=[{"function": "supplied"}])
    assert json.loads(path.read_text())["caller_chain"] == [{"function": "supplied"}]
