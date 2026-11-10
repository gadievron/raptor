"""Exports retain native event axes, freshness calls and ranking outcomes."""
from copy import deepcopy
import json
from pathlib import Path

import pytest

from core.llm.scorecard import EventType, cli
from core.llm.scorecard.scorecard import _EventCounts
from core.llm.scorecard.tests.test_render_scrub import _stat
from core.reporting.writer import load_committed_report


def _reader(tmp_path, monkeypatch, *, empty=False, all_fail=False, drift=False):
    source = tmp_path / "scorecard.json"
    source.write_text("owned source bytes")
    stats = []
    if not empty:
        for model, wins, losses in (("winner", 3, 0), ("zero", 0, 5), ("missing", 0, 0)):
            usage = _stat("_usage", model)
            usage.calls, usage.cost_usd = 10, 2.0
            cell = _stat("owned:class", model)
            cell.events[EventType.CHEAP_SHORT_CIRCUIT] = _EventCounts(correct=100, incorrect=0)
            cell.events[EventType.REASONING_DIVERGENCE] = _EventCounts(correct=7, incorrect=3)
            chain = _stat("exploit_chain_closure", model)
            chain.events[EventType.EXPLOIT_CHAIN_CLOSURE] = _EventCounts(correct=0 if all_fail else wins, incorrect=losses)
            stats.extend([usage, cell, chain])
    baseline = deepcopy(stats)
    if drift:
        for stat in stats:
            if stat.decision_class == "owned:class":
                stat.events[EventType.CHEAP_SHORT_CIRCUIT] = _EventCounts(correct=0, incorrect=2)
    calls = []
    class ReadOnlyScorecard:
        def __init__(self, path):
            assert Path(path) == source
        def get_stats(self, **kwargs):
            calls.append(("stats", kwargs))
            return stats if kwargs.get("freshness_half_life_days") or not drift else baseline
        def measure_freshness_impact(self, days):
            calls.append(("impact", days))
            return {"cells": len(stats), "short_circuit_baseline": 3, "short_circuit_weighted": 0,
                    "flipped_out": 3, "flipped_in": 0}
    monkeypatch.setattr(cli, "ModelScorecard", ReadOnlyScorecard)
    return source, stats, calls


@pytest.mark.parametrize("kind,selection", [("list", []), ("recommend", ["owned:class"]), ("chain-closure", [])])
def test_export_keeps_native_json_rank_order_and_read_count(tmp_path, monkeypatch, capsys, kind, selection):
    source, stats, calls = _reader(tmp_path, monkeypatch)
    before = deepcopy(stats)
    base = ["--path", str(source), "--json", kind, *selection]
    assert cli.main(base) == 0
    native = json.loads(capsys.readouterr().out)
    baseline_calls = list(calls)
    calls.clear()
    assert cli.main([*base, "--report-format", "json", "--report-output", str(tmp_path / "portable-reports" / ("scorecard-" + kind))]) == 0
    shown = capsys.readouterr()
    assert json.loads(shown.out) == native and calls == baseline_calls
    context, document, _ = load_committed_report(tmp_path / "portable-reports" / ("scorecard-" + kind))
    assert document.snapshot_id == context.snapshot_id and context.run_id == "unknown"
    data = context.extensions["raptor.scorecard_read"]
    if kind == "list":
        assert len(data["cells"]) == len(native["cells"])
    elif kind == "recommend":
        assert dict(data["recommendation"])["model"] == native["recommendation"]["model"]
    else:
        assert data["recommendation"] == native["recommendation"] == "winner"
        assert [dict(row)["model"] for row in data["candidates"]] == [row["model"] for row in native["candidates"]]
    assert stats == before and source.read_text() == "owned source bytes"


def test_list_selected_event_counts_do_not_relabel_cheap_policy_axis(tmp_path, monkeypatch, capsys):
    source, _, calls = _reader(tmp_path, monkeypatch)
    assert cli.main(["--path", str(source), "list", "--prefix", "owned", "--event-type", EventType.REASONING_DIVERGENCE,
                     "--report-format", "json", "--report-output", str(tmp_path / "portable-reports" / "scorecard-list")]) == 0
    context, document, _ = load_committed_report(tmp_path / "portable-reports" / "scorecard-list")
    data = context.extensions["raptor.scorecard_read"]
    assert data["selected_event_type"] == EventType.REASONING_DIVERGENCE
    selected = dict(data["cells"][0]["selected_event"])
    native = dict(data["cells"][0]["fields"])
    assert selected["n"] == 10 and selected["correct"] == 7 and selected["correct_column"] == "correct"
    assert native["n"] == 100
    assert document.metadata["Selected event type"] == EventType.REASONING_DIVERGENCE
    assert "Selected event type" in capsys.readouterr().err and len(calls) == 1


def test_freshness_export_reuses_native_measurement_and_records_drift(tmp_path, monkeypatch, capsys):
    source, _, calls = _reader(tmp_path, monkeypatch, drift=True)
    base = ["--path", str(source), "list", "--prefix", "owned", "--freshness", "30"]
    assert cli.main(base) == 0
    native = capsys.readouterr().out
    baseline_calls = list(calls)
    calls.clear()
    assert cli.main([*base, "--report-format", "json", "--report-output", str(tmp_path / "portable-reports" / "scorecard-list")]) == 0
    assert capsys.readouterr().out == native
    assert calls == baseline_calls == [("stats", {"freshness_half_life_days": 30.0}), ("stats", {}), ("impact", 30.0)]
    context, _, _ = load_committed_report(tmp_path / "portable-reports" / "scorecard-list")
    data = context.extensions["raptor.scorecard_read"]
    assert dict(data["freshness_impact"])["flipped_out"] == 3
    assert all(dict(cell["freshness_drift"])["baseline_policy"] != dict(cell["fields"])["policy"] for cell in data["cells"])
    assert any("whole-scorecard" in note and "ignores operator pins" in note for note in context.diagnostics)


@pytest.mark.parametrize("kind,selection", [("recommend", ["unknown-class"]), ("chain-closure", [])])
def test_empty_candidate_scope_preserves_status_and_availability(tmp_path, monkeypatch, capsys, kind, selection):
    source, _, calls = _reader(tmp_path, monkeypatch, empty=True)
    assert cli.main(["--path", str(source), kind, *selection, "--report-format", "json", "--report-output", str(tmp_path / "portable-reports" / ("scorecard-" + kind))]) == 0
    context, _, _ = load_committed_report(tmp_path / "portable-reports" / ("scorecard-" + kind))
    data = context.extensions["raptor.scorecard_read"]
    assert data["recorded_no_candidates"] is True and data["recommendation"] is None
    assert any("not proof" in note for note in context.diagnostics)
    assert len(calls) == 1


def test_chain_observed_zero_and_missing_rate_remain_distinct(tmp_path, monkeypatch, capsys):
    source, _, _ = _reader(tmp_path, monkeypatch, all_fail=True)
    assert cli.main(["--path", str(source), "--json", "chain-closure", "--report-format", "json", "--report-output", str(tmp_path / "portable-reports" / "scorecard-chain-closure")]) == 0
    native = json.loads(capsys.readouterr().out)
    context, _, _ = load_committed_report(tmp_path / "portable-reports" / "scorecard-chain-closure")
    data = context.extensions["raptor.scorecard_read"]
    assert data["recommendation"] is native["recommendation"] is None
    rates = {dict(row)["model"]: dict(row)["success_rate"] for row in data["candidates"]}
    assert rates["zero"] == 0.0 and rates["missing"] is None
    assert data["recommendation_recorded"] is True


@pytest.mark.parametrize("kind,selection", [("list", []), ("recommend", ["owned:class"]), ("chain-closure", [])])
def test_source_collision_precedes_read(tmp_path, monkeypatch, kind, selection):
    source, _, calls = _reader(tmp_path, monkeypatch)
    with pytest.raises(SystemExit) as error:
        cli.main(["--path", str(source), kind, *selection, "--report-format", "json", "--report-output", str(source)])
    assert error.value.code == 2 and not calls
    assert source.read_text() == "owned source bytes"


def test_rank_publisher_fault_cannot_change_native_result(tmp_path, monkeypatch, capsys):
    source, _, calls = _reader(tmp_path, monkeypatch)
    from core.llm.scorecard import read_report
    reached = []
    def fail(*args, **kwargs):
        reached.append(True)
        raise OSError("private fault")
    monkeypatch.setattr(read_report, "complete_reporting", fail)
    assert cli.main(["--path", str(source), "--json", "recommend", "owned:class", "--report-format", "json", "--report-output", str(tmp_path / "portable-reports" / "scorecard-recommend")]) == 0
    shown = capsys.readouterr()
    assert json.loads(shown.out)["recommendation"] is not None
    assert "native view retained" in shown.err and "private fault" not in shown.err
    assert reached == [True] and len(calls) == 1


def test_disabled_list_export_preserves_stale_receipt(tmp_path, monkeypatch, capsys):
    source, _, calls = _reader(tmp_path, monkeypatch)
    root = tmp_path / "portable-reports" / "scorecard-list"
    root.mkdir(parents=True)
    manifest = root / "reporting-manifest.json"
    manifest.write_text("old unparsed receipt")
    assert cli.main(["--path", str(source), "list", "--no-report"]) == 0
    assert "not refreshed" in capsys.readouterr().err
    assert manifest.read_text() == "old unparsed receipt" and not (root / "summary.json").exists()
    assert len(calls) == 1


def test_empty_list_does_not_invent_read_quality_or_rejected_row_counts(tmp_path, monkeypatch):
    source, _, calls = _reader(tmp_path, monkeypatch, empty=True)
    assert cli.main(["--path", str(source), "list", "--report-format", "json", "--report-output", str(tmp_path / "portable-reports" / "scorecard-list")]) == 0
    context, _, _ = load_committed_report(tmp_path / "portable-reports" / "scorecard-list")
    assert context.extensions["raptor.read_quality"] == {
        "completeness": "unknown", "rejected_rows": None, "reason": "not supplied by scorecard stats API"}
    assert any("not proof of complete source coverage" in note for note in context.diagnostics)
    assert context.extensions["raptor.metrics"]["Selected cells"] == 0
    assert len(calls) == 1
