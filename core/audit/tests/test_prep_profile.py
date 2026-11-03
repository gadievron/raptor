"""Prep diagnostics must never change the wrapped analysis outcome."""

from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from core.audit import prep_profile
from core.audit.prep_profile import PrepProfile, profile_call


def test_results_and_errors_are_preserved(monkeypatch):
    profile = PrepProfile()
    config = SimpleNamespace(prep_profile=profile)
    clock = iter((10.0, 12.0, 20.0, 23.0))
    monkeypatch.setattr(prep_profile.time, "perf_counter", lambda: next(clock))
    result = object()
    assert profile_call(config, "peer_groups.resolve", lambda: result) is result
    failure = ValueError("original failure")

    def broken():
        raise failure

    with pytest.raises(ValueError) as caught:
        profile_call(config, "mechanical.detector", broken)
    assert caught.value is failure
    steps = profile.snapshot()["steps"]
    assert steps["peer_groups.resolve"] == {
        "calls": 1, "errors": 0, "wall_time_s": 2.0, "max_wall_time_s": 2.0,
    }
    assert steps["mechanical.detector"]["errors"] == 1
    assert steps["mechanical.detector"]["wall_time_s"] == 3.0


def test_cache_observations_distinguish_empty_hit_from_miss():
    profile = PrepProfile()
    config = SimpleNamespace(prep_profile=profile)
    empty = []
    assert profile_call(config, "mechanical.x.cache_lookup", lambda: empty) is empty
    assert profile_call(config, "mechanical.x.cache_lookup", lambda: None) is None
    row = profile.snapshot()["steps"]["mechanical.x.cache_lookup"]
    assert row["cache_hits"] == row["cache_misses"] == 1
    assert row["calls"] == 2


def test_no_profile_does_not_read_clock(monkeypatch):
    monkeypatch.setattr(prep_profile.time, "perf_counter", lambda: pytest.fail("clock read"))
    result = []
    assert profile_call(SimpleNamespace(), "test", lambda: result) is result


def test_clock_or_recording_failure_cannot_change_result(monkeypatch):
    profile = PrepProfile()
    config = SimpleNamespace(prep_profile=profile)
    result = []

    def fail(*_):
        raise OSError("diagnostic failure")

    monkeypatch.setattr(profile, "record", fail)
    assert profile_call(config, "test", lambda: result) is result
    monkeypatch.setattr(prep_profile.time, "perf_counter", fail)
    assert profile_call(config, "test", lambda: result) is result


def test_write_failure_is_nonfatal(tmp_path, monkeypatch):
    monkeypatch.setattr(prep_profile, "save_json", lambda *_: (_ for _ in ()).throw(OSError()))
    PrepProfile().write(tmp_path)


def test_thread_safe_counts_and_snapshot_isolation():
    profile = PrepProfile()
    config = SimpleNamespace(prep_profile=profile)
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda i: profile_call(config, "mechanical.conditions", lambda: i), range(500)))
    snapshot = profile.snapshot()
    assert snapshot["steps"]["mechanical.conditions"]["calls"] == 500
    snapshot["steps"]["mechanical.conditions"]["calls"] = -1
    assert profile.snapshot()["steps"]["mechanical.conditions"]["calls"] == 500


def test_finalization_writes_profile_separately_from_costs(tmp_path, monkeypatch):
    import json
    from core.audit.orchestrator import (
        OrchestratorConfig, OrchestratorResult, _reconcile_cost_ledgers,
    )
    from core.llm import telemetry

    monkeypatch.setattr(telemetry, "_sink", None)
    config = OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path)
    result = OrchestratorResult()
    result.cost_tracker.record_call("review", cost_usd=0.5)
    profile_call(config, "peer_groups.resolve", lambda: [])
    _reconcile_cost_ledgers(config, result)
    report = json.loads((tmp_path / "prep-profile.json").read_text())
    assert report["scope"] == "config_instance"
    assert report["steps"]["peer_groups.resolve"]["calls"] == 1
    assert result.cost_tracker.total_cost_usd == 0.5
    assert result.llm_spend_usd == 0.5
    assert "prep_profile" not in json.loads((tmp_path / "cost-breakdown.json").read_text())
