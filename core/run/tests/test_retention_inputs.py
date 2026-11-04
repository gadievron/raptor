"""Non-finite ages and clocks must never bypass deletion safety gates."""

import json
import os
import time
from datetime import datetime, timezone
from types import SimpleNamespace
import pytest
from core.config import RaptorConfig
from core.run import tmp_reaper, tmp_ownership, scratch

INVALID = ["nan", "NaN", "inf", "-inf", "Infinity", "1e309", "1e308"]


@pytest.fixture(autouse=True)
def private_roots(tmp_path, monkeypatch):
    monkeypatch.setattr("tempfile.tempdir", str(tmp_path))
    monkeypatch.setattr(tmp_reaper, "_SYSTEM_TMP_ROOTS", ())
    monkeypatch.setattr(tmp_reaper, "_lane_fallback_bases", lambda: ())
    monkeypatch.setattr(tmp_reaper, "_live_cwds", lambda: set())
    monkeypatch.setattr(tmp_ownership, "_live_cwds", lambda: set())
    monkeypatch.setattr(RaptorConfig, "LOG_DIR", tmp_path)
    for key in (
        "RAPTOR_TMP_REAP_MAX_AGE_H",
        "RAPTOR_RUN_REAP_MAX_AGE_D",
        "RAPTOR_LOG_REAP_MAX_AGE_D",
    ):
        monkeypatch.delenv(key, raising=False)


def candidates(tmp_path, kind):
    now = time.time()
    paths = []
    for name, age in (("young", 0), ("old", 90 * 86400)):
        if kind == "logs":
            path = tmp_path / f"raptor_{name}.jsonl"
            path.write_text("audit data")
        elif kind == "runs":
            path = tmp_path / f"scan-{name}"
            path.mkdir()
            stamp = datetime.fromtimestamp(now - age, timezone.utc).isoformat()
            (path / ".raptor-run.json").write_text(
                json.dumps(
                    {
                        "version": 2,
                        "command": "scan",
                        "status": "failed",
                        "timestamp": stamp,
                        "extra": {},
                    }
                )
            )
        else:
            path = tmp_path / (
                "audit_sweep_"
                + ("aaaaaaaa" if name == "young" else "bbbbbbbb")
                + ".yaml"
            )
            path.write_text("rules: []")
        os.utime(path, (now - age,) * 2)
        paths.append(path)
    return paths


@pytest.mark.parametrize("kind", ["tmp", "runs", "logs"])
@pytest.mark.parametrize("raw", INVALID)
def test_invalid_retention_uses_default_or_keeps_opt_in_disabled(
    tmp_path, monkeypatch, kind, raw
):
    young, old = candidates(tmp_path, kind)
    variable = {
        "tmp": "RAPTOR_TMP_REAP_MAX_AGE_H",
        "runs": "RAPTOR_RUN_REAP_MAX_AGE_D",
        "logs": "RAPTOR_LOG_REAP_MAX_AGE_D",
    }[kind]
    monkeypatch.setenv(variable, raw)
    sweep = {
        "tmp": tmp_reaper.reap_stale_tmp,
        "runs": lambda: tmp_reaper.reap_stale_runs(tmp_path),
        "logs": tmp_reaper.reap_stale_logs,
    }[kind]
    removed = sweep()
    assert young.exists()
    if kind == "logs":
        assert removed == [] and old.exists()
    else:
        assert removed == [old] and not old.exists()


@pytest.mark.parametrize("kind", ["tmp", "runs", "logs"])
@pytest.mark.parametrize("clock", [float("nan"), float("inf"), -float("inf")])
def test_invalid_clock_never_deletes_candidates(tmp_path, monkeypatch, kind, clock):
    young, old = candidates(tmp_path, kind)
    monkeypatch.setenv("RAPTOR_LOG_REAP_MAX_AGE_D", "30")
    if kind == "tmp":
        removed = tmp_reaper.reap_stale_tmp(now=clock)
    elif kind == "runs":
        removed = tmp_reaper.reap_stale_runs(tmp_path, now=clock)
    else:
        removed = tmp_reaper.reap_stale_logs(now=clock)
    assert removed == []
    assert young.exists() and old.exists()


@pytest.mark.parametrize("age", [float("nan"), float("inf"), -float("inf")])
def test_invalid_legacy_owner_age_keeps_unmarked_scratch(tmp_path, age):
    tree = tmp_path / "raptor-owned-new"
    tree.mkdir()
    assert (
        tmp_ownership.sweep_dead_owner_dirs("raptor-owned-", legacy_max_age_s=age) == []
    )
    assert tree.exists()


@pytest.mark.parametrize("raw", ["nan", "inf", "-inf", "1e309"])
@pytest.mark.parametrize("free", [20, 5])
def test_invalid_inode_threshold_keeps_default_pressure_warning(
    tmp_path, monkeypatch, caplog, raw, free
):
    monkeypatch.setenv("RAPTOR_TMP_INODE_SOFT_PCT", raw)
    monkeypatch.setattr(scratch, "_last_inode_warning", 0.0)
    monkeypatch.setattr(
        scratch.os, "statvfs", lambda path: SimpleNamespace(f_files=100, f_ffree=free)
    )
    with caplog.at_level("WARNING", logger=scratch.__name__):
        scratch._inode_ceiling_advisory(tmp_path)
    warnings = [record for record in caplog.records if record.name == scratch.__name__]
    if free == 20:
        assert warnings == []
    else:
        assert len(warnings) == 1
        assert warnings[0].args[-2] == scratch._DEFAULT_INODE_SOFT_PCT


@pytest.mark.parametrize("kind", ["tmp", "runs", "logs"])
@pytest.mark.parametrize("raw", ["0", "-1", "-1e308"])
def test_finite_disable_values_still_keep_all_data(tmp_path, monkeypatch, kind, raw):
    young, old = candidates(tmp_path, kind)
    variable = {
        "tmp": "RAPTOR_TMP_REAP_MAX_AGE_H",
        "runs": "RAPTOR_RUN_REAP_MAX_AGE_D",
        "logs": "RAPTOR_LOG_REAP_MAX_AGE_D",
    }[kind]
    monkeypatch.setenv(variable, raw)
    if kind == "tmp":
        removed = tmp_reaper.reap_stale_tmp()
    elif kind == "runs":
        removed = tmp_reaper.reap_stale_runs(tmp_path)
    else:
        removed = tmp_reaper.reap_stale_logs()
    assert removed == []
    assert young.exists() and old.exists()
