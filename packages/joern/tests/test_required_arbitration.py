"""Joern must not publish competing owners or graphs after lock refusal."""

from unittest.mock import Mock

import pytest

from core.atomic_fs import fs_lock
from packages.joern import broker, heap_ledger, runner

pytestmark = pytest.mark.skipif(not fs_lock._HAS_FCNTL, reason="requires flock")


def test_contended_controller_does_not_start_another_owner(tmp_path, monkeypatch):
    family = broker._runtime_family(tmp_path)
    family.mkdir(mode=0o700)
    monkeypatch.setattr(fs_lock, "_ACQUIRE_DEADLINE_S", 0.01)
    monkeypatch.setattr(fs_lock, "_ACQUIRE_POLL_S", 0.001)
    start = Mock()
    monkeypatch.setattr(broker.subprocess, "Popen", start)
    with fs_lock.sidecar_flock(family / "controllers.lock", required=True):
        with pytest.raises(TimeoutError):
            broker.discover(tmp_path)
    start.assert_not_called()
    assert not list(family.glob("*/current.json"))


def test_unsafe_controller_lock_never_starts_an_unconfined_fallback(tmp_path, monkeypatch):
    family = broker._runtime_family(tmp_path)
    family.mkdir(mode=0o700)
    victim = tmp_path / "victim"
    victim.write_text("unchanged")
    (family / "controllers.lock").symlink_to(victim)
    start = Mock()
    monkeypatch.setattr(broker.subprocess, "Popen", start)
    with pytest.raises(OSError, match="refusing unlocked operation"):
        broker.discover(tmp_path)
    start.assert_not_called()
    assert victim.read_text() == "unchanged"


def test_refused_cache_lock_never_builds_or_publishes_graph(tmp_path, monkeypatch):
    target = tmp_path / "source"
    target.mkdir()
    (target / "fixture.py").write_text("def fixture(): return 1\n")
    cache = tmp_path / "cache"
    slot = cache / runner.cpg_cache_slot_name(target=target)
    slot.mkdir(parents=True)
    victim = tmp_path / "victim"
    victim.write_text("unchanged")
    (slot / "cpg.bin.lock").symlink_to(victim)
    build = Mock()
    monkeypatch.setattr(runner, "build_cpg", build)
    with pytest.raises(OSError, match="refusing unlocked operation"):
        runner.build_cpg_cached(target, cache)
    build.assert_not_called()
    assert not (slot / "cpg.bin").exists()
    assert not (slot / "manifest.json").exists()
    assert victim.read_text() == "unchanged"


def test_refused_heap_lock_preserves_advisory_fallback_without_writing(
    tmp_path, caplog,
):
    ledger = tmp_path / "ledger.json"
    victim = tmp_path / "victim"
    victim.write_text("unchanged")
    (tmp_path / "ledger.json.lock").symlink_to(victim)
    reservation = heap_ledger.reserve_heap_mb(2048, derived=True, ledger_path=ledger)
    assert reservation.granted_mb == 2048
    assert not ledger.exists()
    assert victim.read_text() == "unchanged"
    assert "admission bookkeeping skipped" in caplog.text
