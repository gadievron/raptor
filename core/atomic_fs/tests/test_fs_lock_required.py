"""Ownership mutations must never execute without exclusive admission."""

import os

import pytest

from core.atomic_fs import fs_lock


def test_missing_lock_backend_refuses_required_mutation(tmp_path, monkeypatch):
    monkeypatch.setattr(fs_lock, "_HAS_FCNTL", False)
    with pytest.raises(OSError, match="locking unavailable"):
        with fs_lock.artifact_lock(tmp_path / "state.json", required=True):
            pytest.fail("mutation admitted without locking support")


@pytest.mark.skipif(not fs_lock._HAS_FCNTL, reason="requires flock")
@pytest.mark.parametrize("shape", ["symlink", "fifo", "foreign-owner"])
def test_untrusted_lock_refuses_required_mutation(tmp_path, monkeypatch, shape):
    artifact = tmp_path / "state.json"
    lock = tmp_path / "state.json.lock"
    victim = tmp_path / "victim"
    victim.write_text("unchanged")
    if shape == "symlink":
        lock.symlink_to(victim)
    elif shape == "fifo":
        os.mkfifo(lock)
    else:
        lock.touch()
        monkeypatch.setattr(os, "geteuid", lambda: lock.stat().st_uid + 1)
    with pytest.raises(OSError, match="refusing unlocked operation"):
        with fs_lock.artifact_lock(artifact, required=True):
            artifact.write_text("unsafe mutation")
    assert not artifact.exists()
    assert victim.read_text() == "unchanged"


@pytest.mark.skipif(not fs_lock._HAS_FCNTL, reason="requires flock")
def test_required_mutation_waits_for_admission_and_recovers_after_expiry(
    tmp_path, monkeypatch, caplog,
):
    artifact = tmp_path / "state.json"
    monkeypatch.setattr(fs_lock, "_ACQUIRE_DEADLINE_S", 0.01)
    monkeypatch.setattr(fs_lock, "_ACQUIRE_POLL_S", 0.001)
    with fs_lock.artifact_lock(artifact, required=True):
        with pytest.raises(TimeoutError, match="deadline expired"):
            with fs_lock.artifact_lock(artifact, required=True):
                artifact.write_text("competing publication")
        assert not artifact.exists()
    with fs_lock.artifact_lock(artifact, required=True):
        artifact.write_text("admitted publication")
    assert artifact.read_text() == "admitted publication"
    assert "refusing unlocked operation" in caplog.text
    assert "proceeding WITHOUT" not in caplog.text


@pytest.mark.skipif(not fs_lock._HAS_FCNTL, reason="requires flock")
def test_required_lock_releases_after_mutation_raises(tmp_path):
    artifact = tmp_path / "state.json"
    with pytest.raises(ValueError, match="failed mutation"):
        with fs_lock.artifact_lock(artifact, required=True):
            raise ValueError("failed mutation")
    with fs_lock.artifact_lock(artifact, required=True):
        artifact.write_text("recovered")
    assert artifact.read_text() == "recovered"
