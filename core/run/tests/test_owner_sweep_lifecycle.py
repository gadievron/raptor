"""Reclamation is scoped, conservative, independent and receipt-honest."""

import json
import os
import time

import pytest

from core.run import tmp_ownership as owner, tmp_reaper
from core.testing.module_bindings import patch_module_attribute

PREFIX = "raptor-owner-test-"
DEAD = 456789


@pytest.fixture
def sweep_root(tmp_path, monkeypatch):
    patch_module_attribute(monkeypatch, owner, "tempfile", "gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr(tmp_reaper, "_in_child_pid_ns", lambda: False)
    monkeypatch.setattr(owner, "_live_cwds", lambda: set())
    monkeypatch.setattr(owner, "_pid_alive", lambda pid: pid == os.getpid() or pid <= 1)
    return tmp_path


def directory(root, suffix, pid=DEAD):
    path = root / (PREFIX + suffix)
    path.mkdir()
    if pid is not None:
        (path / owner.OWNER_MARKER_NAME).write_text(json.dumps({"pid": pid}))
    else:
        old = time.time() - owner.LEGACY_MAX_AGE_S - 7200
        os.utime(path, (old, old))
    return path


@pytest.mark.parametrize("prefix", ["", ".", "..", "/", "../", "a/", "a\\", " ", "raptor", "ab", "--", None, 123, "r\x00-", "ré-"],
                         ids=["empty", "dot", "parent", "root", "traversal", "slash", "backslash", "space", "undelimited", "short", "ambiguous", "none", "integer", "nul", "unicode"])
def test_invalid_prefix_never_selects_any_directory(sweep_root, prefix):
    candidate = directory(sweep_root, "old", pid=None)
    assert owner.sweep_dead_owner_dirs(prefix) == []
    assert candidate.is_dir()


@pytest.mark.parametrize("age", [float("nan"), float("inf"), float("-inf"), -1, 0, True, None, "old"],
                         ids=["nan", "infinite", "negative-infinite", "negative", "zero", "boolean", "none", "text"])
def test_invalid_grace_permits_no_deletion(sweep_root, age):
    candidate = directory(sweep_root, "old", pid=None)
    assert owner.sweep_dead_owner_dirs(PREFIX, legacy_max_age_s=age) == []
    assert candidate.is_dir()


def test_exact_prefix_name_is_not_a_minted_workspace(sweep_root):
    candidate = sweep_root / PREFIX
    candidate.mkdir()
    (candidate / owner.OWNER_MARKER_NAME).write_text(json.dumps({"pid": DEAD}))
    assert owner.sweep_dead_owner_dirs(PREFIX) == []
    assert candidate.is_dir()


def test_shared_namespace_refusal_keeps_marked_directories(sweep_root, monkeypatch):
    candidate = directory(sweep_root, "marked")
    monkeypatch.setattr(owner, "_pid_alive", tmp_reaper._pid_alive)
    monkeypatch.setattr(tmp_reaper, "_in_child_pid_ns", lambda: True)
    def no_signal(*args):
        pytest.fail("cross-namespace liveness must not issue a signal probe")
    patch_module_attribute(monkeypatch, tmp_reaper, "os", "kill", no_signal)
    assert owner.sweep_dead_owner_dirs(PREFIX) == []
    assert candidate.is_dir()


def test_overflowing_pid_does_not_abort_remaining_cleanup(sweep_root, monkeypatch):
    unknown = directory(sweep_root, "unknown", pid=2**200)
    reclaim = directory(sweep_root, "legacy", pid=None)
    monkeypatch.setattr(owner, "_pid_alive", tmp_reaper._pid_alive)
    assert owner.sweep_dead_owner_dirs(PREFIX) == [reclaim]
    assert unknown.exists() and not reclaim.exists()


def test_init_pid_is_retained_without_a_signal_probe(sweep_root, monkeypatch):
    candidate = directory(sweep_root, "init", pid=1)
    monkeypatch.setattr(owner, "_pid_alive", tmp_reaper._pid_alive)
    def no_signal(*args):
        pytest.fail("init must be retained without a signal probe")
    patch_module_attribute(monkeypatch, tmp_reaper, "os", "kill", no_signal)
    assert owner.sweep_dead_owner_dirs(PREFIX) == []
    assert candidate.exists()


@pytest.mark.parametrize("change", ["new-owner", "stamp-legacy", "refresh-legacy", "owner-disappears", "reused-pid"])
def test_changed_ownership_or_activity_survives_final_check(sweep_root, monkeypatch, change):
    legacy = change in ("stamp-legacy", "refresh-legacy")
    candidate = directory(sweep_root, "candidate", pid=None if legacy else DEAD)
    marker = candidate / owner.OWNER_MARKER_NAME
    probes = []
    def in_use(path, cwds):
        probes.append(path)
        if change in ("new-owner", "stamp-legacy"):
            marker.write_text(json.dumps({"pid": os.getpid()}))
        elif change == "refresh-legacy":
            os.utime(candidate, None)
        elif change == "owner-disappears":
            marker.unlink()
        return False
    monkeypatch.setattr(owner, "_dir_in_use", in_use)
    if change == "reused-pid":
        verdicts = iter([False, True])
        monkeypatch.setattr(owner, "_pid_alive", lambda pid: next(verdicts))
    assert owner.sweep_dead_owner_dirs(PREFIX) == []
    assert probes == [candidate]
    assert candidate.is_dir()


@pytest.mark.parametrize("recent", [False, True], ids=["stale-leaf", "active-leaf"])
def test_legacy_workspace_checks_internal_activity(sweep_root, recent):
    candidate = directory(sweep_root, "legacy", pid=None)
    child = candidate / "objects"
    child.mkdir()
    leaf = child / "data"
    leaf.write_bytes(b"payload")
    old = time.time() - owner.LEGACY_MAX_AGE_S - 7200
    for path in (candidate, child, leaf):
        os.utime(path, (old, old))
    if recent:
        os.utime(leaf, None)
    result = owner.sweep_dead_owner_dirs(PREFIX)
    assert result == ([] if recent else [candidate])
    assert candidate.exists() == recent


@pytest.mark.parametrize("phase", ["probe", "remove", "verify"])
def test_one_directory_error_does_not_lose_other_receipts(sweep_root, monkeypatch, phase):
    first = directory(sweep_root, "first")
    blocked = directory(sweep_root, "blocked")
    last = directory(sweep_root, "last")
    if phase == "probe":
        def in_use(path, cwds):
            if path == blocked:
                raise OSError("socket probe failed")
            return False
        monkeypatch.setattr(owner, "_dir_in_use", in_use)
    else:
        original = owner.rmtree_hardened
        def remove(path):
            if path == blocked:
                if phase == "remove":
                    raise OSError("removal failed")
                # A completed remover can be followed by a new directory at
                # the same name. Its presence must not count as reclamation.
                path.rename(sweep_root / "retired")
                path.mkdir()
                return True
            return original(path)
        monkeypatch.setattr(owner, "rmtree_hardened", remove)
    result = owner.sweep_dead_owner_dirs(PREFIX)
    assert set(result) == {first, last}
    assert blocked.is_dir()
    assert not first.exists() and not last.exists()


def test_false_removal_result_does_not_report_success(sweep_root, monkeypatch):
    candidate = directory(sweep_root, "blocked")
    monkeypatch.setattr(owner, "rmtree_hardened", lambda path: False)
    assert owner.sweep_dead_owner_dirs(PREFIX) == []
    assert candidate.exists()


def test_dangling_replacement_is_not_reported_as_removed(sweep_root, monkeypatch):
    candidate = directory(sweep_root, "candidate")
    def remove(path):
        path.rename(sweep_root / "retired")
        path.symlink_to("missing")
        return True
    monkeypatch.setattr(owner, "rmtree_hardened", remove)
    assert owner.sweep_dead_owner_dirs(PREFIX) == []
    assert candidate.is_symlink()


@pytest.mark.parametrize("change", ["directory", "symlink"])
def test_replaced_candidate_is_not_removed(sweep_root, monkeypatch, change):
    candidate = directory(sweep_root, "candidate")
    borrowed = sweep_root / "borrowed"
    borrowed.mkdir()
    (borrowed / "keep").write_text("retain")
    def in_use(path, cwds):
        candidate.rename(sweep_root / "retired")
        if change == "directory":
            candidate.mkdir()
        else:
            candidate.symlink_to(borrowed, target_is_directory=True)
        return False
    monkeypatch.setattr(owner, "_dir_in_use", in_use)
    assert owner.sweep_dead_owner_dirs(PREFIX) == []
    assert candidate.exists()
    assert (borrowed / "keep").read_text() == "retain"


@pytest.mark.parametrize("error", [KeyboardInterrupt, SystemExit])
def test_cancellation_is_not_swallowed(sweep_root, monkeypatch, error):
    candidate = directory(sweep_root, "candidate")
    def in_use(*a):
        raise error("cancel")
    monkeypatch.setattr(owner, "_dir_in_use", in_use)
    with pytest.raises(error, match="cancel"):
        owner.sweep_dead_owner_dirs(PREFIX)
    assert candidate.exists()
