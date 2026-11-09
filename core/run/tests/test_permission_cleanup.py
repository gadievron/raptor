"""Owned scratch and expired trees must not survive restrictive tool modes."""

import contextlib
import json
import os
import time
from datetime import datetime, timezone
import pytest
from core.atomic_fs import rmtree_hardened
from core.run import scratch, tmp_reaper, tmp_ownership, workdir
from core.testing.restricted_tree import restricted_tree

import core.run.tmp_reaper as _tempfile_owner


@pytest.fixture(autouse=True)
def _owned_tempfile_namespace(monkeypatch):
    """Share temporary-root faults only among this file's consumers."""
    from core.testing.tempdirs import private_tempfile_module
    import core.run.tmp_reaper as consumer_0
    import core.run.tmp_ownership as consumer_1
    import core.run.scratch as consumer_2
    import core.run.workdir as consumer_3

    private = private_tempfile_module(consumer_0.tempfile)
    monkeypatch.setattr(consumer_0, "tempfile", private)
    monkeypatch.setattr(consumer_1, "tempfile", private)
    monkeypatch.setattr(consumer_2, "tempfile", private)
    monkeypatch.setattr(consumer_3, "tempfile", private)
    monkeypatch.setitem(globals(), "tempfile", private)


@pytest.fixture(autouse=True)
def private_reaper_roots(tmp_path, monkeypatch, _owned_tempfile_namespace):
    monkeypatch.setattr(_tempfile_owner.tempfile, 'tempdir', str(tmp_path))
    monkeypatch.setattr(tmp_reaper, "_SYSTEM_TMP_ROOTS", ())
    monkeypatch.setattr(tmp_reaper, "_lane_fallback_bases", lambda: ())
    monkeypatch.setattr(tmp_reaper, "_live_cwds", lambda: set())
    monkeypatch.setattr(tmp_reaper, "_in_child_pid_ns", lambda: False)
    monkeypatch.setattr(tmp_ownership, "_live_cwds", lambda: set())
    monkeypatch.delenv("RAPTOR_TMP_REAP_MAX_AGE_H", raising=False)
    monkeypatch.delenv("RAPTOR_RUN_REAP_MAX_AGE_D", raising=False)


@pytest.mark.parametrize("mode", [0o000, 0o500, 0o555])
@pytest.mark.parametrize("scope", ["system", "run-output"])
def test_scratch_teardown_reclaims_restricted_output(tmp_path, mode, scope):
    allocated = None
    try:
        with contextlib.ExitStack() as cleanup:
            with scratch.scratch_dir(
                "raptor-permission-test-",
                dir=tmp_path if scope == "run-output" else None,
            ) as allocated:
                cleanup.enter_context(restricted_tree(allocated, mode))
            assert not allocated.exists()
    finally:
        if allocated is not None:
            rmtree_hardened(allocated)


@pytest.mark.parametrize("mode", [0o000, 0o500, 0o555])
@pytest.mark.parametrize(
    "kind", ["temp", "failed-run", "dead-pid", "dead-owner", "workdir"]
)
def test_expired_restricted_tree_is_reclaimed(tmp_path, monkeypatch, mode, kind):
    old = time.time() - 60 * 86400
    name = {
        "temp": "raptor_decomp_abcdefgh",
        "failed-run": "scan-old",
        "dead-pid": "pytest-9999999999999",
        "dead-owner": "raptor-owned-dead",
        "workdir": "session-9999999999999-1",
    }[kind]
    with restricted_tree(tmp_path / name, mode) as tree:
        if kind == "failed-run":
            (tree / ".raptor-run.json").write_text(
                json.dumps(
                    {
                        "version": 2,
                        "command": "scan",
                        "status": "failed",
                        "timestamp": datetime.fromtimestamp(
                            old, timezone.utc
                        ).isoformat(),
                        "extra": {},
                    }
                )
            )
        if kind == "dead-owner":
            tmp_ownership.write_owner_marker(tree)
            monkeypatch.setattr(tmp_ownership, "_pid_alive", lambda pid: False)
        if kind == "workdir":
            monkeypatch.setattr(workdir, "_pid_alive", lambda pid: False)
            monkeypatch.setattr(workdir, "_live_cwds", lambda: set())
        # Only stale descendant mtimes qualify for the activity probe.
        # Restrictive modes may block the walk, so restore traversal briefly.
        (tree / "locked").chmod(0o700)
        for parent, dirs, names in os.walk(tree):
            for name in names:
                os.utime(os.path.join(parent, name), (old, old))
            os.utime(parent, (old, old))
        (tree / "locked").chmod(mode)
        os.utime(tree, (old, old))
        if kind == "temp":
            # Mode bits alone do not establish unreadability for privileged
            # identities. Probe the owned fixture's actual traversal ability.
            unreadable = False
            try:
                with os.scandir(tree / "locked") as entries:
                    for entry in entries:
                        entry.stat(follow_symlinks=False)
            except PermissionError:
                unreadable = True
            removed = tmp_reaper.reap_stale_tmp()
            if unreadable:
                assert tree not in removed
                assert tree.exists()
                (tree / "locked").chmod(0o700)
                removed = tmp_reaper.reap_stale_tmp()
        elif kind == "failed-run":
            removed = tmp_reaper.reap_stale_runs(tmp_path)
        elif kind == "dead-pid":
            removed = tmp_reaper.reap_dead_pid_dirs(tmp_path, "pytest-")
        elif kind == "dead-owner":
            removed = tmp_ownership.sweep_dead_owner_dirs("raptor-owned-")
        else:
            workdir._sweep_dead_sessions(tmp_path)
            removed = [tree] if not tree.exists() else []
        assert tree in removed
        assert not tree.exists()


@pytest.mark.parametrize("mode", [0o000, 0o555])
def test_workdir_exit_callback_reclaims_restricted_tree(tmp_path, monkeypatch, mode):
    callbacks = []
    monkeypatch.setenv("RAPTOR_WORK_DIR", str(tmp_path))
    from core.testing.module_bindings import patch_module_attribute
    patch_module_attribute(
        monkeypatch, workdir, "atexit", "register",
        lambda fn, *a, **kw: callbacks.append((fn, a, kw)),
    )
    allocation = workdir._create_session_dir()
    assert allocation is not None
    tree, _ = allocation
    with restricted_tree(tree, mode):
        fn, args, kwargs = callbacks[-1]
        fn(*args, **kwargs)
        assert not tree.exists()


def test_common_removal_does_not_repair_permissions_on_normal_tree(
    tmp_path, monkeypatch
):
    tree = tmp_path / "plain"
    tree.mkdir()
    (tree / "data").write_bytes(b"data")

    def unexpected(*args, **kw):
        raise AssertionError("normal cleanup must not chmod every directory")

    monkeypatch.setattr(os, "chmod", unexpected)
    assert rmtree_hardened(tree)


@pytest.mark.parametrize("mode", [0o000, 0o500, 0o555])
def test_age_based_cleanup_retains_recent_descendants_until_stale(tmp_path, mode):
    old = time.time() - 60 * 86400
    with restricted_tree(tmp_path / "raptor_decomp_recent", mode) as tree:
        (tree / "locked").chmod(0o700)
        for parent, dirs, names in os.walk(tree):
            for name in names:
                os.utime(os.path.join(parent, name), (old, old))
            os.utime(parent, (old, old))
        payload = tree / "locked" / "nested" / "payload"
        os.utime(payload, None)
        (tree / "locked").chmod(mode)
        os.utime(tree, (old, old))
        assert tree not in tmp_reaper.reap_stale_tmp()
        assert tree.exists()
        (tree / "locked").chmod(0o700)
        assert tree not in tmp_reaper.reap_stale_tmp()
        assert payload.exists()
        os.utime(payload, (old, old))
        assert tree in tmp_reaper.reap_stale_tmp()
        assert not tree.exists()
