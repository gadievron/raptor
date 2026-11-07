"""Concurrency tests reject missing behavior and retire workers on failures."""
from __future__ import annotations

from contextlib import nullcontext
import os
import json
from pathlib import Path
import threading

import pytest

from core.run import parent_liveness
from core.testing.state_isolation import pin_user_state_dirs


def _assert_workers_retired(before):
    names = {'project-pin-rename-probe', 'raptor-orphan-watchdog-trigger'}
    assert not [worker for worker in threading.enumerate()
                if worker not in before and worker.name in names]


@pytest.mark.skipif(os.name != 'posix', reason='native flock contention')
def test_project_contention_probe_rejects_an_unlocked_rewrite(tmp_path, monkeypatch):
    from core.project.tests.test_project import TestRenamePinRewriteLocked
    import core.run.metadata as metadata

    pin_user_state_dirs(monkeypatch, tmp_path / 'user-state')
    monkeypatch.setattr(metadata, '_metadata_lock', lambda *_: nullcontext())
    before = set(threading.enumerate())
    case = TestRenamePinRewriteLocked('test_rewrite_blocks_on_the_marker_lock')
    try:
        case.setUp()
        with pytest.raises(AssertionError, match='did not encounter marker contention'):
            case.test_rewrite_blocks_on_the_marker_lock()
        project = case.mgr.load("new")
        marker = Path(project.output_dir) / "scan-20260101-000000/.raptor-run.json"
        assert json.loads(marker.read_text())["project"] == "new", "control never performed the unlocked write"
    finally:
        case.doCleanups()
    _assert_workers_retired(before)


@pytest.mark.parametrize('failure', ['premature-action', 'missing-action'])
def test_watchdog_probe_retires_worker_on_assertion_failure(failure):
    from core.run.tests.test_parent_liveness import TestTrigger

    before = set(threading.enumerate())
    borrowed_os, borrowed_time = parent_liveness.os, parent_liveness.time
    borrowed_getppid = os.getppid
    calls = ['premature'] if failure == 'premature-action' else []
    with pytest.MonkeyPatch.context() as scope:
        action = calls.append if failure == 'premature-action' else lambda _: None
        scope.setattr(parent_liveness, '_terminate_group', action)
        expected = ("fired while parent was alive" if failure == "premature-action"
                    else "did not fire after parent change")
        with pytest.raises(AssertionError, match=expected):
            TestTrigger().test_ppid_change_fires(scope, calls)
        _assert_workers_retired(before)
        if failure == 'premature-action':
            assert calls == ['premature', 'trigger'], 'cleanup did not release the parked worker'
    assert parent_liveness.os is borrowed_os
    assert parent_liveness.time is borrowed_time
    assert os.getppid is borrowed_getppid
