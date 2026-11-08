"""Fork-child state can report inode pressure without inherited mutex waits."""
from contextlib import ExitStack
import threading
from types import SimpleNamespace

import pytest

from core.run import scratch
from core.testing.module_bindings import patch_module_attribute
from core.testing.module_state import isolated_module_state


@pytest.mark.parametrize('held', ['inode', 'keepalive', 'both'])
@pytest.mark.parametrize('pressure', [False, True], ids=['below-ceiling', 'past-ceiling'])
def test_child_callback_replaces_all_inherited_scratch_mutexes(monkeypatch, tmp_path, caplog, held, pressure):
    warning_lock, keepalive_lock = threading.Lock(), threading.Lock()
    paths = {'parent-owned-scratch'}
    replacements = {
        '_inode_warn_lock': warning_lock,
        '_last_inode_warning': 0.0,
        '_keepalive_lock': keepalive_lock,
        '_keepalive_paths': paths,
        '_keepalive_thread': None,
    }
    monkeypatch.setenv('RAPTOR_TMP_INODE_SOFT_PCT', '90')
    calls = []
    def usage(path):
        calls.append(path)
        return SimpleNamespace(f_files=1000, f_ffree=10 if pressure else 500)
    patch_module_attribute(monkeypatch, scratch, 'os', 'statvfs', usage)
    with isolated_module_state(scratch, replacements, lock=scratch._keepalive_lock):
        with ExitStack() as held_locks:
            if held in {'inode', 'both'}:
                held_locks.enter_context(warning_lock)
            if held in {'keepalive', 'both'}:
                held_locks.enter_context(keepalive_lock)
            scratch._reinit_after_fork_in_child()
            assert scratch._inode_warn_lock is not warning_lock
            assert scratch._keepalive_lock is not keepalive_lock
            assert not scratch._inode_warn_lock.locked()
            assert not scratch._keepalive_lock.locked()
            assert scratch._keepalive_paths == set()
            assert scratch._keepalive_thread is None
            caplog.clear()
            with caplog.at_level('WARNING'):
                scratch._inode_ceiling_advisory(tmp_path)
            assert calls == [tmp_path]
            assert ('inode usage' in caplog.text) is pressure
            assert warning_lock.locked() is (held in {'inode', 'both'})
            assert keepalive_lock.locked() is (held in {'keepalive', 'both'})
