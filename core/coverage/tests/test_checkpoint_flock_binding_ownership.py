"""Actual checkpoint instrumentation owns only its locking consumer."""
import fcntl

import pytest

import core.atomic_fs.fs_lock as fs_lock
import core.coverage.journal as journal
import core.coverage.journal_compact as compact
from core.coverage.tests import test_journal_checkpoint as native
from core.testing.state_isolation import pin_user_state_dirs


CASES = [
    (native.TestGuard, "test_lock_order_collector_flush_precedes_first_flock"),
    (native.TestForeignAppenderAcrossCheckpoint, "test_appender_blocked_across_swap_lands_in_live_journal"),
]


@pytest.mark.parametrize("cls,method", CASES)
@pytest.mark.parametrize("error", [None, RuntimeError, KeyboardInterrupt, SystemExit])
def test_actual_flock_instrumentation_is_consumer_owned(tmp_path, monkeypatch, cls, method, error):
    pin_user_state_dirs(monkeypatch, tmp_path / "user")
    borrowed = fcntl.flock
    bindings = (fs_lock.fcntl, journal.fcntl, compact.fcntl)
    failure = error("owned publication boundary fault") if error else None
    observed = []
    called = []
    with pytest.MonkeyPatch.context() as scope:
        class ObservedPatch:
            def setattr(self, target, name, value, *args, **kwargs):
                assert fcntl.flock is borrowed
                if name == "flock":
                    callback = value
                    def value(*args, **kwargs):
                        called.append(args[1])
                        assert fcntl.flock is borrowed
                        return callback(*args, **kwargs)
                scope.setattr(target, name, value, *args, **kwargs)
                assert fcntl.flock is borrowed

            def setitem(self, target, key, value):
                scope.setitem(target, key, value)
                if target is vars(fs_lock) and key == "fcntl":
                    observed.append(value)
                    assert value is fs_lock.fcntl and value is not bindings[0]
                    assert value.flock is not borrowed
                    assert fcntl.flock is borrowed
                    assert journal.fcntl is bindings[1]
                    assert compact.fcntl is bindings[2]
                    if failure is not None:
                        raise failure

        if error:
            with pytest.raises(error) as caught:
                getattr(cls(), method)(tmp_path / "journal", ObservedPatch())
            assert caught.value is failure
        else:
            getattr(cls(), method)(tmp_path / "journal", ObservedPatch())
            assert any(op & fcntl.LOCK_EX for op in called)
        assert len(observed) == 1
        assert fcntl.flock is borrowed
    assert (fs_lock.fcntl, journal.fcntl, compact.fcntl) == bindings
    assert fs_lock.fcntl is bindings[0]
    assert fcntl.flock is borrowed
