"""Native checkpoint appender retirement across actual caller boundaries."""
from types import FunctionType, ModuleType
import threading

import pytest

from core.coverage.tests import test_journal_checkpoint as native
from core.testing.state_isolation import pin_user_state_dirs


def _exercise(tmp_path, monkeypatch, operation, error, after):
    pin_user_state_dirs(monkeypatch, tmp_path / "user")
    workers, events = [], []
    main = threading.current_thread()
    failure = error("owned checkpoint boundary fault") if error else None
    fired = False
    original = native.TestForeignAppenderAcrossCheckpoint.test_appender_blocked_across_swap_lands_in_live_journal
    native_thread = threading.Thread

    class Event(threading.Event):
        def wait(self, *args, **kwargs):
            nonlocal fired
            if operation == "wait" and self is events[0] and threading.current_thread() is main and not fired:
                fired = True
                if after:
                    assert super().wait(*args, **kwargs), "native flock gate not reached"
                raise failure
            return super().wait(*args, **kwargs)

    class Worker(native_thread):
        def start(self):
            nonlocal fired
            if operation == "start" and not fired:
                fired = True
                if after:
                    super().start()
                raise failure
            return super().start()

        def join(self, *args, **kwargs):
            nonlocal fired
            if operation == "join" and not fired:
                fired = True
                if after:
                    super().join(*args, **kwargs)
                raise failure
            return super().join(*args, **kwargs)

    def event():
        value = Event()
        events.append(value)
        return value

    def thread(*args, **kwargs):
        worker = Worker(*args, **kwargs)
        workers.append(worker)
        return worker

    private = ModuleType("threading")
    vars(private).update(vars(threading))
    private.Event, private.Thread = event, thread
    body = FunctionType(original.__code__, {**original.__globals__, "threading": private})
    try:
        if error:
            with pytest.raises(error) as caught:
                body(native.TestForeignAppenderAcrossCheckpoint(), tmp_path / "journal", monkeypatch)
            assert caught.value is failure
            assert fired
        else:
            body(native.TestForeignAppenderAcrossCheckpoint(), tmp_path / "journal", monkeypatch)
        assert len(events) == 2 and len(workers) == 1
        assert events[1].is_set()
        assert not workers[0].is_alive()
        if operation == "start" and not after:
            assert workers[0].ident is None
        else:
            assert workers[0].ident is not None
        assert threading.Thread is native_thread
        assert native.TestForeignAppenderAcrossCheckpoint.test_appender_blocked_across_swap_lands_in_live_journal is original
    finally:
        if len(events) > 1:
            events[1].set()
        for worker in workers:
            if worker.ident is not None:
                native_thread.join(worker, timeout=30)
                assert not worker.is_alive()


@pytest.mark.parametrize("operation", ["start", "wait", "join"])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("after", [False, True])
def test_appender_retires_on_caller_fault(tmp_path, monkeypatch, operation, error, after):
    _exercise(tmp_path, monkeypatch, operation, error, after)


def test_native_appender_positive_control(tmp_path, monkeypatch):
    _exercise(tmp_path, monkeypatch, None, None, False)
