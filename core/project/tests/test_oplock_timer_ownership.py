"""Native project-lock timers retire before their holder and fixture owners."""

import threading

import pytest

from core.project.tests import test_oplock as native
from core.testing.module_bindings import patch_module_attribute

CASES = [
    (native.OpLockPrimitiveTest, "test_release_within_grace_is_silent", 0.3),
    (native.OpLockPrimitiveTest, "test_wait_blocks_until_release", 0.5),
    (native.OpLockCliTest, "test_set_wait_queues_and_lands", 0.5),
]


@pytest.mark.parametrize("cls,name,interval", CASES)
@pytest.mark.parametrize("after,error", [(a, e) for a in (False, True)
                                         for e in (OSError, KeyboardInterrupt, SystemExit)]
                         + [(None, None)])
def test_native_timers_owned_before_start(
    cls, name, interval, after, error, monkeypatch,
):
    timers, joined, cancelled, callbacks = [], [], [], []
    entered, release = threading.Event(), threading.Event()
    failure = error("owned timer startup failure") if error else None

    class Timer(threading.Timer):
        def __init__(self, seconds, function, *a, **k):
            assert seconds == interval

            def invoke(*args, **kwargs):
                callbacks.append(self)
                return function(*args, **kwargs)

            super().__init__(seconds, invoke, *a, **k)
            timers.append(self)

        def run(self):
            if error:
                entered.set()
                assert release.wait(10), "owned timer safety release timed out"
            super().run()

        def start(self):
            if error and not after:
                raise failure
            super().start()
            if error:
                assert entered.wait(10)
                raise failure

        def cancel(self):
            cancelled.append(self)
            super().cancel()

        def join(self, timeout=None):
            joined.append(self)
            release.set()
            super().join(timeout)

    case = cls(name)
    with monkeypatch.context() as patch:
        patch_module_attribute(patch, native, "threading", "Timer", Timer)
        try:
            case.setUp()
            if error:
                with pytest.raises(error) as caught:
                    getattr(case, name)()
                assert caught.value is failure
            else:
                getattr(case, name)()
            assert len(timers) == 1
            assert not timers[0].is_alive()
            assert timers[0].finished.is_set()
            assert cancelled == timers
            assert joined == (timers if timers[0].ident is not None else [])
            assert callbacks == ([] if error else timers)
        finally:
            # Observe native cleanup above; this guard protects the suite if
            # the fixture regresses, before its native temp owners undo.
            for timer in timers:
                threading.Timer.cancel(timer)
            release.set()
            for timer in timers:
                if timer.ident is not None:
                    threading.Thread.join(timer, 10)
                    assert not timer.is_alive()
            case.doCleanups()
