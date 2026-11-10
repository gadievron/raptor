"""Run-contention timer is retired before its native fixture unwinds."""

import importlib
from pathlib import Path
import threading
from types import FunctionType, ModuleType

import pytest

from core.testing.sandbox_state_scope import isolated_sandbox_state

pytestmark = pytest.mark.slow


def _exercise(tmp_path, *, phase=None, error=None):
    native = importlib.import_module("core.run.tests.test_run_contention")
    case = native.StartRunGateTest("test_wait_queues_until_holder_finishes")
    resources, joined, joined_while_owned, callbacks, reached = [], [], [], [], []
    failure = error("owned timer boundary failure") if error else None

    class Timer(threading.Timer):
        def __init__(self, interval, function, *args, **kwargs):
            def callback():
                callbacks.append(Path(case._tmp.name).is_dir())
                function()
            super().__init__(interval, callback, *args, **kwargs)
            assert interval == .5
            self.gate, self.entered = threading.Event(), threading.Event()
            resources.append(self)

        def run(self):
            # Model a started thread paused before it enters Timer.run.
            # Cancellation retains native finished-event semantics; joining
            # releases the scheduling pause and observes actual termination.
            self.entered.set()
            if phase in ("after_start", "body"):
                self.gate.wait()
            super().run()

        def start(self):
            if phase == "before_start":
                reached.append(phase)
                raise failure
            super().start()
            assert self.entered.wait(5)
            if phase == "after_start":
                reached.append(phase)
                raise failure

        def cancel(self):
            result = super().cancel()
            if phase == "cancel":
                reached.append(phase)
                raise failure
            return result

        def join(self, timeout=None):
            joined_while_owned.append(Path(case._tmp.name).is_dir())
            self.gate.set()
            super().join(timeout)
            joined.append(self)
            if phase == "join":
                reached.append(phase)
                raise failure

    view = ModuleType("threading")
    vars(view).update(vars(threading))
    view.Timer = Timer

    def refuse_body(*args, **kwargs):
        reached.append("body")
        raise failure

    original = case.test_wait_queues_until_holder_finishes.__func__
    namespace = dict(vars(native), threading=view)
    if phase == "body":
        namespace["start_run"] = refuse_body
    invoke = FunctionType(original.__code__, namespace, original.__name__,
                          original.__defaults__, original.__closure__)
    state = native._user_state_in_tmp.__wrapped__(tmp_path)
    with isolated_sandbox_state(()):
        next(state)
        try:
            case.setUp()
            if error:
                with pytest.raises(error) as caught:
                    invoke(case)
                assert caught.value is failure and reached == [phase]
            else:
                invoke(case)
                assert not reached
            assert len(resources) == 1 and resources[0].interval == .5
            timer = resources[0]
            assert not timer.is_alive()
            if phase == "before_start":
                assert timer.ident is None and not joined
            else:
                assert joined == [timer] and joined_while_owned == [True]
            assert callbacks == ([True] if phase in (None, "cancel", "join") else [])
            assert native.StartRunGateTest.test_wait_queues_until_holder_finishes is original
        finally:
            # Independent containment never calls a faulting cancel/join
            # override, and never releases an uncancelled delayed callback.
            for timer in resources:
                threading.Timer.cancel(timer)
                timer.gate.set()
                if timer.ident is not None:
                    threading.Thread.join(timer, 5)
                assert not timer.is_alive()
            case.doCleanups()
            state.close()


@pytest.mark.parametrize("phase", ["before_start", "after_start", "body", "cancel", "join"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
def test_timer_boundary_error_retires_before_native_cleanup(phase, error, tmp_path):
    _exercise(tmp_path, phase=phase, error=error)


def test_real_native_timer_finishes_holder_before_scope_exit(tmp_path):
    _exercise(tmp_path)
