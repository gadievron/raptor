"""Test backstops retain borrowed handlers, intervals and earlier deadlines."""

import ast
from contextlib import contextmanager
import os
from pathlib import Path
import signal
import time

import pytest

from core.testing import signals as module


class DefaultSignal(BaseException):
    pass


class Kernel:
    SIGALRM = signal.SIGALRM if hasattr(signal, "SIGALRM") else 14
    SIG_DFL, SIG_IGN, ITIMER_REAL = 0, 1, 0

    def __init__(self):
        self.now, self.due, self.interval = 100.0, None, 0
        self.handler = self.SIG_DFL

    def getsignal(self, number):
        assert number == self.SIGALRM
        return self.handler

    def signal(self, number, handler):
        previous = self.getsignal(number)
        self.handler = handler
        return previous

    def getitimer(self, kind):
        assert kind == self.ITIMER_REAL
        return (max(0, self.due - self.now) if self.due is not None else 0, self.interval)

    def setitimer(self, kind, delay, interval=0):
        previous = self.getitimer(kind)
        self.due = self.now + delay if delay else None
        self.interval = interval
        return previous

    def raise_signal(self, number):
        assert number == self.SIGALRM
        raise DefaultSignal()

    def advance(self, seconds):
        end = self.now + seconds
        while self.due is not None and self.due <= end:
            self.now = self.due
            self.due = self.due + self.interval if self.interval else None
            self.handler(self.SIGALRM, None)
        self.now = end


@pytest.fixture
def kernel(monkeypatch):
    from types import SimpleNamespace

    kernel = Kernel()
    monkeypatch.setattr(module, "signal", kernel)
    monkeypatch.setattr(module, "time", SimpleNamespace(monotonic=lambda: kernel.now))
    return kernel


@pytest.mark.parametrize("finish", ["normal", "error", "interrupt", "close"])
@pytest.mark.parametrize("delay,interval", [(0, 0), (20, 0), (20, 3), (0, 3)])
def test_scope_retains_borrowed_state_and_elapsed_budget(kernel, finish, delay, interval):
    borrowed = lambda *args: None
    kernel.handler = borrowed
    kernel.setitimer(kernel.ITIMER_REAL, delay, interval)
    context = module.alarm_after(10, lambda *args: None)
    context.__enter__()
    kernel.advance(2)
    if finish == "normal":
        context.__exit__(None, None, None)
    elif finish == "close":
        context.gen.close()
    else:
        failure = RuntimeError("body failed") if finish == "error" else KeyboardInterrupt("body interrupted")
        with pytest.raises(type(failure)) as caught:
            context.gen.throw(failure)
        assert caught.value is failure
    assert kernel.handler is borrowed
    assert kernel.getitimer(kernel.ITIMER_REAL) == (delay - 2 if delay else 0, interval)


@pytest.mark.parametrize("interval", [0, 2])
def test_earlier_borrowed_handler_is_not_delayed_or_resurrected(kernel, interval):
    calls = []
    borrowed = lambda *args: calls.append(("borrowed", kernel.now))
    kernel.handler = borrowed
    kernel.setitimer(kernel.ITIMER_REAL, 1, interval)
    with module.alarm_after(5, lambda *args: calls.append(("owned", kernel.now))):
        kernel.advance(5.25)
    assert calls[0] == ("borrowed", 101)
    assert sum(name == "borrowed" for name, _ in calls) == (3 if interval else 1)
    assert len([name for name, _ in calls if name == "owned"]) == 1
    assert 105 <= next(when for name, when in calls if name == "owned") < 105.25
    # A tie is dispatched to the borrowed timer first; the owned timer stays due.
    if interval:
        assert kernel.getitimer(kernel.ITIMER_REAL) == (1.75, 2)
    else:
        assert calls[-1] == ("owned", 105)
        assert kernel.getitimer(kernel.ITIMER_REAL) == (0, 0)
    assert kernel.handler is borrowed


@pytest.mark.parametrize("handler", [0, 1])
def test_borrowed_default_and_ignored_dispositions_remain_meaningful(kernel, handler):
    kernel.handler = handler
    kernel.setitimer(kernel.ITIMER_REAL, 1)
    if handler == kernel.SIG_DFL:
        with pytest.raises(DefaultSignal):
            with module.alarm_after(5, lambda *args: None):
                kernel.advance(1)
    else:
        with module.alarm_after(5, lambda *args: None):
            kernel.advance(1)
    assert kernel.handler == handler
    assert kernel.getitimer(kernel.ITIMER_REAL) == (0, 0)


@pytest.mark.parametrize("borrowed_first", [False, True])
def test_handler_exception_identity_and_timer_retirement(kernel, borrowed_first):
    failure = KeyboardInterrupt("deadline fired")

    def raises(*args):
        raise failure

    borrowed = raises if borrowed_first else lambda *args: None
    kernel.handler = borrowed
    kernel.setitimer(kernel.ITIMER_REAL, 1 if borrowed_first else 20)
    with pytest.raises(KeyboardInterrupt) as caught:
        with module.alarm_after(5, raises):
            kernel.advance(5)
    assert caught.value is failure
    assert kernel.handler is borrowed
    assert kernel.getitimer(kernel.ITIMER_REAL) == ((0, 0) if borrowed_first else (15, 0))


@pytest.mark.parametrize("inner_first", [False, True])
def test_nested_owners_keep_outer_deadline_and_periodic_caller(kernel, inner_first):
    calls = []
    borrowed = lambda *args: calls.append(("borrowed", kernel.now))
    kernel.handler = borrowed
    kernel.setitimer(kernel.ITIMER_REAL, 1, 2)
    with module.alarm_after(4, lambda *args: calls.append(("outer", kernel.now))):
        with module.alarm_after(2 if inner_first else 8, lambda *args: calls.append(("inner", kernel.now))):
            kernel.advance(5)
        kernel.advance(1)
    assert [(name, when) for name, when in calls if name == "outer"] == [("outer", 104)]
    assert [(name, when) for name, when in calls if name == "inner"] == ([("inner", 102)] if inner_first else [])
    assert [when for name, when in calls if name == "borrowed"] == [101, 103, 105]
    assert kernel.handler is borrowed
    assert kernel.getitimer(kernel.ITIMER_REAL) == (1, 2)


@pytest.mark.parametrize("seconds", [0, -1])
def test_invalid_duration_does_not_mutate_borrowed_state(kernel, seconds):
    borrowed = kernel.handler
    with pytest.raises(ValueError):
        with module.alarm_after(seconds, lambda *args: None):
            pass
    assert kernel.handler is borrowed
    assert kernel.getitimer(kernel.ITIMER_REAL) == (0, 0)


@pytest.mark.parametrize("operation", ["signal", "setitimer"])
@pytest.mark.parametrize("after_effect", [False, True])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_setup_failure_restores_handler_and_timer(kernel, operation, after_effect, error, monkeypatch):
    borrowed = lambda *args: None
    kernel.handler = borrowed
    kernel.setitimer(kernel.ITIMER_REAL, 20, 3)
    raw = getattr(kernel, operation)
    failure = error("alarm setup interrupted")
    failed = False

    def injected(*args):
        nonlocal failed
        selected = (callable(args[1]) and args[1] is not borrowed if operation == "signal"
                    else args[1] == 10)
        if selected and not failed:
            failed = True
            if after_effect:
                raw(*args)
            raise failure
        return raw(*args)

    monkeypatch.setattr(kernel, operation, injected)
    with pytest.raises(error) as caught:
        with module.alarm_after(10, lambda *args: None):
            pytest.fail("setup failure must not enter the consumer")
    assert caught.value is failure
    assert kernel.handler is borrowed
    assert kernel.getitimer(kernel.ITIMER_REAL) == (20, 3)


def test_overdue_borrowed_deadline_stays_due_after_scope(kernel):
    calls = []
    borrowed = lambda *args: calls.append("borrowed")
    kernel.handler = borrowed
    kernel.setitimer(kernel.ITIMER_REAL, 1)
    with module.alarm_after(10, lambda *args: calls.append("owned")):
        # Model a pending signal whose Python handler has not run yet.
        kernel.now += 2
    assert kernel.handler is borrowed
    kernel.advance(0.01)
    assert calls == ["borrowed"]


@contextmanager
def _real_timer_guard():
    handler = signal.getsignal(signal.SIGALRM)
    delay, interval = signal.getitimer(signal.ITIMER_REAL)
    started = time.monotonic()
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, handler)
        remaining = max(1e-6, delay - (time.monotonic() - started)) if delay else 0
        signal.setitimer(signal.ITIMER_REAL, remaining, interval)


@pytest.mark.skipif(not hasattr(signal, "setitimer"), reason="POSIX real-time interval timers")
@pytest.mark.parametrize("borrowed_first", [False, True])
def test_native_deadline_calls_the_correct_owner_and_restores_timer(borrowed_first):
    failure = LookupError("native deadline fired")

    def raises(*args):
        raise failure

    with _real_timer_guard():
        borrowed = raises if borrowed_first else lambda *args: None
        signal.signal(signal.SIGALRM, borrowed)
        signal.setitimer(signal.ITIMER_REAL, 0.02 if borrowed_first else 120, 11)
        with pytest.raises(LookupError) as caught:
            with module.alarm_after(1 if borrowed_first else 0.02, raises):
                signal.pause()
        assert caught.value is failure
        assert signal.getsignal(signal.SIGALRM) is borrowed
        remaining, interval = signal.getitimer(signal.ITIMER_REAL)
        assert 0 < remaining <= (11 if borrowed_first else 120)
        assert interval == 11


@pytest.mark.skipif(not hasattr(os, "mkfifo") or not hasattr(signal, "setitimer"), reason="POSIX FIFO and timers")
def test_actual_fifo_case_keeps_borrowed_timer(tmp_path):
    from core.run.tmp_ownership import OWNER_MARKER_NAME

    root = Path(__file__).resolve().parents[3]
    path = root / "core/run/tests/test_tmp_ownership.py"
    tree = ast.parse(path.read_text())
    cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "TestOwnerPidGatedRead")
    method = next(node for node in cls.body if getattr(node, "name", None) == "test_fifo_marker_none_not_hung")
    namespace = dict(os=os, pytest=pytest, Path=Path, OWNER_MARKER_NAME=OWNER_MARKER_NAME)
    exec(compile(ast.Module(body=[method], type_ignores=[]), str(path), "exec"), namespace)
    with _real_timer_guard():
        borrowed = lambda *args: None
        signal.signal(signal.SIGALRM, borrowed)
        signal.setitimer(signal.ITIMER_REAL, 120, 11)
        namespace["test_fifo_marker_none_not_hung"](None, tmp_path)
        assert signal.getsignal(signal.SIGALRM) is borrowed
        remaining, interval = signal.getitimer(signal.ITIMER_REAL)
        assert 0 < remaining <= 120
        assert interval == 11
