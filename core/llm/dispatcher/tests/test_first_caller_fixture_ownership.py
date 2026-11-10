"""Native first-caller fixture ownership across caller startup and joins."""

import atexit
import builtins
import importlib
import os
import threading
from types import FunctionType, ModuleType

import pytest

from core.testing.module_bindings import patch_module_attribute


@pytest.mark.parametrize(
    "operation,after,position,error",
    [("start", after, position, error)
     for after in (False, True) for position in (1, 2)
     for error in (OSError, KeyboardInterrupt, SystemExit)]
    + [("join", after, position, OSError)
       for after in (False, True) for position in (1, 2)]
    + [(None, False, 1, OSError)],
)
def test_native_first_callers_retire_before_patch_restoration(
    monkeypatch, operation, after, position, error,
):
    native = importlib.import_module("core.llm.dispatcher.tests.test_lifecycle")
    lifecycle = importlib.import_module("core.llm.dispatcher.lifecycle")
    workers, callbacks, owners, removed = [], [], [], []
    failure = error("owned caller boundary failure")
    fired = False

    class Worker(threading.Thread):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            workers.append(self)

        def boundary(self, name, action):
            nonlocal fired
            selected = operation == name and self is workers[position - 1] and not fired
            if selected:
                fired = True
                if not after:
                    raise failure
            action()
            if selected:
                raise failure

        def start(self):
            self.boundary("start", lambda: threading.Thread.start(self))

        def join(self, timeout=None):
            self.boundary("join", lambda: threading.Thread.join(self, timeout))

    private = ModuleType("threading")
    vars(private).update(vars(threading))
    private.Thread = Worker

    def importing(name, *args, **kwargs):
        if name == "threading":
            return private
        return builtins.__import__(name, *args, **kwargs)

    original = native.TestConcurrentFirstCallers.test_concurrent_first_callers_construct_one_dispatcher
    namespace = dict(vars(native), __builtins__=dict(vars(builtins), __import__=importing))
    invoke = FunctionType(original.__code__, namespace, original.__name__,
                          original.__defaults__, original.__closure__)

    def register(callback, *args, **kwargs):
        callbacks.append(callback)
        owners.append(callback.__self__)
        return atexit.register(callback, *args, **kwargs)

    def unregister(callback):
        removed.append(callback)
        return atexit.unregister(callback)

    fields = ("RAPTOR_LLM_SOCKET", "RAPTOR_LLM_TOKEN_FD")
    borrowed = {key: os.environ.get(key) for key in fields}
    borrowed_atexit = lifecycle.atexit
    with monkeypatch.context() as patch:
        patch_module_attribute(patch, lifecycle, "atexit", "register", register)
        patch_module_attribute(patch, lifecycle, "atexit", "unregister", unregister)
        try:
            if operation is None:
                invoke(native.TestConcurrentFirstCallers(), monkeypatch=patch)
            else:
                with pytest.raises(error) as caught:
                    invoke(native.TestConcurrentFirstCallers(), monkeypatch=patch)
                assert caught.value is failure
                assert fired
            assert len(workers) == 2
            assert all(not worker.is_alive() for worker in workers)
            assert all(owner._shutdown_done and not owner._thread.is_alive() for owner in owners)
            assert removed == callbacks
            assert all(key not in os.environ for key in fields)
            if operation is None:
                assert len(owners) == 1
        finally:
            # An external safety guard prevents a broken fixture from leaking
            # into another test, but assertions above observe native cleanup.
            for worker in workers:
                if worker.ident is not None:
                    threading.Thread.join(worker, 10)
                    assert not worker.is_alive()
            for owner in owners:
                owner.shutdown()
            for callback in callbacks:
                atexit.unregister(callback)
            for key in fields:
                os.environ.pop(key, None)
    assert lifecycle.atexit is borrowed_atexit
    assert {key: os.environ.get(key) for key in fields} == borrowed
