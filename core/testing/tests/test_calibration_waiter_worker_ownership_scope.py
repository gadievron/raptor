from contextlib import contextmanager
from types import ModuleType
import threading
import pytest
import core.sandbox.tests.test_calibration_cache_identity as native
from core.testing.module_views import module_function_view

@contextmanager
def exercise(phase, tmp_path):
    real = threading.Thread
    threads = []
    error = KeyboardInterrupt if "interrupt" in phase else RuntimeError
    borrowed = (native.memo._CACHE, native.cal._CACHE_DIR, native.cal.load_or_calibrate)
    patch = pytest.MonkeyPatch()
    native.isolated_cache.__wrapped__(tmp_path, patch)
    binary = native.binary.__wrapped__(tmp_path)
    class Thread(real):
        def __init__(self, *args, **kwargs):
            target = kwargs["target"]
            self.native_target = target
            state = dict(zip(target.__code__.co_freevars, (c.cell_contents for c in target.__closure__)))
            self.errors = state["errors"]
            self.loader = native.cal.load_or_calibrate
            cells = dict(zip(self.loader.__code__.co_freevars, (c.cell_contents for c in self.loader.__closure__)))
            self.started, self.release, self.profile = cells["started"], cells["release"], cells["profile"]
            self.results = kwargs["args"][0]
            self.timeout = kwargs["args"][1]
            self.completed, self.joins = False, []
            def running(*args, **kwargs):
                result = target(*args, **kwargs)
                self.completed = True
                return result
            kwargs["target"] = running
            super().__init__(*args, **kwargs)
            threads.append(self)
        def start(self):
            if self.timeout == 20 and phase.startswith("before-"):
                raise error("owned start failure")
            super().start()
            if self.timeout == 20 and phase.startswith("after-"):
                assert self.started.wait(5), "actual local loader was not entered"
                raise error("owned start failure")
        def join(self, *args, **kwargs):
            self.joins.append((args, kwargs))
            assert native.cal.load_or_calibrate is self.loader
            return super().join(*args, **kwargs)
    namespace = ModuleType("threading")
    vars(namespace).update(vars(threading))
    namespace.Thread = Thread
    function = native.test_waiter_timeout_does_not_cancel_or_replace_owner
    view = module_function_view(native, bindings={"_owned_case": function, "threading": namespace})
    assert view._owned_case.__code__ is function.__code__
    try:
        yield lambda: view._owned_case(patch, binary), threads
    finally:
        try:
            for thread in threads:
                thread.release.set()
            for thread in threads:
                if thread.ident is not None:
                    real.join(thread, timeout=5)
                    assert not thread.is_alive()
        finally:
            patch.undo()
    assert native.memo._CACHE is borrowed[0]
    assert native.cal._CACHE_DIR is borrowed[1]
    assert native.cal.load_or_calibrate is borrowed[2]


@pytest.mark.parametrize("phase", ["normal", "before-error", "after-error", "before-interrupt", "after-interrupt"])
def test_cache_owner_retires_before_loader_and_cache_restore(phase, tmp_path):
    original_thread = threading.Thread
    borrowed_cache = native.memo._CACHE
    borrowed_directory = native.cal._CACHE_DIR
    borrowed_loader = native.cal.load_or_calibrate
    with exercise(phase, tmp_path) as (invoke, threads):
        if phase == "normal":
            invoke()
        else:
            error = KeyboardInterrupt if "interrupt" in phase else RuntimeError
            with pytest.raises(error, match="owned start failure"):
                invoke()
        assert len(threads) == 2
        assert [thread.timeout for thread in threads] == [20, 0]
        started = [thread for thread in threads if thread.ident is not None]
        expected = 2 if phase == "normal" else (0 if phase.startswith("before-") else 1)
        assert len(started) == expected
        assert all(not thread.is_alive() for thread in threads)
        assert all(thread.completed and thread.joins for thread in started)
        assert all(not thread.completed and not thread.joins for thread in threads if thread.ident is None)
        assert not threads[0].errors
        assert threads[0].release.is_set()
        assert threads[0].results == ([threads[0].profile] if expected else [])
        assert threads[1].results == ([None] if phase == "normal" else [])
        assert native.memo._CACHE is not borrowed_cache
        assert native.cal._CACHE_DIR == tmp_path / "profiles"
        assert native.cal.load_or_calibrate is threads[0].loader
        assert threading.Thread is original_thread
    assert native.memo._CACHE is borrowed_cache
    assert native.cal._CACHE_DIR is borrowed_directory
    assert native.cal.load_or_calibrate is borrowed_loader
