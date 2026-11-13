from contextlib import contextmanager
from types import ModuleType
import threading
import pytest
import core.sandbox.tests.test_proxy_persist_snapshots as native
from core.testing.module_views import module_function_view

@contextmanager
def exercise(phase, tmp_path):
    real = threading.Thread
    threads = []
    error = KeyboardInterrupt if "interrupt" in phase else RuntimeError
    borrowed = native.summary._proxy_persist_state
    patch = pytest.MonkeyPatch()
    native.isolated_mirror.__wrapped__(patch)
    class Thread(real):
        def __init__(self, *args, **kwargs):
            target = kwargs["target"]
            self.native_target = target
            cells = dict(zip(target.__code__.co_freevars, (c.cell_contents for c in target.__closure__)))
            self.release, self.errors = cells["release"], cells["errors"]
            self.entered = threading.Event()
            self.completed, self.joins = False, []
            def running(*args, **kwargs):
                self.entered.set()
                result = target(*args, **kwargs)
                self.completed = True
                return result
            kwargs["target"] = running
            super().__init__(*args, **kwargs)
            threads.append(self)
        def start(self):
            if phase.startswith("before-"):
                raise error("owned start failure")
            super().start()
            if phase.startswith("after-"):
                assert self.entered.wait(5), "actual updater was not entered"
                raise error("owned start failure")
        def join(self, *args, **kwargs):
            self.joins.append((args, kwargs))
            assert native.summary._proxy_persist_state is not borrowed
            return super().join(*args, **kwargs)
    namespace = ModuleType("threading")
    vars(namespace).update(vars(threading))
    namespace.Thread = Thread
    function = native.test_snapshot_survives_an_update_from_another_thread
    view = module_function_view(native, bindings={"_owned_case": function, "threading": namespace})
    assert view._owned_case.__code__ is function.__code__
    try:
        yield lambda: view._owned_case(tmp_path), threads
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
    assert native.summary._proxy_persist_state is borrowed


@pytest.mark.parametrize("phase", ["normal", "before-error", "after-error", "before-interrupt", "after-interrupt"])
def test_proxy_updater_retires_before_mirror_restores(phase, tmp_path):
    original_thread = threading.Thread
    borrowed = native.summary._proxy_persist_state
    borrowed_items = list(borrowed.items())
    with exercise(phase, tmp_path) as (invoke, threads):
        if phase == "normal":
            invoke()
        else:
            error = KeyboardInterrupt if "interrupt" in phase else RuntimeError
            with pytest.raises(error, match="owned start failure"):
                invoke()
        assert len(threads) == 1
        thread = threads[0]
        assert not thread.is_alive()
        if phase.startswith("before-"):
            assert thread.ident is None
            assert not thread.completed and not thread.joins
            expected = {"expected_count": 1, "flags": ["first"]}
        else:
            assert thread.completed and thread.joins
            expected = {"expected_count": 2, "flags": ["first", "second"]}
        assert thread.release.is_set()
        assert not thread.errors
        assert native.summary.get_proxy_persist_state(tmp_path) == expected
        assert native.summary._proxy_persist_state is not borrowed
        assert thread.native_target.__code__.co_name == "update"
        assert threading.Thread is original_thread
    assert native.summary._proxy_persist_state is borrowed
    assert list(borrowed.items()) == borrowed_items
