import json
import pytest
from contextlib import contextmanager
import builtins
import threading
from types import ModuleType
import packages.sca.supply_chain.tests.test_typosquat_triage as native
from core.testing.module_views import module_function_view

@contextmanager
def exercise(phase, tmp_path):
    real = threading.Thread
    release = threading.Event()
    threads = []
    error = KeyboardInterrupt if 'interrupt' in phase else RuntimeError
    class Thread(real):
        def __init__(self, *args, **kwargs):
            target = kwargs['target']
            self.native_target = target
            cells = dict(zip(target.__code__.co_freevars, (c.cell_contents for c in target.__closure__)))
            self.path = cells['rl']
            assert self.path == tmp_path / "reviewed_legit.json"
            self.completed = False
            def running(*args, **kwargs):
                assert release.wait(10), 'owned worker gate not released'
                result = target(*args, **kwargs)
                self.completed = True
                return result
            kwargs['target'] = running
            self.index, self.joins = len(threads), []
            super().__init__(*args, **kwargs)
            threads.append(self)
        def start(self):
            if self.index == 0 and phase.startswith('before-'):
                raise error('owned start failure')
            if phase == 'normal':
                release.set()
            super().start()
            if self.index == 0 and phase.startswith('after-'):
                raise error('owned start failure')
        def join(self, *args, **kwargs):
            self.joins.append((args, kwargs))
            release.set()
            return super().join(*args, **kwargs)
    namespace = ModuleType('threading')
    vars(namespace).update(vars(threading))
    namespace.Thread = Thread
    original_import = builtins.__import__
    def importer(name, globals=None, locals=None, fromlist=(), level=0):
        if name == 'threading' and level == 0:
            return namespace
        return original_import(name, globals, locals, fromlist, level)
    function = native.test_apply_auto_legit_concurrent_writers_lose_nothing
    view = module_function_view(native, bindings={'_owned_case': function}, import_hook=importer)
    assert view._owned_case.__code__ is function.__code__
    try:
        yield lambda: view._owned_case(tmp_path), threads
    finally:
        release.set()
        for thread in threads:
            if thread.ident is not None:
                real.join(thread, timeout=30)
                assert not thread.is_alive()


@pytest.mark.parametrize("phase", ["normal", "before-error", "after-error", "before-interrupt", "after-interrupt"])
def test_typosquat_writers_retire_before_artifact_scope_exit(phase, tmp_path):
    original_thread = threading.Thread
    original_import = builtins.__import__
    with exercise(phase, tmp_path) as (invoke, threads):
        if phase == "normal":
            invoke()
        else:
            error = KeyboardInterrupt if "interrupt" in phase else RuntimeError
            with pytest.raises(error, match="owned start failure"):
                invoke()
        assert len(threads) == 16
        started = [thread for thread in threads if thread.ident is not None]
        expected = 16 if phase == "normal" else (0 if phase.startswith("before-") else 1)
        assert len(started) == expected
        assert all(not thread.is_alive() for thread in threads)
        assert all(thread.completed and thread.joins for thread in started)
        assert all(not thread.completed and not thread.joins for thread in threads if thread.ident is None)
        path = tmp_path / "reviewed_legit.json"
        if expected:
            data = json.loads(path.read_text(encoding="utf-8"))
            assert set(data["npm"]) == {f"legitpkg{i}" for i in range(expected)}
        else:
            assert not path.exists()
        assert all(thread.native_target.__code__.co_name == "_file" for thread in threads)
        assert threading.Thread is original_thread
        assert builtins.__import__ is original_import
