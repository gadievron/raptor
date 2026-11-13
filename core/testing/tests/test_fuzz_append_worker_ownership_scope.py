import pytest
from contextlib import contextmanager
import builtins
import threading
from types import ModuleType
import packages.binary_analysis.tests.test_artifact_lock as native
from core.testing.module_views import module_function_view

@contextmanager
def exercise(phase, tmp_path):
    patch = pytest.MonkeyPatch()
    borrowed_load = native.pipeline.load_json
    real = threading.Thread
    release = threading.Event()
    threads = []
    error = KeyboardInterrupt if 'interrupt' in phase else RuntimeError
    class Thread(real):
        def __init__(self, *args, **kwargs):
            target = kwargs['target']
            self.native_target = target
            cells = dict(zip(target.__code__.co_freevars, (c.cell_contents for c in target.__closure__)))
            self.path = cells['tmp_path']
            self.errors = cells['errs']
            assert self.path == tmp_path
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
    function = native.TestConcurrentFuzzAppend.test_concurrent_appends_keep_both_evidence_records
    view = module_function_view(native, bindings={'_owned_case': function, 'threading': namespace}, import_hook=importer)
    assert view._owned_case.__code__ is function.__code__
    try:
        yield lambda: view._owned_case(native.TestConcurrentFuzzAppend(), tmp_path, patch), threads
    finally:
        release.set()
        for thread in threads:
            if thread.ident is not None:
                real.join(thread, timeout=30)
                assert not thread.is_alive()
        patch.undo()
        assert native.pipeline.load_json is borrowed_load


@pytest.mark.parametrize("phase", ["normal", "before-error", "after-error", "before-interrupt", "after-interrupt"])
def test_append_workers_retire_before_load_binding_restores(phase, tmp_path):
    original_thread = threading.Thread
    original_import = builtins.__import__
    original_load = native.pipeline.load_json
    with exercise(phase, tmp_path) as (invoke, threads):
        if phase == "normal":
            invoke()
        else:
            error = KeyboardInterrupt if "interrupt" in phase else RuntimeError
            with pytest.raises(error, match="owned start failure"):
                invoke()
        assert len(threads) == 2
        started = [thread for thread in threads if thread.ident is not None]
        expected = 2 if phase == "normal" else (0 if phase.startswith("before-") else 1)
        assert len(started) == expected
        assert all(not thread.is_alive() for thread in threads)
        assert all(thread.completed and thread.joins for thread in started)
        assert all(not thread.completed and not thread.joins for thread in threads if thread.ident is None)
        assert not threads[0].errors
        payload = native.load_json(tmp_path / "binary-evidence.json")
        tools = sorted(item["tool"] for item in payload["evidence"])
        expected_tools = ["afl-A", "afl-B"] if expected == 2 else (["afl-A"] if expected else [])
        assert tools == expected_tools
        assert native.pipeline.load_json is not original_load
        assert all(thread.native_target.__code__.co_name == "worker" for thread in threads)
        assert threading.Thread is original_thread
        assert builtins.__import__ is original_import
    assert native.pipeline.load_json is original_load
