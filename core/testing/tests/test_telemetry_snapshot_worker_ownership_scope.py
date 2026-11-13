import pytest
from contextlib import contextmanager
from types import ModuleType
import builtins
import shutil
import tempfile
import threading
import packages.fuzzing.tests.test_telemetry as native
from core.testing.module_views import module_function_view

@contextmanager
def exercise(phase, tmp_path):
    real = threading.Thread
    release = threading.Event()
    threads, exits = [], []
    error = KeyboardInterrupt if "interrupt" in phase else RuntimeError
    class Thread(real):
        def __init__(self, *args, **kwargs):
            target = kwargs["target"]
            self.native_target = target
            cells = dict(zip(target.__code__.co_freevars, (c.cell_contents for c in target.__closure__)))
            self.tel, self.stop = cells["tel"], cells["stop"]
            assert type(self.tel) is native.FuzzingTelemetry
            self.stream = self.tel._events_fp
            self.completed, self.joins = False, []
            def running(*args, **kwargs):
                assert release.wait(10), "owned worker gate not released"
                result = target(*args, **kwargs)
                self.completed = True
                return result
            kwargs["target"] = running
            super().__init__(*args, **kwargs)
            threads.append(self)
        def start(self):
            if phase.startswith("before-"):
                raise error("owned start failure")
            if phase == "normal" or phase.startswith("body-"):
                release.set()
            super().start()
            if phase.startswith("after-"):
                raise error("owned start failure")
        def join(self, *args, **kwargs):
            self.joins.append((args, kwargs))
            release.set()
            return super().join(*args, **kwargs)
    class Directory:
        def __init__(self, *args, **kwargs):
            kwargs["dir"] = tmp_path
            self.directory = tempfile.TemporaryDirectory(*args, **kwargs)
        def __enter__(self):
            return self.directory.__enter__()
        def __exit__(self, *args):
            exits.append([(thread.is_alive(), thread.stream.closed) for thread in threads])
            return self.directory.__exit__(*args)
    class Case(native.TestFuzzingTelemetry):
        def assertIsInstance(self, obj, cls, msg=None):
            if phase.startswith("body-"):
                raise error("owned snapshot assertion failure")
            return super().assertIsInstance(obj, cls, msg)
    namespace = ModuleType("threading")
    vars(namespace).update(vars(threading))
    namespace.Thread = Thread
    temp_namespace = ModuleType("tempfile")
    vars(temp_namespace).update(vars(tempfile))
    temp_namespace.TemporaryDirectory = Directory
    original_import = builtins.__import__
    def importer(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "threading" and level == 0:
            return namespace
        return original_import(name, globals, locals, fromlist, level)
    function = native.TestFuzzingTelemetry.test_thread_safe_snapshot
    view = module_function_view(native, bindings={"_owned_case": function, "tempfile": temp_namespace}, import_hook=importer)
    assert view._owned_case.__code__ is function.__code__
    try:
        yield lambda: view._owned_case(Case()), threads, exits
    finally:
        for thread in threads:
            thread.stop.set()
        release.set()
        for thread in threads:
            if thread.ident is not None:
                real.join(thread, timeout=2)
                assert not thread.is_alive()
            assert thread.tel.out_dir.resolve().is_relative_to(tmp_path.resolve())
            if thread.tel._events_fp is not None:
                thread.tel.stop()
            if thread.tel.out_dir.exists():
                shutil.rmtree(thread.tel.out_dir)


@pytest.mark.parametrize("phase", ["normal", "before-error", "after-error", "before-interrupt", "after-interrupt", "body-error", "body-interrupt"])
def test_snapshot_worker_and_stream_retire_before_directory(phase, tmp_path):
    original_thread = threading.Thread
    original_import = builtins.__import__
    original_directory = tempfile.TemporaryDirectory
    with exercise(phase, tmp_path) as (invoke, threads, exits):
        if phase == "normal":
            invoke()
        else:
            error = KeyboardInterrupt if "interrupt" in phase else RuntimeError
            message = "owned snapshot assertion failure" if phase.startswith("body-") else "owned start failure"
            with pytest.raises(error, match=message):
                invoke()
        assert len(threads) == 1
        thread = threads[0]
        assert not thread.is_alive()
        if phase.startswith("before-"):
            assert thread.ident is None
            assert not thread.completed and not thread.joins
        else:
            assert thread.completed and thread.joins
        assert thread.stop.is_set()
        assert thread.stream.closed
        assert thread.tel._events_fp is None
        assert exits == [[(False, True)]]
        assert not thread.tel.out_dir.exists()
        assert thread.native_target.__code__.co_name == "updater"
        assert threading.Thread is original_thread
        assert builtins.__import__ is original_import
        assert tempfile.TemporaryDirectory is original_directory
