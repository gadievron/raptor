"""Actual FIFO watchdog with a private blocking-open regression seam."""

import builtins
from contextlib import contextmanager
from types import ModuleType
import stat
import threading
from core.coverage import store_summary as producer
from core.coverage.tests import test_reader_budgets as native
from core.coverage.tests.test_reader_fd_discipline import _retiring_fifo_thread
from core.testing.module_views import module_function_view

@contextmanager
def exercise(phase, tmp_path):
    workers, done = [], []
    opening = threading.Event()
    real = threading.Thread
    error = KeyboardInterrupt if "interrupt" in phase else RuntimeError
    fifo = tmp_path / "coverage-progress.jsonl"
    borrowed = native.format_progress_trend
    source = ModuleType("core.source")
    def blocking_open(path, mode):
        assert path == fifo and mode == "rb"
        assert stat.S_ISFIFO(path.lstat().st_mode)
        opening.set()
        return builtins.open(path, mode)
    source.open_regular = blocking_open
    def producer_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "core.source":
            return source
        return builtins.__import__(name, globals, locals, fromlist, level)
    view = module_function_view(producer, import_hook=producer_import)
    class Thread(real):
        def __init__(self, *args, **kwargs):
            target = kwargs["target"]
            cells = dict(zip(target.__code__.co_freevars, (c.cell_contents for c in target.__closure__)))
            done.append(cells["done"])
            self.joins = []
            super().__init__(*args, **kwargs)
            workers.append(self)
        def start(self):
            if phase.startswith("before-"):
                raise error("owned start failure")
            super().start()
            if phase.startswith("after-"):
                assert opening.wait(2), "actual FIFO blocking-open seam not reached"
                raise error("owned start failure")
        def join(self, *args, **kwargs):
            self.joins.append((args, kwargs))
            return super().join(*args, **kwargs)
    threads = ModuleType("threading")
    vars(threads).update(vars(threading))
    threads.Thread = Thread
    def native_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "threading":
            return threads
        return builtins.__import__(name, globals, locals, fromlist, level)
    function = native.TestProgressTrend.test_fifo_trail_refused_without_blocking
    function_view = module_function_view(native, bindings={"_owned_case": function, "format_progress_trend": borrowed if phase == "normal" else view.format_progress_trend}, import_hook=native_import)
    assert function_view._owned_case.__code__ is function.__code__
    try:
        yield lambda: function_view._owned_case(native.TestProgressTrend(), tmp_path), workers, done, opening
    finally:
        for worker, finished in zip(workers, done):
            with _retiring_fifo_thread(worker, finished, fifo, writer=False):
                pass
            assert not worker.is_alive()
    assert native.format_progress_trend is borrowed
    assert threading.Thread is real
