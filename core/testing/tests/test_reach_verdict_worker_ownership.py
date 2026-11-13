"""Counter workers retire before the source-backed accumulator owner restores."""

from contextlib import contextmanager
import os
import threading
from types import ModuleType

import pytest

from core.testing.tests._reach_verdict_workers import load_worker_module


def _exercise(stage, error, position, after, tmp_path):
    failure = error("owned verdict worker lifecycle fault") if error else None
    release = threading.Event()
    workers = []
    fired = []
    joins = []

    class Worker(threading.Thread):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.ready = threading.Event()
            self.position = len(workers)
            workers.append(self)

        def run(self):
            self.ready.set()
            assert release.wait(10), "owned worker gate was not released"
            super().run()

        def start(self):
            selected = stage == "start" and self.position == position and not fired
            if selected and not after:
                fired.append(True)
                raise failure
            super().start()
            if selected:
                assert self.ready.wait(5), "owned worker did not enter its startup gate"
                fired.append(True)
                raise failure

        def join(self, timeout=None):
            selected = stage == "join" and self.position == position and not fired
            if selected and not after:
                assert all(worker.ready.wait(5) for worker in workers if worker.ident is not None)
                fired.append(True)
                raise failure
            release.set()
            result = super().join(timeout=timeout)
            joins.append(self.position)
            if selected:
                fired.append(True)
                raise failure
            return result

    thread_view = ModuleType("threading")
    vars(thread_view).update(vars(threading))
    thread_view.Thread = Worker
    payload = {"preserved": 7}
    borrowed = {"borrowed": payload}
    native = load_worker_module(thread_view, borrowed)
    owner = native.reach_verdict_log
    lock = owner._LOCK
    before_env = {key: os.environ.get(key) for key in
                  ("RAPTOR_REACH_VERDICT_LOG", "RAPTOR_REACH_VERDICT_LOG_DISABLED")}
    with pytest.MonkeyPatch.context() as patch:
        try:
            with contextmanager(native._isolated_sidecar)(tmp_path, patch) as sidecar:
                active = owner._IN_MEMORY
                assert active is not borrowed and not active
                if error:
                    with pytest.raises(error) as caught:
                        native.test_concurrent_record_threadsafe(sidecar)
                    assert caught.value is failure and fired == [True]
                else:
                    native.test_concurrent_record_threadsafe(sidecar)
                    assert not fired
                assert len(workers) == 8 and all(not worker.is_alive() for worker in workers)
                started = [worker.position for worker in workers if worker.ident is not None]
                assert set(joins) == set(started)
                expected = (position + int(after)) * 100 if stage == "start" else 800
                assert active.get("python", {}).get("reachable", 0) == expected
                assert owner._IN_MEMORY is active and owner._LOCK is lock
                assert not sidecar.exists()
            assert owner._IN_MEMORY is borrowed and owner._LOCK is lock
            assert borrowed == {"borrowed": {"preserved": 7}} and borrowed["borrowed"] is payload
        finally:
            # Keep the owned environment active until every rescued worker stops.
            release.set()
            for worker in workers:
                if worker.ident is not None:
                    threading.Thread.join(worker, timeout=10)
                    assert not worker.is_alive(), "owned worker survived independent rescue"
    assert {key: os.environ.get(key) for key in before_env} == before_env


@pytest.mark.parametrize("position", [0, 3, 7])
@pytest.mark.parametrize("after", [False, True])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_partial_start_retires_workers_before_cache_restore(position, after, error, tmp_path):
    _exercise("start", error, position, after, tmp_path)


@pytest.mark.parametrize("position", [0, 3, 7])
@pytest.mark.parametrize("after", [False, True])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_join_fault_retires_workers_before_cache_restore(position, after, error, tmp_path):
    _exercise("join", error, position, after, tmp_path)


def test_actual_eight_workers_preserve_all_eight_hundred_counts(tmp_path):
    _exercise("normal", None, 0, False, tmp_path)


def test_loader_preserves_import_and_logging_state():
    import logging
    import sys

    absent = object()
    previous = sys.modules.get("core.analysis.reach_verdict_log", absent)
    root = logging.getLogger()
    raptor = logging.getLogger("raptor")
    root_handlers, raptor_handlers = root.handlers, raptor.handlers
    root_values, raptor_values = list(root_handlers), list(raptor_handlers)
    levels = root.level, raptor.level, raptor.propagate
    native = load_worker_module()
    assert sys.modules.get("core.analysis.reach_verdict_log", absent) is previous
    assert root.handlers is root_handlers and raptor.handlers is raptor_handlers
    assert root.handlers == root_values and raptor.handlers == raptor_values
    assert (root.level, raptor.level, raptor.propagate) == levels
    assert native.reach_verdict_log.record_verdict.__globals__ is vars(native.reach_verdict_log)
    assert native.reach_verdict_log.record_verdict.__code__.co_filename.endswith("core/analysis/reach_verdict_log.py")
