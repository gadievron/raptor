"""The real counter-concurrency workers retire when their harness unwinds."""

import ast
import sys
import threading
import types
from pathlib import Path

import pytest

from core.testing.threads import retiring_threads


@pytest.mark.parametrize("kind", [RuntimeError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("after", [False, True], ids=["before", "after"])
@pytest.mark.parametrize("position", [0, 1, 7])
def test_counter_threads_retire_on_start_failure(kind, after, position):
    _exercise("start", kind, after, position)


@pytest.mark.parametrize("kind", [RuntimeError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("after", [False, True], ids=["before", "after"])
def test_counter_threads_retire_on_join_failure(kind, after):
    _exercise("join", kind, after, 0)


def _exercise(operation, kind, after, position):
    from core.audit.orchestrator import _make_tier_counters

    source = Path(__file__).resolve().parents[3] / "core/audit/tests/test_tier_timing.py"
    tree = ast.parse(source.read_text())
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef)
               and n.name == "TestIncrementTierThreadSafety")
    method = next(n for n in cls.body if isinstance(n, ast.FunctionDef)
                  and n.name == "test_concurrent_increments_are_exact")
    workers = []
    barriers = []
    failure = kind("owned counter-worker fault")
    fired = False

    def barrier(*args, **kwargs):
        value = threading.Barrier(*args, **kwargs)
        barriers.append(value)
        return value

    class Worker(threading.Thread):
        def start(self):
            nonlocal fired
            selected = operation == "start" and workers.index(self) == position and not fired
            if selected:
                fired = True
                if after:
                    super().start()
                raise failure
            return super().start()

        def join(self, *args, **kwargs):
            nonlocal fired
            selected = operation == "join" and workers.index(self) == position and not fired
            if selected:
                fired = True
                if after:
                    super().join(*args, **kwargs)
                raise failure
            return super().join(*args, **kwargs)

    def thread(*args, **kwargs):
        value = Worker(*args, **kwargs)
        workers.append(value)
        return value

    private = types.SimpleNamespace(Thread=thread, Barrier=barrier,
                                    BrokenBarrierError=threading.BrokenBarrierError)
    namespace = dict(threading=private, types=types, sys=sys,
                     _make_tier_counters=_make_tier_counters,
                     retiring_threads=retiring_threads)
    module = ast.fix_missing_locations(ast.Module(body=[method], type_ignores=[]))
    exec(compile(module, str(source), "exec"), namespace)
    previous = sys.getswitchinterval()
    try:
        with pytest.raises(kind) as caught:
            namespace[method.name](None)
        assert caught.value is failure
        assert fired
        assert sys.getswitchinterval() == previous
        assert not any(worker.is_alive() for worker in workers)
    finally:
        # External recovery protects the runner if the owning cleanup regresses.
        for value in barriers:
            value.abort()
        for worker in workers:
            if worker.ident is not None:
                threading.Thread.join(worker, timeout=2)
        sys.setswitchinterval(previous)
        assert not any(worker.is_alive() for worker in workers)


@pytest.mark.parametrize("case", ["checkpoint", "heartbeat"])
@pytest.mark.parametrize("kind", [RuntimeError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("after", [False, True], ids=["before", "after"])
@pytest.mark.parametrize("position", ["first", "middle", "last"])
def test_writer_threads_retire_on_start_failure(case, kind, after, position, tmp_path):
    _exercise_writer(case, "start", kind, after, position, tmp_path)


@pytest.mark.parametrize("case", ["checkpoint", "heartbeat"])
@pytest.mark.parametrize("kind", [RuntimeError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("after", [False, True], ids=["before", "after"])
def test_writer_threads_retire_on_join_failure(case, kind, after, tmp_path):
    _exercise_writer(case, "join", kind, after, "first", tmp_path)


def _exercise_writer(case, operation, kind, after, position, tmp_path):
    import importlib.util

    from core.testing.module_views import module_function_view

    cases = {
        "checkpoint": ("test_sweep_checkpoint.py", "test_concurrent_writers_all_records_line_atomic", 32),
        "heartbeat": ("test_heartbeat.py", "test_concurrent_beats_never_tear", 17),
    }
    filename, name, count = cases[case]
    source = Path(__file__).resolve().parents[3] / "core/audit/tests" / filename
    spec = importlib.util.spec_from_file_location("owned_writer_" + case, source)
    owner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(owner)
    workers, barriers, events = [], [], []
    failure = kind("owned writer-worker fault")
    fired = False
    index = {"first": 0, "middle": 2, "last": count - 1}[position]

    class Worker(threading.Thread):
        def start(self):
            nonlocal fired
            if operation == "start" and workers.index(self) == index and not fired:
                fired = True
                if after:
                    super().start()
                raise failure
            return super().start()

        def join(self, *args, **kwargs):
            nonlocal fired
            if operation == "join" and workers.index(self) == index and not fired:
                fired = True
                if after:
                    super().join(*args, **kwargs)
                raise failure
            return super().join(*args, **kwargs)

    def thread(*args, **kwargs):
        value = Worker(*args, **kwargs)
        workers.append(value)
        return value

    def barrier(*args, **kwargs):
        value = threading.Barrier(*args, **kwargs)
        barriers.append(value)
        return value

    def event():
        value = threading.Event()
        events.append(value)
        return value

    private = types.SimpleNamespace(Thread=thread, Barrier=barrier, Event=event,
                                    BrokenBarrierError=threading.BrokenBarrierError)
    view = module_function_view(owner, bindings={"threading": private})
    original = getattr(owner, name)
    try:
        with pytest.raises(kind) as caught:
            getattr(view, name)(tmp_path)
        assert caught.value is failure
        assert fired
        assert getattr(owner, name) is original
        assert owner.threading is threading
        assert not any(worker.is_alive() for worker in workers)
    finally:
        for value in events:
            value.set()
        for value in barriers:
            value.abort()
        for worker in workers:
            if worker.ident is not None:
                threading.Thread.join(worker, timeout=2)
        assert not any(worker.is_alive() for worker in workers)
