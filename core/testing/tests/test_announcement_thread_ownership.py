"""Real announcement and study workers retire without shared thread patches."""

import ast
import builtins
import importlib.util
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest


_CASES = {
    "degraded": ("test_codeql_degraded_dispatch.py", "TestDegradedBannerThreadSafety",
                 "test_parallel_first_skips_announce_once", 8),
    "unsupported": ("test_codeql_degraded_dispatch.py", "TestUnsupportedIdThreadSafety",
                    "test_parallel_first_misses_announce_once_per_id", 8),
    "study": ("test_study_consumer.py", "TestStudyQueue", "test_thread_safety", 4),
}


@pytest.mark.parametrize("case", list(_CASES))
@pytest.mark.parametrize("kind", [RuntimeError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("after", [False, True], ids=["before", "after"])
@pytest.mark.parametrize("position", ["first", "middle", "last"])
def test_started_workers_retire(case, kind, after, position, monkeypatch):
    _exercise(case, "start", kind, after, position, monkeypatch)


@pytest.mark.parametrize("case", list(_CASES))
@pytest.mark.parametrize("kind", [RuntimeError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("after", [False, True], ids=["before", "after"])
def test_join_interruptions_retire_workers(case, kind, after, monkeypatch):
    _exercise(case, "join", kind, after, "first", monkeypatch)


def _exercise(case, operation, kind, after, position, monkeypatch):
    filename, classname, name, count = _CASES[case]
    source = Path(__file__).resolve().parents[3] / "core/audit/tests" / filename
    spec = importlib.util.spec_from_file_location("owned_announcement_" + case, source)
    owner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(owner)
    cls = next(n for n in ast.parse(source.read_text()).body
               if isinstance(n, ast.ClassDef) and n.name == classname)
    method = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == name)
    workers, barriers = [], []
    failure = kind("owned announcement-worker fault")
    fired = False
    index = {"first": 0, "middle": 1, "last": count - 1}[position]

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

    private = SimpleNamespace(Thread=thread, Barrier=barrier,
                              BrokenBarrierError=threading.BrokenBarrierError)

    def importing(name, *args, **kwargs):
        if name == "threading":
            return private
        return builtins.__import__(name, *args, **kwargs)

    namespace = dict(vars(owner), threading=private,
                     __builtins__=dict(vars(builtins), __import__=importing))
    module = ast.fix_missing_locations(ast.Module(body=[method], type_ignores=[]))
    exec(compile(module, str(source), "exec"), namespace)
    original = getattr(getattr(owner, classname), name)
    arguments = (getattr(owner, classname)(),)
    if case != "study":
        arguments += (monkeypatch,)
    try:
        with pytest.raises(kind) as caught:
            namespace[name](*arguments)
        assert caught.value is failure
        assert fired
        assert getattr(getattr(owner, classname), name) is original
        assert threading.Thread is not Worker
        assert not any(worker.is_alive() for worker in workers)
    finally:
        for value in barriers:
            value.abort()
        for worker in workers:
            if worker.ident is not None:
                threading.Thread.join(worker, timeout=2)
        assert not any(worker.is_alive() for worker in workers)
