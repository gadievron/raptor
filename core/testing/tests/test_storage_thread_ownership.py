"""Storage race tests retire real writers before their temporary state exits."""

import ast
import builtins
import importlib.util
import threading
from pathlib import Path
from types import ModuleType

import pytest


_CASES = {
    "witness-same": ("core/witness/tests/test_store.py", None,
                     "test_concurrent_same_hash_writes_do_not_race", 16),
    "witness-distinct": ("core/witness/tests/test_store.py", None,
                         "test_concurrent_distinct_hash_writes_succeed", 8),
    "attempts": ("core/labeled_attempts/test_store.py", None,
                 "test_concurrent_writes_do_not_overwrite", 20),
    "cache": ("core/json/tests/test_cache.py", None,
              "test_concurrent_threads_same_key_no_torn_writes", 8),
    "json": ("core/json/tests/test_utils.py", "TestSaveJson",
             "test_concurrent_threads_same_path_no_torn_writes", 8),
}


@pytest.mark.parametrize("case", list(_CASES))
@pytest.mark.parametrize("kind", [RuntimeError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("after", [False, True], ids=["before", "after"])
@pytest.mark.parametrize("position", ["first", "middle", "last"])
def test_started_writers_retire(case, kind, after, position, tmp_path):
    _exercise(case, "start", kind, after, position, tmp_path)


@pytest.mark.parametrize("case", list(_CASES))
@pytest.mark.parametrize("kind", [RuntimeError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("after", [False, True], ids=["before", "after"])
def test_join_faults_retire_writers(case, kind, after, tmp_path):
    _exercise(case, "join", kind, after, "first", tmp_path)


def _exercise(case, operation, kind, after, position, tmp_path):
    filename, classname, name, count = _CASES[case]
    source = Path(__file__).resolve().parents[3] / filename
    spec = importlib.util.spec_from_file_location("owned_storage_" + case.replace("-", "_"), source)
    owner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(owner)
    tree = ast.parse(source.read_text())
    body = (next(n for n in tree.body if isinstance(n, ast.ClassDef)
                 and n.name == classname).body if classname else tree.body)
    method = next(n for n in body if isinstance(n, ast.FunctionDef) and n.name == name)
    workers, barriers = [], []
    failure = kind("owned storage-worker fault")
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

    private = ModuleType("threading")
    vars(private).update(vars(threading))
    private.Thread = thread
    private.Barrier = barrier

    def importing(name, *args, **kwargs):
        if name == "threading":
            return private
        return builtins.__import__(name, *args, **kwargs)

    namespace = dict(vars(owner), __builtins__=dict(vars(builtins), __import__=importing))
    module = ast.fix_missing_locations(ast.Module(body=[method], type_ignores=[]))
    exec(compile(module, str(source), "exec"), namespace)
    native_owner = getattr(owner, classname) if classname else owner
    original = getattr(native_owner, name)
    arguments = (native_owner(),) if classname else (tmp_path,)
    try:
        with pytest.raises(kind) as caught:
            namespace[name](*arguments)
        assert caught.value is failure
        assert fired
        assert getattr(native_owner, name) is original
        assert threading.Thread is not Worker
        assert not any(worker.is_alive() for worker in workers)
    finally:
        for value in barriers:
            value.abort()
        for worker in workers:
            if worker.ident is not None:
                threading.Thread.join(worker, timeout=2)
        assert not any(worker.is_alive() for worker in workers)
