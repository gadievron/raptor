"""Native project/key concurrency fixtures retire workers before borrowed state."""

import ast
import builtins
from contextlib import contextmanager, ExitStack
import importlib.util
import os
from pathlib import Path
import threading
from types import ModuleType

import pytest


_CASES = {
    "project": ("core/project/tests/test_project.py", "TestProjectManager",
                "test_concurrent_creates_different_names_never_share_a_dir", 2),
    "key": ("core/sage/tests/test_rowmac.py", "TestKeyLifecycle",
            "test_concurrent_first_create_converges_on_one_key", 8),
}


@contextmanager
def _native_case(owner, classname, name, tmp_path):
    import core.project.project as projects
    import core.security.mac_key as clock

    before_env = dict(os.environ)
    borrowed_output, borrowed_clock = projects.DEFAULT_OUTPUT_BASE, clock.time
    borrowed_key = (owner.rowmac._key_path, owner.rowmac._warned_paths) if hasattr(owner, "rowmac") else None
    try:
        with pytest.MonkeyPatch.context() as patch, ExitStack() as cleanup:
            if hasattr(owner, "_user_state_in_tmp"):
                generator = owner._user_state_in_tmp.__wrapped__(tmp_path)
                next(generator)
                cleanup.callback(generator.close)
            if hasattr(owner, "_isolate_clock_patch_targets"):
                owner._isolate_clock_patch_targets.__wrapped__(patch)
            instance = getattr(owner, classname)(methodName=name)
            cleanup.callback(instance.doCleanups)
            instance.setUp()
            cleanup.callback(instance.tearDown)
            yield instance
    finally:
        restored = dict(os.environ) == before_env
        assert restored
        assert projects.DEFAULT_OUTPUT_BASE is borrowed_output
        assert clock.time is borrowed_clock
        if borrowed_key is not None:
            assert owner.rowmac._key_path is borrowed_key[0]
            assert owner.rowmac._warned_paths is borrowed_key[1]


@pytest.mark.parametrize("case,position", [(case, position) for case in _CASES
                                         for position in (("first", "last") if case == "project"
                                                          else ("first", "middle", "last"))])
@pytest.mark.parametrize("kind", [RuntimeError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("after", [False, True], ids=["before", "after"])
def test_started_workers_retire_before_fixture_cleanup(case, kind, after, position, tmp_path):
    _exercise(case, "start", kind, after, position, tmp_path)


@pytest.mark.parametrize("case", list(_CASES))
@pytest.mark.parametrize("kind", [RuntimeError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("after", [False, True], ids=["before", "after"])
def test_join_faults_retire_before_fixture_cleanup(case, kind, after, tmp_path):
    _exercise(case, "join", kind, after, "first", tmp_path)


def _exercise(case, operation, kind, after, position, tmp_path):
    filename, classname, name, count = _CASES[case]
    source = Path(__file__).resolve().parents[3] / filename
    spec = importlib.util.spec_from_file_location("owned_project_key_" + case, source)
    owner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(owner)
    cls = next(n for n in ast.parse(source.read_text()).body
               if isinstance(n, ast.ClassDef) and n.name == classname)
    method = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == name)
    workers, barriers = [], []
    failure = kind("owned project/key worker fault")
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
    private.Thread, private.Barrier = thread, barrier

    def importing(name, *args, **kwargs):
        if name == "threading":
            return private
        return builtins.__import__(name, *args, **kwargs)

    namespace = dict(vars(owner), threading=private,
                     __builtins__=dict(vars(builtins), __import__=importing))
    module = ast.fix_missing_locations(ast.Module(body=[method], type_ignores=[]))
    exec(compile(module, str(source), "exec"), namespace)
    with _native_case(owner, classname, name, tmp_path) as instance:
        try:
            with pytest.raises(kind) as caught:
                namespace[name](instance)
            assert caught.value is failure
            assert fired
            assert not any(worker.is_alive() for worker in workers)
        finally:
            for value in barriers:
                value.abort()
            for worker in workers:
                if worker.ident is not None:
                    threading.Thread.join(worker, timeout=2)
            assert not any(worker.is_alive() for worker in workers)
