"""Fake-provider cache and budget harnesses retire real workers on failure."""

import ast
import builtins
import importlib.util
import threading
from pathlib import Path
from types import ModuleType

import pytest


_CASES = {'budget': ('core/llm/tests/test_budget_reservation_estimate.py', 'TestReservationDispatch', 'test_concurrent_dispatch_no_overshoot', 8), 'estimate-error': ('core/llm/tests/test_budget_reservation_estimate.py', 'TestReservationDispatch', 'test_concurrent_overshoot_bounded_by_estimate_error', 8), 'cache-same': ('core/llm/tests/test_structured_response_cache.py', None, 'test_concurrent_same_key_dedupes_to_one_provider_call', 8), 'cache-distinct': ('core/llm/tests/test_structured_response_cache.py', None, 'test_concurrent_distinct_keys_run_in_parallel', 8), 'acquire': ('core/llm/tests/test_llm_callbacks.py', 'TestBudgetReservationConcurrency', 'test_concurrent_acquires_respect_cap', 4)}


@pytest.fixture(autouse=True)
def _owned_client_state(monkeypatch):
    from core.llm import client, telemetry
    from core.testing.module_state import isolated_module_state

    for name in ("_MODEL_BANNER_SHOWN", "_TRANSPORT_BANNER_SHOWN",
                 "_UNCAPPED_BANNER_SHOWN", "_DEFAULT_CEILING_LOG_SHOWN"):
        monkeypatch.setattr(client, name, False)
    with isolated_module_state(telemetry, {"_sink": None}, lock=telemetry._sink_lock):
        yield


@pytest.mark.parametrize("case", list(_CASES))
@pytest.mark.parametrize("kind", [RuntimeError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("after", [False, True], ids=["before", "after"])
@pytest.mark.parametrize("position", ["first", "middle", "last"])
def test_started_workers_retire(case, kind, after, position, tmp_path):
    _exercise(case, "start", kind, after, position, tmp_path)


@pytest.mark.parametrize("case", list(_CASES))
@pytest.mark.parametrize("kind", [RuntimeError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("after", [False, True], ids=["before", "after"])
def test_join_faults_retire_workers(case, kind, after, tmp_path):
    _exercise(case, "join", kind, after, "first", tmp_path)


def _exercise(case, operation, kind, after, position, tmp_path):
    filename, classname, name, count = _CASES[case]
    source = Path(__file__).resolve().parents[3] / filename
    spec = importlib.util.spec_from_file_location("owned_client_" + case.replace("-", "_"), source)
    owner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(owner)
    tree = ast.parse(source.read_text())
    body = (next(n for n in tree.body if isinstance(n, ast.ClassDef)
                 and n.name == classname).body if classname else tree.body)
    method = next(n for n in body if isinstance(n, ast.FunctionDef) and n.name == name)
    workers, barriers = [], []
    failure = kind("owned client-worker fault")
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

    namespace = dict(vars(owner), threading=private, __builtins__=dict(vars(builtins), __import__=importing))
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
