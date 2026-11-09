"""Native registry fixtures restore borrowed sinks, breakers and locks."""

import ast
from contextlib import contextmanager
from importlib import import_module
from pathlib import Path
from types import FunctionType, ModuleType

import pytest


ROOT = Path(__file__).resolve().parents[3]
CASES = [
    ("test_telemetry.py", "_clean_sink"),
    ("test_telemetry_attribution.py", "clean_sink"),
    ("test_truncation_matrix.py", "_clean_sink"),
    ("test_budget_reservation_estimate.py", "_no_telemetry_sink"),
    ("test_degraded_breaker.py", "_isolated_breaker"),
]


def _view(name):
    view = ModuleType(name)
    view.__dict__.update(vars(import_module(name)))
    return view


class _Lock:
    def __init__(self):
        self.held = False
        self.entries = 0

    def __enter__(self):
        assert not self.held
        self.held = True
        self.entries += 1

    def __exit__(self, *exc):
        self.held = False


def _fixture(case, tmp_path, warm, fault=None):
    telemetry = _view("core.llm.telemetry")
    breaker = _view("core.llm.breaker")
    telemetry._sink_lock = _Lock()
    breaker._singleton_lock = _Lock()
    sink = telemetry.TelemetrySink(tmp_path / "borrowed.jsonl")
    sink.record({"event": "call", "call_class": "review", "cost_usd": 0.5})
    borrowed_breaker = breaker.DegradedModeBreaker(clock=lambda: 100.0)
    borrowed_breaker.record("retryable")
    telemetry._sink = sink if warm else None
    breaker._singleton = borrowed_breaker if warm else None
    path = tmp_path / "borrowed.jsonl"
    evidence = (path.read_bytes(), sink.summary_line(), borrowed_breaker.to_dict())
    rows = [(telemetry, "_sink", telemetry._sink, telemetry._sink_lock)]
    if case[1] == "_isolated_breaker":
        rows.insert(0, (breaker, "_singleton", breaker._singleton, breaker._singleton_lock))
    writes = 0

    class Patch(pytest.MonkeyPatch):
        def setattr(self, owner, field, value, **kwargs):
            nonlocal writes
            row = next(row for row in rows if row[0] is owner and row[1] == field)
            assert row[3].held
            super().setattr(owner, field, value, **kwargs)
            writes += 1
            if fault is not None and writes == fault[0]:
                raise fault[1]("registry publication interrupted")

    helper = _view("core.testing.module_state")
    pytest_view = _view("pytest")
    pytest_view.MonkeyPatch = Patch
    raw = helper.isolated_module_state.__wrapped__
    clone = FunctionType(raw.__code__, dict(raw.__globals__, pytest=pytest_view))
    clone.__kwdefaults__ = raw.__kwdefaults__
    helper.isolated_module_state = contextmanager(clone)
    llm = _view("core.llm")
    llm.telemetry, llm.breaker = telemetry, breaker

    def private_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "core.testing.module_state":
            return helper
        if name == "core.llm":
            return llm
        return __import__(name, globals, locals, fromlist, level)

    namespace = {"telemetry": telemetry, "llm_telemetry": telemetry,
                 "breaker_mod": breaker, "set_sink": lambda value: setattr(telemetry, "_sink", value),
                 "set_degradation_breaker": lambda value: setattr(breaker, "_singleton", value),
                 "__builtins__": dict(vars(import_module("builtins")), __import__=private_import)}
    source = ROOT / "core/llm/tests" / case[0]
    node = next(n for n in ast.parse(source.read_text()).body if getattr(n, "name", None) == case[1])
    node.decorator_list = []
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(source), "exec"), namespace)

    def restored():
        for owner, field, original, lock in rows:
            assert getattr(owner, field) is original
            assert not lock.held
            assert lock.entries == 0 or lock.entries >= 2
        assert telemetry._sink_lock is rows[-1][3]
        assert (path.read_bytes(), sink.summary_line(), borrowed_breaker.to_dict()) == evidence

    return namespace[case[1]], rows, restored


@pytest.mark.parametrize("case", CASES, ids=[c[0] for c in CASES])
@pytest.mark.parametrize("warm", [False, True], ids=["cold", "warm"])
@pytest.mark.parametrize("finish", ["resume", "close", "interrupt"])
@pytest.mark.parametrize("body_patch", [False, True], ids=["direct", "patched"])
def test_registry_fixture_restores_borrowed_state(case, warm, finish, body_patch, tmp_path):
    fixture, rows, restored = _fixture(case, tmp_path, warm)
    patch = pytest.MonkeyPatch()
    generator = fixture(monkeypatch=patch)
    try:
        next(generator)
        for owner, field, _, lock in rows:
            assert getattr(owner, field) is None
            assert not lock.held
            value = owner.TelemetrySink(tmp_path / "owned.jsonl") if field == "_sink" else owner.DegradedModeBreaker()
            if body_patch:
                patch.setattr(owner, field, value)
            else:
                setattr(owner, field, value)
        if finish == "resume":
            with pytest.raises(StopIteration):
                next(generator)
        elif finish == "interrupt":
            with pytest.raises(KeyboardInterrupt):
                generator.throw(KeyboardInterrupt)
        else:
            generator.close()
        patch.undo()
        restored()
    finally:
        generator.close()
        patch.undo()


FAULTS = [(case, step) for case in CASES for step in range(1, 3 if case[1] == "_isolated_breaker" else 2)]


@pytest.mark.parametrize("case,step", FAULTS, ids=[c[0] + ":" + str(step) for c, step in FAULTS])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
@pytest.mark.parametrize("warm", [False, True], ids=["cold", "warm"])
def test_registry_fixture_restores_partial_publication(case, step, error, warm, tmp_path):
    fixture, rows, restored = _fixture(case, tmp_path, warm, (step, error))
    patch = pytest.MonkeyPatch()
    generator = fixture(monkeypatch=patch)
    try:
        with pytest.raises(error, match="registry publication interrupted"):
            next(generator)
        restored()
    finally:
        generator.close()
        patch.undo()
