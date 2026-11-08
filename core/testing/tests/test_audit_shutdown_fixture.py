"""Shutdown fixtures preserve real event/module state and join owned workers."""

import ast
from contextlib import contextmanager
from importlib import import_module
import os
from pathlib import Path
import threading
from types import FunctionType, ModuleType

import pytest


CASES = [
    "core/audit/tests/test_sigterm_grace.py",
    "core/audit/tests/test_sigterm_joern_reap.py",
    "core/audit/tests/test_joern_exit_release.py",
    "core/audit/tests/test_executor.py",
    "core/audit/tests/test_run_progress.py",
]
ROOT = Path(__file__).resolve().parents[3]


def _prepare(path, initial, fail_at=None, failure_type=RuntimeError):
    owner = ModuleType("private_audit_orchestrator")
    owner._sigterm_event = threading.Event()
    owner._shutdown_event = threading.Event()
    if initial == "term":
        owner._sigterm_event.set()
    if initial == "shutdown":
        owner._shutdown_event.set()
    owner._sigterm_state = {"installed": False, "count": 7, "prev": None}
    owner._sigterm_flush_hooks = [lambda: None]
    owner.os = os
    owner._threading = threading
    snapshot = dict(vars(owner))
    steps = []

    class Patch(pytest.MonkeyPatch):
        def setattr(self, *args, **kwargs):
            super().setattr(*args, **kwargs)
            steps.append(None)
            if len(steps) == fail_at:
                raise failure_type("injected setup failure")

    def fixture_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "core.audit":
            view = ModuleType(name)
            view.orchestrator = owner
            return view
        if name == "core.testing.audit_shutdown":
            helper = import_module(name).isolated_audit_shutdown.__wrapped__
            pytest_view = ModuleType("private_pytest")
            pytest_view.__dict__.update(vars(pytest))
            pytest_view.MonkeyPatch = Patch
            clone = FunctionType(
                helper.__code__,
                dict(helper.__globals__, pytest=pytest_view),
                helper.__name__,
            )
            view = ModuleType(name)
            view.isolated_audit_shutdown = contextmanager(clone)
            return view
        return __import__(name, globals, locals, fromlist, level)

    namespace = {
        "orch": owner,
        "__builtins__": dict(vars(__import__("builtins")), __import__=fixture_import),
    }
    tree = ast.parse((ROOT / path).read_text())
    node = next(
        n
        for n in tree.body
        if isinstance(n, ast.FunctionDef) and n.name == "_reset_term_state"
    )
    node.decorator_list = []
    exec(compile(ast.Module(body=[node], type_ignores=[]), path, "exec"), namespace)
    return namespace[node.name], owner, snapshot


def _restored(owner, snapshot, initial):
    for name, value in snapshot.items():
        assert getattr(owner, name) is value
    assert owner._sigterm_event.is_set() is (initial == "term")
    assert owner._shutdown_event.is_set() is (initial == "shutdown")
    assert owner._sigterm_state == {"installed": False, "count": 7, "prev": None}
    assert len(owner._sigterm_flush_hooks) == 1


@pytest.mark.parametrize("path", CASES, ids=["grace", "reap", "release", "executor", "progress"])
@pytest.mark.parametrize("initial", ["clear", "term", "shutdown"])
@pytest.mark.parametrize("mode", ["normal", "close", "throw"])
def test_shutdown_fixture_preserves_borrowed_state(path, initial, mode):
    fixture, owner, snapshot = _prepare(path, initial)
    generator = fixture()
    original_thread = threading.Thread
    original_exit = os._exit
    try:
        next(generator)
        assert isinstance(owner, ModuleType)
        assert isinstance(owner._sigterm_event, threading.Event)
        assert owner._sigterm_event is not snapshot["_sigterm_event"]
        assert owner._shutdown_event is not snapshot["_shutdown_event"]
        assert not owner._sigterm_event.is_set()
        assert not owner._shutdown_event.is_set()
        assert owner._sigterm_state == {"installed": False, "count": 0, "prev": None}
        assert owner._sigterm_flush_hooks == []
        assert isinstance(owner.os, ModuleType)
        assert isinstance(owner._threading, ModuleType)
        assert owner.os is not os
        assert owner._threading is not threading
        owner._threading.Thread = lambda: None
        owner.os._exit = lambda code: None
        assert threading.Thread is original_thread
        assert os._exit is original_exit
        owner._sigterm_event.set()
        owner._shutdown_event.set()
        owner._sigterm_state["count"] = 3
        owner._sigterm_flush_hooks.append(lambda: None)
        if mode == "close":
            generator.close()
        elif mode == "throw":
            with pytest.raises(KeyboardInterrupt):
                generator.throw(KeyboardInterrupt)
        else:
            with pytest.raises(StopIteration):
                next(generator)
    finally:
        generator.close()
    _restored(owner, snapshot, initial)


@pytest.mark.parametrize("path", CASES, ids=["grace", "reap", "release", "executor", "progress"])
@pytest.mark.parametrize("fail_at", range(1, 7))
@pytest.mark.parametrize("failure_type", [RuntimeError, KeyboardInterrupt])
def test_shutdown_setup_failure_restores_completed_pins(path, fail_at, failure_type):
    fixture, owner, snapshot = _prepare(path, "term", fail_at, failure_type)
    generator = fixture()
    try:
        with pytest.raises(failure_type, match="injected setup failure"):
            next(generator)
    finally:
        generator.close()
    _restored(owner, snapshot, "term")


@pytest.mark.parametrize("path", CASES, ids=["grace", "reap", "release", "executor", "progress"])
def test_shutdown_fixture_finishes_workers_before_restoring_state(path):
    fixture, owner, snapshot = _prepare(path, "clear")
    generator = fixture()
    release = threading.Event()
    started = threading.Event()
    observed = []
    worker = None
    try:
        next(generator)
        assert owner._threading is not threading
        private_event = owner._sigterm_event

        def work():
            started.set()
            release.wait()
            observed.append(owner._sigterm_event is private_event)

        worker = owner._threading.Thread(target=work, name="owned-fixture-worker")
        assert isinstance(worker, threading.Thread)
        worker.start()
        assert started.wait(5), "owned worker failed to start"
    finally:
        release.set()
        try:
            generator.close()
        finally:
            if worker is not None:
                worker.join(5)
                assert not worker.is_alive(), "owned worker survived fixture cleanup"
    assert observed == [True]
    _restored(owner, snapshot, "clear")


def test_shutdown_cleanup_attempts_every_owned_worker_after_join_failure():
    fixture, owner, snapshot = _prepare(CASES[0], "clear")
    generator = fixture()
    release = threading.Event()
    workers = []
    joins = []
    originals = []
    try:
        next(generator)
        assert owner._threading is not threading
        for name in ("first", "second"):
            worker = owner._threading.Thread(target=release.wait, name=name)
            workers.append(worker)
            originals.append(worker.join)
            worker.start()

        def first_join(timeout):
            originals[0](timeout)
            joins.append("first")
            raise RuntimeError("join failed after reaping")

        def second_join(timeout):
            originals[1](timeout)
            joins.append("second")
            assert owner._sigterm_event is not snapshot["_sigterm_event"]

        workers[0].join = first_join
        workers[1].join = second_join
        release.set()
        with pytest.raises(RuntimeError, match="join failed after reaping"):
            generator.close()
        assert joins == ["first", "second"]
    finally:
        release.set()
        generator.close()
        for worker, join in zip(workers, originals):
            join(5)
            assert not worker.is_alive(), f"worker survived cleanup: {worker.name}"
    _restored(owner, snapshot, "clear")
