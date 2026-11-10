"""Key-creator teardown never re-enters process-shared barrier state."""
import ast
import importlib
import multiprocessing
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

from core.testing.module_views import module_function_view
from core.testing.tests import test_key_process_fixture_ownership as native


class OwnerAbortLookup(RuntimeError):
    pass


class RecoveryAbortAttempt(RuntimeError):
    pass


class _Endpoint:
    closed = False

    def close(self):
        self.closed = True


class _Queue:
    def __init__(self, context):
        self.context = context
        self._closed = False
        self._reader, self._writer = _Endpoint(), _Endpoint()

    def get(self, *args, **kwargs):
        return self.context.key.hex(), []

    def close(self):
        self._closed = True

    def join_thread(self):
        pass


class _Process:
    def __init__(self, context, *args, **kwargs):
        self.context, self.args = context, kwargs["args"]
        self.pid = self.exitcode = None
        self._closed = False

    def start(self):
        if self.context.start_failure is not None:
            raise self.context.start_failure
        self.pid = 100000 + self.context.processes.index(self)
        self.exitcode = 0
        path = Path(self.args[0])
        path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        path.write_bytes(self.context.key)
        path.chmod(0o600)

    def is_alive(self):
        return False

    def kill(self):
        self.exitcode = -9

    def join(self, *args, **kwargs):
        pass

    def close(self):
        self._closed = True


class _Barrier:
    def __init__(self, context):
        self.context = context

    @property
    def abort(self):
        context = self.context
        context.lookups.append(True)
        if context.owner_trap:
            raise OwnerAbortLookup("cleanup looked up barrier abort")

        def abort():
            if context.processes and all(p._closed for p in context.processes):
                raise RecoveryAbortAttempt("recovery re-entered barrier after retirement")
            context.calls.append(True)
        return abort


class _Context:
    def __init__(self, *, owner_trap=False, start_failure=None):
        owner = importlib.import_module("core.security.tests.test_mac_key")
        self.key = b"K" * owner._KEY_LEN
        self.owner_trap, self.start_failure = owner_trap, start_failure
        self.processes, self.queues, self.lookups, self.calls = [], [], [], []

    def Process(self, *args, **kwargs):
        value = _Process(self, *args, **kwargs)
        self.processes.append(value)
        return value

    def Queue(self):
        value = _Queue(self)
        self.queues.append(value)
        return value

    def Barrier(self, parties):
        assert parties == 8
        return _Barrier(self)


def _multiprocessing_view(context, method):
    private = ModuleType("multiprocessing")
    vars(private).update(vars(multiprocessing))
    private.get_all_start_methods = lambda: [method]
    private.get_context = lambda chosen: context
    return private


def _assert_retired(context):
    assert len(context.processes) == 8
    assert all(p._closed for p in context.processes)
    assert len(context.queues) == 1
    assert all(q._closed and q._reader.closed and q._writer.closed for q in context.queues)


def _owner_control(error, tmp_path):
    owner = importlib.import_module("core.security.tests.test_mac_key")
    source = Path(owner.__file__)
    cls = next(n for n in ast.parse(source.read_text()).body
               if isinstance(n, ast.ClassDef) and n.name == "TestParallelCreators")
    body = next(n for n in cls.body if isinstance(n, ast.FunctionDef)
                and n.name == "test_parallel_creators_converge_on_one_key_without_warnings")
    failure = error("owned first-start failure")
    context = _Context(owner_trap=True, start_failure=failure)
    namespace = dict(vars(owner), multiprocessing=_multiprocessing_view(context, native._PREFERRED))
    tree = ast.fix_missing_locations(ast.Module(body=[body], type_ignores=[]))
    exec(compile(tree, str(source), "exec"), namespace)
    try:
        with pytest.raises(error) as caught:
            namespace[body.name](owner.TestParallelCreators(), owner.key_path.__wrapped__(tmp_path))
        assert caught.value is failure
        assert context.lookups == context.calls == []
    finally:
        _assert_retired(context)


def _model_control(method, operation, after, index, error, tmp_path):
    context = _Context()
    view = module_function_view(native, bindings={
        "multiprocessing": _multiprocessing_view(context, method),
    })
    view._exercise(method, operation, after, index, error, tmp_path)
    _assert_retired(context)
    assert context.lookups == context.calls == []


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
def test_owner_never_registers_barrier_abort(error, tmp_path):
    _owner_control(error, tmp_path)


@pytest.mark.parametrize("method,operation,after,index,error", native._FAULTS)
def test_failure_recovery_never_calls_barrier_abort(
    method, operation, after, index, error, tmp_path
):
    _model_control(method, operation, after, index, error, tmp_path)


_NATIVE = [(method, operation, after, index, error)
           for method in ("fork", "spawn") if method in native._METHODS
           for operation, after, index, error in [
               ("start", True, 0 if method == "fork" else 1, KeyboardInterrupt),
               ("get", False, 0, SystemExit if method == "fork" else KeyboardInterrupt),
               ("join", True, 0, KeyboardInterrupt),
           ]]


@pytest.mark.parametrize("method,operation,after,index,error", _NATIVE)
def test_native_ownership_controls_do_not_touch_abort(
    method, operation, after, index, error, tmp_path
):
    actual = multiprocessing.get_context(method)
    processes, queues, barriers, attempted = [], [], [], []

    def process(*args, **kwargs):
        value = actual.Process(*args, **kwargs)
        processes.append(value)
        return value

    def queue():
        value = actual.Queue()
        queues.append(value)
        return value

    def barrier(*args, **kwargs):
        value = actual.Barrier(*args, **kwargs)
        barriers.append(value)

        def abort():
            attempted.append(True)
            raise RuntimeError("native control attempted barrier abort")
        value.abort = abort
        return value

    context = SimpleNamespace(Process=process, Queue=queue, Barrier=barrier)
    view = module_function_view(native, bindings={
        "multiprocessing": _multiprocessing_view(context, method),
    })
    try:
        view._exercise(method, operation, after, index, error, tmp_path)
        assert len(processes) == 8 and len(queues) == len(barriers) == 1
        assert all(p._closed for p in processes)
        assert attempted == []
    finally:
        # Own only native handles created above; never acquire barrier state.
        for value in processes:
            if value._closed:
                continue
            if value.pid is not None:
                if value.is_alive():
                    value.kill()
                value.join(5)
                assert not value.is_alive()
            value.close()
        for value in queues:
            value.close()
            value.join_thread()
            value._reader.close()
            value._writer.close()
