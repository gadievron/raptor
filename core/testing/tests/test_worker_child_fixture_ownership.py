"""Worker helpers retain process ownership and their launch-state lifetime."""

import ast
import builtins
import importlib
from collections.abc import Iterator
from contextlib import contextmanager, ExitStack, nullcontext
from inspect import signature
import os
from pathlib import Path
import subprocess
import sys
from types import FunctionType, ModuleType
import unittest

import pytest

from core.json import load_json, save_json
from core.run.metadata import (
    RUN_METADATA_FILE, STATUS_RUNNING, complete_run, worker_liveness_for_meta,
)
from core.testing.processes import reap_on_exit
from core.testing.sandbox_state_scope import isolated_sandbox_state


ROOT = Path(__file__).resolve().parents[3]
LIVE = "core/run/tests/test_worker_liveness.py"
TRANSIENT = "core/run/tests/test_hook_finalize_precedence.py"
pytestmark = [pytest.mark.slow, pytest.mark.skipif(os.name != "posix", reason="POSIX worker process ownership")]


def _namespace(path, *, process_view=subprocess, import_error=None):
    def private_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "core.testing.processes" and import_error is not None:
            raise import_error("owner import interrupted")
        return builtins.__import__(name, globals, locals, fromlist, level)

    namespace = dict(pytest=pytest, Path=Path, Iterator=Iterator, contextmanager=contextmanager,
                     os=os, sys=sys, subprocess=process_view, REPO_ROOT=ROOT,
                     RUN_METADATA_FILE=RUN_METADATA_FILE, STATUS_RUNNING=STATUS_RUNNING,
                     save_json=save_json, worker_liveness_for_meta=worker_liveness_for_meta,
                     _meta=lambda run: load_json(run / RUN_METADATA_FILE),
                     __builtins__=dict(vars(builtins), __import__=private_import))
    tree = ast.parse((ROOT / path).read_text())
    constants = {"_STARTER_CHILD", "_TRANSIENT_PARENT", "SESSION_PID", "_AGED_TS"}
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id in constants for t in node.targets):
            exec(compile(ast.Module(body=[node], type_ignores=[]), path, "exec"), namespace)
        elif isinstance(node, ast.FunctionDef) and node.name in ("_user_state_in_tmp", "_owned_run_summary", "monkeypatch"):
            node.decorator_list = []
            exec(compile(ast.Module(body=[node], type_ignores=[]), path, "exec"), namespace)
    qualified = ("TestWorkerStampRecorder._distinct_live_parent" if path == LIVE
                 else "TestForcedDeadWorkerWindow._start_run_with_dead_worker")
    node = tree
    for name in qualified.split("."):
        node = next(n for n in node.body if getattr(n, "name", None) == name)
    exec(compile(ast.Module(body=[node], type_ignores=[]), path, "exec"), namespace)
    return namespace


@contextmanager
def _owned_context(path, base):
    """Run the native user, summary and body-patch dependency closure."""
    base.mkdir(parents=True)
    namespace = _namespace(path)
    with isolated_sandbox_state(()), ExitStack() as cleanup:
        values = {"tmp_path": base}
        for name in ("_user_state_in_tmp", "_owned_run_summary", "monkeypatch"):
            if name not in namespace:
                continue
            function = namespace[name]
            generator = function(**{key: values[key] for key in signature(function).parameters})
            values[name] = next(generator)
            cleanup.callback(generator.close)
        yield values["monkeypatch"]


def _process_view(*, streams, phase=None, error=None):
    view = ModuleType("subprocess")
    view.__dict__.update(vars(subprocess))
    processes, records = [], []

    def fail():
        if error is subprocess.TimeoutExpired:
            raise error("owned worker", 120)
        raise error("worker boundary interrupted")

    def spawn(*args, **kwargs):
        if streams:
            kwargs.update(stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        process = subprocess.Popen(*args, **kwargs)
        processes.append(process)
        env = kwargs.get("env", os.environ)
        record = {"environment": {key: env.get(key) for key in (
            "HOME", "XDG_DATA_HOME", "CLAUDECODE", "_RAPTOR_SCRATCH_AUTH",
            "RAPTOR_SESSION_PID", "RAPTOR_SESSION_TOKEN", "RAPTOR_CALLER_DIR", "RAPTOR_LAUNCH_TARGET",
        )}, "process_group": kwargs.get("process_group"),
            "session": os.getsid(process.pid), "waits": []}
        records.append(record)
        wait, kill = process.wait, process.kill
        count = 0

        def waiting(*args, **kwargs):
            nonlocal count
            count += 1
            record["waits"].append(kwargs)
            if phase == "before_wait" and count == 1:
                fail()
            result = wait(*args, **kwargs)
            if phase in ("after_wait", "cleanup_wait") and count == 1:
                fail()
            return result

        def killing():
            result = kill()
            if phase == "cleanup_kill":
                fail()
            return result

        process.wait, process.kill = waiting, killing
        return process

    view.Popen = spawn
    return view, processes, records


def _assert_reaped(processes):
    assert len(processes) == 1
    for process in processes:
        assert process.returncode is not None
        with pytest.raises(ChildProcessError):
            os.waitpid(process.pid, os.WNOHANG)
        assert all(stream is None or stream.closed for stream in (process.stdin, process.stdout, process.stderr))


def _cleanup(processes, group=False):
    for process in processes:
        with reap_on_exit(process, process_group=group):
            pass


@pytest.mark.parametrize("path", [LIVE, TRANSIENT])
@pytest.mark.parametrize("body_patch", [False, True])
@pytest.mark.parametrize("finish", ["resume", "close", "error", "interrupt"])
def test_native_fixture_graph_restores_launch_state(path, body_patch, finish, tmp_path, monkeypatch):
    borrowed = tmp_path / "borrowed-data"
    borrowed.mkdir()
    (borrowed / "caller.key").write_bytes(b"borrowed key")
    monkeypatch.setenv("XDG_DATA_HOME", str(borrowed))
    monkeypatch.setenv("_RAPTOR_SCRATCH_AUTH", "borrowed authorization")
    context = _owned_context(path, tmp_path / "owner")
    expected = pytest.raises(RuntimeError if finish == "error" else KeyboardInterrupt) if finish in ("error", "interrupt") else nullcontext()
    with expected:
        with context as patch:
            assert Path(os.environ["XDG_DATA_HOME"]).is_dir()
            assert Path(os.environ["XDG_DATA_HOME"]) != borrowed
            assert "_RAPTOR_SCRATCH_AUTH" not in os.environ
            if body_patch:
                patch.setenv("XDG_DATA_HOME", str(tmp_path / "body-data"))
                patch.setenv("_RAPTOR_SCRATCH_AUTH", "body authorization")
            if finish == "close":
                context.gen.close()
            elif finish == "error":
                raise RuntimeError("body interrupted")
            elif finish == "interrupt":
                raise KeyboardInterrupt("body interrupted")
    assert os.environ["XDG_DATA_HOME"] == str(borrowed)
    assert os.environ["_RAPTOR_SCRATCH_AUTH"] == "borrowed authorization"
    assert (borrowed / "caller.key").read_bytes() == b"borrowed key"


@pytest.mark.parametrize("streams", [False, True])
@pytest.mark.parametrize("body_error", [None, RuntimeError, KeyboardInterrupt])
def test_live_parent_is_owned_through_real_unittest_body(streams, body_error):
    view, processes, _ = _process_view(streams=streams)
    helper = _namespace(LIVE, process_view=view)["_distinct_live_parent"]

    def body():
        with helper(case) as pid:
            assert pid > 1 and pid != os.getpid()
            assert processes[0].poll() is None
            if body_error is not None:
                raise body_error("body interrupted")

    case = unittest.FunctionTestCase(body)
    result = unittest.TestResult()
    try:
        with pytest.raises(KeyboardInterrupt) if body_error is KeyboardInterrupt else nullcontext():
            case.run(result)
        assert not result.failures
        assert len(result.errors) == (1 if body_error is RuntimeError else 0)
        _assert_reaped(processes)
    finally:
        _cleanup(processes)


@pytest.mark.parametrize("streams", [False, True])
@pytest.mark.parametrize("phase", ["cleanup_kill", "cleanup_wait"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_live_parent_cleanup_error_still_reaps_and_closes(streams, phase, error):
    view, processes, _ = _process_view(streams=streams, phase=phase, error=error)
    helper = _namespace(LIVE, process_view=view)["_distinct_live_parent"]
    try:
        with pytest.raises(error, match="worker boundary interrupted"):
            with helper(object()):
                pass
        _assert_reaped(processes)
    finally:
        _cleanup(processes)


@pytest.mark.parametrize("error", [ImportError, KeyboardInterrupt])
def test_live_parent_import_failure_creates_no_child(error):
    view, processes, _ = _process_view(streams=False)
    helper = _namespace(LIVE, process_view=view, import_error=error)["_distinct_live_parent"]
    with pytest.raises(error, match="owner import interrupted"):
        with helper(object()):
            pytest.fail("body reached after import failure")
    assert processes == []


@pytest.mark.parametrize("streams", [False, True])
@pytest.mark.parametrize("stale", [False, True])
def test_transient_parent_keeps_shared_data_for_parent_finalisation(streams, stale, tmp_path, monkeypatch):
    if stale:
        monkeypatch.setenv("_RAPTOR_SCRATCH_AUTH", "borrowed authorization")
    view, processes, records = _process_view(streams=streams)
    namespace = _namespace(TRANSIENT, process_view=view)
    helper = namespace["_start_run_with_dead_worker"]
    try:
        with _owned_context(TRANSIENT, tmp_path / "state"):
            data = Path(os.environ["XDG_DATA_HOME"])
            run = helper(unittest.TestCase(), tmp_path)
            assert load_json(run / RUN_METADATA_FILE)["status"] == STATUS_RUNNING
            assert records[0]["environment"]["XDG_DATA_HOME"] == str(data)
            assert data.is_dir()
            assert not Path(records[0]["environment"]["HOME"]).exists()
            complete_run(run)
            assert load_json(run / RUN_METADATA_FILE)["status"] == "completed"
            _assert_reaped(processes)
    finally:
        _cleanup(processes, group=True)


@pytest.mark.parametrize("streams", [False, True])
@pytest.mark.parametrize("stale", [False, True])
@pytest.mark.parametrize("phase", ["before_wait", "after_wait"])
@pytest.mark.parametrize("error", [subprocess.TimeoutExpired, OSError, KeyboardInterrupt])
def test_transient_parent_wait_failure_owns_group_and_launch_context(streams, stale, phase, error, tmp_path):
    view, processes, records = _process_view(streams=streams, phase=phase, error=error)
    helper = _namespace(TRANSIENT, process_view=view)["_start_run_with_dead_worker"]
    try:
        with _owned_context(TRANSIENT, tmp_path / "state") as patch:
            data = os.environ["XDG_DATA_HOME"]
            if stale:
                patch.setenv("_RAPTOR_SCRATCH_AUTH", "body authorization")
                patch.setenv("RAPTOR_SESSION_PID", "1")
                patch.setenv("RAPTOR_SESSION_TOKEN", "borrowed token")
                patch.setenv("RAPTOR_CALLER_DIR", str(tmp_path / "borrowed-target"))
                patch.setenv("RAPTOR_LAUNCH_TARGET", "borrowed target")
            with pytest.raises(error):
                helper(unittest.TestCase(), tmp_path)
            _assert_reaped(processes)
            record = records[0]
            assert record["process_group"] == 0
            assert record["session"] == os.getsid(0)
            assert record["waits"][0] == {"timeout": 120}
            assert record["environment"]["XDG_DATA_HOME"] == data
            assert record["environment"]["CLAUDECODE"] == "1"
            assert record["environment"]["RAPTOR_CALLER_DIR"] == str(tmp_path)
            assert record["environment"]["RAPTOR_LAUNCH_TARGET"] is None
            for key in ("_RAPTOR_SCRATCH_AUTH", "RAPTOR_SESSION_PID", "RAPTOR_SESSION_TOKEN"):
                assert record["environment"][key] is None
            assert not Path(record["environment"]["HOME"]).exists()
            assert Path(data).is_dir()
            assert os.environ.get("_RAPTOR_SCRATCH_AUTH") == ("body authorization" if stale else None)
    finally:
        _cleanup(processes, group=True)


@pytest.mark.parametrize("streams", [False, True])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_metadata_read_error_follows_process_cleanup(streams, error, tmp_path):
    view, processes, _ = _process_view(streams=streams)
    namespace = _namespace(TRANSIENT, process_view=view)

    def read_error(run):
        assert load_json(run / RUN_METADATA_FILE)["status"] == STATUS_RUNNING
        raise error("metadata read interrupted")

    namespace["_meta"] = read_error
    try:
        with _owned_context(TRANSIENT, tmp_path / "state"):
            with pytest.raises(error, match="metadata read interrupted"):
                namespace["_start_run_with_dead_worker"](unittest.TestCase(), tmp_path)
            _assert_reaped(processes)
    finally:
        _cleanup(processes, group=True)


DEAD_WORKER_CASES = [
    ("TestToolPidAlive", "test_dead_pid_is_dead_regardless_of_stamp"),
    ("TestCleanLivenessGrace", "test_sessionless_dead_worker_recent_activity_is_live"),
    ("TestCleanLivenessGrace", "test_sessionless_dead_worker_quiet_run_not_live"),
]


def _dead_worker_method(case_name, view, *, import_error=None):
    owner = importlib.import_module("core.run.tests.test_worker_liveness")
    classname, method = case_name
    cls = getattr(owner, classname)
    case = cls(method)
    original = getattr(cls, method)

    def private_import(name, *args, **kwargs):
        if name == "subprocess":
            return view
        if name == "core.testing.processes" and import_error is not None:
            raise import_error("owner import interrupted")
        return builtins.__import__(name, *args, **kwargs)

    namespace = dict(vars(owner), subprocess=view,
                     __builtins__=dict(vars(builtins), __import__=private_import))
    function = FunctionType(original.__code__, namespace, original.__name__,
                            original.__defaults__, original.__closure__)
    function.__kwdefaults__ = original.__kwdefaults__
    return lambda: function(case), lambda: getattr(cls, method) is original


@pytest.mark.parametrize("case_name", DEAD_WORKER_CASES)
@pytest.mark.parametrize("streams", [False, True])
def test_dead_worker_native_assertions_and_reaping(case_name, streams, tmp_path):
    view, processes, _ = _process_view(streams=streams)
    invoke, unchanged = _dead_worker_method(case_name, view)
    try:
        with _owned_context(LIVE, tmp_path / "state"):
            invoke()
        assert processes[0].args == [sys.executable, "-c", "pass"]
        assert processes[0].returncode == 0
        _assert_reaped(processes)
        assert unchanged()
    finally:
        _cleanup(processes)


@pytest.mark.parametrize("case_name", DEAD_WORKER_CASES)
@pytest.mark.parametrize("streams", [False, True])
@pytest.mark.parametrize("phase", ["before_wait", "after_wait"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
def test_dead_worker_wait_failure_reaps_and_closes(case_name, streams, phase, error, tmp_path):
    view, processes, _ = _process_view(streams=streams, phase=phase, error=error)
    invoke, unchanged = _dead_worker_method(case_name, view)
    try:
        with _owned_context(LIVE, tmp_path / "state"):
            with pytest.raises(error, match="worker boundary interrupted"):
                invoke()
        assert processes[0].args == [sys.executable, "-c", "pass"]
        _assert_reaped(processes)
        assert unchanged()
    finally:
        _cleanup(processes)


@pytest.mark.parametrize("case_name", DEAD_WORKER_CASES)
@pytest.mark.parametrize("error", [ImportError, KeyboardInterrupt])
def test_dead_worker_owner_import_precedes_spawn(case_name, error):
    view, processes, _ = _process_view(streams=False)
    invoke, unchanged = _dead_worker_method(case_name, view, import_error=error)
    with pytest.raises(error, match="owner import interrupted"):
        invoke()
    assert processes == []
    assert unchanged()
