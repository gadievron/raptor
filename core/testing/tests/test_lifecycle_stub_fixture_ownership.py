"""Lifecycle identity stubs transfer ready children and close their streams."""

import ast
from contextlib import contextmanager, nullcontext
from importlib import import_module
import io
from pathlib import Path
import subprocess
import sys
from types import ModuleType
import unittest
from unittest.mock import patch

import pytest

from core.testing.processes import cleanup_on_startup_error, reap_on_exit
from core.testing.sandbox_state_scope import isolated_sandbox_state
from core.testing.state_isolation import pin_user_state_dirs


ROOT = Path(__file__).resolve().parents[3]
SOURCE = "core/run/tests/test_lifecycle_hook.py"
pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX identity stub")


def _helpers(*, all_streams, fault=None, error=None):
    view = ModuleType("subprocess")
    view.__dict__.update(vars(subprocess))
    processes, reads, waits = [], [], []

    class Reader:
        def __init__(self, stream):
            self.stream = stream

        def readline(self):
            reads.append("entered")
            if fault == "read_before":
                raise error("read interrupted")
            line = self.stream.readline()
            reads.append("consumed")
            if fault == "read_after":
                raise error("read interrupted")
            return "not ready\n" if fault == "wrong_ready" else line

        def close(self):
            self.stream.close()
            if fault == "close_after":
                raise error("close interrupted")

        @property
        def closed(self):
            return self.stream.closed

    def spawn(*args, **kwargs):
        if all_streams:
            kwargs.update(stdin=subprocess.PIPE, stderr=subprocess.PIPE)
        process = subprocess.Popen(*args, **kwargs)
        processes.append(process)
        process.stdout = Reader(process.stdout)
        kill, wait = process.kill, process.wait
        waiting = 0

        def killing():
            result = kill()
            if fault == "kill_after":
                raise error("kill interrupted")
            return result

        def awaiting(*args, **kwargs):
            nonlocal waiting
            waiting += 1
            waits.append(kwargs)
            result = wait(*args, **kwargs)
            if fault == "wait_after" and waiting == 1:
                raise error("wait interrupted")
            return result

        process.kill, process.wait = killing, awaiting
        return process

    view.Popen = spawn
    tree = ast.parse((ROOT / SOURCE).read_text())
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "TestSessionEndLivenessProof")
    nodes = [n for n in cls.body if getattr(n, "name", None) in ("_spawn_claude_shaped_stub", "_reap_stub")]
    for node in nodes:
        node.decorator_list = []
    namespace = dict(Path=Path, subprocess=view, sys=sys,
                     cleanup_on_startup_error=cleanup_on_startup_error, reap_on_exit=reap_on_exit)
    exec(compile(ast.Module(body=nodes, type_ignores=[]), SOURCE, "exec"), namespace)

    def cleaned():
        assert len(processes) == 1
        process = processes[0]
        assert process.returncode is not None
        assert all(stream is None or stream.closed for stream in (process.stdin, process.stdout, process.stderr))

    def guard():
        for process in processes:
            # A failed close injector may still be attached. The underlying
            # stream is independently owned by this external regression guard.
            reader = process.stdout
            with reap_on_exit(process):
                if isinstance(reader, Reader):
                    process.stdout = reader.stream

    return namespace, processes, reads, waits, cleaned, guard


@pytest.mark.parametrize("all_streams", [False, True])
@pytest.mark.parametrize("state", ["live", "reaped"])
@pytest.mark.parametrize("repeat", [False, True])
@pytest.mark.slow
def test_ready_stub_retains_identity_until_caller_cleanup(all_streams, state, repeat, tmp_path):
    helpers, processes, reads, waits, cleaned, guard = _helpers(all_streams=all_streams)
    try:
        process = helpers["_spawn_claude_shaped_stub"](tmp_path)
        assert process is processes[0]
        assert process.poll() is None
        assert not process.stdout.closed
        assert reads == ["entered", "consumed"]
        if sys.platform == "linux":
            assert Path(f"/proc/{process.pid}/comm").read_text().strip() == "claude"
        if state == "reaped":
            process.terminate()
            process.wait(timeout=10)
        helpers["_reap_stub"](process)
        if repeat:
            helpers["_reap_stub"](process)
        cleaned()
        assert waits[-1] == {"timeout": 10}
    finally:
        guard()


READ_FAULTS = [
    ("read_before", OSError), ("read_after", OSError),
    ("read_before", KeyboardInterrupt), ("read_after", KeyboardInterrupt),
    ("wrong_ready", AssertionError),
]


@pytest.mark.parametrize("all_streams", [False, True])
@pytest.mark.parametrize("fault,error", READ_FAULTS)
@pytest.mark.slow
def test_startup_read_failure_reaps_actual_child(all_streams, fault, error, tmp_path):
    helpers, _, reads, _, cleaned, guard = _helpers(all_streams=all_streams, fault=fault, error=error)
    try:
        with pytest.raises(error):
            helpers["_spawn_claude_shaped_stub"](tmp_path)
        assert reads == (["entered"] if fault == "read_before" else ["entered", "consumed"])
        cleaned()
    finally:
        guard()


CLEANUP_FAULTS = [
    ("live", "kill_after", OSError), ("live", "kill_after", KeyboardInterrupt),
    ("live", "wait_after", OSError), ("live", "wait_after", KeyboardInterrupt),
    ("reaped", "wait_after", OSError), ("reaped", "wait_after", KeyboardInterrupt),
    ("live", "close_after", OSError), ("live", "close_after", KeyboardInterrupt),
    ("reaped", "close_after", OSError), ("reaped", "close_after", KeyboardInterrupt),
]


@pytest.mark.parametrize("all_streams", [False, True])
@pytest.mark.parametrize("state,fault,error", CLEANUP_FAULTS)
@pytest.mark.slow
def test_cleanup_fault_still_reaps_and_attempts_stream_closure(all_streams, state, fault, error, tmp_path):
    helpers, _, _, _, cleaned, guard = _helpers(all_streams=all_streams)
    process = None
    original_stdout = original_kill = original_wait = None
    try:
        process = helpers["_spawn_claude_shaped_stub"](tmp_path)
        original_stdout, original_kill, original_wait = process.stdout, process.kill, process.wait
        if state == "reaped":
            process.terminate()
            process.wait(timeout=10)
        # Arm after readiness and any intentional pre-reap, so the fault
        # belongs to the cleanup boundary rather than fixture preparation.
        actual = process.stdout.stream

        class CloseError:
            def close(self):
                actual.close()
                raise error("close interrupted")

            @property
            def closed(self):
                return actual.closed

        kill, wait = process.kill, process.wait

        def kill_error():
            kill()
            raise error("kill interrupted")

        def wait_error(*args, **kwargs):
            wait(*args, **kwargs)
            raise error("wait interrupted")

        if fault == "kill_after":
            process.kill = kill_error
        elif fault == "wait_after":
            process.wait = wait_error
        else:
            process.stdout = CloseError()
        if fault == "close_after" and error is OSError:
            helpers["_reap_stub"](process)
        else:
            with pytest.raises(error):
                helpers["_reap_stub"](process)
        cleaned()
    finally:
        # Remove cleanup fault injection before the external safety guard.
        if process is not None:
            process.kill, process.wait = original_kill, original_wait
            process.stdout = original_stdout
        guard()


@pytest.mark.parametrize("all_streams", [False, True])
@pytest.mark.parametrize("error", [None, RuntimeError, KeyboardInterrupt])
@pytest.mark.slow
def test_native_caller_finally_owns_stub_through_unittest_exit(all_streams, error, tmp_path):
    helpers, _, _, _, cleaned, guard = _helpers(all_streams=all_streams)

    def body():
        process = helpers["_spawn_claude_shaped_stub"](tmp_path)
        try:
            assert process.poll() is None
            if error is not None:
                raise error("body interrupted")
        finally:
            helpers["_reap_stub"](process)

    result = unittest.TestResult()
    try:
        if error is KeyboardInterrupt:
            with pytest.raises(error):
                unittest.FunctionTestCase(body).run(result)
        else:
            unittest.FunctionTestCase(body).run(result)
        assert not result.failures
        assert len(result.errors) == (1 if error is RuntimeError else 0)
        cleaned()
    finally:
        guard()


@pytest.mark.parametrize("tuple_args", [False, True], ids=["list", "tuple"])
@pytest.mark.parametrize("mutation", ["assignment", "slice", "append"])
@pytest.mark.parametrize("finish", ["resume", "close", "error", "interrupt"])
def test_native_hook_input_scope_restores_borrowed_arguments(tuple_args, mutation, finish, monkeypatch):
    tree = ast.parse((ROOT / SOURCE).read_text())
    node = next(n for n in tree.body if getattr(n, "name", None) == "_stdin")
    namespace = dict(contextmanager=contextmanager, patch=patch, sys=sys, io=io)
    exec(compile(ast.Module(body=[node], type_ignores=[]), SOURCE, "exec"), namespace)
    borrowed = ("caller", "--owned") if tuple_args else ["caller", "--owned"]
    incoming = io.StringIO("caller input")
    monkeypatch.setattr(sys, "argv", borrowed)
    monkeypatch.setattr(sys, "stdin", incoming)
    context = namespace["_stdin"]("fixture input")
    expected = (pytest.raises(RuntimeError if finish == "error" else KeyboardInterrupt)
                if finish in ("error", "interrupt") else nullcontext())
    with expected:
        with context as stream:
            assert stream is sys.stdin
            assert stream.read() == "fixture input"
            assert sys.argv == list(borrowed)
            assert sys.argv is not borrowed
            if mutation == "assignment":
                sys.argv = ["hook", "stop"]
            elif mutation == "slice":
                sys.argv[:] = ["hook", "session-end"]
            else:
                sys.argv.append("--fixture")
            if finish == "close":
                context.gen.close()
            elif finish == "error":
                raise RuntimeError("body interrupted")
            elif finish == "interrupt":
                raise KeyboardInterrupt("body interrupted")
    assert sys.argv is borrowed
    assert list(borrowed) == ["caller", "--owned"]
    assert sys.stdin is incoming
    assert incoming.getvalue() == "caller input"


def _argument_callers():
    def owns_arguments(node):
        if isinstance(node, ast.Assign):
            return any(isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name)
                       and t.value.id == "sys" and t.attr == "argv" for t in node.targets)
        return (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name) and node.func.value.id == "patch"
                and node.func.attr == "object" and len(node.args) > 1
                and isinstance(node.args[0], ast.Name) and node.args[0].id == "sys"
                and isinstance(node.args[1], ast.Constant) and node.args[1].value == "argv")

    tree = ast.parse((ROOT / SOURCE).read_text())
    return [(cls.name, method.name) for cls in tree.body if isinstance(cls, ast.ClassDef)
            for method in cls.body if isinstance(method, ast.FunctionDef) and method.name.startswith("test_")
            and any(owns_arguments(node) for node in ast.walk(method))]


ARGUMENT_CALLERS = _argument_callers()


@contextmanager
def _caller_state(tmp_path):
    with isolated_sandbox_state(()), pytest.MonkeyPatch.context() as owner:
        owner.setenv("HOME", str(tmp_path / "home"))
        owner.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
        owner.setenv("RAPTOR_OUT_DIR", str(tmp_path / "out"))
        owner.delenv("_RAPTOR_SCRATCH_AUTH", raising=False)
        pin_user_state_dirs(owner, tmp_path / "registry")
        yield owner


@pytest.mark.parametrize("class_name,method_name", ARGUMENT_CALLERS, ids=[c + "." + m for c, m in ARGUMENT_CALLERS])
@pytest.mark.parametrize("error", [None, RuntimeError, KeyboardInterrupt])
@pytest.mark.slow
def test_native_argument_callers_restore_state_after_dispatch(class_name, method_name, error, tmp_path):
    with _caller_state(tmp_path) as owner:
        module = import_module("core.run.tests.test_lifecycle_hook")
        cls = getattr(module, class_name)
        method = getattr(cls, method_name)
        if getattr(cls, "__unittest_skip__", False) or getattr(method, "__unittest_skip__", False):
            pytest.skip("native caller is unavailable on this platform")
        borrowed = ["caller", "--owned"]
        owner.setattr(sys, "argv", borrowed)
        invoked = []

        def interrupted_dispatch():
            invoked.append(tuple(sys.argv))
            raise error("dispatch interrupted")

        case, result = cls(method_name), unittest.TestResult()
        if error is None:
            case.run(result)
            if result.skipped:
                pytest.skip(result.skipped[0][1])
            assert result.wasSuccessful(), (result.errors, result.failures)
        else:
            with patch.object(module._hook_mod, "main", interrupted_dispatch):
                if error is KeyboardInterrupt:
                    with pytest.raises(error, match="dispatch interrupted"):
                        case.run(result)
                else:
                    case.run(result)
            assert invoked, "the native dispatch boundary was not reached"
        assert sys.argv is borrowed
        assert borrowed == ["caller", "--owned"]


@pytest.mark.parametrize("helper_name", ["_run_stop_hook", "TestStopFreshnessFloor._stop"])
@pytest.mark.parametrize("tuple_args", [False, True], ids=["list", "tuple"])
@pytest.mark.parametrize("error", [None, RuntimeError, KeyboardInterrupt])
@pytest.mark.slow
def test_finalisation_argument_helpers_restore_caller(helper_name, tuple_args, error, tmp_path):
    with _caller_state(tmp_path) as owner:
        module = import_module("core.run.tests.test_hook_finalize_precedence")
        borrowed = ("caller", "--owned") if tuple_args else ["caller", "--owned"]
        owner.setattr(sys, "argv", borrowed)
        invoked = []

        def interrupted_dispatch():
            invoked.append(tuple(sys.argv))
            raise error("dispatch interrupted")

        def invoke():
            if helper_name == "_run_stop_hook":
                module._run_stop_hook(tmp_path)
            else:
                module.TestStopFreshnessFloor()._stop(str(tmp_path))

        if error is None:
            invoke()
        else:
            with patch.object(module._hook_mod, "main", interrupted_dispatch):
                with pytest.raises(error, match="dispatch interrupted"):
                    invoke()
            assert invoked == [("hook", "stop")]
        assert sys.argv is borrowed
        assert list(borrowed) == ["caller", "--owned"]
