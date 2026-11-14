"""Audit pipe read failures using actual source and inert I/O owners."""

import ast
from collections.abc import Callable, Iterable
import contextlib
from copy import deepcopy
import errno
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest


SANDBOX = Path(__file__).resolve().parents[1]


def drain_view(script, *, deadline=None, ready=True):
    tree = ast.parse((SANDBOX / "_landlock_audit.py").read_text())
    function = next(node for node in tree.body
                    if isinstance(node, ast.FunctionDef)
                    and node.name == "_drain_pipes_until_eof")
    reads = iter(script)
    events = []
    clock = iter(index / 100 for index in range(100))

    def read(fd, size):
        assert fd in (71, 72) and size == 65536
        value = next(reads)
        events.append(value)
        if isinstance(value, BaseException):
            raise value
        return value

    namespace = {
        "Iterable": Iterable,
        "os": SimpleNamespace(read=read, waitid=lambda *args: None,
                              P_PID=1, WEXITED=2, WNOHANG=4, WNOWAIT=8),
        "time": SimpleNamespace(monotonic=lambda: next(clock)),
        "logger": SimpleNamespace(warning=lambda *args: None),
        "_readable_fds": lambda fds, wait: list(fds) if ready else [],
        "_DRAIN_IDLE_POLL_S": 0.05,
        "_DRAIN_LIVENESS_POLL_S": 0.05,
        "_DRAIN_FINAL_SWEEP_S": 0.2,
        "_DRAIN_MAX_BYTES_PER_FD": 1024,
    }
    exec(compile(ast.Module(body=[function], type_ignores=[]),
                 "<actual-audit-drain>", "exec"), namespace)
    return namespace, events


@pytest.mark.parametrize("fault", [BlockingIOError(errno.EAGAIN, "retry"),
                                  InterruptedError(errno.EINTR, "retry")])
@pytest.mark.parametrize("prefix", [b"", b"before"])
def test_transient_read_fault_keeps_stream_open(fault, prefix):
    script = ([prefix] if prefix else []) + [fault, b"after", b""]
    namespace, events = drain_view(script)
    result = namespace["_drain_pipes_until_eof"]([71], 73)
    assert result == {71: prefix + b"after"}
    assert events == script


@pytest.mark.parametrize("code", [errno.EIO, errno.EBADF])
@pytest.mark.parametrize("prefix", [b"", b"before"])
def test_unexpected_read_error_is_not_reported_as_eof(code, prefix):
    failure = OSError(code, "read failed")
    script = ([prefix] if prefix else []) + [failure]
    namespace, events = drain_view(script)
    with pytest.raises(OSError) as caught:
        namespace["_drain_pipes_until_eof"]([71], 73)
    assert caught.value is failure
    assert events == script


def test_healthy_data_and_eof_remain_unchanged():
    script = [b"before", b"after", b""]
    namespace, events = drain_view(script)
    assert namespace["_drain_pipes_until_eof"]([71], 73) == {71: b"beforeafter"}
    assert events == script


def test_repeated_transient_reads_still_obey_deadline():
    fault = BlockingIOError(errno.EAGAIN, "retry")
    namespace, events = drain_view([fault] * 20)
    assert namespace["_drain_pipes_until_eof"]([71], 73, deadline=0.05) == {71: b""}
    assert 1 <= len(events) < 20


def test_cancellation_is_not_a_capture_result():
    cancellation = KeyboardInterrupt("cancelled")
    namespace, events = drain_view([cancellation])
    with pytest.raises(KeyboardInterrupt) as caught:
        namespace["_drain_pipes_until_eof"]([71], 73)
    assert caught.value is cancellation
    assert events == [cancellation]


@pytest.mark.parametrize("cleanup_fails", [False, True])
def test_actual_caller_retires_all_owners_with_read_error_primary(cleanup_fails):
    failure = OSError(errno.EIO, "capture read failed")
    namespace, reads = drain_view([failure])
    tree = ast.parse((SANDBOX / "_landlock_audit.py").read_text())
    caller = next(node for node in tree.body
                  if isinstance(node, ast.FunctionDef) and node.name == "run_landlock_audit")
    owner = deepcopy(next(node for node in caller.body
                          if isinstance(node, ast.Try) and node.finalbody
                          and any(isinstance(item, ast.Call)
                                  and isinstance(item.func, ast.Name)
                                  and item.func.id == "_retire_parent_resources"
                                  for item in ast.walk(ast.Module(body=node.finalbody, type_ignores=[])))))
    capture = next(node for node in owner.body
                   if isinstance(node, ast.If) and isinstance(node.test, ast.Name)
                   and node.test.id == "_capture_any"
                   and any(isinstance(item, ast.Call)
                           and isinstance(item.func, ast.Name)
                           and item.func.id == "_drain_pipes_until_eof"
                           for item in ast.walk(node)))
    # Execute the actual capture call and its original exception/finally owner;
    # omit setup/native execution and the success-only return construction.
    owner.body = [capture]
    retirement = ast.parse((SANDBOX / "_retirement.py").read_text())
    selected = [node for node in retirement.body
                if isinstance(node, (ast.ClassDef, ast.Assign, ast.FunctionDef))]
    namespace.update(Callable=Callable, contextlib=contextlib, sys=sys)
    exec(compile(ast.Module(body=selected, type_ignores=[]),
                 "<actual-parent-retirement>", "exec"), namespace)
    events = []

    def cleanup(name):
        def retire():
            events.append(name)
            if cleanup_fails and name == "fds":
                raise MemoryError("cleanup failed")
        return retire

    namespace.update(_capture_any=True, out_r=71, err_r=72, target_pid=73,
                     deadline=None, _operation_error=None,
                     _retire_parent_resources=namespace["retire_parent_resources"],
                     _cleanup_fds=cleanup("fds"), _retire_target=cleanup("target"),
                     _retire_tracer=cleanup("tracer"), _retire_config=cleanup("config"),
                     _retire_evidence=cleanup("evidence"))
    with pytest.raises(OSError) as caught:
        exec(compile(ast.Module(body=[owner], type_ignores=[]),
                     "<actual-audit-capture-owner>", "exec"), namespace)
    assert caught.value is failure
    assert reads == [failure]
    assert events == ["fds", "target", "tracer", "config", "evidence"]
