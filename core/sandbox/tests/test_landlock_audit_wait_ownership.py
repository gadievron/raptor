"""Normal audit waits retain child ownership when an observation is interrupted."""

import ast
from collections.abc import Callable
import contextlib
from copy import deepcopy
import errno
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest


SANDBOX = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("site", ["timed", "blocking", "tracer"])
@pytest.mark.parametrize("case", ["interrupt", "cancel", "lost", "hard", "terminal",
                                 "interrupt_cleanup"])
def test_actual_normal_wait_and_retirement_ownership(site, case):
    tree = ast.parse((SANDBOX / "_landlock_audit.py").read_text())
    caller = next(n for n in tree.body if isinstance(n, ast.FunctionDef)
                  and n.name == "run_landlock_audit")
    owner = deepcopy(next(n for n in caller.body if isinstance(n, ast.Try)
                          and any(isinstance(v, ast.Call) and isinstance(v.func, ast.Name)
                                  and v.func.id == "_retire_parent_resources"
                                  for v in ast.walk(ast.Module(body=n.finalbody, type_ignores=[])))))
    wanted = "tracer_pid" if site == "tracer" else "target_pid"
    statements = [n for n in owner.body if isinstance(n, ast.If)
                  and any(isinstance(v, ast.Call) and isinstance(v.func, ast.Attribute)
                          and v.func.attr == "waitpid" and v.args
                          and isinstance(v.args[0], ast.Name) and v.args[0].id == wanted
                          for v in ast.walk(n))]
    if site == "tracer":
        fragment = next(n for n in statements if isinstance(n.test, ast.Compare)
                        and isinstance(n.test.left, ast.Name) and n.test.left.id == "tracer_pid")
    else:
        fragment = next(n for n in statements if isinstance(n.test, ast.Compare)
                        and isinstance(n.test.left, ast.Name) and n.test.left.id == "deadline")
    owner.body = [fragment]
    failure = (KeyboardInterrupt("cancelled") if case == "cancel"
               else ChildProcessError("already reaped") if case == "lost"
               else OSError(errno.EIO, "legacy wait error") if case == "hard"
               else InterruptedError(errno.EINTR, "interrupted"))
    waits, callbacks, retained = [], [], []

    def waitpid(pid, flags):
        waits.append((pid, flags))
        assert len(waits) == 1
        if case == "terminal":
            return pid, 0
        raise failure

    namespace = dict(Callable=Callable, contextlib=contextlib, sys=sys,
                     os=SimpleNamespace(waitpid=waitpid, WNOHANG=1,
                                        WIFEXITED=lambda status: True,
                                        WEXITSTATUS=lambda status: 0),
                     time=SimpleNamespace(monotonic=lambda: 0, sleep=lambda delay: None),
                     subprocess=subprocess, target_pid=73 if site != "tracer" else -1,
                     tracer_pid=74 if site == "tracer" else -1,
                     target_rc=-1, deadline=1 if site == "timed" else None,
                     _TRACER_REAP_TIMEOUT_S=1, _operation_error=None)
    retirement = ast.parse((SANDBOX / "_retirement.py").read_text())
    selected = [n for n in retirement.body
                if isinstance(n, (ast.ClassDef, ast.Assign, ast.FunctionDef))]
    exec(compile(ast.Module(body=selected, type_ignores=[]),
                 "<actual-parent-retirement>", "exec"), namespace)

    def cleanup(name):
        def retire():
            callbacks.append(name)
            if name in ("target", "tracer"):
                pid = namespace[name + "_pid"]
                if pid > 0:
                    retained.append((name, pid))
                    namespace[name + "_pid"] = -1
            if name == "fds" and case == "interrupt_cleanup":
                raise MemoryError("secondary cleanup error")
        return retire

    namespace.update(_retire_parent_resources=namespace["retire_parent_resources"],
                     _cleanup_fds=cleanup("fds"), _retire_target=cleanup("target"),
                     _retire_tracer=cleanup("tracer"), _retire_config=cleanup("config"),
                     _retire_evidence=cleanup("evidence"))
    code = compile(ast.Module(body=[owner], type_ignores=[]),
                   "<actual-normal-wait-and-owner>", "exec")
    if case in ("interrupt", "cancel", "interrupt_cleanup"):
        with pytest.raises(BaseException) as caught:
            exec(code, namespace)
        assert caught.value is failure
        assert retained == [("tracer", 74) if site == "tracer" else ("target", 73)]
    else:
        exec(code, namespace)
        assert retained == []
    assert callbacks == ["fds", "target", "tracer", "config", "evidence"]
    assert waits == [(74 if site == "tracer" else 73, 0 if site == "blocking" else 1)]
