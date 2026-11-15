"""Normal macOS parent retirement using actual source and inert owners."""

import ast
from collections.abc import Callable
import contextlib
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest


SANDBOX = Path(__file__).resolve().parents[1]
CASES = [(slot, sweep, False) for slot in (None, "stdout", "stderr", "stdin")
         for sweep in ("none", "ordinary", "cancel")]
CASES += [(None, "ordinary", True), ("stdout", "ordinary", True),
          ("absent", "none", False)]
IDS = [f"{slot or 'healthy'}-{sweep}{'-log' if log else ''}"
       for slot, sweep, log in CASES]


@pytest.mark.parametrize("case", CASES, ids=IDS)
def test_normal_stream_retirement_always_attempts_descendant_sweep(case):
    slot, sweep_kind, log_fails = case
    tree = ast.parse((SANDBOX / "_macos_spawn.py").read_text())
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef)
              and n.name == "run_sandboxed")
    owner = next(n for n in fn.body if isinstance(n, ast.Try)
                 and any(isinstance(v, ast.Name) and v.id == "_stop_audit_streamer"
                         for v in ast.walk(ast.Module(body=n.finalbody, type_ignores=[]))))
    selected = []
    for node in owner.body:
        if (isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
                and isinstance(node.value.func, ast.Name)
                and node.value.func.id == "_retire_parent_resources"
                and any(isinstance(a, ast.Starred) for a in node.value.args)):
            selected.append(node)
        elif (isinstance(node, ast.Try)
              and any(isinstance(v, ast.Call) and isinstance(v.func, ast.Name)
                      and v.func.id == "_sweep_descendants" for v in ast.walk(node))):
            selected.append(node)
        elif isinstance(node, ast.FunctionDef) and node.name == "_sweep_after_wait":
            selected.append(node)
    assert len(selected) == 2
    events = []
    close_error = {"stdout": KeyboardInterrupt("close stdout"),
                   "stderr": MemoryError("close stderr"),
                   "stdin": OSError("close stdin")}.get(slot)
    sweep_error = (OSError("sweep failed") if sweep_kind == "ordinary"
                   else KeyboardInterrupt("sweep cancelled"))
    log_error = MemoryError("warning failed")

    def close(name):
        def retire():
            events.append(name)
            if name == slot:
                raise close_error
        return retire

    def harvest():
        events.append("harvest")
        return b"G114\n"

    def parse(report):
        events.append("parse")
        assert report == b"G114\n"
        return 114

    def sweep(pid, *, extra_pgids):
        events.append("sweep")
        assert pid == 31337 and extra_pgids == (114,)
        if sweep_kind != "none":
            raise sweep_error

    def warning(*args, **kwargs):
        events.append("warning")
        assert kwargs == {"exc_info": True}
        if log_fails:
            raise log_error

    namespace = dict(Callable=Callable, contextlib=contextlib, sys=sys,
                     _process=SimpleNamespace(pid=31337,
                                              stdout=SimpleNamespace(close=close("stdout")),
                                              stderr=SimpleNamespace(close=close("stderr")),
                                              stdin=SimpleNamespace(close=close("stdin"))),
                     _harvest_status=harvest, _parse_group_report=parse,
                     _sweep_descendants=sweep, logger=SimpleNamespace(warning=warning))
    if slot == "absent":
        namespace["_process"].stdout = None
        namespace["_process"].stderr = None
        namespace["_process"].stdin = None
    retirement = ast.parse((SANDBOX / "_retirement.py").read_text())
    nodes = [n for n in retirement.body
             if isinstance(n, (ast.ClassDef, ast.Assign, ast.FunctionDef))]
    exec(compile(ast.Module(body=nodes, type_ignores=[]),
                 "<actual-parent-retirement>", "exec"), namespace)
    namespace["_retire_parent_resources"] = namespace["retire_parent_resources"]
    escaped = None
    try:
        exec(compile(ast.Module(body=selected, type_ignores=[]),
                     "<actual-normal-macos-retirement>", "exec"), namespace)
    except BaseException as error:
        escaped = error
    assert events == ([] if slot == "absent" else ["stdout", "stderr", "stdin"]) + (
        ["harvest", "parse", "sweep"]) + (
        ["warning"] if sweep_kind == "ordinary" else [])
    expected = (close_error if close_error is not None
                else log_error if log_fails
                else sweep_error if sweep_kind == "cancel" else None)
    assert escaped is expected
