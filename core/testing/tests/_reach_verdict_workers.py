"""Selected counter, fixture and worker source without import-time hooks."""

import ast
import builtins
from copy import copy
import os
from pathlib import Path
import threading
from types import ModuleType

from core.testing.threads import retiring_threads

ROOT = Path(__file__).resolve().parents[3]


def load_worker_module(thread_view=None, borrowed=None):
    production = ROOT / "core/analysis/reach_verdict_log.py"
    source = ROOT / "core/analysis/tests/test_reach_verdict_log.py"
    producer = ModuleType("owned_reach_verdict_log")
    producer.__file__ = str(production)
    producer.os = os
    producer._LOCK = threading.Lock()
    producer._IN_MEMORY = {} if borrowed is None else borrowed
    tree = ast.parse(production.read_text(), filename=str(production))
    nodes = [n for n in tree.body if isinstance(n, ast.ImportFrom) and n.module == "__future__"]
    record = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "record_verdict")
    assert not record.decorator_list
    nodes.append(record)
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(production), "exec"), vars(producer))
    module = ModuleType("owned_reach_verdict_test")
    module.__file__ = str(source)
    module.__dict__.update(reach_verdict_log=producer, Path=Path, retiring_threads=retiring_threads)

    def importer(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 0 and name == "threading" and thread_view is not None:
            return thread_view
        return builtins.__import__(name, globals, locals, fromlist, level)

    module.__dict__["__builtins__"] = dict(vars(builtins), __import__=importer)
    tree = ast.parse(source.read_text(), filename=str(source))
    nodes = [n for n in tree.body if isinstance(n, ast.ImportFrom) and n.module == "__future__"]
    fixture = copy(next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_isolated_sidecar"))
    assert len(fixture.decorator_list) == 1
    fixture.decorator_list = []
    test = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "test_concurrent_record_threadsafe")
    assert not test.decorator_list
    nodes.extend([fixture, test])
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(source), "exec"), vars(module))
    return module
