"""Selected terminal-writer race without importing unrelated test probes."""

import ast
import builtins
from copy import copy
from pathlib import Path
from tempfile import TemporaryDirectory
from types import ModuleType
import unittest

ROOT = Path(__file__).resolve().parents[3]


def load_worker_module(thread_view=None, directory=None):
    from core.json import load_json
    from core.run import metadata

    source = ROOT / "core/run/tests/test_metadata.py"
    module = ModuleType("owned_terminal_metadata_test")
    module.__file__ = str(source)
    module.__dict__.update(Path=Path, TemporaryDirectory=TemporaryDirectory if directory is None else directory,
                          unittest=unittest, RUN_METADATA_FILE=metadata.RUN_METADATA_FILE, load_json=load_json)

    def importer(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 0 and name == "threading" and thread_view is not None:
            return thread_view
        return builtins.__import__(name, globals, locals, fromlist, level)

    module.__dict__["__builtins__"] = dict(vars(builtins), __import__=importer)
    tree = ast.parse(source.read_text(), filename=str(source))
    cls = copy(next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "TestUpdateStatusConcurrency"))
    assert [ast.unparse(n) for n in cls.bases] == ["unittest.TestCase"] and not cls.decorator_list
    cls.body = [n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == "test_racing_terminal_writers_keep_first_verdict"]
    assert len(cls.body) == 1 and not cls.body[0].decorator_list
    exec(compile(ast.Module(body=[cls], type_ignores=[]), str(source), "exec"), vars(module))
    return module
