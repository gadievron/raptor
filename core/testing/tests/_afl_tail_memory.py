"""Exact source-backed tail proof without importing the fuzzing package."""

import ast
from copy import copy
import os
from pathlib import Path
import re
from types import ModuleType

ROOT = Path(__file__).resolve().parents[3]


def _class_node(tree, name, method):
    node = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == name)
    assert not node.bases and not node.keywords and not node.decorator_list
    selected = [n for n in node.body if isinstance(n, ast.FunctionDef) and n.name == method]
    assert len(selected) == 1
    result = copy(node)
    result.body = selected
    return result


def load_memory_module():
    native = ROOT / "packages/fuzzing/tests/test_afl_runner.py"
    producer = ROOT / "packages/fuzzing/afl_runner.py"
    sanitizer = ROOT / "packages/fuzzing/output_hygiene.py"
    module = ModuleType("owned_afl_tail_memory")
    module.__file__ = str(native)
    module.__dict__.update(os=os, Path=Path, re=re)
    tree = ast.parse(sanitizer.read_text(), filename=str(sanitizer))
    selected = []
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module == "__future__":
            selected.append(node)
        elif isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id == "_CONTROL_CHARS_RE":
            assert isinstance(node.value, ast.Call) and ast.unparse(node.value.func) == "re.compile"
            assert len(node.value.args) == 1 and isinstance(node.value.args[0], ast.Constant)
            assert isinstance(node.value.args[0].value, str) and not node.value.keywords
            selected.append(node)
        elif isinstance(node, ast.FunctionDef) and node.name == "strip_terminal_controls":
            assert not node.decorator_list and not node.args.defaults
            selected.append(node)
    assert len(selected) == 3
    exec(compile(ast.Module(body=selected, type_ignores=[]), str(sanitizer), "exec"), module.__dict__)
    tree = ast.parse(producer.read_text(), filename=str(producer))
    cls = _class_node(tree, "AFLRunner", "_tail_file")
    assert [ast.unparse(n) for n in cls.body[0].decorator_list] == ["staticmethod"]
    exec(compile(ast.Module(body=[cls], type_ignores=[]), str(producer), "exec"), module.__dict__)
    tree = ast.parse(native.read_text(), filename=str(native))
    selected = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_run_afl_tail_memory_proof"]
    if selected:
        assert len(selected) == 1
        from core.testing.processes import run_in_process_group

        module._run_memory_process = run_in_process_group
    cls = _class_node(tree, "TestBoundedTargetWritableReads", "test_tail_file_does_not_materialise_whole_file")
    assert not cls.body[0].decorator_list
    selected.append(cls)
    exec(compile(ast.Module(body=selected, type_ignores=[]), str(native), "exec"), module.__dict__)
    return module
