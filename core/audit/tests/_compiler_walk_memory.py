"""Load the walk memory case without compiler availability probes."""

import ast
from pathlib import Path
from types import ModuleType

from core.testing.processes import run_in_process_group as _run_memory_process


def load_memory_module():
    """Execute only the original declarations needed by the selected case."""
    from core.audit import compiler_sweep

    source = Path(__file__).with_name("test_compiler_sweep.py")
    tree = ast.parse(source.read_text(), filename=str(source))
    selected = []
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module == "__future__":
            selected.append(node)
        elif isinstance(node, ast.FunctionDef) and node.name in {"_write", "_clean"}:
            assert not node.decorator_list and not node.args.defaults
            assert not node.args.kw_defaults
            selected.append(node)
        elif isinstance(node, ast.ClassDef) and node.name == "TestChangePointOwners":
            assert not node.bases and not node.keywords and not node.decorator_list
            assert all(
                isinstance(method, ast.FunctionDef)
                and not method.decorator_list and not method.args.defaults
                and not method.args.kw_defaults
                for method in node.body
            )
            selected.append(node)
    assert len(selected) == 4
    module = ModuleType("owned_compiler_walk_memory")
    module.__file__ = str(source)
    module.__dict__.update(Path=Path, compiler_sweep=compiler_sweep)
    exec(compile(ast.Module(body=selected, type_ignores=[]), str(source), "exec"),
         module.__dict__)
    return module


def run_memory_proof(tmp_path):
    """Measure the exact source-backed method in a fresh owned interpreter."""
    import subprocess
    import sys

    from core.testing.standalone_cli import standalone_cli_env

    root = Path(__file__).resolve().parents[3]
    script = """\
import sys
import tracemalloc
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from pytest import MonkeyPatch
from core.testing.state_isolation import pin_user_state_dirs
from core.audit.tests._compiler_walk_memory import load_memory_module
assert not tracemalloc.is_tracing()
owned = Path(sys.argv[2])
with MonkeyPatch.context() as patch:
    pin_user_state_dirs(patch, owned / "memory-child-state")
    native = load_memory_module()
    native.TestChangePointOwners().test_layer2_walk_memory_is_not_per_line(owned)
assert not tracemalloc.is_tracing()
print("compiler-walk-memory-proof-ok")
"""
    with standalone_cli_env() as env:
        result = _run_memory_process(
            [sys.executable, "-I", "-c", script, str(root), str(tmp_path)],
            timeout=30, env=env, cwd=root,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "compiler-walk-memory-proof-ok", result.stdout
