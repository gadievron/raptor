"""The e2e scripts spawn child-process trees that re-import RAPTOR;
each must hard-pin RAPTOR_DIR to THIS checkout so a stale env export
for another checkout can't make the children validate the wrong tree.
Mechanical parity check across the sibling scripts — the deepest
child-spawner (execute-witness) is exactly the one where an unpinned
env does the most damage.

Checked on the parsed AST, not source text: the previous source-grep
also passed on a commented-out call. A module-level ``Expr(Call(...))``
cannot be faked by a comment, and executing the e2e scripts at import
time just to observe the pin would drag their heavy import graphs into
the unit suite.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

_SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"


def _module_level_calls(tree: ast.Module) -> list[str]:
    """Names of functions invoked as bare module-level statements."""
    names = []
    for node in tree.body:
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            func = node.value.func
            if isinstance(func, ast.Name):
                names.append(func.id)
            elif isinstance(func, ast.Attribute):
                names.append(func.attr)
    return names


@pytest.mark.parametrize("script", [
    "e2e_execute_witness.py",
    "e2e_verify_exploit.py",
    "e2e_intent_match.py",
])
def test_e2e_script_pins_raptor_dir(script: str) -> None:
    tree = ast.parse(
        (_SCRIPTS_DIR / script).read_text(encoding="utf-8"),
        filename=script,
    )
    assert "pin_raptor_dir_in_environ" in _module_level_calls(tree), (
        f"{script}: no module-level pin_raptor_dir_in_environ() call — "
        "child processes would inherit a stale RAPTOR_DIR"
    )
