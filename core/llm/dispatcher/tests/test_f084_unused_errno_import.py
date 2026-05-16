"""Regression test for F084.

``core/llm/dispatcher/server.py`` had ``import errno`` at module top
with zero references in the file. Likely a leftover from earlier
socket-error-handling scaffolding (peer-UID verification handles
``OSError`` directly, not via errno codes).

Mirrors the F091 cleanup style — ``cleanup(core/smt_solver/availability):
drop unused 'import os'`` (commit 4bcaadb).

The test is AST-based so it doesn't need to import the dispatcher
module (which pulls in heavy socket/threading machinery). It parses
``server.py`` with ``ast`` and asserts every top-level module import
is referenced somewhere by ``ast.Name`` or ``ast.Attribute`` in the
file.
"""

from __future__ import annotations

import ast
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "server.py"


def _collect_top_level_imports(tree: ast.Module) -> set[str]:
    """Return the names introduced by top-level ``import X`` statements.

    Skipped: ``from X import Y`` (those names are usually re-exported
    or used as decorators and have more nuanced reachability) and
    aliased imports inside function bodies (lazy imports are
    deliberately not at module top).
    """
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.asname or alias.name.split(".")[0])
    return names


def _collect_referenced_names(tree: ast.Module) -> set[str]:
    """Walk the module collecting Name/Attribute base identifiers."""
    refs: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            refs.add(node.id)
        elif isinstance(node, ast.Attribute):
            # find the leftmost base of a.b.c
            base = node
            while isinstance(base, ast.Attribute):
                base = base.value
            if isinstance(base, ast.Name):
                refs.add(base.id)
    return refs


def test_dispatcher_server_has_no_unused_top_level_imports() -> None:
    source = MODULE_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)

    imported = _collect_top_level_imports(tree)
    referenced = _collect_referenced_names(tree)
    unused = imported - referenced

    assert not unused, (
        f"dispatcher/server.py imports {sorted(unused)} at module top "
        f"with zero references in the file body. Drop the import(s)."
    )
