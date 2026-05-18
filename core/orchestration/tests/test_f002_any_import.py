"""Regression test for F002.

``core/orchestration/agentic_passes.py`` uses ``Optional[Any]`` at line 120
but only imports ``Optional`` from ``typing`` — ``Any`` is referenced but
never imported. Under ``from __future__ import annotations`` the bug is
latent at module-load (annotations are strings) but blows up the moment
anything calls ``typing.get_type_hints`` on ``UnderstandPrepassResult``
(dataclass introspection, pydantic-style validation, etc.).

This test parses the module with ``ast`` (no heavy import needed — keeps
the test runnable with stdlib + pytest only) and asserts: if a name from
``typing`` is referenced in a type annotation, it must be in the
``from typing import ...`` clause.
"""

from __future__ import annotations

import ast
from pathlib import Path

MODULE_PATH = (
    Path(__file__).resolve().parents[1] / "agentic_passes.py"
)


def _collect_typing_imports(tree: ast.Module) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "typing":
            for alias in node.names:
                names.add(alias.asname or alias.name)
    return names


def _collect_typing_refs_in_annotations(tree: ast.Module) -> set[str]:
    """Return Names appearing inside annotation contexts.

    Limits the scan to typing-ish capitalised identifiers we care about
    (Any, Optional, Union, List, Dict, Tuple, Callable, etc.) so we don't
    flag user-defined classes used as types.
    """
    candidates = {
        "Any",
        "Optional",
        "Union",
        "List",
        "Dict",
        "Tuple",
        "Set",
        "Callable",
        "Iterable",
        "Iterator",
        "Sequence",
        "Mapping",
        "Type",
        "ClassVar",
        "Final",
        "Literal",
    }
    refs: set[str] = set()

    def visit_annotation(node: ast.AST) -> None:
        for sub in ast.walk(node):
            if isinstance(sub, ast.Name) and sub.id in candidates:
                refs.add(sub.id)

    for node in ast.walk(tree):
        # function arg + return annotations
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for arg in (
                node.args.args
                + node.args.kwonlyargs
                + node.args.posonlyargs
            ):
                if arg.annotation is not None:
                    visit_annotation(arg.annotation)
            if node.returns is not None:
                visit_annotation(node.returns)
        # AnnAssign (class-body and module-level annotated assigns)
        elif isinstance(node, ast.AnnAssign):
            if node.annotation is not None:
                visit_annotation(node.annotation)
    return refs


def test_agentic_passes_typing_names_are_imported() -> None:
    """Any name from `typing` used in an annotation must be imported."""
    source = MODULE_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)

    imported = _collect_typing_imports(tree)
    referenced = _collect_typing_refs_in_annotations(tree)
    missing = referenced - imported

    assert not missing, (
        f"agentic_passes.py references {sorted(missing)} from typing "
        f"in annotations but doesn't import them. "
        f"Imported: {sorted(imported)}. Referenced: {sorted(referenced)}."
    )
