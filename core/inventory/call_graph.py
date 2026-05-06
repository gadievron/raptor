"""Per-file call-graph extraction.

Companion to :mod:`core.inventory.extractors`, which captures
function *definitions*. This module captures the data needed to
answer "is qualified function ``X.Y.Z`` actually called from this
project?":

  * **Import map** — for each imported name available in the file's
    namespace, the dotted target it resolves to. ``import requests``
    → ``{"requests": "requests"}``. ``import os.path as p`` →
    ``{"p": "os.path"}``. ``from requests.utils import
    extract_zipped_paths as ezp`` → ``{"ezp":
    "requests.utils.extract_zipped_paths"}``.

  * **Call sites** — every call expression in the file, recorded as
    the attribute chain of the callee (``foo.bar.baz()`` →
    ``["foo", "bar", "baz"]``), plus the line and the enclosing
    function name. We don't record arguments or the call's value;
    the resolver only needs "did this name get called".

  * **Indirection flags** — set bits indicating the file does
    something the static analysis can't follow:
      * ``getattr(mod, "name")(...)`` — name-by-string dispatch.
      * ``importlib.import_module("x.y")`` — runtime import.
      * ``from x import *`` — wildcard imports a name we can't
        statically know.

Indirection flags are file-scoped (not per-call) because once any
of them is present, every NOT_CALLED claim about that file becomes
UNCERTAIN. Tracking per-call would let the resolver narrow the
uncertainty, but the resolver consumers (SCA reachability, codeql
pre-filter) treat UNCERTAIN as "don't downgrade severity" anyway —
finer granularity buys nothing.

Pure-AST. We never ``import_module`` the target, never look at any
filesystem outside the source tree. String-shape only.

This module is Python-only at first cut. JavaScript / Go / Java
extension is straightforward — replace ``_PythonCallGraph`` with a
language-specific AST walker that emits the same dataclasses. The
resolver in :mod:`core.inventory.reachability` is language-agnostic.
"""

from __future__ import annotations

import ast
import logging
import warnings
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

logger = logging.getLogger(__name__)


# Indirection-flag values. Strings (not enum) so they round-trip
# through JSON cleanly without a from_dict shim.
INDIRECTION_GETATTR = "getattr"
INDIRECTION_IMPORTLIB = "importlib"
INDIRECTION_WILDCARD_IMPORT = "wildcard_import"
INDIRECTION_DUNDER_IMPORT = "dunder_import"     # __import__("x.y")


@dataclass
class CallSite:
    """One call expression in a file.

    ``chain`` is the attribute chain of the callee. ``foo.bar.baz()``
    → ``["foo", "bar", "baz"]``. Plain function call ``f()`` →
    ``["f"]``. Calls with non-name callees (e.g. ``(lambda x: x)()``,
    ``f()()``, ``arr[0]()``) are NOT emitted — we have no qualified
    name to match against.

    ``caller`` is the name of the lexically-enclosing function /
    method, or ``None`` for module-level calls. The resolver doesn't
    use this today, but it's cheap to capture and useful for future
    "transitively reachable from entry-point X" queries.
    """
    line: int
    chain: List[str]
    caller: Optional[str] = None


@dataclass
class FileCallGraph:
    """All call-graph data for one Python file.

    ``getattr_targets`` records the literal string second-arguments
    seen in ``getattr(obj, "name")(...)`` calls. The resolver uses
    this to detect "the file is plausibly calling target_func via
    string dispatch" — a file that contains
    ``getattr(requests, 'get')`` is a confounder for queries about
    ``requests.get`` even if no static call chain has tail ``get``.
    """
    imports: Dict[str, str] = field(default_factory=dict)
    calls: List[CallSite] = field(default_factory=list)
    indirection: Set[str] = field(default_factory=set)
    getattr_targets: Set[str] = field(default_factory=set)

    def to_dict(self) -> dict:
        return {
            "imports": dict(self.imports),
            "calls": [
                {"line": c.line, "chain": list(c.chain),
                 "caller": c.caller}
                for c in self.calls
            ],
            "indirection": sorted(self.indirection),
            "getattr_targets": sorted(self.getattr_targets),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "FileCallGraph":
        return cls(
            imports=dict(d.get("imports") or {}),
            calls=[
                CallSite(
                    line=int(c.get("line", 0)),
                    chain=list(c.get("chain") or []),
                    caller=c.get("caller"),
                )
                for c in (d.get("calls") or [])
            ],
            indirection=set(d.get("indirection") or []),
            getattr_targets=set(d.get("getattr_targets") or []),
        )


def extract_call_graph_python(content: str) -> FileCallGraph:
    """Walk a Python source string and return its
    :class:`FileCallGraph`.

    Returns an empty graph (no imports, no calls, no indirection)
    on syntax errors — a malformed file shouldn't blow up the
    inventory build, and the resolver treats "no data" as "no
    evidence", which collapses to NOT_CALLED for the function in
    question (correct: a file we can't parse can't demonstrably
    call anything).
    """
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            tree = ast.parse(content)
    except SyntaxError as e:
        logger.debug("call_graph: skip unparseable file (%s)", e)
        return FileCallGraph()

    walker = _PythonCallGraph()
    walker.visit(tree)
    return walker.graph


class _PythonCallGraph(ast.NodeVisitor):
    """Single-pass AST walk emitting imports + call sites + flags."""

    def __init__(self) -> None:
        self.graph = FileCallGraph()
        # Stack of enclosing function names, top is innermost.
        self._enclosing: List[str] = []

    # ------------------------------------------------------------------
    # Imports
    # ------------------------------------------------------------------

    def visit_Import(self, node: ast.Import) -> None:
        # ``import x``                  → {"x": "x"}
        # ``import x.y``                → {"x": "x"} (the binding is x,
        #                                  not x.y — Python convention)
        # ``import x.y as p``           → {"p": "x.y"}
        for alias in node.names:
            target = alias.name
            if alias.asname is not None:
                self.graph.imports[alias.asname] = target
            else:
                # Bound name is the first component.
                first = target.split(".", 1)[0]
                self.graph.imports[first] = first
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        # ``from x.y import z``         → {"z": "x.y.z"}
        # ``from x.y import z as q``    → {"q": "x.y.z"}
        # ``from x import *``           → flag wildcard, no map entry
        # ``from . import z``           → relative; skip (we don't
        #                                  resolve package roots here)
        module = node.module or ""
        if node.level and node.level > 0:
            # Relative import — without the package root we can't
            # resolve to a qualified name. Don't record; let downstream
            # treat as out-of-scope.
            self.generic_visit(node)
            return
        for alias in node.names:
            if alias.name == "*":
                self.graph.indirection.add(INDIRECTION_WILDCARD_IMPORT)
                continue
            local = alias.asname or alias.name
            qualified = f"{module}.{alias.name}" if module else alias.name
            self.graph.imports[local] = qualified
        self.generic_visit(node)

    # ------------------------------------------------------------------
    # Function-scope tracking
    # ------------------------------------------------------------------

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._enclosing.append(node.name)
        try:
            self.generic_visit(node)
        finally:
            self._enclosing.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._enclosing.append(node.name)
        try:
            self.generic_visit(node)
        finally:
            self._enclosing.pop()

    # ------------------------------------------------------------------
    # Calls + indirection
    # ------------------------------------------------------------------

    def visit_Call(self, node: ast.Call) -> None:
        chain = _attribute_chain(node.func)
        if chain is None:
            # Non-name callee (lambda, subscript, returned function
            # call, etc.) — nothing for the resolver to match.
            self.generic_visit(node)
            return

        # Indirection: getattr(obj, "name")(...)
        if (chain == ["getattr"] and len(node.args) >= 2
                and isinstance(node.args[1], ast.Constant)
                and isinstance(node.args[1].value, str)):
            self.graph.indirection.add(INDIRECTION_GETATTR)
            self.graph.getattr_targets.add(node.args[1].value)

        # Indirection: importlib.import_module("x.y")
        if chain == ["importlib", "import_module"]:
            self.graph.indirection.add(INDIRECTION_IMPORTLIB)
        if chain == ["import_module"]:
            # ``from importlib import import_module`` then bare call.
            qualified = self.graph.imports.get("import_module")
            if qualified == "importlib.import_module":
                self.graph.indirection.add(INDIRECTION_IMPORTLIB)

        # Indirection: __import__("x.y")
        if chain == ["__import__"]:
            self.graph.indirection.add(INDIRECTION_DUNDER_IMPORT)

        caller = self._enclosing[-1] if self._enclosing else None
        self.graph.calls.append(CallSite(
            line=getattr(node, "lineno", 0),
            chain=chain,
            caller=caller,
        ))
        self.generic_visit(node)


def _attribute_chain(node: ast.AST) -> Optional[List[str]]:
    """Convert ``foo.bar.baz`` into ``["foo", "bar", "baz"]``.

    Returns ``None`` for non-name callees (function returns,
    subscripts, lambdas, etc.) — those have no qualified name we
    could resolve against an import map.
    """
    parts: List[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return list(reversed(parts))
    return None


__all__ = [
    "CallSite",
    "FileCallGraph",
    "INDIRECTION_DUNDER_IMPORT",
    "INDIRECTION_GETATTR",
    "INDIRECTION_IMPORTLIB",
    "INDIRECTION_WILDCARD_IMPORT",
    "extract_call_graph_python",
]
