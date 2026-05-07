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
      * Python: ``getattr(mod, "name")``, ``importlib.import_module``,
        ``__import__``, wildcard ``from x import *``.
      * JavaScript / TypeScript: dynamic ``import(<var>)``,
        ``require(<var>)``, bracket dispatch ``obj[<var>](...)``,
        ``eval`` / ``new Function(...)``.
      * Go: dot import ``. "pkg"`` (analog of wildcard),
        ``reflect`` package usage (any reflective dispatch).
      * Java: wildcard imports ``import x.*``, ``Class.forName``
        / ``Method.invoke`` reflective dispatch.

Indirection flags are file-scoped (not per-call) because once any
of them is present, every NOT_CALLED claim about that file becomes
UNCERTAIN. Tracking per-call would let the resolver narrow the
uncertainty, but the resolver consumers (SCA reachability, codeql
pre-filter) treat UNCERTAIN as "don't downgrade severity" anyway —
finer granularity buys nothing.

Pure-AST. We never import / require / eval the target, never look
at any filesystem outside the source tree. String-shape only.

Languages today: Python (stdlib ``ast``) + JavaScript /
TypeScript + Go + Java (all tree-sitter-driven for non-Python;
gracefully empty when the grammar isn't installed). The resolver
in :mod:`core.inventory.reachability` is language-agnostic.
"""

from __future__ import annotations

import ast
import logging
import warnings
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


# Indirection-flag values. Strings (not enum) so they round-trip
# through JSON cleanly without a from_dict shim.
INDIRECTION_GETATTR = "getattr"
INDIRECTION_IMPORTLIB = "importlib"
INDIRECTION_WILDCARD_IMPORT = "wildcard_import"
INDIRECTION_DUNDER_IMPORT = "dunder_import"     # __import__("x.y")
# JavaScript / TypeScript flags. The resolver's masking logic
# treats them the same as the Python flags: any present →
# UNCERTAIN for queries against names this file mentions.
INDIRECTION_DYNAMIC_IMPORT = "dynamic_import"   # JS import(<var>) / require(<var>)
INDIRECTION_BRACKET_DISPATCH = "bracket_dispatch"  # JS obj[<var>](...)
INDIRECTION_EVAL = "eval"                        # JS eval / new Function


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


# ---------------------------------------------------------------------------
# JavaScript / TypeScript
# ---------------------------------------------------------------------------


def extract_call_graph_javascript(content: str) -> FileCallGraph:
    """Walk a JavaScript / TypeScript source string via tree-sitter
    and return its :class:`FileCallGraph`.

    Returns an empty graph when:

      * tree-sitter or ``tree_sitter_javascript`` isn't installed
        (the inventory builder degrades; resolver treats absence
        as no-evidence)
      * The file is unparseable

    Captures both ES-module imports and CommonJS requires; both
    populate the same ``imports`` map. Default imports
    (``import x from 'foo'``) bind ``x`` to ``foo``; named imports
    (``import { y } from 'foo'``) bind ``y`` to ``foo.y`` —
    matching the Python ``from foo import y`` convention so the
    resolver's chain semantics work unchanged.
    """
    try:
        import tree_sitter_javascript as ts_js
        from tree_sitter import Language, Parser
    except ImportError:
        logger.debug(
            "call_graph: tree-sitter JavaScript grammar not "
            "installed; returning empty graph",
        )
        return FileCallGraph()

    try:
        parser = Parser(Language(ts_js.language()))
        tree = parser.parse(content.encode("utf-8", errors="replace"))
    except Exception as e:                          # noqa: BLE001
        logger.debug("call_graph: JS parse failed (%s)", e)
        return FileCallGraph()

    walker = _JsCallGraph()
    walker.walk(tree.root_node)
    return walker.graph


class _JsCallGraph:
    """Single-pass tree-sitter walk emitting imports + call sites
    + indirection flags for one JS / TS file."""

    # Node types per tree-sitter-javascript grammar (also used by
    # tree-sitter-typescript via the same import path).
    _CALL_NODE = "call_expression"
    _IMPORT_NODE = "import_statement"
    _MEMBER_NODE = "member_expression"
    _SUBSCRIPT_NODE = "subscript_expression"
    _IDENT_NODE = "identifier"
    _PROP_IDENT_NODE = "property_identifier"
    _STRING_NODE = "string"
    _STRING_FRAG_NODE = "string_fragment"
    _ARGS_NODE = "arguments"
    _LEX_DECL_NODES = ("lexical_declaration", "variable_declaration")
    _VAR_DECLARATOR_NODE = "variable_declarator"
    _FUNC_NODES = (
        "function_declaration", "function_expression",
        "function", "arrow_function", "method_definition",
        "generator_function_declaration", "generator_function",
    )
    _NEW_NODE = "new_expression"

    def __init__(self) -> None:
        self.graph = FileCallGraph()
        self._enclosing: List[str] = []

    def walk(self, node) -> None:
        """Recursive descent. We push/pop the enclosing-function
        stack on the way down/up so the ``CallSite.caller`` field
        is the innermost NAMED enclosing function — anonymous
        functions / arrows are walked-through without affecting
        the caller attribution."""
        if node.type in self._FUNC_NODES:
            name = self._function_name(node)
            if name is not None:
                self._enclosing.append(name)
                try:
                    for child in node.children:
                        self.walk(child)
                finally:
                    self._enclosing.pop()
                return
            # Anonymous function / arrow — descend without a frame
            # so calls inside attribute to the outer named scope.

        # Top-level shapes we care about. Calls come first because
        # an import_statement can't contain a call (and we never
        # want to emit imports as calls).
        if node.type == self._IMPORT_NODE:
            self._visit_import(node)
            # Don't descend further; nothing useful inside.
            return

        if node.type in self._LEX_DECL_NODES:
            self._visit_lex_decl(node)
            # Continue descent so calls / functions inside (e.g.
            # ``const x = foo()`` — the ``foo()`` call) are seen.

        if node.type == self._CALL_NODE:
            self._visit_call(node)
            # Descend into args to capture nested calls.

        for child in node.children:
            self.walk(child)

    # ------------------------------------------------------------------
    # Imports
    # ------------------------------------------------------------------

    def _visit_import(self, node) -> None:
        """``import x from 'foo'`` / ``import { y, z as zz } from 'foo'``
        / ``import * as p from 'foo'`` / mixed forms."""
        # First ``string`` child holds the module name.
        module = self._import_module_name(node)
        if not module:
            return
        clause = self._first_child_of_type(node, ("import_clause",))
        if clause is None:
            return
        for c in clause.children:
            if c.type == self._IDENT_NODE:
                # Default import: ``import x from 'foo'`` → bind x
                # to the whole module.
                self.graph.imports[c.text.decode()] = module
            elif c.type == "named_imports":
                for spec in c.children:
                    if spec.type != "import_specifier":
                        continue
                    self._add_named_import(spec, module)
            elif c.type == "namespace_import":
                # ``import * as p from 'foo'`` — last identifier is
                # the bound name.
                last_id = self._last_child_of_type(c, (self._IDENT_NODE,))
                if last_id:
                    self.graph.imports[last_id.text.decode()] = module

    def _add_named_import(self, spec, module: str) -> None:
        """``y`` → bind y to ``module.y``;
        ``z as zz`` → bind zz to ``module.z``."""
        ids = [c for c in spec.children if c.type == self._IDENT_NODE]
        if not ids:
            return
        original = ids[0].text.decode()
        bound = ids[-1].text.decode() if len(ids) > 1 else original
        self.graph.imports[bound] = f"{module}.{original}"

    def _visit_lex_decl(self, node) -> None:
        """``const x = require('foo')`` / ``const { y } = require('foo')``."""
        for declarator in node.children:
            if declarator.type != self._VAR_DECLARATOR_NODE:
                continue
            value = self._declarator_value(declarator)
            if value is None:
                continue
            module = self._require_module_name(value)
            if module is None:
                continue
            target = declarator.children[0] if declarator.children else None
            if target is None:
                continue
            if target.type == self._IDENT_NODE:
                # ``const x = require('foo')`` → bind x to foo.
                self.graph.imports[target.text.decode()] = module
            elif target.type == "object_pattern":
                # ``const { y, z: zz } = require('foo')`` —
                # destructured names map to module.y / module.z.
                for prop in target.children:
                    if prop.type == "shorthand_property_identifier_pattern":
                        nm = prop.text.decode()
                        self.graph.imports[nm] = f"{module}.{nm}"
                    elif prop.type == "pair_pattern":
                        # ``z: zz`` — alias. Original is a
                        # ``property_identifier`` (the key); alias
                        # is an ``identifier`` (the binding).
                        ids = [
                            c for c in prop.children
                            if c.type in (
                                self._IDENT_NODE, self._PROP_IDENT_NODE,
                            )
                        ]
                        if len(ids) == 2:
                            orig = ids[0].text.decode()
                            alias = ids[1].text.decode()
                            self.graph.imports[alias] = f"{module}.{orig}"

    # ------------------------------------------------------------------
    # Calls + indirection
    # ------------------------------------------------------------------

    def _visit_call(self, node) -> None:
        """Every ``call_expression``. Detect:

          * Plain ``foo()`` and ``a.b.c()`` → recorded as CallSite.
          * Dynamic ``import(x)`` → ``INDIRECTION_DYNAMIC_IMPORT``.
          * ``require(<var>)`` → ``INDIRECTION_DYNAMIC_IMPORT``
            (string-arg require is already handled in
            ``_visit_lex_decl``).
          * Bracket-dispatch ``obj[<var>](...)`` →
            ``INDIRECTION_BRACKET_DISPATCH``.
          * ``eval(...)``, ``new Function(...)()`` →
            ``INDIRECTION_EVAL``.
        """
        callee = self._call_callee(node)
        if callee is None:
            return

        # Dynamic ``import(...)`` — callee is the keyword.
        if callee.type == "import":
            self.graph.indirection.add(INDIRECTION_DYNAMIC_IMPORT)
            return

        # Subscript dispatch: ``obj[expr](...)``.
        if callee.type == self._SUBSCRIPT_NODE:
            self.graph.indirection.add(INDIRECTION_BRACKET_DISPATCH)
            # Bracket with literal string ``obj["name"]()`` is the
            # JS analog of Python's ``getattr(obj, "name")``.
            # Capture the string for the resolver's
            # ``getattr_targets`` mechanism.
            literal = self._subscript_string_literal(callee)
            if literal is not None:
                self.graph.getattr_targets.add(literal)
            return

        # Bare-name and chain calls.
        chain = self._callee_chain(callee)
        if chain is None:
            # ``new Function(...)()`` — outer call has a
            # ``new_expression`` callee. Flag eval-style and skip.
            if callee.type == self._NEW_NODE:
                cls = self._first_child_of_type(callee, (self._IDENT_NODE,))
                if cls is not None and cls.text.decode() == "Function":
                    self.graph.indirection.add(INDIRECTION_EVAL)
            return

        # ``eval('...')`` — bare-name; also flag.
        if chain == ["eval"]:
            self.graph.indirection.add(INDIRECTION_EVAL)

        # ``require(<non-string>)`` — chain `["require"]`. Already
        # flagged for the bracket / dynamic case; here it's the
        # variable-arg require pattern.
        if chain == ["require"] and not self._call_first_arg_is_string(node):
            self.graph.indirection.add(INDIRECTION_DYNAMIC_IMPORT)

        caller = self._enclosing[-1] if self._enclosing else None
        self.graph.calls.append(CallSite(
            line=node.start_point[0] + 1,
            chain=chain,
            caller=caller,
        ))

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _function_name(self, node) -> Optional[str]:
        """Best-effort name extraction for a function-shape node.

        ``function foo() {}`` → ``foo``.
        ``method foo() {}``   → ``foo``.
        ``() => {}`` and ``function() {}`` → None.

        Arrow functions and anonymous function expressions don't
        carry a name; their first identifier child is a parameter,
        not the function name. Returning None for those collapses
        ``caller`` to whatever frame is above (or None for
        module-level), which matches operator intuition.
        """
        # Only ``function_declaration`` /
        # ``generator_function_declaration`` / ``method_definition``
        # carry a real name. Arrow functions, function expressions,
        # and anonymous-function nodes don't — their first identifier
        # is a parameter.
        named_kinds = (
            "function_declaration",
            "generator_function_declaration",
            "method_definition",
        )
        if node.type not in named_kinds:
            return None
        ident = self._first_child_of_type(
            node, (self._IDENT_NODE, self._PROP_IDENT_NODE),
        )
        if ident is not None:
            return ident.text.decode()
        return None

    def _call_callee(self, call_node):
        """The first non-trivia child of a ``call_expression`` is
        the callee. Skip anonymous nodes."""
        for c in call_node.children:
            if c.type == self._ARGS_NODE:
                return None
            if c.is_named:
                return c
        return None

    def _callee_chain(self, callee) -> Optional[List[str]]:
        """Convert a call's callee node into the dotted attribute
        chain. Returns None for non-name callees (subscripts,
        function returns, ``new_expression``, etc.)."""
        if callee is None:
            return None
        if callee.type == self._IDENT_NODE:
            return [callee.text.decode()]
        if callee.type == self._MEMBER_NODE:
            parts: List[str] = []
            cur = callee
            while cur is not None and cur.type == self._MEMBER_NODE:
                prop = self._last_child_of_type(
                    cur, (self._PROP_IDENT_NODE,),
                )
                if prop is None:
                    return None
                parts.append(prop.text.decode())
                cur = cur.children[0] if cur.children else None
            if cur is not None and cur.type == self._IDENT_NODE:
                parts.append(cur.text.decode())
                return list(reversed(parts))
            return None
        return None

    def _call_first_arg_is_string(self, call_node) -> bool:
        args = self._first_child_of_type(call_node, (self._ARGS_NODE,))
        if args is None:
            return False
        for c in args.children:
            if c.is_named:
                return c.type == self._STRING_NODE
        return False

    def _subscript_string_literal(self, subscript_node) -> Optional[str]:
        """``obj["name"]`` → ``"name"``. Returns None for
        ``obj[var]``."""
        # The subscript_expression children (named) are
        # [object, index]. The index is the second named child.
        named = [c for c in subscript_node.children if c.is_named]
        if len(named) < 2:
            return None
        idx = named[1]
        if idx.type != self._STRING_NODE:
            return None
        frag = self._first_child_of_type(idx, (self._STRING_FRAG_NODE,))
        if frag is None:
            return None
        return frag.text.decode()

    def _import_module_name(self, import_node) -> Optional[str]:
        """First ``string`` child of an ``import_statement`` carries
        the module path."""
        s = self._first_child_of_type(import_node, (self._STRING_NODE,))
        if s is None:
            return None
        frag = self._first_child_of_type(s, (self._STRING_FRAG_NODE,))
        if frag is None:
            return None
        return frag.text.decode()

    def _declarator_value(self, declarator):
        """The value-expression child of a ``variable_declarator``
        (``= <expr>``). Returns None when no initializer."""
        named = [c for c in declarator.children if c.is_named]
        # First named is the binding (identifier / object_pattern);
        # last is the value (when present).
        if len(named) < 2:
            return None
        return named[-1]

    def _require_module_name(self, value_node) -> Optional[str]:
        """Detect ``require('foo')`` and return ``'foo'``. Anything
        else (including ``require(variable)``) → None."""
        if value_node.type != self._CALL_NODE:
            return None
        callee = self._call_callee(value_node)
        if (callee is None
            or callee.type != self._IDENT_NODE
            or callee.text.decode() != "require"):
            return None
        args = self._first_child_of_type(value_node, (self._ARGS_NODE,))
        if args is None:
            return None
        for c in args.children:
            if not c.is_named:
                continue
            if c.type != self._STRING_NODE:
                # ``require(variable)`` — caller flags as dynamic.
                return None
            frag = self._first_child_of_type(c, (self._STRING_FRAG_NODE,))
            if frag is not None:
                return frag.text.decode()
            return None
        return None

    @staticmethod
    def _first_child_of_type(node, types):
        for c in node.children:
            if c.type in types:
                return c
        return None

    @staticmethod
    def _last_child_of_type(node, types):
        last = None
        for c in node.children:
            if c.type in types:
                last = c
        return last


# ---------------------------------------------------------------------------
# Go
# ---------------------------------------------------------------------------


# Go-specific flag — ``reflect.ValueOf(x).MethodByName(...)`` and
# friends. Any use of the ``reflect`` package's call-by-name surface
# is the analog of Python's ``getattr`` / ``importlib`` dispatch.
INDIRECTION_REFLECT = "reflect"


def extract_call_graph_go(content: str) -> FileCallGraph:
    """Walk a Go source string via tree-sitter and return its
    :class:`FileCallGraph`.

    Returns an empty graph when:

      * tree-sitter or ``tree_sitter_go`` isn't installed
        (the inventory builder degrades; resolver treats absence
        as no-evidence)
      * The file is unparseable

    Go-specific import handling:

      * ``import "fmt"``        → ``{"fmt": "fmt"}`` (last segment
                                   binds; full path is the value).
      * ``import "net/http"``   → ``{"http": "net/http"}``.
      * ``import str "strings"``→ ``{"str": "strings"}`` (alias).
      * ``import . "errors"``   → no map entry; flag wildcard.
      * ``import _ "x"``        → no binding (side-effect only);
                                   not callable, no record.

    The resolver matches OSV symbols like ``net/http.HandlerFunc``
    where the module path includes slashes. Unlike Python's dotted
    paths, Go imports' ``map[name] = full_path`` retains the slash
    so ``http.HandlerFunc(...)`` resolves to ``"net/http" +
    ".HandlerFunc"`` for the resolver's chain comparison.
    """
    try:
        import tree_sitter_go as ts_go
        from tree_sitter import Language, Parser
    except ImportError:
        logger.debug(
            "call_graph: tree-sitter Go grammar not installed; "
            "returning empty graph",
        )
        return FileCallGraph()

    try:
        parser = Parser(Language(ts_go.language()))
        tree = parser.parse(content.encode("utf-8", errors="replace"))
    except Exception as e:                          # noqa: BLE001
        logger.debug("call_graph: Go parse failed (%s)", e)
        return FileCallGraph()

    walker = _GoCallGraph()
    walker.walk(tree.root_node)
    return walker.graph


class _GoCallGraph:
    """Single-pass tree-sitter walk emitting imports + call sites
    + indirection flags for one Go file."""

    _CALL_NODE = "call_expression"
    _SELECTOR_NODE = "selector_expression"
    _IDENT_NODE = "identifier"
    _PKG_IDENT_NODE = "package_identifier"
    _FIELD_IDENT_NODE = "field_identifier"
    _BLANK_IDENT_NODE = "blank_identifier"
    _IMPORT_DECL_NODE = "import_declaration"
    _IMPORT_SPEC_LIST = "import_spec_list"
    _IMPORT_SPEC = "import_spec"
    _STRING_LIT_NODE = "interpreted_string_literal"
    _STRING_CONTENT_NODE = "interpreted_string_literal_content"
    _DOT_NODE = "dot"
    _ARG_LIST_NODE = "argument_list"
    _FUNC_DECL_NODE = "function_declaration"
    _METHOD_DECL_NODE = "method_declaration"

    def __init__(self) -> None:
        self.graph = FileCallGraph()
        self._enclosing: List[str] = []

    def walk(self, node) -> None:
        """Recursive descent. Push/pop enclosing-function stack so
        ``CallSite.caller`` carries the innermost named function."""
        if node.type == self._FUNC_DECL_NODE:
            name = self._first_child_of_type(
                node, (self._IDENT_NODE,),
            )
            self._enclosing.append(
                name.text.decode() if name else "<anon>"
            )
            try:
                for child in node.children:
                    self.walk(child)
            finally:
                self._enclosing.pop()
            return

        if node.type == self._METHOD_DECL_NODE:
            # ``func (r Recv) Name() {}`` — the function name is a
            # ``field_identifier`` child, not the receiver's identifier.
            name = self._first_child_of_type(
                node, (self._FIELD_IDENT_NODE,),
            )
            self._enclosing.append(
                name.text.decode() if name else "<anon>"
            )
            try:
                for child in node.children:
                    self.walk(child)
            finally:
                self._enclosing.pop()
            return

        if node.type == self._IMPORT_DECL_NODE:
            self._visit_import(node)
            # Don't recurse inside (no calls / functions live there).
            return

        if node.type == self._CALL_NODE:
            self._visit_call(node)
            # Continue recursion to capture nested calls in args.

        for child in node.children:
            self.walk(child)

    # ------------------------------------------------------------------
    # Imports
    # ------------------------------------------------------------------

    def _visit_import(self, node) -> None:
        """Both single (``import "x"``) and block (``import (...)``)
        forms have ``import_spec`` children; for the block form
        wrapped in an ``import_spec_list``."""
        for child in node.children:
            if child.type == self._IMPORT_SPEC:
                self._handle_import_spec(child)
            elif child.type == self._IMPORT_SPEC_LIST:
                for spec in child.children:
                    if spec.type == self._IMPORT_SPEC:
                        self._handle_import_spec(spec)

    def _handle_import_spec(self, spec) -> None:
        """Extract one ``import_spec`` into the imports map.

        Shapes:
          * ``"fmt"``           → bare; bind last-segment of path.
          * ``alias "fmt"``     → alias binding.
          * ``. "errors"``      → dot import; flag wildcard.
          * ``_ "x"``           → blank; no binding.
        """
        path = self._import_path(spec)
        if path is None:
            return
        # First non-string named child (if any) is the binding hint.
        binding = None
        for c in spec.children:
            if c.type == self._STRING_LIT_NODE:
                continue
            if c.is_named:
                binding = c
                break

        if binding is not None:
            if binding.type == self._DOT_NODE:
                # ``. "errors"`` — dot import. The Go analog of
                # ``from x import *``: every exported name from the
                # package becomes available in this file's scope
                # without qualification.
                self.graph.indirection.add(INDIRECTION_WILDCARD_IMPORT)
                return
            if binding.type == self._BLANK_IDENT_NODE:
                # ``_ "..."`` — side-effect-only; no name binding,
                # no calls of this package will appear in this file.
                return
            if binding.type == self._PKG_IDENT_NODE:
                self.graph.imports[binding.text.decode()] = path
                return

        # Bare import: bind the LAST segment of the path.
        last_segment = path.rsplit("/", 1)[-1]
        if last_segment:
            self.graph.imports[last_segment] = path

    def _import_path(self, spec) -> Optional[str]:
        """Pull the string literal out of an import_spec."""
        s = self._first_child_of_type(spec, (self._STRING_LIT_NODE,))
        if s is None:
            return None
        content = self._first_child_of_type(
            s, (self._STRING_CONTENT_NODE,),
        )
        if content is None:
            return None
        return content.text.decode()

    # ------------------------------------------------------------------
    # Calls + indirection
    # ------------------------------------------------------------------

    def _visit_call(self, node) -> None:
        """Every ``call_expression``. Detect:

          * Plain ``foo()`` and ``a.b.c()`` → recorded as CallSite.
          * Anything reaching through ``reflect.*`` → flag.
          * Type assertions / function values / method-on-value
            calls — not recorded as CallSites (no statically
            resolvable qualified name).
        """
        callee = self._call_callee(node)
        if callee is None:
            return

        chain = self._callee_chain(callee)
        if chain is None:
            return

        # Reflect-based dispatch is Go's analog of Python's getattr.
        # ``reflect.ValueOf(...).MethodByName("name").Call(...)`` —
        # any chain with reflect.MethodByName / reflect.Value.Call
        # / reflect.ValueOf.* indicates name-by-string dispatch.
        if chain and chain[0] == "reflect":
            self.graph.indirection.add(INDIRECTION_REFLECT)
            # Still record the call — the chain itself isn't
            # interesting for CVE-symbol matching, but recording it
            # keeps the data shape consistent.

        caller = self._enclosing[-1] if self._enclosing else None
        self.graph.calls.append(CallSite(
            line=node.start_point[0] + 1,
            chain=chain,
            caller=caller,
        ))

    def _call_callee(self, call_node):
        """First non-trivia named child is the callee."""
        for c in call_node.children:
            if c.type == self._ARG_LIST_NODE:
                return None
            if c.is_named:
                return c
        return None

    def _callee_chain(self, callee) -> Optional[List[str]]:
        """``foo`` → ``["foo"]``;
        ``foo.Bar`` → ``["foo", "Bar"]``;
        ``foo.Bar.Baz`` → ``["foo", "Bar", "Baz"]``."""
        if callee.type == self._IDENT_NODE:
            return [callee.text.decode()]
        if callee.type == self._SELECTOR_NODE:
            parts: List[str] = []
            cur = callee
            while cur is not None and cur.type == self._SELECTOR_NODE:
                # ``selector_expression`` → operand + field_identifier.
                # Children order: operand first, then ``.``, then
                # the field. Pull the field; descend into the operand.
                field = self._last_child_of_type(
                    cur, (self._FIELD_IDENT_NODE,),
                )
                if field is None:
                    return None
                parts.append(field.text.decode())
                # Operand is the first named child.
                operand = None
                for c in cur.children:
                    if c.is_named:
                        operand = c
                        break
                cur = operand
            if cur is not None and cur.type == self._IDENT_NODE:
                parts.append(cur.text.decode())
                return list(reversed(parts))
            return None
        return None

    # ------------------------------------------------------------------
    # Helpers (shared shape with the JS extractor — duplicated to
    # keep the two walkers loosely coupled)
    # ------------------------------------------------------------------

    @staticmethod
    def _first_child_of_type(node, types):
        for c in node.children:
            if c.type in types:
                return c
        return None

    @staticmethod
    def _last_child_of_type(node, types):
        last = None
        for c in node.children:
            if c.type in types:
                last = c
        return last


# ---------------------------------------------------------------------------
# Java
# ---------------------------------------------------------------------------


def extract_call_graph_java(content: str) -> FileCallGraph:
    """Walk a Java source string via tree-sitter and return its
    :class:`FileCallGraph`.

    Returns an empty graph when:
      * tree-sitter or ``tree_sitter_java`` isn't installed
      * The file is unparseable

    Java-specific shapes:

      * ``import com.example.Util;`` →
        ``imports["Util"] = "com.example.Util"`` (last
        component binds; full path is the value).
      * ``import static com.example.Helpers.helper;`` →
        ``imports["helper"] = "com.example.Helpers.helper"``
        (static imports bind the symbol directly).
      * ``import com.example.*;`` → flagged as
        ``INDIRECTION_WILDCARD_IMPORT`` (analog of Python
        ``from x import *`` — the bound names are statically
        unknowable).
      * ``Class.forName("x.y.Z")`` →
        ``INDIRECTION_IMPORTLIB`` (Java analog of Python
        ``importlib.import_module``).
      * ``method.invoke(target, args)`` /
        ``Class.getMethod(...).invoke(...)`` →
        ``INDIRECTION_REFLECT`` (reflective method dispatch).

    Documented limitation: Java's dominant call shape is
    instance-method calls where the variable name doesn't match
    the type (``Util util = ...; util.execute()``). The resolver's
    chain matching follows imports, not type-tracking. Operators
    will see correct verdicts for STATIC method calls and
    CLASS-level access (``Util.staticMethod()``,
    ``Cls.method()``) but instance-method calls show the variable
    name in the chain and won't bind to the type's qualified
    name. Same limitation as Go interface dispatch and Python
    method-on-instance — out of scope; CodeQL is the right tool
    when type-aware reachability matters.
    """
    try:
        import tree_sitter_java as ts_java
        from tree_sitter import Language, Parser
    except ImportError:
        logger.debug(
            "call_graph: tree-sitter Java grammar not installed; "
            "returning empty graph",
        )
        return FileCallGraph()

    try:
        parser = Parser(Language(ts_java.language()))
        tree = parser.parse(content.encode("utf-8", errors="replace"))
    except Exception as e:                          # noqa: BLE001
        logger.debug("call_graph: Java parse failed (%s)", e)
        return FileCallGraph()

    walker = _JavaCallGraph()
    walker.walk(tree.root_node)
    return walker.graph


class _JavaCallGraph:
    """Single-pass tree-sitter walk emitting imports + call sites
    + indirection flags for one Java file."""

    _METHOD_INVOCATION = "method_invocation"
    _IMPORT_DECL = "import_declaration"
    _SCOPED_IDENT = "scoped_identifier"
    _IDENT = "identifier"
    _FIELD_ACCESS = "field_access"
    _ARG_LIST = "argument_list"
    _METHOD_DECL = "method_declaration"
    _CONSTRUCTOR_DECL = "constructor_declaration"
    _CLASS_DECL = "class_declaration"
    _ASTERISK = "asterisk"
    _STATIC = "static"
    _STRING_LIT = "string_literal"

    def __init__(self) -> None:
        self.graph = FileCallGraph()
        self._enclosing: List[str] = []

    def walk(self, node) -> None:
        """Recursive descent. Push/pop enclosing-method stack so
        ``CallSite.caller`` carries the innermost named method."""
        if node.type == self._METHOD_DECL:
            name = self._first_child_of_type(node, (self._IDENT,))
            self._enclosing.append(
                name.text.decode() if name else "<anon>"
            )
            try:
                for child in node.children:
                    self.walk(child)
            finally:
                self._enclosing.pop()
            return

        if node.type == self._CONSTRUCTOR_DECL:
            # Constructors use the class name as the identifier.
            name = self._first_child_of_type(node, (self._IDENT,))
            self._enclosing.append(
                name.text.decode() if name else "<ctor>"
            )
            try:
                for child in node.children:
                    self.walk(child)
            finally:
                self._enclosing.pop()
            return

        if node.type == self._IMPORT_DECL:
            self._visit_import(node)
            return

        if node.type == self._METHOD_INVOCATION:
            self._visit_call(node)
            # Continue recursion to capture nested calls in args.

        for child in node.children:
            self.walk(child)

    # ------------------------------------------------------------------
    # Imports
    # ------------------------------------------------------------------

    def _visit_import(self, node) -> None:
        """``import x.y.Z;`` / ``import static x.y.Z.method;`` /
        ``import x.y.*;``."""
        # Wildcard import — has an ``asterisk`` child.
        has_asterisk = any(
            c.type == self._ASTERISK for c in node.children
        )
        if has_asterisk:
            self.graph.indirection.add(INDIRECTION_WILDCARD_IMPORT)
            return

        # The path is the scoped_identifier child.
        scoped = self._first_child_of_type(node, (self._SCOPED_IDENT,))
        if scoped is None:
            # Single-segment import (rare; e.g.
            # ``import Foo;`` for unnamed-package types).
            simple = self._first_child_of_type(node, (self._IDENT,))
            if simple is not None:
                name = simple.text.decode()
                self.graph.imports[name] = name
            return

        full_path = self._scoped_identifier_text(scoped)
        if not full_path:
            return
        # Bound name = last component.
        last_dot = full_path.rfind(".")
        bound = full_path[last_dot + 1:] if last_dot >= 0 else full_path
        if not bound:
            return
        self.graph.imports[bound] = full_path

    def _scoped_identifier_text(self, node) -> str:
        """Convert a ``scoped_identifier`` subtree to its dotted
        form. Tree-sitter-java emits a left-recursive nested
        structure (``a.b.c`` is ``scoped_identifier(
        scoped_identifier(a, b), c)``); we just take the source
        text which has the right shape."""
        try:
            return node.text.decode().strip()
        except Exception:                           # noqa: BLE001
            return ""

    # ------------------------------------------------------------------
    # Calls + indirection
    # ------------------------------------------------------------------

    def _visit_call(self, node) -> None:
        """Every ``method_invocation``. Detect:

          * Plain ``foo()`` — chain ``["foo"]``.
          * ``Cls.staticMethod()`` — chain ``["Cls", "staticMethod"]``.
          * ``a.b.c()`` (field access chain) — chain
            ``["a", "b", "c"]``.
          * ``Class.forName("x.y.Z")`` →
            ``INDIRECTION_IMPORTLIB``.
          * ``<anything>.invoke(...)`` →
            ``INDIRECTION_REFLECT``.
        """
        chain = self._invocation_chain(node)
        if chain is None:
            return

        # Reflective dispatch — Java's analog of Python's
        # importlib / getattr-by-name. We flag the file
        # whenever the standard reflective shapes appear:
        #   * Class.forName(...)
        #   * <method-or-class>.invoke(...) — covers the
        #     Method.invoke / Constructor.newInstance patterns.
        if chain == ["Class", "forName"]:
            self.graph.indirection.add(INDIRECTION_IMPORTLIB)
        elif chain[-1:] == ["invoke"] and len(chain) >= 2:
            self.graph.indirection.add(INDIRECTION_REFLECT)
        elif chain[-1:] == ["newInstance"] and len(chain) >= 2:
            self.graph.indirection.add(INDIRECTION_REFLECT)

        caller = self._enclosing[-1] if self._enclosing else None
        self.graph.calls.append(CallSite(
            line=node.start_point[0] + 1,
            chain=chain,
            caller=caller,
        ))

    def _invocation_chain(self, node) -> Optional[List[str]]:
        """Convert a ``method_invocation`` node into the dotted
        chain.

        Shapes:
          * ``foo()`` — single ``identifier`` child + arg list.
          * ``Cls.method()`` — ``identifier`` + ``.`` +
            ``identifier`` + arg list.
          * ``a.b.c()`` — ``field_access`` (operand) + ``.`` +
            ``identifier`` (method name) + arg list.

        Returns None for non-name shapes (call results,
        casts, parenthesised expressions, etc.).
        """
        # The method_invocation's named children before
        # ``argument_list`` are some subset of:
        #   * receiver — identifier OR field_access (optional)
        #   * method name — identifier (always present)
        #   * type arguments — type_arguments (optional, ignored)
        #
        # The method name is always the LAST named identifier
        # before the argument_list; preceding names are the
        # receiver chain.
        named_before_args: List[Any] = []
        for child in node.children:
            if child.type == self._ARG_LIST:
                break
            if not child.is_named:
                continue
            if child.type in (self._IDENT, self._FIELD_ACCESS):
                named_before_args.append(child)
            elif child.type == "type_arguments":
                # Java generics on the call: ``foo.<T>bar()`` —
                # not relevant for chain extraction.
                continue
            else:
                # Unhandled operand shape (call result, cast,
                # parenthesised, etc.). Out of scope.
                return None

        if not named_before_args:
            return None
        method_ident = named_before_args[-1]
        if method_ident.type != self._IDENT:
            return None
        operand = (
            named_before_args[-2]
            if len(named_before_args) >= 2 else None
        )

        method_name = method_ident.text.decode()

        if operand is None:
            return [method_name]

        if operand.type == self._IDENT:
            return [operand.text.decode(), method_name]

        if operand.type == self._FIELD_ACCESS:
            parts = self._field_access_chain(operand)
            if parts is None:
                return None
            return parts + [method_name]

        return None

    def _field_access_chain(self, node) -> Optional[List[str]]:
        """``a.b.c`` (a ``field_access`` subtree) → ``["a", "b", "c"]``."""
        # field_access children: object + . + field
        parts: List[str] = []
        cur = node
        while cur is not None and cur.type == self._FIELD_ACCESS:
            field = self._last_child_of_type(cur, (self._IDENT,))
            if field is None:
                return None
            parts.append(field.text.decode())
            # Operand is the first named child.
            operand = None
            for c in cur.children:
                if c.is_named:
                    operand = c
                    break
            cur = operand
        if cur is not None and cur.type == self._IDENT:
            parts.append(cur.text.decode())
            return list(reversed(parts))
        return None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _first_child_of_type(node, types):
        for c in node.children:
            if c.type in types:
                return c
        return None

    @staticmethod
    def _last_child_of_type(node, types):
        last = None
        for c in node.children:
            if c.type in types:
                last = c
        return last


# ===========================================================================
# Rust
# ===========================================================================


def extract_call_graph_rust(content: str) -> FileCallGraph:
    """Walk a Rust source string via tree-sitter-rust and return its
    :class:`FileCallGraph`.

    Returns an empty graph when ``tree_sitter_rust`` isn't installed
    or the file is unparseable.

    Rust shapes:

      * ``use foo::bar::Baz;`` -> ``imports["Baz"] = "foo::bar::Baz"``
      * ``use foo::bar as alias;`` -> ``imports["alias"] = "foo::bar"``
      * ``use foo::{Bar, Baz as B};`` -> binds both
      * ``use foo::*;`` -> ``INDIRECTION_WILDCARD_IMPORT``
      * ``Baz::new()`` (scoped path call) -> chain ``["Baz", "new"]``
      * ``a::b::c()`` -> chain ``["a", "b", "c"]``
      * ``inst.method()`` -> chain ``["inst", "method"]``
        (instance-method limitation as in Java/Go)

    Reflection-style indirection is uncommon in Rust; we don't flag
    macros (compile-time expansion is genuinely transparent). Type
    erasure (``Any::downcast_ref``) is rare in CVE-relevant code
    and emits a normal call chain.
    """
    try:
        import tree_sitter_rust as ts_rust
        from tree_sitter import Language, Parser
    except ImportError:
        logger.debug(
            "call_graph: tree-sitter Rust grammar not installed; "
            "returning empty graph",
        )
        return FileCallGraph()

    try:
        parser = Parser(Language(ts_rust.language()))
        tree = parser.parse(content.encode("utf-8", errors="replace"))
    except Exception as e:                              # noqa: BLE001
        logger.debug("call_graph: Rust parse failed (%s)", e)
        return FileCallGraph()

    walker = _RustCallGraph()
    walker.walk(tree.root_node)
    return walker.graph


class _RustCallGraph:
    """Single-pass tree-sitter-rust walk."""

    _USE_DECL = "use_declaration"
    _SCOPED_IDENT = "scoped_identifier"
    _SCOPED_USE_LIST = "scoped_use_list"
    _USE_LIST = "use_list"
    _USE_AS_CLAUSE = "use_as_clause"
    _USE_WILDCARD = "use_wildcard"
    _IDENT = "identifier"
    _FIELD_IDENT = "field_identifier"
    _FUNCTION_ITEM = "function_item"
    _CALL_EXPR = "call_expression"
    _FIELD_EXPR = "field_expression"
    _ARGS = "arguments"

    def __init__(self) -> None:
        self.graph = FileCallGraph()
        self._enclosing: List[str] = []

    def walk(self, node) -> None:
        if node.type == self._FUNCTION_ITEM:
            name = self._first_child_of_type(node, (self._IDENT,))
            self._enclosing.append(
                name.text.decode() if name else "<anon>"
            )
            try:
                for c in node.children:
                    self.walk(c)
            finally:
                self._enclosing.pop()
            return

        if node.type == self._USE_DECL:
            self._handle_use(node)
            return

        if node.type == self._CALL_EXPR:
            chain = self._call_chain(node)
            if chain:
                line = node.start_point[0] + 1
                caller = self._enclosing[-1] if self._enclosing else None
                self.graph.calls.append(
                    CallSite(line=line, chain=chain, caller=caller)
                )
            for c in node.children:
                self.walk(c)
            return

        for c in node.children:
            self.walk(c)

    # --- use ---

    def _handle_use(self, node) -> None:
        for c in node.children:
            if c.type == self._USE_WILDCARD:
                self.graph.indirection.add(INDIRECTION_WILDCARD_IMPORT)
            elif c.type == self._SCOPED_IDENT:
                parts = self._scoped_parts(c)
                if parts:
                    bound = parts[-1]
                    # Use ``.`` separator (matches the cross-language
                    # resolver's qualified-name convention) even
                    # though Rust source uses ``::``. Keeps OSV
                    # symbol matching uniform across ecosystems.
                    self.graph.imports[bound] = ".".join(parts)
            elif c.type == self._SCOPED_USE_LIST:
                self._handle_scoped_use_list(c)
            elif c.type == self._USE_AS_CLAUSE:
                # Top-level ``use foo::bar::Baz as Q;`` — no prefix.
                self._handle_use_as(c, prefix=())
            elif c.type == "use_wildcard":
                self.graph.indirection.add(INDIRECTION_WILDCARD_IMPORT)
            elif c.type == self._IDENT:
                # ``use foo;`` (rare standalone)
                name = c.text.decode()
                self.graph.imports[name] = name

    def _handle_scoped_use_list(self, node) -> None:
        prefix: List[str] = []
        list_node = None
        for c in node.children:
            if c.type == self._IDENT:
                prefix.append(c.text.decode())
            elif c.type == self._SCOPED_IDENT:
                prefix.extend(self._scoped_parts(c))
            elif c.type == self._USE_LIST:
                list_node = c
        if list_node is None:
            return
        for c in list_node.children:
            if c.type == self._IDENT:
                name = c.text.decode()
                self.graph.imports[name] = ".".join(prefix + [name])
            elif c.type == self._USE_AS_CLAUSE:
                self._handle_use_as(c, prefix=tuple(prefix))
            elif c.type == self._USE_WILDCARD:
                self.graph.indirection.add(INDIRECTION_WILDCARD_IMPORT)
            elif c.type == self._SCOPED_IDENT:
                parts = self._scoped_parts(c)
                if parts:
                    bound = parts[-1]
                    self.graph.imports[bound] = ".".join(
                        prefix + parts
                    )

    def _handle_use_as(self, node, *, prefix=()) -> None:
        """``Original as Alias`` (use_as_clause). The original
        side may be a bare identifier (inside a use_list) or a
        scoped_identifier (top-level ``use foo::bar::Baz as Q;``)."""
        original_parts: List[str] = []
        alias: Optional[str] = None
        idents_seen = 0
        for c in node.children:
            if c.type == self._SCOPED_IDENT:
                original_parts = self._scoped_parts(c)
            elif c.type == self._IDENT:
                if not original_parts and idents_seen == 0:
                    original_parts = [c.text.decode()]
                    idents_seen += 1
                else:
                    alias = c.text.decode()
        if not original_parts or alias is None:
            return
        full = ".".join(list(prefix) + original_parts)
        self.graph.imports[alias] = full

    def _scoped_parts(self, node) -> List[str]:
        """``foo::bar::Baz`` -> ``["foo", "bar", "Baz"]``."""
        out: List[str] = []
        # Recursive: scoped_identifier nests with deeper scope_identifier
        # on the left.
        cur = node
        stack: List[List[str]] = []
        # Walk down the LHS scoped_identifier chain.
        while cur is not None and cur.type == self._SCOPED_IDENT:
            named = [c for c in cur.children if c.is_named]
            if not named:
                return []
            # Last named is the trailing identifier; first is the
            # remaining LHS (recurse).
            trailing = named[-1]
            if trailing.type != self._IDENT:
                return []
            stack.append([trailing.text.decode()])
            cur = named[0] if named[0].type == self._SCOPED_IDENT else None
            if named[0].type == self._IDENT:
                out.append(named[0].text.decode())
                break
        # Append the popped trailing names in left-to-right order.
        for s in reversed(stack):
            out.extend(s)
        return out

    # --- calls ---

    def _call_chain(self, node) -> Optional[List[str]]:
        """First named child is the callee. ``arguments`` follows."""
        callee = None
        for c in node.children:
            if c.type == self._ARGS:
                break
            if c.is_named:
                callee = c
                break
        if callee is None:
            return None
        if callee.type == self._IDENT:
            return [callee.text.decode()]
        if callee.type == self._SCOPED_IDENT:
            return self._scoped_parts(callee) or None
        if callee.type == self._FIELD_EXPR:
            return self._field_chain(callee)
        return None

    def _field_chain(self, node) -> Optional[List[str]]:
        """``a.b.c`` (field_expression) -> ``["a", "b", "c"]``."""
        parts: List[str] = []
        cur = node
        while cur is not None and cur.type == self._FIELD_EXPR:
            field = None
            for c in cur.children:
                if c.type == self._FIELD_IDENT:
                    field = c
            if field is None:
                return None
            parts.append(field.text.decode())
            operand = None
            for c in cur.children:
                if c.is_named:
                    operand = c
                    break
            cur = operand
        if cur is None:
            return None
        if cur.type == self._IDENT:
            parts.append(cur.text.decode())
            return list(reversed(parts))
        if cur.type == self._SCOPED_IDENT:
            scoped = self._scoped_parts(cur)
            if not scoped:
                return None
            return scoped + list(reversed(parts))
        return None

    @staticmethod
    def _first_child_of_type(node, types):
        for c in node.children:
            if c.type in types:
                return c
        return None


# ===========================================================================
# Ruby
# ===========================================================================


def extract_call_graph_ruby(content: str) -> FileCallGraph:
    """Walk a Ruby source string via tree-sitter-ruby and return its
    :class:`FileCallGraph`.

    Returns an empty graph when ``tree_sitter_ruby`` isn't installed
    or the file is unparseable.

    Ruby shapes:

      * ``require "json"`` / ``require_relative "x/y"`` -> imports
      * ``Foo.bar`` (constant + method) -> chain ``["Foo", "bar"]``
      * ``foo`` (bare) -> chain ``["foo"]``
      * ``a.b.c`` -> chain ``["a", "b", "c"]``
      * ``send / public_send / __send__`` -> ``INDIRECTION_REFLECT``
      * ``Object.const_get("X")`` /
        ``Kernel.const_get("X")`` -> ``INDIRECTION_IMPORTLIB``
      * ``eval(...)`` / ``instance_eval`` / ``class_eval`` ->
        ``INDIRECTION_EVAL``

    Limitation: Ruby's metaprogramming is heavy. We catch the
    common reflection vectors but ``define_method`` /
    ``method_missing`` / etc. produce calls invisible to static
    analysis — same family of limitation as Python ``getattr``.
    """
    try:
        import tree_sitter_ruby as ts_ruby
        from tree_sitter import Language, Parser
    except ImportError:
        logger.debug(
            "call_graph: tree-sitter Ruby grammar not installed; "
            "returning empty graph",
        )
        return FileCallGraph()

    try:
        parser = Parser(Language(ts_ruby.language()))
        tree = parser.parse(content.encode("utf-8", errors="replace"))
    except Exception as e:                              # noqa: BLE001
        logger.debug("call_graph: Ruby parse failed (%s)", e)
        return FileCallGraph()

    walker = _RubyCallGraph()
    walker.walk(tree.root_node)
    return walker.graph


class _RubyCallGraph:
    """Single-pass tree-sitter-ruby walk."""

    _CALL = "call"
    _METHOD = "method"
    _IDENT = "identifier"
    _CONSTANT = "constant"
    _SCOPE_RES = "scope_resolution"
    _STRING = "string"
    _STRING_CONTENT = "string_content"
    _ARG_LIST = "argument_list"

    _REFLECT_NAMES = {"send", "public_send", "__send__"}
    _CONST_GET_NAMES = {"const_get"}
    _EVAL_NAMES = {"eval", "instance_eval", "class_eval", "module_eval"}
    _REQUIRE_NAMES = {"require", "require_relative", "load"}

    def __init__(self) -> None:
        self.graph = FileCallGraph()
        self._enclosing: List[str] = []

    def walk(self, node) -> None:
        if node.type == self._METHOD:
            name = self._first_child_of_type(node, (self._IDENT,))
            self._enclosing.append(
                name.text.decode() if name else "<anon>"
            )
            try:
                for c in node.children:
                    self.walk(c)
            finally:
                self._enclosing.pop()
            return

        if node.type == "identifier" and node.parent and node.parent.type not in (
            self._CALL, self._METHOD,
        ):
            # bare-identifier "call" — Ruby allows ``foo`` without
            # parens to call ``foo()``. Tree-sitter wraps this as
            # an identifier in some contexts; for static analysis
            # we focus on explicit ``call`` nodes (see below) to
            # avoid over-reporting.
            pass

        if node.type == self._CALL:
            self._handle_call(node)
            for c in node.children:
                self.walk(c)
            return

        for c in node.children:
            self.walk(c)

    def _handle_call(self, node) -> None:
        # ``call`` shape: receiver + . + method + arguments
        receiver = None
        method = None
        for c in node.children:
            if c.type == self._ARG_LIST:
                break
            if c.is_named:
                if method is None and c.type in (
                    self._IDENT, self._CONSTANT,
                ):
                    if receiver is None:
                        # First named child — could be the method
                        # (no receiver) or the receiver of a chain.
                        receiver = c
                    else:
                        method = c
                elif c.type == self._SCOPE_RES:
                    receiver = c
                elif c.type == self._CALL:
                    receiver = c
                else:
                    continue
        # Bare-call branch: ``foo()`` or ``require "x"`` parses as
        # a call with only a receiver (the function name itself)
        # and an arg_list, no separate ``method`` child.
        if method is None and receiver is not None:
            chain = self._chain_from_node(receiver)
            if chain:
                self._record(node, chain)
                bare = chain[0]
                if bare in self._REQUIRE_NAMES:
                    self._extract_require_arg(node)
                if bare in self._EVAL_NAMES:
                    self.graph.indirection.add(INDIRECTION_EVAL)
                if bare in self._REFLECT_NAMES:
                    self.graph.indirection.add(INDIRECTION_REFLECT)
                if bare in self._CONST_GET_NAMES:
                    self.graph.indirection.add(INDIRECTION_IMPORTLIB)
            return

        # Method-found branch: ``Foo.bar(...)`` / ``inst.method(...)``.
        if method is None:
            return
        receiver_chain = (
            self._chain_from_node(receiver) if receiver else []
        )
        method_name = method.text.decode()
        chain = receiver_chain + [method_name]
        self._record(node, chain)
        if method_name in self._REFLECT_NAMES:
            self.graph.indirection.add(INDIRECTION_REFLECT)
        if method_name in self._CONST_GET_NAMES:
            self.graph.indirection.add(INDIRECTION_IMPORTLIB)
        if method_name in self._EVAL_NAMES:
            self.graph.indirection.add(INDIRECTION_EVAL)

    def _extract_require_arg(self, node) -> None:
        """For a ``require "x"`` call node, register the string arg
        as an import binding."""
        args = self._first_child_of_type(node, (self._ARG_LIST,))
        if args is None:
            return
        for a in args.children:
            if a.type == self._STRING:
                for sc in a.children:
                    if sc.type == self._STRING_CONTENT:
                        path = sc.text.decode()
                        bound = path.split("/")[-1]
                        self.graph.imports[bound] = path

    def _chain_from_node(self, node) -> List[str]:
        if node is None:
            return []
        if node.type in (self._IDENT, self._CONSTANT):
            return [node.text.decode()]
        if node.type == self._SCOPE_RES:
            parts: List[str] = []
            for c in node.children:
                if c.type in (self._IDENT, self._CONSTANT):
                    parts.append(c.text.decode())
                elif c.type == self._SCOPE_RES:
                    parts = self._chain_from_node(c) + parts
            return parts
        if node.type == self._CALL:
            # nested chain a.b.c
            return self._chain_from_call(node)
        return []

    def _chain_from_call(self, node) -> List[str]:
        receiver = None
        method = None
        for c in node.children:
            if c.type == self._ARG_LIST:
                break
            if c.is_named:
                if receiver is None and c.type in (
                    self._IDENT, self._CONSTANT, self._SCOPE_RES, self._CALL,
                ):
                    receiver = c
                elif method is None and c.type in (
                    self._IDENT, self._CONSTANT,
                ):
                    method = c
        if receiver is None:
            return []
        rc = self._chain_from_node(receiver)
        if method is None:
            return rc
        return rc + [method.text.decode()]

    def _record(self, node, chain: List[str]) -> None:
        line = node.start_point[0] + 1
        caller = self._enclosing[-1] if self._enclosing else None
        self.graph.calls.append(
            CallSite(line=line, chain=chain, caller=caller)
        )

    @staticmethod
    def _first_child_of_type(node, types):
        for c in node.children:
            if c.type in types:
                return c
        return None


# ===========================================================================
# C# (NuGet)
# ===========================================================================


def extract_call_graph_csharp(content: str) -> FileCallGraph:
    """Walk a C# source string via tree-sitter-c-sharp and return
    its :class:`FileCallGraph`.

    Returns an empty graph when ``tree_sitter_c_sharp`` isn't
    installed or the file is unparseable.

    C# shapes:

      * ``using System.Text;`` -> ``imports["Text"] = "System.Text"``
      * ``using static System.Math;`` -> static-class import
      * ``using JsonNet = Newtonsoft.Json.Linq;`` -> alias import
      * ``Foo.Bar()`` (static class) -> chain ``["Foo", "Bar"]``
      * ``inst.Method()`` -> chain ``["inst", "Method"]``
      * ``Type.GetMethod("X")`` /
        ``Activator.CreateInstance(...)`` -> ``INDIRECTION_REFLECT``
      * ``Assembly.Load(...)`` -> ``INDIRECTION_IMPORTLIB``
    """
    try:
        import tree_sitter_c_sharp as ts_cs
        from tree_sitter import Language, Parser
    except ImportError:
        logger.debug(
            "call_graph: tree-sitter C# grammar not installed; "
            "returning empty graph",
        )
        return FileCallGraph()

    try:
        parser = Parser(Language(ts_cs.language()))
        tree = parser.parse(content.encode("utf-8", errors="replace"))
    except Exception as e:                              # noqa: BLE001
        logger.debug("call_graph: C# parse failed (%s)", e)
        return FileCallGraph()

    walker = _CSharpCallGraph()
    walker.walk(tree.root_node)
    return walker.graph


class _CSharpCallGraph:
    """Single-pass tree-sitter-c-sharp walk."""

    _USING = "using_directive"
    _QUALIFIED = "qualified_name"
    _IDENT = "identifier"
    _METHOD_DECL = "method_declaration"
    _CONSTRUCTOR_DECL = "constructor_declaration"
    _INVOCATION = "invocation_expression"
    _MEMBER_ACCESS = "member_access_expression"
    _ARG_LIST = "argument_list"

    _REFLECT_METHODS = {
        "Invoke", "GetMethod", "CreateInstance",
        "InvokeMember",
    }
    _ASSEMBLY_LOAD = {"Load", "LoadFrom", "LoadFile", "LoadWithPartialName"}

    def __init__(self) -> None:
        self.graph = FileCallGraph()
        self._enclosing: List[str] = []

    def walk(self, node) -> None:
        if node.type in (self._METHOD_DECL, self._CONSTRUCTOR_DECL):
            name = self._first_child_of_type(node, (self._IDENT,))
            self._enclosing.append(
                name.text.decode() if name else "<anon>"
            )
            try:
                for c in node.children:
                    self.walk(c)
            finally:
                self._enclosing.pop()
            return

        if node.type == self._USING:
            self._handle_using(node)
            return

        if node.type == self._INVOCATION:
            chain = self._invocation_chain(node)
            if chain:
                line = node.start_point[0] + 1
                caller = self._enclosing[-1] if self._enclosing else None
                self.graph.calls.append(
                    CallSite(line=line, chain=chain, caller=caller)
                )
                # Indirection flags
                tail = chain[-1]
                if tail in self._REFLECT_METHODS:
                    self.graph.indirection.add(INDIRECTION_REFLECT)
                # ``Assembly.Load`` / ``Assembly.LoadFrom``
                if (
                    tail in self._ASSEMBLY_LOAD
                    and len(chain) >= 2
                    and chain[-2] == "Assembly"
                ):
                    self.graph.indirection.add(INDIRECTION_IMPORTLIB)
            else:
                # Couldn't reduce to a clean chain — but we should
                # still flag reflection if a known reflect method
                # name appears as the trailing identifier of the
                # invocation's callee subtree.
                tail_name = self._tail_identifier(node)
                if tail_name in self._REFLECT_METHODS:
                    self.graph.indirection.add(INDIRECTION_REFLECT)
            for c in node.children:
                self.walk(c)
            return

        for c in node.children:
            self.walk(c)

    def _handle_using(self, node) -> None:
        # ``using System.Text;`` -> binds last component to full name.
        # ``using JsonNet = Newtonsoft.Json.Linq;`` -> alias.
        # ``using static System.Math;`` -> static-class import.
        target = None
        alias = None
        for c in node.children:
            if c.type == self._QUALIFIED:
                target = c
            elif c.type == self._IDENT:
                # First identifier could be alias name (when followed by '=')
                if alias is None:
                    alias = c
        if target is None:
            return
        parts = self._qualified_parts(target)
        if not parts:
            return
        full = ".".join(parts)
        if alias is not None and alias.text.decode() != parts[-1]:
            self.graph.imports[alias.text.decode()] = full
        else:
            self.graph.imports[parts[-1]] = full

    def _qualified_parts(self, node) -> List[str]:
        if node.type == self._IDENT:
            return [node.text.decode()]
        if node.type == self._QUALIFIED:
            parts: List[str] = []
            for c in node.children:
                if c.type == self._IDENT:
                    parts.append(c.text.decode())
                elif c.type == self._QUALIFIED:
                    parts = self._qualified_parts(c) + parts
            return parts
        return []

    def _invocation_chain(self, node) -> Optional[List[str]]:
        # invocation_expression: function + argument_list
        callee = None
        for c in node.children:
            if c.type == self._ARG_LIST:
                break
            if c.is_named:
                callee = c
                break
        if callee is None:
            return None
        if callee.type == self._IDENT:
            return [callee.text.decode()]
        if callee.type == self._MEMBER_ACCESS:
            return self._member_access_chain(callee)
        if callee.type == self._QUALIFIED:
            return self._qualified_parts(callee) or None
        return None

    def _member_access_chain(self, node) -> Optional[List[str]]:
        """``a.b.c`` (member_access_expression)."""
        parts: List[str] = []
        cur = node
        while cur is not None and cur.type == self._MEMBER_ACCESS:
            # member_access: expression + . + name (identifier)
            named = [c for c in cur.children if c.is_named]
            if len(named) < 2:
                return None
            tail = named[-1]
            if tail.type != self._IDENT:
                return None
            parts.append(tail.text.decode())
            cur = named[0]
        if cur is None:
            return None
        if cur.type == self._IDENT:
            parts.append(cur.text.decode())
            return list(reversed(parts))
        if cur.type == self._QUALIFIED:
            qparts = self._qualified_parts(cur)
            if not qparts:
                return None
            return qparts + list(reversed(parts))
        return None

    def _tail_identifier(self, node) -> Optional[str]:
        """Return the rightmost simple identifier reachable from
        the invocation's callee subtree. Used as a fallback when
        the chain is too complex to extract cleanly."""
        callee = None
        for c in node.children:
            if c.type == self._ARG_LIST:
                break
            if c.is_named:
                callee = c
                break
        if callee is None:
            return None
        # Walk down member_access tail
        cur = callee
        while cur is not None:
            if cur.type == self._IDENT:
                return cur.text.decode()
            if cur.type == self._MEMBER_ACCESS:
                # last named child is the tail name
                named = [c for c in cur.children if c.is_named]
                if not named:
                    return None
                tail = named[-1]
                if tail.type == self._IDENT:
                    return tail.text.decode()
                cur = tail
                continue
            if cur.type == self._QUALIFIED:
                parts = self._qualified_parts(cur)
                return parts[-1] if parts else None
            return None
        return None

    @staticmethod
    def _first_child_of_type(node, types):
        for c in node.children:
            if c.type in types:
                return c
        return None


# ===========================================================================
# PHP (Composer / Packagist)
# ===========================================================================


def extract_call_graph_php(content: str) -> FileCallGraph:
    """Walk a PHP source string via tree-sitter-php and return its
    :class:`FileCallGraph`.

    Returns an empty graph when ``tree_sitter_php`` isn't installed
    or the file is unparseable.

    PHP shapes:

      * ``use Foo\\Bar\\Baz;`` -> ``imports["Baz"] = "Foo\\Bar\\Baz"``
      * ``use Foo\\Bar as B;`` -> alias
      * ``use function Foo\\bar;`` / ``use const Foo\\BAR;``
      * ``Baz::method()`` (static) -> chain ``["Baz", "method"]``
      * ``$inst->method()`` -> chain ``["inst", "method"]``
      * ``call_user_func(...)`` /
        ``call_user_func_array(...)`` -> ``INDIRECTION_REFLECT``
      * ``$$var(...)`` (variable variable as call) ->
        ``INDIRECTION_REFLECT``
      * ``eval(...)`` / ``create_function(...)`` ->
        ``INDIRECTION_EVAL``
      * ``include`` / ``require`` (with var) ->
        ``INDIRECTION_DYNAMIC_IMPORT``
    """
    try:
        import tree_sitter_php as ts_php
        from tree_sitter import Language, Parser
    except ImportError:
        logger.debug(
            "call_graph: tree-sitter PHP grammar not installed; "
            "returning empty graph",
        )
        return FileCallGraph()

    try:
        # tree-sitter-php exports php_only / php (with HTML mixed).
        # For .php files we use php_only, but tolerate either.
        lang_fn = getattr(ts_php, "language_php", None) or ts_php.language()
        if callable(lang_fn):
            lang_fn = lang_fn()
        parser = Parser(Language(lang_fn))
        tree = parser.parse(content.encode("utf-8", errors="replace"))
    except Exception as e:                              # noqa: BLE001
        logger.debug("call_graph: PHP parse failed (%s)", e)
        return FileCallGraph()

    walker = _PhpCallGraph()
    walker.walk(tree.root_node)
    return walker.graph


class _PhpCallGraph:
    """Single-pass tree-sitter-php walk."""

    _NAMESPACE_USE_DECL = "namespace_use_declaration"
    _NAMESPACE_USE_CLAUSE = "namespace_use_clause"
    _NAMESPACE_NAME = "namespace_name"
    _QUALIFIED = "qualified_name"
    _NAME = "name"
    _IDENT = "name"          # PHP grammar uses ``name`` for identifiers
    _FUNCTION_DEF = "function_definition"
    _METHOD_DECL = "method_declaration"
    _FUNCTION_CALL = "function_call_expression"
    _SCOPED_CALL = "scoped_call_expression"
    _MEMBER_CALL = "member_call_expression"
    _MEMBER_ACCESS = "member_access_expression"
    _ARGS = "arguments"
    _VAR = "variable_name"

    _REFLECT_FNS = {
        "call_user_func", "call_user_func_array",
        "ReflectionMethod", "ReflectionClass",
    }
    _EVAL_FNS = {"eval", "create_function", "assert"}
    _DYNAMIC_INCLUDE = {
        "include", "include_once", "require", "require_once",
    }

    def __init__(self) -> None:
        self.graph = FileCallGraph()
        self._enclosing: List[str] = []

    def walk(self, node) -> None:
        if node.type in (self._FUNCTION_DEF, self._METHOD_DECL):
            name = self._first_child_of_type(node, (self._NAME,))
            self._enclosing.append(
                name.text.decode() if name else "<anon>"
            )
            try:
                for c in node.children:
                    self.walk(c)
            finally:
                self._enclosing.pop()
            return

        if node.type == self._NAMESPACE_USE_DECL:
            self._handle_use(node)
            return

        if node.type in (
            self._FUNCTION_CALL, self._SCOPED_CALL, self._MEMBER_CALL,
        ):
            self._handle_call(node)
            for c in node.children:
                self.walk(c)
            return

        for c in node.children:
            self.walk(c)

    def _handle_use(self, node) -> None:
        for c in node.children:
            if c.type == self._NAMESPACE_USE_CLAUSE:
                self._handle_use_clause(c)

    def _handle_use_clause(self, node) -> None:
        target_parts: List[str] = []
        alias_name: Optional[str] = None
        for c in node.children:
            if c.type in (self._QUALIFIED, self._NAMESPACE_NAME):
                target_parts = self._namespace_parts(c)
            elif c.type == self._NAME and target_parts:
                alias_name = c.text.decode()
        if not target_parts:
            return
        full = "\\".join(target_parts)
        bound = alias_name or target_parts[-1]
        self.graph.imports[bound] = full

    def _namespace_parts(self, node) -> List[str]:
        """``Foo\\Bar\\Baz`` (qualified_name with nested
        namespace_name LHS) -> ``["Foo", "Bar", "Baz"]``.

        tree-sitter-php nests deep namespaces: ``qualified_name``
        contains ``namespace_name`` (Foo\\Bar) plus a trailing
        ``name`` (Baz). Recurse into any child of type
        ``qualified_name`` / ``namespace_name`` for the LHS.
        """
        parts: List[str] = []
        for c in node.children:
            if c.type == self._NAME:
                parts.append(c.text.decode())
            elif c.type in (self._QUALIFIED, self._NAMESPACE_NAME):
                parts = self._namespace_parts(c) + parts
        return parts

    def _handle_call(self, node) -> None:
        chain = None
        if node.type == self._FUNCTION_CALL:
            chain = self._function_call_chain(node)
        elif node.type == self._SCOPED_CALL:
            chain = self._scoped_call_chain(node)
        elif node.type == self._MEMBER_CALL:
            chain = self._member_call_chain(node)
        if not chain:
            return
        line = node.start_point[0] + 1
        caller = self._enclosing[-1] if self._enclosing else None
        self.graph.calls.append(
            CallSite(line=line, chain=chain, caller=caller)
        )
        # Indirection flags
        tail = chain[-1]
        if tail in self._REFLECT_FNS or chain[0] in self._REFLECT_FNS:
            self.graph.indirection.add(INDIRECTION_REFLECT)
        if tail in self._EVAL_FNS or chain[0] in self._EVAL_FNS:
            self.graph.indirection.add(INDIRECTION_EVAL)
        if chain[0] in self._DYNAMIC_INCLUDE:
            self.graph.indirection.add(INDIRECTION_DYNAMIC_IMPORT)

    def _function_call_chain(self, node) -> Optional[List[str]]:
        # function_call_expression: function (qualified_name | name | variable) + arguments
        for c in node.children:
            if c.type == self._ARGS:
                break
            if c.type in (self._QUALIFIED, self._NAMESPACE_NAME):
                parts = self._namespace_parts(c)
                if parts:
                    return parts
            if c.type == self._NAME:
                return [c.text.decode()]
            if c.type == self._VAR:
                # ``$fn(...)`` — variable callable. Unknowable.
                self.graph.indirection.add(INDIRECTION_REFLECT)
                return None
        return None

    def _scoped_call_chain(self, node) -> Optional[List[str]]:
        # scoped_call_expression: scope (Class) :: name + arguments
        scope = None
        method = None
        for c in node.children:
            if c.type == self._ARGS:
                break
            if c.is_named:
                if scope is None:
                    scope = c
                elif method is None:
                    method = c
        if scope is None or method is None:
            return None
        if scope.type == self._NAME:
            scope_parts = [scope.text.decode()]
        elif scope.type in (self._QUALIFIED, self._NAMESPACE_NAME):
            scope_parts = self._namespace_parts(scope)
        else:
            return None
        return scope_parts + [method.text.decode()]

    def _member_call_chain(self, node) -> Optional[List[str]]:
        # member_call_expression: object -> name + arguments
        obj = None
        method = None
        for c in node.children:
            if c.type == self._ARGS:
                break
            if c.is_named:
                if obj is None:
                    obj = c
                elif method is None:
                    method = c
        if obj is None or method is None:
            return None
        obj_chain = self._object_chain(obj)
        if obj_chain is None:
            return None
        return obj_chain + [method.text.decode()]

    def _object_chain(self, node) -> Optional[List[str]]:
        if node.type == self._VAR:
            return [node.text.decode().lstrip("$")]
        if node.type == self._NAME:
            return [node.text.decode()]
        if node.type == self._MEMBER_ACCESS:
            parts: List[str] = []
            for c in node.children:
                if c.is_named:
                    parts.append(self._object_chain(c) or [])
            flat: List[str] = []
            for p in parts:
                flat.extend(p)
            return flat
        if node.type == self._MEMBER_CALL:
            return self._member_call_chain(node)
        return None

    @staticmethod
    def _first_child_of_type(node, types):
        for c in node.children:
            if c.type in types:
                return c
        return None


__all__ = [
    "CallSite",
    "FileCallGraph",
    "INDIRECTION_BRACKET_DISPATCH",
    "INDIRECTION_DUNDER_IMPORT",
    "INDIRECTION_DYNAMIC_IMPORT",
    "INDIRECTION_EVAL",
    "INDIRECTION_GETATTR",
    "INDIRECTION_IMPORTLIB",
    "INDIRECTION_REFLECT",
    "INDIRECTION_WILDCARD_IMPORT",
    "extract_call_graph_csharp",
    "extract_call_graph_go",
    "extract_call_graph_java",
    "extract_call_graph_javascript",
    "extract_call_graph_php",
    "extract_call_graph_python",
    "extract_call_graph_ruby",
    "extract_call_graph_rust",
]
