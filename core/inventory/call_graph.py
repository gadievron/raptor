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

Indirection flags are file-scoped (not per-call) because once any
of them is present, every NOT_CALLED claim about that file becomes
UNCERTAIN. Tracking per-call would let the resolver narrow the
uncertainty, but the resolver consumers (SCA reachability, codeql
pre-filter) treat UNCERTAIN as "don't downgrade severity" anyway —
finer granularity buys nothing.

Pure-AST. We never import / require / eval the target, never look
at any filesystem outside the source tree. String-shape only.

Languages today: Python (stdlib ``ast``) + JavaScript / TypeScript
(tree-sitter when the grammar is installed; empty result
otherwise). Adding Go / Java means writing one more
``extract_call_graph_<lang>`` function emitting the same
dataclasses; the resolver in :mod:`core.inventory.reachability` is
language-agnostic.
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


__all__ = [
    "CallSite",
    "FileCallGraph",
    "INDIRECTION_BRACKET_DISPATCH",
    "INDIRECTION_DUNDER_IMPORT",
    "INDIRECTION_DYNAMIC_IMPORT",
    "INDIRECTION_EVAL",
    "INDIRECTION_GETATTR",
    "INDIRECTION_IMPORTLIB",
    "INDIRECTION_WILDCARD_IMPORT",
    "extract_call_graph_javascript",
    "extract_call_graph_python",
]
