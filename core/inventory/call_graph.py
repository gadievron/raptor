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
from typing import Any, Dict, List, Optional, Set, Tuple

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

    ``receiver_class`` is the name of the enclosing class when this
    call site is a ``self.X()`` or ``cls.X()`` call and the chain is
    length-2 (e.g. ``["self", "foo"]``). The reachability resolver
    uses this to narrow ``method_match`` candidates by class
    hierarchy: a ``self.foo()`` inside ``class B`` can't be calling
    ``class C.foo`` if B and C are unrelated. ``None`` everywhere
    else — module-level call, non-self chain, longer chain than the
    safe-narrow case.
    """
    line: int
    chain: List[str]
    caller: Optional[str] = None
    receiver_class: Optional[str] = None


@dataclass
class DecoratedFunction:
    """One ``def`` (sync or async) that carries one or more
    decorators. Methods of classes are tracked the same way —
    the reachability resolver doesn't differentiate framework-
    decorated module-level functions from framework-decorated
    methods when surfacing framework-callable entry points.

    ``decorators`` is a list of attribute chains, one per
    ``@decorator`` line. ``@functools.cache`` →
    ``[["functools", "cache"]]``. ``@app.route("/x")`` →
    ``[["app", "route"]]`` (the call arguments aren't stored;
    only the chain that names the decorator). Decorators that
    aren't a plain name/attribute chain (e.g. ``@make_deco()``)
    are NOT recorded — we have no qualified name to match.
    """
    name: str
    line: int
    decorators: List[List[str]] = field(default_factory=list)


@dataclass
class ClassDef:
    """One ``class`` definition in a file.

    ``bases`` is the raw base-name list as it appears in the source
    (``class B(A, mixins.M)`` → ``["A", "mixins.M"]``). The
    reachability resolver tries to resolve each base against
    same-file class names for narrowing; unresolved bases (imported
    classes, dynamic bases) signal "don't narrow" — stay over-
    inclusive rather than drop a real caller.

    ``methods`` lists the methods defined at depth 1 inside the
    class body — i.e. methods of the class itself, not methods of
    nested classes. Each entry is ``(method_name, line)``.

    ``nested`` is True when this class is itself nested inside
    another class or function. The resolver currently treats nested
    classes as opaque — same as no class context.
    """
    name: str
    line: int
    bases: List[str] = field(default_factory=list)
    methods: List[Tuple[str, int]] = field(default_factory=list)
    nested: bool = False


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
    classes: List[ClassDef] = field(default_factory=list)
    decorated_functions: List[DecoratedFunction] = field(default_factory=list)
    # Module/package/namespace declared inside this file. The
    # reachability resolver uses this to canonicalise cross-package
    # references into project-defined functions for languages where
    # the source file's package isn't derivable from the file path
    # alone — Go (``package <name>``), Java (``package com.foo;``),
    # Rust (``mod`` chains), C# (``namespace Foo.Bar``), PHP
    # (``namespace Foo\Bar``). For Python this stays ``None``: the
    # resolver derives the qualified name from the file path
    # heuristically. For JS/TS each file IS its module — also
    # path-derivable, so stays ``None``. For Ruby the
    # module/class nesting at file scope.
    package_name: Optional[str] = None
    # Relative imports (Python ``from . import x`` /
    # ``from ..pkg import y``). Stored as
    # ``(level, module_or_empty, name, asname_or_None)`` quads. Not
    # resolved at extraction time — the package root depends on the
    # file's location in the inventory tree, which the per-file
    # extractor doesn't know. The resolver in
    # :mod:`core.inventory.reachability` consumes these to model
    # ``__init__.py`` re-exports.
    relative_imports: List[Tuple[int, str, str, Optional[str]]] = field(
        default_factory=list,
    )

    def to_dict(self) -> dict:
        return {
            "imports": dict(self.imports),
            "calls": [
                {"line": c.line, "chain": list(c.chain),
                 "caller": c.caller,
                 "receiver_class": c.receiver_class}
                for c in self.calls
            ],
            "indirection": sorted(self.indirection),
            "getattr_targets": sorted(self.getattr_targets),
            "classes": [
                {"name": k.name, "line": k.line,
                 "bases": list(k.bases),
                 "methods": [list(m) for m in k.methods],
                 "nested": bool(k.nested)}
                for k in self.classes
            ],
            "decorated_functions": [
                {"name": d.name, "line": d.line,
                 "decorators": [list(ch) for ch in d.decorators]}
                for d in self.decorated_functions
            ],
            "package_name": self.package_name,
            "relative_imports": [list(ri) for ri in self.relative_imports],
        }

    @classmethod
    def from_dict(cls, d: dict) -> "FileCallGraph":
        rel = d.get("relative_imports") or []
        return cls(
            imports=dict(d.get("imports") or {}),
            calls=[
                CallSite(
                    line=int(c.get("line", 0)),
                    chain=list(c.get("chain") or []),
                    caller=c.get("caller"),
                    receiver_class=c.get("receiver_class"),
                )
                for c in (d.get("calls") or [])
            ],
            indirection=set(d.get("indirection") or []),
            getattr_targets=set(d.get("getattr_targets") or []),
            classes=[
                ClassDef(
                    name=str(k.get("name", "")),
                    line=int(k.get("line", 0)),
                    bases=list(k.get("bases") or []),
                    methods=[
                        (str(m[0]), int(m[1]))
                        for m in (k.get("methods") or [])
                        if isinstance(m, (list, tuple)) and len(m) >= 2
                    ],
                    nested=bool(k.get("nested", False)),
                )
                for k in (d.get("classes") or [])
            ],
            decorated_functions=[
                DecoratedFunction(
                    name=str(df.get("name", "")),
                    line=int(df.get("line", 0)),
                    decorators=[
                        list(ch) for ch in (df.get("decorators") or [])
                        if isinstance(ch, (list, tuple))
                    ],
                )
                for df in (d.get("decorated_functions") or [])
            ],
            package_name=d.get("package_name"),
            relative_imports=[
                (int(r[0]), str(r[1] or ""), str(r[2] or ""),
                 r[3] if len(r) > 3 else None)
                for r in rel if isinstance(r, (list, tuple)) and len(r) >= 3
            ],
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
        # Stack of enclosing ClassDefs, top is innermost. Used to
        # tag CallSite.receiver_class for ``self.X()`` calls and to
        # register methods on their owning class. The stack supports
        # nested classes; we only consider the innermost element
        # when tagging calls.
        self._class_stack: List[ClassDef] = []

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
        # ``from x.y import z``         → imports {"z": "x.y.z"}
        # ``from x.y import z as q``    → imports {"q": "x.y.z"}
        # ``from x import *``           → flag wildcard, no map entry
        # ``from . import z``           → relative_imports entry; the
        #                                  resolver in reachability.py
        #                                  resolves the package root
        #                                  from the file's path
        module = node.module or ""
        if node.level and node.level > 0:
            for alias in node.names:
                if alias.name == "*":
                    self.graph.indirection.add(INDIRECTION_WILDCARD_IMPORT)
                    continue
                self.graph.relative_imports.append(
                    (node.level, module, alias.name, alias.asname),
                )
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
        self._handle_function_def(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._handle_function_def(node)

    def _handle_function_def(self, node) -> None:
        # Register as a method on the immediately-enclosing class
        # only when this def is at depth 1 inside the class body.
        # ``_enclosing`` being empty AND ``_class_stack`` non-empty
        # is the "method of current class" case; if ``_enclosing``
        # is non-empty we're a function inside another function /
        # method, not a method of the class.
        if self._class_stack and not self._enclosing:
            self._class_stack[-1].methods.append(
                (node.name, getattr(node, "lineno", 0)),
            )
        # Decorators are evaluated in the ENCLOSING scope (where
        # the def statement appears), not inside the function body.
        # Visit them BEFORE pushing the function name onto
        # ``_enclosing``, otherwise ``@app.route(...)`` looks like
        # a call from inside the decorated function — wrong scope.
        decorator_chains: List[List[str]] = []
        for deco in getattr(node, "decorator_list", []) or []:
            # ``@foo`` → name node
            # ``@foo.bar`` → attribute chain
            # ``@foo(...)`` → Call whose ``.func`` is the chain
            # ``@foo.bar(...)`` → Call whose ``.func`` is the chain
            chain = _decorator_chain(deco)
            if chain is not None:
                decorator_chains.append(chain)
            # Walk the decorator expression in the OUTER scope so
            # any nested calls inside the decorator (e.g.
            # ``@app.route(rule_for("x"))``) attribute to the
            # enclosing function, not the decorated one.
            self.visit(deco)
        # Record decorator chains for this def. The reachability
        # resolver inspects this to flag framework-callable
        # entry points.
        if decorator_chains:
            self.graph.decorated_functions.append(
                DecoratedFunction(
                    name=node.name,
                    line=getattr(node, "lineno", 0),
                    decorators=decorator_chains,
                ),
            )
        # Now push the function name and walk the body. Skip the
        # decorator_list this time — already handled above.
        self._enclosing.append(node.name)
        try:
            # generic_visit walks ``args`` + ``body`` + ``returns``.
            # ``decorator_list`` is also iterated by generic_visit;
            # to avoid double-visit we walk the non-decorator
            # children explicitly.
            #
            # ``type_params`` is PEP 695 (Python 3.12+) — covers
            # ``def f[T: bound_call()](...)``. The bound expression
            # is evaluated in the enclosing scope; if we don't walk
            # it, ``bound_call()`` becomes an invisible call site.
            # ``getattr`` with a default keeps the code working on
            # 3.10/3.11 where the field doesn't exist.
            for child_name in (
                "args", "body", "returns", "type_comment", "type_params",
            ):
                child = getattr(node, child_name, None)
                if isinstance(child, list):
                    for item in child:
                        self.visit(item)
                elif child is not None and hasattr(child, "_fields"):
                    self.visit(child)
        finally:
            self._enclosing.pop()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        bases = []
        for b in node.bases:
            base_chain = _attribute_chain(b)
            if base_chain is not None:
                bases.append(".".join(base_chain))
            # Bases that aren't plain name / attribute chains
            # (e.g. ``class X(metaclass_fn())``) are dropped — we
            # can't resolve them and the resolver's narrowing
            # already treats partial/missing bases conservatively.
        cdef = ClassDef(
            name=node.name,
            line=getattr(node, "lineno", 0),
            bases=bases,
            nested=bool(self._class_stack) or bool(self._enclosing),
        )
        self.graph.classes.append(cdef)
        self._class_stack.append(cdef)
        try:
            self.generic_visit(node)
        finally:
            self._class_stack.pop()

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
        # ``self.foo()`` / ``cls.foo()`` inside a class body — tag
        # with the enclosing class name so the reachability resolver
        # can narrow method_match candidates. Only the length-2
        # case is safe (``self.foo`` resolves on ``self``); longer
        # chains like ``self.x.foo`` route through an attribute of
        # unknown type and shouldn't drive narrowing.
        receiver_class = None
        if (self._class_stack and not self._class_stack[-1].nested
                and len(chain) == 2 and chain[0] in ("self", "cls")):
            receiver_class = self._class_stack[-1].name
        self.graph.calls.append(CallSite(
            line=getattr(node, "lineno", 0),
            chain=chain,
            caller=caller,
            receiver_class=receiver_class,
        ))
        self.generic_visit(node)


def _decorator_chain(deco: ast.AST) -> Optional[List[str]]:
    """Return the attribute chain naming a decorator, or ``None``.

    ``@foo``                → ``["foo"]``
    ``@foo.bar``            → ``["foo", "bar"]``
    ``@foo(...)``           → ``["foo"]`` (peel off the call)
    ``@foo.bar(...)``       → ``["foo", "bar"]``
    ``@make_deco()(...)``   → ``None``  (decorator is a call result)
    ``@foo[0]``             → ``None``  (subscript, no name)
    """
    if isinstance(deco, ast.Call):
        return _attribute_chain(deco.func)
    return _attribute_chain(deco)


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
    _CLASS_DECL = "class_declaration"
    _CLASS_EXPR = "class"  # tree-sitter-js node type for class expressions
    _CLASS_BODY = "class_body"
    _CLASS_HERITAGE = "class_heritage"
    _METHOD_DEF = "method_definition"
    _THIS_NODE = "this"

    def __init__(self) -> None:
        self.graph = FileCallGraph()
        self._enclosing: List[str] = []
        # Class context for ``class Foo { method() { this.x(); } }``.
        # JS classes are single-inheritance (one ``extends`` target)
        # but mixin patterns mean class_heritage may carry a call
        # expression — we capture the surface identifier when present.
        self._class_stack: List[ClassDef] = []

    def walk(self, node) -> None:
        """Recursive descent. We push/pop the enclosing-function
        stack on the way down/up so the ``CallSite.caller`` field
        is the innermost NAMED enclosing function — anonymous
        functions / arrows are walked-through without affecting
        the caller attribution."""
        if node.type == self._CLASS_DECL:
            name_node = self._first_child_of_type(node, (self._IDENT_NODE,))
            if name_node is not None:
                bases: List[str] = []
                heritage = self._first_child_of_type(node, (
                    self._CLASS_HERITAGE,
                ))
                if heritage is not None:
                    # ``extends Foo`` → identifier child; ``extends
                    # mixin(Base)`` → call_expression. Capture the
                    # innermost identifier where present.
                    for hc in heritage.children:
                        if hc.type == self._IDENT_NODE:
                            bases.append(hc.text.decode())
                cdef = ClassDef(
                    name=name_node.text.decode(),
                    line=node.start_point[0] + 1,
                    bases=bases,
                    nested=bool(self._class_stack) or bool(self._enclosing),
                )
                self.graph.classes.append(cdef)
                self._class_stack.append(cdef)
                try:
                    for child in node.children:
                        self.walk(child)
                finally:
                    self._class_stack.pop()
                return
            # Anon class — recurse without push.
            for child in node.children:
                self.walk(child)
            return

        if node.type in self._FUNC_NODES:
            name = self._function_name(node)
            if name is not None:
                # Register method on the immediate class (only when
                # this is a method_definition, not a nested function
                # or arrow inside a method).
                if (node.type == self._METHOD_DEF
                        and self._class_stack
                        and not self._enclosing):
                    self._class_stack[-1].methods.append(
                        (name, node.start_point[0] + 1),
                    )
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
        """``const x = require('foo')`` / ``const { y } = require('foo')``
        / ``const Foo = class extends Bar { ... }``."""
        for declarator in node.children:
            if declarator.type != self._VAR_DECLARATOR_NODE:
                continue
            value = self._declarator_value(declarator)
            if value is None:
                continue
            # ``const Foo = class ... {}`` — synthesise a ClassDef
            # with the LHS identifier as the class name. Bases come
            # from class_heritage; methods from the class_body. We
            # only synthesise metadata here; the walker still
            # descends into the body so calls inside class methods
            # are recorded as call sites (just without class
            # context, since class expressions are anonymous in the
            # grammar and we don't push class_stack from here).
            if value.type == self._CLASS_EXPR:
                target = declarator.children[0] if declarator.children else None
                if (target is not None
                        and target.type == self._IDENT_NODE):
                    self._synthesise_class_from_expr(
                        value, target.text.decode(),
                    )
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

    def _synthesise_class_from_expr(self, cls_node, name: str) -> None:
        """``const Foo = class extends Bar { method() {} };``

        Pulls bases from class_heritage and method names from
        class_body.method_definition. Adds a ClassDef carrying
        ``name`` (taken from the variable_declarator's LHS,
        since class expressions are anonymous in the grammar).
        """
        bases: List[str] = []
        body = None
        for c in cls_node.children:
            if c.type == self._CLASS_HERITAGE:
                for hc in c.children:
                    if hc.type == self._IDENT_NODE:
                        bases.append(hc.text.decode())
            elif c.type == self._CLASS_BODY:
                body = c
        methods: List[Tuple[str, int]] = []
        if body is not None:
            for c in body.children:
                if c.type != self._METHOD_DEF:
                    continue
                m_name = self._first_child_of_type(c, (
                    self._IDENT_NODE, self._PROP_IDENT_NODE,
                    "private_property_identifier",
                ))
                if m_name is not None:
                    methods.append((
                        m_name.text.decode(),
                        c.start_point[0] + 1,
                    ))
        self.graph.classes.append(ClassDef(
            name=name,
            line=cls_node.start_point[0] + 1,
            bases=bases,
            methods=methods,
            nested=bool(self._class_stack) or bool(self._enclosing),
        ))

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
        # ``this.foo()`` inside an instance method → narrow to the
        # enclosing class. Unqualified ``foo()`` inside a method
        # does NOT — JS unqualified names resolve through the
        # lexical scope (could be a module-level function, an
        # import, or a closure variable), not via implicit-this.
        receiver_class: Optional[str] = None
        if (self._class_stack and not self._class_stack[-1].nested
                and self._enclosing
                and len(chain) >= 2 and chain[0] == "this"):
            receiver_class = self._class_stack[-1].name
        self.graph.calls.append(CallSite(
            line=node.start_point[0] + 1,
            chain=chain,
            caller=caller,
            receiver_class=receiver_class,
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
            node, (
                self._IDENT_NODE, self._PROP_IDENT_NODE,
                "private_property_identifier",
            ),
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
                    cur, (self._PROP_IDENT_NODE,
                          "private_property_identifier"),
                )
                if prop is None:
                    return None
                parts.append(prop.text.decode())
                cur = cur.children[0] if cur.children else None
            if cur is not None and cur.type == self._IDENT_NODE:
                parts.append(cur.text.decode())
                return list(reversed(parts))
            if cur is not None and cur.type == self._THIS_NODE:
                # ``this.X.Y()`` — preserve ``this`` as the head so
                # the call site can be tagged with the enclosing
                # class as receiver_class.
                parts.append("this")
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


def _go_bare_binding_names(path: str) -> List[str]:
    """Binding names a bare Go ``import "<path>"`` makes available.

    Go's nominal rule is "the last path segment is the package
    identifier", but two well-known conventions make that wrong
    often enough to bite SCA's function-level reachability on
    real-world Go code:

      * **Versioned modules.** ``github.com/foo/bar/v2`` is a Go-
        modules path-versioning convention. The package name is
        almost always ``bar`` (the pre-version segment), not ``v2``
        — callers write ``bar.SomeFunc(...)``. Bare-last-segment
        binding misses every call to such a package.
      * **Hyphenated dir names.** Go identifiers can't contain
        hyphens, so a package at ``github.com/foo/bar-utils``
        declares its package name without the hyphen (usually
        ``barutils``, sometimes a shorter form). Bare-last-segment
        gives ``"bar-utils"`` which no real Go call site uses.

    Both conventions are common — versioned modules grow with
    every major release post-2019; hyphenated dirs hit any
    multi-word package name. Adding the convention-aware aliases
    converts MISSED call edges into resolved ones without false
    positives (the aliases coexist with the literal last-segment
    binding; the resolver only matches what's actually called).

    Returns a list (LAST segment first, then aliases). Caller
    binds in order without overwriting existing entries — first
    import wins, matching Go's compile-time duplicate-name rule.
    """
    names: List[str] = []
    last = path.rsplit("/", 1)[-1]
    if not last:
        return names

    names.append(last)

    # Versioned module suffix: also bind the pre-version segment.
    if last.startswith("v") and len(last) > 1 and last[1:].isdigit():
        stripped = path.rsplit("/", 1)[0]
        if stripped:
            pre_v_last = stripped.rsplit("/", 1)[-1]
            if pre_v_last:
                names.append(pre_v_last)
                if "-" in pre_v_last:
                    names.append(pre_v_last.replace("-", ""))

    # Hyphenated last segment: also bind a hyphen-collapsed form.
    if "-" in last:
        names.append(last.replace("-", ""))

    return names


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
    _PKG_CLAUSE_NODE = "package_clause"

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

        if node.type == self._PKG_CLAUSE_NODE:
            # Every Go source file starts with ``package <name>``.
            # The package name authoritatively identifies cross-
            # file references; the dir name is NOT canonical.
            # We store the package-as-declared (a single identifier,
            # not the full module path — the latter requires
            # go.mod context which the per-file extractor doesn't
            # have). The reachability resolver combines this with
            # the function name to seed ``qualified_to_internal``.
            pkg_ident = self._first_child_of_type(
                node, (self._PKG_IDENT_NODE, self._IDENT_NODE),
            )
            if pkg_ident is not None:
                try:
                    self.graph.package_name = pkg_ident.text.decode(
                        "utf-8", errors="replace",
                    ).strip()
                except Exception:                       # noqa: BLE001
                    pass
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

        # Bare import: bind the LAST segment plus convention-aware
        # aliases (versioned modules / hyphenated dirs). Don't
        # overwrite existing bindings — Go's "first import wins"
        # semantics handle real collisions via explicit aliasing.
        for name in _go_bare_binding_names(path):
            if name and name not in self.graph.imports:
                self.graph.imports[name] = path

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
    _PKG_DECL = "package_declaration"
    _SCOPED_IDENT = "scoped_identifier"
    _IDENT = "identifier"
    _FIELD_ACCESS = "field_access"
    _ARG_LIST = "argument_list"
    _METHOD_DECL = "method_declaration"
    _CONSTRUCTOR_DECL = "constructor_declaration"
    _CLASS_DECL = "class_declaration"
    _INTERFACE_DECL = "interface_declaration"
    _RECORD_DECL = "record_declaration"
    _ENUM_DECL = "enum_declaration"
    _SUPERCLASS = "superclass"
    _SUPER_INTERFACES = "super_interfaces"
    _EXTENDS_INTERFACES = "extends_interfaces"
    _TYPE_IDENT = "type_identifier"
    _ASTERISK = "asterisk"
    _STATIC = "static"
    _STRING_LIT = "string_literal"

    def __init__(self) -> None:
        self.graph = FileCallGraph()
        self._enclosing: List[str] = []
        # Class-context stack — Java methods always live inside a
        # class. The innermost class is what ``self.method()`` /
        # ``this.method()`` calls dispatch on. Captured for
        # class-aware narrowing parity with Python.
        self._class_stack: List[ClassDef] = []

    def walk(self, node) -> None:
        """Recursive descent. Push/pop enclosing-method stack so
        ``CallSite.caller`` carries the innermost named method."""
        if node.type == self._METHOD_DECL:
            name = self._first_child_of_type(node, (self._IDENT,))
            method_name = name.text.decode() if name else "<anon>"
            # Register the method on the directly-enclosing class
            # (depth-1 only; nested-class methods stay on the
            # nested class). ``_enclosing`` is empty here because
            # methods aren't nested inside methods in Java.
            if self._class_stack and not self._enclosing:
                self._class_stack[-1].methods.append(
                    (method_name, node.start_point[0] + 1),
                )
            self._enclosing.append(method_name)
            try:
                for child in node.children:
                    self.walk(child)
            finally:
                self._enclosing.pop()
            return

        if node.type == self._CONSTRUCTOR_DECL:
            # Constructors use the class name as the identifier.
            name = self._first_child_of_type(node, (self._IDENT,))
            ctor_name = name.text.decode() if name else "<ctor>"
            if self._class_stack and not self._enclosing:
                self._class_stack[-1].methods.append(
                    (ctor_name, node.start_point[0] + 1),
                )
            self._enclosing.append(ctor_name)
            try:
                for child in node.children:
                    self.walk(child)
            finally:
                self._enclosing.pop()
            return

        if node.type == self._IMPORT_DECL:
            self._visit_import(node)
            return

        if node.type == self._PKG_DECL:
            # ``package com.foo.bar;`` — the dotted prefix every
            # class in this file lives under. Java's fully-qualified
            # name is ``<package>.<class>`` (and method invocations
            # resolve via the import map + class hierarchy).
            scoped = self._first_child_of_type(node, (
                self._SCOPED_IDENT, self._IDENT,
            ))
            if scoped is not None:
                if scoped.type == self._SCOPED_IDENT:
                    pkg = self._scoped_identifier_text(scoped)
                else:
                    pkg = scoped.text.decode("utf-8", errors="replace")
                if pkg:
                    self.graph.package_name = pkg.strip()
            return

        if node.type in (self._CLASS_DECL, self._INTERFACE_DECL,
                         self._RECORD_DECL, self._ENUM_DECL):
            # Capture for class-aware narrowing. Java's
            # ``superclass`` + ``super_interfaces`` lists are
            # the bases; record them so ancestor resolution at
            # query time can narrow correctly. ``record_declaration``
            # (Java 14+) and ``enum_declaration`` share the same
            # body+heritage shape and host method definitions same
            # as a class.
            name_node = self._first_child_of_type(node, (
                self._IDENT, self._TYPE_IDENT,
            ))
            cls_name = (
                name_node.text.decode("utf-8", errors="replace")
                if name_node is not None else None
            )
            bases: List[str] = []
            for child in node.children:
                if child.type == self._SUPERCLASS:
                    # ``extends Base`` — direct type_identifier child.
                    for sub in child.children:
                        if sub.type in (self._IDENT, self._TYPE_IDENT,
                                        self._SCOPED_IDENT):
                            text = (
                                self._scoped_identifier_text(sub)
                                if sub.type == self._SCOPED_IDENT
                                else sub.text.decode(
                                    "utf-8", errors="replace",
                                )
                            )
                            if text:
                                bases.append(text)
                elif child.type in (self._SUPER_INTERFACES,
                                    self._EXTENDS_INTERFACES):
                    # ``implements A, B`` (class) or ``extends A, B``
                    # (interface) — both wrap a ``type_list``.
                    for grandchild in child.children:
                        if grandchild.type != "type_list":
                            continue
                        for sub in grandchild.children:
                            if sub.type in (self._IDENT, self._TYPE_IDENT,
                                            self._SCOPED_IDENT):
                                text = (
                                    self._scoped_identifier_text(sub)
                                    if sub.type == self._SCOPED_IDENT
                                    else sub.text.decode(
                                        "utf-8", errors="replace",
                                    )
                                )
                                if text:
                                    bases.append(text)
            if cls_name:
                cdef = ClassDef(
                    name=cls_name,
                    line=node.start_point[0] + 1,
                    bases=bases,
                    nested=bool(self._class_stack) or bool(self._enclosing),
                )
                self.graph.classes.append(cdef)
                self._class_stack.append(cdef)
                try:
                    for child in node.children:
                        self.walk(child)
                finally:
                    self._class_stack.pop()
                return
            # Anon / malformed — recurse without class push
            for child in node.children:
                self.walk(child)
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

        # Class-aware narrowing. Java implicit-receiver calls
        # (``foo()`` from inside a method) and ``this.foo()``
        # dispatch on the innermost non-nested enclosing class.
        # ``super.foo()`` is the parent — leave receiver_class
        # None and let the resolver search bases via the hierarchy.
        receiver_class: Optional[str] = None
        if (self._class_stack and not self._class_stack[-1].nested
                and self._enclosing):
            if len(chain) == 1:
                receiver_class = self._class_stack[-1].name
            elif len(chain) == 2 and chain[0] == "this":
                receiver_class = self._class_stack[-1].name

        self.graph.calls.append(CallSite(
            line=node.start_point[0] + 1,
            chain=chain,
            caller=caller,
            receiver_class=receiver_class,
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
            if child.type in (self._IDENT, self._FIELD_ACCESS,
                              "this", "super"):
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

        if operand.type in ("this", "super"):
            return [operand.type, method_name]

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
    _FUNCTION_SIG = "function_signature_item"
    _CALL_EXPR = "call_expression"
    _FIELD_EXPR = "field_expression"
    _ARGS = "arguments"
    _TYPE_IDENT = "type_identifier"
    _STRUCT_ITEM = "struct_item"
    _ENUM_ITEM = "enum_item"
    _UNION_ITEM = "union_item"
    _TRAIT_ITEM = "trait_item"
    _IMPL_ITEM = "impl_item"
    _MOD_ITEM = "mod_item"
    _DECL_LIST = "declaration_list"
    _SELF = "self"

    def __init__(self) -> None:
        self.graph = FileCallGraph()
        self._enclosing: List[str] = []
        # Class context for ``impl Foo { fn m() {} }`` — methods
        # in the impl block belong to ``Foo``. ``impl Trait for
        # Foo`` also belongs to ``Foo`` (the second type_identifier).
        # Same convention as Python / Java class_stack.
        self._class_stack: List[ClassDef] = []
        # Module nesting for mod_item; not threaded into
        # package_name (Rust file modules are path-derived) but
        # used to mark nested classes.
        self._mod_depth: int = 0

    def walk(self, node) -> None:
        if node.type == self._FUNCTION_ITEM:
            name = self._first_child_of_type(node, (self._IDENT,))
            method_name = name.text.decode() if name else "<anon>"
            # Register the method on the directly-enclosing impl
            # block (the innermost class on the stack). Skip if
            # we're inside a nested function (functions can be
            # nested inside other functions in Rust — those aren't
            # methods of the outer class).
            if self._class_stack and not self._enclosing:
                self._class_stack[-1].methods.append(
                    (method_name, node.start_point[0] + 1),
                )
            self._enclosing.append(method_name)
            try:
                for c in node.children:
                    self.walk(c)
            finally:
                self._enclosing.pop()
            return

        if node.type == self._FUNCTION_SIG:
            # ``fn name(args);`` inside a trait body — no body, no
            # calls to walk, but does count as a method definition
            # on the trait.
            name = self._first_child_of_type(node, (self._IDENT,))
            if name is not None and self._class_stack:
                method_name = name.text.decode()
                self._class_stack[-1].methods.append(
                    (method_name, node.start_point[0] + 1),
                )
            return

        if node.type == self._USE_DECL:
            self._handle_use(node)
            return

        if node.type == self._MOD_ITEM:
            self._mod_depth += 1
            try:
                for c in node.children:
                    self.walk(c)
            finally:
                self._mod_depth -= 1
            return

        if node.type in (self._STRUCT_ITEM, self._ENUM_ITEM,
                         self._UNION_ITEM, self._TRAIT_ITEM):
            # ``struct Foo;`` / ``enum E { ... }`` / ``trait T``
            # declares the class itself. Bases are the trait
            # supertraits for trait_item (``trait T: A + B``); for
            # struct/enum/union there are no bases (impls add them).
            name_node = self._first_child_of_type(node, (
                self._TYPE_IDENT,
            ))
            bases: List[str] = []
            if node.type == self._TRAIT_ITEM:
                # Trait supertraits live inside a ``trait_bounds``
                # node — collect type_identifiers there.
                bounds = self._first_child_of_type(node, (
                    "trait_bounds",
                ))
                if bounds is not None:
                    for sub in bounds.children:
                        if sub.type == self._TYPE_IDENT:
                            bases.append(sub.text.decode())
            if name_node is not None:
                cdef = ClassDef(
                    name=name_node.text.decode(),
                    line=node.start_point[0] + 1,
                    bases=bases,
                    nested=(
                        bool(self._class_stack)
                        or bool(self._enclosing)
                        or self._mod_depth > 0
                    ),
                )
                self.graph.classes.append(cdef)
                # Trait bodies hold method signatures we want
                # registered; struct/enum bodies don't define
                # methods (those live in separate impl blocks).
                self._class_stack.append(cdef)
                try:
                    for c in node.children:
                        self.walk(c)
                finally:
                    self._class_stack.pop()
                return
            # Anon — recurse without push.
            for c in node.children:
                self.walk(c)
            return

        if node.type == self._IMPL_ITEM:
            # ``impl Foo`` or ``impl Trait for Foo``. Method
            # definitions inside belong to ``Foo``. The grammar
            # emits two type_identifier children for the second
            # shape; the impl target is the LAST one. Generic
            # impls (``impl<T> Box<T>``) wrap the target in a
            # ``generic_type`` node whose first child is the
            # type_identifier we want.
            target_names: List[str] = []
            for c in node.children:
                if c.type == self._TYPE_IDENT:
                    target_names.append(c.text.decode())
                elif c.type == "generic_type":
                    ti = self._first_child_of_type(c, (self._TYPE_IDENT,))
                    if ti is not None:
                        target_names.append(ti.text.decode())
                elif c.type == self._SCOPED_IDENT:
                    parts = self._scoped_parts(c)
                    if parts:
                        target_names.append(parts[-1])
            if not target_names:
                # Unsupported shape — skip class binding, still
                # recurse so calls inside are still captured.
                for c in node.children:
                    self.walk(c)
                return
            target = target_names[-1]
            # Try to bind to the already-recorded ClassDef
            # (same-file struct/enum) so methods accumulate on a
            # single ClassDef rather than per-impl. If the impl
            # target wasn't declared in this file, synthesise an
            # impl-only ClassDef so cross-file method matching
            # still works.
            target_cls = next(
                (c for c in self.graph.classes if c.name == target),
                None,
            )
            if target_cls is None:
                target_cls = ClassDef(
                    name=target,
                    line=node.start_point[0] + 1,
                    bases=[],
                    nested=self._mod_depth > 0,
                )
                self.graph.classes.append(target_cls)
            self._class_stack.append(target_cls)
            try:
                for c in node.children:
                    self.walk(c)
            finally:
                self._class_stack.pop()
            return

        if node.type == self._CALL_EXPR:
            chain = self._call_chain(node)
            if chain:
                line = node.start_point[0] + 1
                caller = self._enclosing[-1] if self._enclosing else None
                # Class-aware: ``self.foo()`` inside a method
                # dispatches on the enclosing impl target. The
                # chain shape is ``["self", "foo"]``.
                receiver_class: Optional[str] = None
                if (self._class_stack and self._enclosing
                        and len(chain) == 2 and chain[0] == "self"):
                    receiver_class = self._class_stack[-1].name
                self.graph.calls.append(
                    CallSite(
                        line=line, chain=chain, caller=caller,
                        receiver_class=receiver_class,
                    )
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
        if cur.type == self._SELF:
            parts.append("self")
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
    _SINGLETON_METHOD = "singleton_method"
    _IDENT = "identifier"
    _CONSTANT = "constant"
    _SCOPE_RES = "scope_resolution"
    _STRING = "string"
    _STRING_CONTENT = "string_content"
    _ARG_LIST = "argument_list"
    _CLASS_NODE = "class"
    _MODULE_NODE = "module"
    _SUPERCLASS = "superclass"
    _SELF = "self"

    _REFLECT_NAMES = {"send", "public_send", "__send__"}
    _CONST_GET_NAMES = {"const_get"}
    _EVAL_NAMES = {"eval", "instance_eval", "class_eval", "module_eval"}
    _REQUIRE_NAMES = {"require", "require_relative", "load"}

    def __init__(self) -> None:
        self.graph = FileCallGraph()
        self._enclosing: List[str] = []
        # Class context. Ruby ``self.foo()`` dispatches on the
        # innermost ``class`` (modules dispatch to module functions
        # but those aren't instance-bound, so we don't tag
        # receiver_class for modules).
        self._class_stack: List[ClassDef] = []
        # Module nesting stack — used to build ``package_name``
        # for nested modules. Ruby's top-level file is its own
        # module; nested ``module Foo; module Bar; ...`` produce
        # ``package_name="Foo.Bar"``.
        self._mod_stack: List[str] = []

    def walk(self, node) -> None:
        if node.type == self._MODULE_NODE:
            name_node = self._first_child_of_type(node, (
                self._CONSTANT,
            ))
            if name_node is not None:
                mod_name = name_node.text.decode()
                self._mod_stack.append(mod_name)
                # Set graph.package_name to the dotted form of the
                # current module nesting. Last setter wins per
                # file — typical Ruby files declare one or two
                # module nesting levels at file top, so the deepest
                # nesting is the canonical package.
                self.graph.package_name = ".".join(self._mod_stack)
                try:
                    for c in node.children:
                        self.walk(c)
                finally:
                    self._mod_stack.pop()
                return
            for c in node.children:
                self.walk(c)
            return

        if node.type == self._CLASS_NODE:
            name_node = self._first_child_of_type(node, (
                self._CONSTANT,
            ))
            if name_node is not None:
                bases: List[str] = []
                # Ruby is single-inheritance — ``superclass`` carries
                # exactly one base.
                supercls = self._first_child_of_type(node, (
                    self._SUPERCLASS,
                ))
                if supercls is not None:
                    base_node = self._first_child_of_type(supercls, (
                        self._CONSTANT, self._SCOPE_RES,
                    ))
                    if base_node is not None:
                        if base_node.type == self._SCOPE_RES:
                            bases = [".".join(
                                self._chain_from_node(base_node)
                            )]
                        else:
                            bases = [base_node.text.decode()]
                cdef = ClassDef(
                    name=name_node.text.decode(),
                    line=node.start_point[0] + 1,
                    bases=bases,
                    nested=bool(self._class_stack) or bool(self._enclosing),
                )
                self.graph.classes.append(cdef)
                self._class_stack.append(cdef)
                try:
                    for c in node.children:
                        self.walk(c)
                finally:
                    self._class_stack.pop()
                return
            for c in node.children:
                self.walk(c)
            return

        if node.type in (self._METHOD, self._SINGLETON_METHOD):
            # ``def helper`` (method) and ``def self.helper`` /
            # ``def Cls.helper`` (singleton_method) share the same
            # method-name shape — the first ``identifier`` after the
            # ``def`` keyword. Singleton methods inside a module
            # body are the typical ``self.x`` module function form.
            name = self._first_child_of_type(node, (self._IDENT,))
            method_name = name.text.decode() if name else "<anon>"
            if self._class_stack and not self._enclosing:
                self._class_stack[-1].methods.append(
                    (method_name, node.start_point[0] + 1),
                )
            self._enclosing.append(method_name)
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
                elif c.type == self._SELF and receiver is None:
                    # ``self.foo`` — keep ``self`` as the receiver
                    # so the chain reads ``["self", "foo"]``.
                    receiver = c
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
        if node.type == self._SELF:
            return ["self"]
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
        # ``self.foo()`` inside an instance method → narrow to the
        # enclosing class. Bare-name ``foo()`` resolves through
        # Ruby's method-lookup chain (could be from a mixin, the
        # superclass, or the same class); without runtime semantics
        # we can't narrow it, so leave receiver_class None.
        receiver_class: Optional[str] = None
        if (self._class_stack and not self._class_stack[-1].nested
                and self._enclosing
                and len(chain) >= 2 and chain[0] == "self"):
            receiver_class = self._class_stack[-1].name
        self.graph.calls.append(
            CallSite(
                line=line, chain=chain, caller=caller,
                receiver_class=receiver_class,
            )
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
    _NAMESPACE_DECL = "namespace_declaration"
    _FILE_NAMESPACE_DECL = "file_scoped_namespace_declaration"
    _CLASS_DECL = "class_declaration"
    _INTERFACE_DECL = "interface_declaration"
    _STRUCT_DECL = "struct_declaration"
    _RECORD_DECL = "record_declaration"
    _BASE_LIST = "base_list"
    _THIS = "this_expression"

    _REFLECT_METHODS = {
        "Invoke", "GetMethod", "CreateInstance",
        "InvokeMember",
    }
    _ASSEMBLY_LOAD = {"Load", "LoadFrom", "LoadFile", "LoadWithPartialName"}

    def __init__(self) -> None:
        self.graph = FileCallGraph()
        self._enclosing: List[str] = []
        self._class_stack: List[ClassDef] = []
        # Namespace nesting; can be ``namespace Foo.Bar { ... }``
        # (one node carrying dotted form) OR nested ``namespace Foo
        # { namespace Bar { ... } }``. Track each segment separately.
        self._ns_stack: List[str] = []

    def walk(self, node) -> None:
        if node.type == self._FILE_NAMESPACE_DECL:
            # C# 10's file-scoped namespace: ``namespace Foo.Bar;``
            # with no braces. The namespace applies to every
            # declaration that follows in the same compilation
            # unit (which are SIBLINGS of this node, not children).
            # Set ``package_name`` once and let the normal recursion
            # continue — don't push/pop the stack because the scope
            # doesn't close.
            name_node = self._first_child_of_type(node, (
                self._QUALIFIED, self._IDENT,
            ))
            if name_node is not None:
                if name_node.type == self._QUALIFIED:
                    parts = self._qualified_parts(name_node)
                else:
                    parts = [name_node.text.decode()]
                self._ns_stack.extend(parts)
                self.graph.package_name = ".".join(self._ns_stack)
            return

        if node.type == self._NAMESPACE_DECL:
            # Braced ``namespace Foo.Bar { ... }`` — applies to the
            # nested declaration_list only.
            name_node = self._first_child_of_type(node, (
                self._QUALIFIED, self._IDENT,
            ))
            if name_node is not None:
                if name_node.type == self._QUALIFIED:
                    parts = self._qualified_parts(name_node)
                else:
                    parts = [name_node.text.decode()]
                self._ns_stack.extend(parts)
                self.graph.package_name = ".".join(self._ns_stack)
                try:
                    for c in node.children:
                        self.walk(c)
                finally:
                    for _ in parts:
                        self._ns_stack.pop()
                return
            for c in node.children:
                self.walk(c)
            return

        if node.type in (self._CLASS_DECL, self._INTERFACE_DECL,
                         self._STRUCT_DECL, self._RECORD_DECL):
            name_node = self._first_child_of_type(node, (self._IDENT,))
            if name_node is not None:
                bases: List[str] = []
                bl = self._first_child_of_type(node, (self._BASE_LIST,))
                if bl is not None:
                    for sub in bl.children:
                        if sub.type == self._IDENT:
                            bases.append(sub.text.decode())
                        elif sub.type == self._QUALIFIED:
                            qparts = self._qualified_parts(sub)
                            if qparts:
                                bases.append(".".join(qparts))
                cdef = ClassDef(
                    name=name_node.text.decode(),
                    line=node.start_point[0] + 1,
                    bases=bases,
                    nested=bool(self._class_stack) or bool(self._enclosing),
                )
                self.graph.classes.append(cdef)
                self._class_stack.append(cdef)
                try:
                    for c in node.children:
                        self.walk(c)
                finally:
                    self._class_stack.pop()
                return
            for c in node.children:
                self.walk(c)
            return

        if node.type in (self._METHOD_DECL, self._CONSTRUCTOR_DECL):
            name = self._first_child_of_type(node, (self._IDENT,))
            method_name = name.text.decode() if name else "<anon>"
            if self._class_stack and not self._enclosing:
                self._class_stack[-1].methods.append(
                    (method_name, node.start_point[0] + 1),
                )
            self._enclosing.append(method_name)
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
                # ``this.X()`` inside an instance method → narrow
                # to the enclosing class. C# unqualified ``X()``
                # also dispatches via implicit-this (no module-
                # level functions in C#), so tag length-1 chains
                # too when inside a class.
                receiver_class: Optional[str] = None
                if (self._class_stack
                        and not self._class_stack[-1].nested
                        and self._enclosing):
                    if len(chain) == 1:
                        receiver_class = self._class_stack[-1].name
                    elif len(chain) == 2 and chain[0] == "this":
                        receiver_class = self._class_stack[-1].name
                self.graph.calls.append(
                    CallSite(
                        line=line, chain=chain, caller=caller,
                        receiver_class=receiver_class,
                    )
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
        """``a.b.c`` (member_access_expression).

        ``this.X`` and ``base.X`` use unnamed keyword tokens for the
        LHS in tree-sitter-c_sharp — special-cased below."""
        parts: List[str] = []
        cur = node
        while cur is not None and cur.type == self._MEMBER_ACCESS:
            named = [c for c in cur.children if c.is_named]
            if len(named) == 1:
                # Only the trailing name is named — LHS is an
                # unnamed keyword. Check for ``this`` / ``base``.
                has_this = any(
                    not c.is_named and c.type in ("this", "base")
                    for c in cur.children
                )
                if not has_this:
                    return None
                tail = named[-1]
                if tail.type != self._IDENT:
                    return None
                parts.append(tail.text.decode())
                # Synthesise the unnamed-this LHS as the chain head.
                kw = next(
                    (c.type for c in cur.children
                     if not c.is_named and c.type in ("this", "base")),
                    "this",
                )
                parts.append(kw)
                return list(reversed(parts))
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
        if cur.type == self._THIS:
            parts.append("this")
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
    _NAMESPACE_DEF = "namespace_definition"
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
    _CLASS_DECL = "class_declaration"
    _INTERFACE_DECL = "interface_declaration"
    _TRAIT_DECL = "trait_declaration"
    _ENUM_DECL = "enum_declaration"
    _BASE_CLAUSE = "base_clause"
    _CLASS_INTERFACE_CLAUSE = "class_interface_clause"

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
        self._class_stack: List[ClassDef] = []

    def walk(self, node) -> None:
        if node.type == self._NAMESPACE_DEF:
            # ``namespace Foo\Bar;`` — capture as dotted package
            # name. The namespace_name child carries the parts.
            ns_name = self._first_child_of_type(node, (
                self._NAMESPACE_NAME,
            ))
            if ns_name is not None:
                parts = self._namespace_parts(ns_name)
                if parts:
                    self.graph.package_name = ".".join(parts)
            # Descend into the namespace body (declarations live
            # inside compound_statement if braced, or as siblings).
            for c in node.children:
                self.walk(c)
            return

        if node.type in (self._CLASS_DECL, self._INTERFACE_DECL,
                         self._TRAIT_DECL, self._ENUM_DECL):
            name_node = self._first_child_of_type(node, (self._NAME,))
            if name_node is not None:
                bases: List[str] = []
                # ``extends Base`` (single-class inheritance in PHP).
                bc = self._first_child_of_type(node, (self._BASE_CLAUSE,))
                if bc is not None:
                    for sub in bc.children:
                        if sub.type == self._NAME:
                            bases.append(sub.text.decode())
                        elif sub.type == self._QUALIFIED:
                            qparts = self._namespace_parts(sub)
                            if qparts:
                                bases.append(".".join(qparts))
                # ``implements I1, I2`` (multiple interfaces).
                cic = self._first_child_of_type(node, (
                    self._CLASS_INTERFACE_CLAUSE,
                ))
                if cic is not None:
                    for sub in cic.children:
                        if sub.type == self._NAME:
                            bases.append(sub.text.decode())
                        elif sub.type == self._QUALIFIED:
                            qparts = self._namespace_parts(sub)
                            if qparts:
                                bases.append(".".join(qparts))
                cdef = ClassDef(
                    name=name_node.text.decode(),
                    line=node.start_point[0] + 1,
                    bases=bases,
                    nested=bool(self._class_stack) or bool(self._enclosing),
                )
                self.graph.classes.append(cdef)
                self._class_stack.append(cdef)
                try:
                    for c in node.children:
                        self.walk(c)
                finally:
                    self._class_stack.pop()
                return
            for c in node.children:
                self.walk(c)
            return

        if node.type in (self._FUNCTION_DEF, self._METHOD_DECL):
            name = self._first_child_of_type(node, (self._NAME,))
            method_name = name.text.decode() if name else "<anon>"
            if (node.type == self._METHOD_DECL
                    and self._class_stack and not self._enclosing):
                self._class_stack[-1].methods.append(
                    (method_name, node.start_point[0] + 1),
                )
            self._enclosing.append(method_name)
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
        # ``$this->X()`` (already canonicalised to chain ``["this",
        # "X"]`` by _object_chain stripping the $) inside an
        # instance method → narrow to the enclosing class. Bare
        # function calls are NOT implicit-this in PHP — they
        # resolve to namespaced/global functions.
        # ``self::X()`` and ``static::X()`` (late-static-binding)
        # also dispatch on the enclosing class; ``parent::X()``
        # dispatches on the parent (leave None, let resolver
        # search bases).
        receiver_class: Optional[str] = None
        if (self._class_stack and not self._class_stack[-1].nested
                and self._enclosing
                and len(chain) >= 2):
            if (node.type == self._MEMBER_CALL
                    and chain[0] == "this"):
                receiver_class = self._class_stack[-1].name
            elif (node.type == self._SCOPED_CALL
                  and chain[0] in ("self", "static")):
                receiver_class = self._class_stack[-1].name
        self.graph.calls.append(
            CallSite(
                line=line, chain=chain, caller=caller,
                receiver_class=receiver_class,
            )
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
        # scoped_call_expression: scope (Class) :: name + arguments.
        # PHP's ``self::method()`` / ``static::method()`` /
        # ``parent::method()`` use a ``relative_scope`` node holding
        # the keyword. ``Class::method()`` uses a ``name`` or
        # ``qualified_name`` scope.
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
        elif scope.type == "relative_scope":
            # ``self``/``static``/``parent``. Use the keyword as
            # the chain head so receiver_class can be set when
            # applicable.
            kw = None
            for sub in scope.children:
                if sub.type in ("self", "static", "parent"):
                    kw = sub.type
                    break
            if kw is None:
                return None
            scope_parts = [kw]
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


# ===========================================================================
# C
# ===========================================================================
#
# C semantics differ from the higher-level languages above:
#
#   * No module system. ``#include "foo.h"`` is preprocessor text
#     substitution; there's no qualified-name space the linker
#     exposes by file. ``imports`` records included headers as
#     ``basename(header) -> header path`` so the resolver can
#     match ``foo`` → ``foo.h`` at the call site.
#
#   * Function pointers are first-class. ``fp()`` where ``fp`` is a
#     local variable is statically indistinguishable from a direct
#     call without type-resolution. Walker emits the call with chain
#     ``[<name>]`` and adds ``INDIRECTION_FN_POINTER`` to the
#     indirection set. Resolver downstream can downweight matches.
#
#   * Macros that look like calls (``BUG_ON(...)``,
#     ``container_of(...)``) appear as ``call_expression`` to
#     tree-sitter — the preprocessor isn't run. The walker emits
#     them as regular calls with the macro identifier as chain.
#     Downstream consumers can disambiguate via the inventory's
#     macro list.
#
#   * No classes, no namespaces (C++ handles those separately).

INDIRECTION_FN_POINTER = "fn_pointer"  # C/C++ call through a fn pointer var


def extract_call_graph_c(content: str) -> FileCallGraph:
    """Walk a C source string via tree-sitter-c and return its
    :class:`FileCallGraph`.

    Returns an empty graph when ``tree_sitter_c`` isn't installed or
    the file is unparseable.

    Shapes captured:

      * ``#include "x.h"`` / ``#include <x.h>`` → ``imports``: the
        basename without extension maps to the full header path.
        ``#include "subdir/x.h"`` records both ``x`` → ``subdir/x.h``.
      * ``foo(...)`` → chain ``["foo"]``
      * ``obj.foo(...)`` → chain ``["obj", "foo"]``
        (struct field access via tree-sitter ``field_expression``)
      * ``obj->foo(...)`` → chain ``["obj", "foo"]``
        (pointer-to-struct field access; same node type)
      * ``a.b.c(...)`` / ``a->b->c(...)`` → chain ``["a", "b", "c"]``
      * ``(*fp)(...)`` → chain ``[<name>]`` + ``INDIRECTION_FN_POINTER``
      * ``fp(...)`` where ``fp`` looks like a local variable —
        statically indistinguishable from a direct call; emitted as a
        regular call. Downstream consumers wanting to filter
        function-pointer-likely callees should consult the inventory
        for whether ``fp`` is a known function name.

    Limitations (deliberate, not bugs):

      * Macros that expand to call expressions are not seen as such —
        the walker reads pre-preprocessor source. ``BUG_ON(x)`` is
        emitted as a call to ``BUG_ON``; its expansion (``do { if
        (x) { ... } } while (0)``) is invisible.
      * Typedef'd function-pointer types aren't traced; only the
        syntactic ``(*fp)(...)`` form is recognised as indirection.
      * K&R-style function definitions are accepted by tree-sitter
        but the declarator walk only handles ANSI prototypes for
        signature/parameters extraction.
    """
    try:
        import tree_sitter_c as ts_c
        from tree_sitter import Language, Parser
    except ImportError:
        logger.debug(
            "call_graph: tree-sitter C grammar not installed; "
            "returning empty graph",
        )
        return FileCallGraph()

    try:
        parser = Parser(Language(ts_c.language()))
        tree = parser.parse(content.encode("utf-8", errors="replace"))
    except Exception as e:                              # noqa: BLE001
        logger.debug("call_graph: C parse failed (%s)", e)
        return FileCallGraph()

    walker = _CCallGraph()
    walker.walk(tree.root_node)
    return walker.graph


class _CCallGraph:
    """Single-pass tree-sitter-c walk.

    Maintains a stack of enclosing function names so each emitted
    ``CallSite`` knows its lexical container. The stack is keyed by
    function identifier; for static functions and externs the
    identifier is sufficient because C's single global namespace per
    translation unit means name + file is unique.
    """

    # Top-level constructs.
    _FUNCTION_DEFINITION = "function_definition"
    _PREPROC_INCLUDE = "preproc_include"

    # Declarator wrapping.
    _FUNCTION_DECLARATOR = "function_declarator"
    _POINTER_DECLARATOR = "pointer_declarator"
    _PARENTHESIZED_DECLARATOR = "parenthesized_declarator"

    # Expressions.
    _CALL_EXPRESSION = "call_expression"
    _FIELD_EXPRESSION = "field_expression"
    _POINTER_EXPRESSION = "pointer_expression"
    _PARENTHESIZED_EXPRESSION = "parenthesized_expression"

    # Leaf names.
    _IDENTIFIER = "identifier"
    _FIELD_IDENTIFIER = "field_identifier"

    # Header strings.
    _STRING_LITERAL = "string_literal"
    _SYSTEM_LIB_STRING = "system_lib_string"
    _STRING_CONTENT = "string_content"

    def __init__(self) -> None:
        self.graph = FileCallGraph()
        # Stack of lexically-enclosing function names. ``None`` is
        # never pushed — file-scope ``CallSite``s (initialisers) emit
        # with ``caller=None``.
        self._enclosing: List[str] = []

    # ------------------------------------------------------------------
    # Walk dispatch
    # ------------------------------------------------------------------

    def walk(self, node) -> None:
        """Pre-order traversal. Function definitions push their name
        before children are visited; pop on the way back up."""
        t = node.type
        if t == self._PREPROC_INCLUDE:
            self._visit_include(node)
            # Includes don't have function/call children worth walking.
            return
        if t == self._FUNCTION_DEFINITION:
            name = self._function_name(node)
            if name is not None:
                self._enclosing.append(name)
                try:
                    for child in node.children:
                        self.walk(child)
                    return
                finally:
                    self._enclosing.pop()
        if t == self._CALL_EXPRESSION:
            self._visit_call(node)
            # Fall through so nested calls inside the arg list are visited.
        for child in node.children:
            self.walk(child)

    # ------------------------------------------------------------------
    # Includes
    # ------------------------------------------------------------------

    def _visit_include(self, node) -> None:
        # tree-sitter-c structure:
        #   preproc_include "#include" (string_literal | system_lib_string)
        for child in node.children:
            if child.type == self._STRING_LITERAL:
                # "foo/bar.h" → unwrap the string_content.
                path = self._unwrap_string(child)
                if path:
                    self._record_include(path)
            elif child.type == self._SYSTEM_LIB_STRING:
                # <stdio.h> — the whole text including angle brackets.
                raw = child.text.decode("utf-8", errors="replace").strip()
                if raw.startswith("<") and raw.endswith(">"):
                    path = raw[1:-1]
                    if path:
                        self._record_include(path)

    def _record_include(self, path: str) -> None:
        # basename without extension as the local binding name.
        # ``net/dst.h`` → ``dst``; ``stdio.h`` → ``stdio``.
        from os.path import basename, splitext
        local = splitext(basename(path))[0]
        if local:
            self.graph.imports[local] = path

    # ------------------------------------------------------------------
    # Calls
    # ------------------------------------------------------------------

    def _visit_call(self, node) -> None:
        # call_expression: function (argument_list)
        # The "function" field is the first named child before
        # argument_list.
        callee_node = None
        for c in node.children:
            if c.type == "argument_list":
                break
            if c.is_named:
                callee_node = c
                break
        if callee_node is None:
            return

        chain, is_fn_pointer = self._callee_chain(callee_node)
        if chain is None:
            return

        if is_fn_pointer:
            self.graph.indirection.add(INDIRECTION_FN_POINTER)

        caller = self._enclosing[-1] if self._enclosing else None
        self.graph.calls.append(CallSite(
            line=node.start_point[0] + 1,  # tree-sitter is 0-indexed
            chain=chain,
            caller=caller,
        ))

    def _callee_chain(self, node) -> Tuple[Optional[List[str]], bool]:
        """Resolve the callee expression to an attribute chain.

        Returns (chain, is_fn_pointer). ``chain`` is None when the
        callee shape isn't statically nameable (lambda result,
        subscripted array, complex expression).
        """
        # Unwrap parenthesised expressions: ``(*fp)(...)`` parses as
        # call_expression{parenthesized_expression{pointer_expression{
        # identifier "fp"}}}.
        if node.type == self._PARENTHESIZED_EXPRESSION:
            inner = self._first_named_child(node)
            if inner is None:
                return None, False
            chain, _ = self._callee_chain(inner)
            # Anything inside parens that resolved to a chain is
            # function-pointer-shaped if we unwrap a pointer_expression
            # next.
            return chain, chain is not None and inner.type == self._POINTER_EXPRESSION

        if node.type == self._POINTER_EXPRESSION:
            # ``*fp`` — the pointed-to is the operand.
            inner = self._first_named_child(node)
            if inner is None:
                return None, False
            chain, _ = self._callee_chain(inner)
            return chain, chain is not None

        if node.type == self._IDENTIFIER:
            return [node.text.decode("utf-8", errors="replace")], False

        if node.type == self._FIELD_EXPRESSION:
            return self._field_chain(node), False

        return None, False

    def _field_chain(self, node) -> Optional[List[str]]:
        """Resolve ``a.b.c`` / ``a->b->c`` / mixed → ``["a","b","c"]``."""
        parts: List[str] = []
        cur = node
        # field_expression: argument . | -> field
        while cur is not None and cur.type == self._FIELD_EXPRESSION:
            field_node = None
            for c in cur.children:
                if c.type == self._FIELD_IDENTIFIER:
                    field_node = c
            if field_node is None:
                return None
            parts.append(field_node.text.decode("utf-8", errors="replace"))
            # Operand is the first named child (the "argument" side).
            operand = None
            for c in cur.children:
                if c.is_named and c.type != self._FIELD_IDENTIFIER:
                    operand = c
                    break
            cur = operand
        if cur is None:
            return None
        if cur.type == self._IDENTIFIER:
            parts.append(cur.text.decode("utf-8", errors="replace"))
            return list(reversed(parts))
        # Other tail shapes (subscript, call result) aren't statically
        # nameable; bail out.
        return None

    # ------------------------------------------------------------------
    # Function name extraction
    # ------------------------------------------------------------------

    def _function_name(self, fn_def_node) -> Optional[str]:
        """Find the function identifier inside a function_definition.

        The declarator subtree may be wrapped:
          * ``int foo(...)``           → function_declarator{identifier}
          * ``int *foo(...)``          → pointer_declarator{
                                            function_declarator{identifier}}
          * ``int (*foo)(...)``        → function pointer typedef — NOT a
                                            function definition; tree-sitter
                                            parses this differently, so we
                                            wouldn't be in this branch.
        """
        for c in fn_def_node.children:
            if not c.is_named:
                continue
            if c.type == self._FUNCTION_DECLARATOR:
                return self._declarator_name(c)
            if c.type == self._POINTER_DECLARATOR:
                inner = self._find_function_declarator(c)
                if inner is not None:
                    return self._declarator_name(inner)
        return None

    def _declarator_name(self, fn_declarator_node) -> Optional[str]:
        # function_declarator first named child is the name (identifier)
        # or another declarator that wraps the name.
        for c in fn_declarator_node.children:
            if not c.is_named:
                continue
            if c.type == self._IDENTIFIER:
                return c.text.decode("utf-8", errors="replace")
            if c.type == self._PARENTHESIZED_DECLARATOR:
                inner = self._first_named_child(c)
                if inner is not None and inner.type == self._IDENTIFIER:
                    return inner.text.decode("utf-8", errors="replace")
        return None

    def _find_function_declarator(self, node):
        """Recursively descend through pointer/parenthesized wrappers
        to the inner function_declarator."""
        for c in node.children:
            if c.type == self._FUNCTION_DECLARATOR:
                return c
            if c.type in (self._POINTER_DECLARATOR, self._PARENTHESIZED_DECLARATOR):
                inner = self._find_function_declarator(c)
                if inner is not None:
                    return inner
        return None

    # ------------------------------------------------------------------
    # Small utilities
    # ------------------------------------------------------------------

    @staticmethod
    def _first_named_child(node):
        for c in node.children:
            if c.is_named:
                return c
        return None

    @staticmethod
    def _unwrap_string(string_node) -> Optional[str]:
        """``"foo/bar.h"`` → ``foo/bar.h``."""
        for c in string_node.children:
            if c.type == "string_content":
                return c.text.decode("utf-8", errors="replace")
        # Fallback: strip outer quotes from the raw text.
        raw = string_node.text.decode("utf-8", errors="replace")
        if len(raw) >= 2 and raw[0] == '"' and raw[-1] == '"':
            return raw[1:-1]
        return None


# ===========================================================================
# C++
# ===========================================================================
#
# C++ extends C with classes, namespaces, qualified identifiers,
# destructors, templates. The walker subclasses ``_CCallGraph`` and
# overrides the dispatch + the constructs C doesn't have:
#
#   * ``class_specifier`` / ``struct_specifier`` → ``ClassDef`` entry,
#     class stack pushed for inline-method calls to acquire
#     ``receiver_class``.
#   * In-class method definitions populate ``ClassDef.methods``.
#   * Out-of-line definitions (``int Foo::bar() {...}``) emit calls
#     inside ``bar`` with ``receiver_class="Foo"`` even though the
#     class body isn't lexically enclosing — the qualified declarator
#     carries the class.
#   * ``qualified_identifier`` (``Foo::bar``, ``std::cout``,
#     ``ns::sub::fn``) → chain with ``::``-joined name components.
#   * Inside a class body, a bare ``member()`` call is implicit-this;
#     ``this->member()`` is the explicit form. Both tag the call
#     with ``receiver_class`` = current class.
#   * ``~Foo`` (destructor_name) → name ``~Foo``.
#   * ``template_declaration`` wrappers are descended into; the
#     template itself doesn't appear in the call graph.
#   * Lambdas are opaque: the call expression they appear in is still
#     emitted, but a lambda *call* (``[]{...}()``) returns no chain.

def extract_call_graph_cpp(content: str) -> FileCallGraph:
    """Walk a C++ source string via tree-sitter-cpp and return its
    :class:`FileCallGraph`.

    Returns an empty graph when ``tree_sitter_cpp`` isn't installed or
    the file is unparseable.

    Shapes captured (in addition to all C shapes — see
    :func:`extract_call_graph_c`):

      * ``Foo::bar(...)`` → chain ``["Foo", "bar"]``
      * ``std::cout`` (used as a callee chain root) → chain
        ``["std", "cout", ...]``
      * ``namespace ns { void f() {...} }`` → ``f`` is recorded
        bare; we do NOT prepend namespace to the function name
        (the inventory's resolver matches on bare names today;
        prepending would create a second namespace-resolution
        problem for downstream).
      * ``class Foo { void bar(); }`` → ``ClassDef(name="Foo",
        methods=[("bar", line), ...])`` in
        ``FileCallGraph.classes``.
      * ``int Foo::bar() {...}`` (out-of-line) → ``bar`` is pushed
        as the caller name (matches the C convention); calls inside
        bar's body tagged with ``receiver_class="Foo"``.
      * ``this->member()`` inside class body → chain ``["this",
        "member"]`` + ``receiver_class`` = enclosing class.
      * Bare ``member()`` inside class body → chain ``["member"]``;
        treated as implicit-this only when the name is in the
        current class's method list — otherwise emitted as a plain
        call.

    Out of scope at this revision:

      * Template instantiation. ``vector<int>`` callees emit the
        bare ``vector`` (the type-args are dropped). Method-template
        calls are emitted with the bare method name.
      * Operator overloading. ``a + b`` doesn't emit a call to
        ``operator+`` even though it resolves to one.
      * Implicit conversion / constructor calls. Only syntactic
        calls are emitted.
      * ``using namespace ns;`` doesn't fold ``ns::`` qualifiers off
        of subsequent calls.
    """
    try:
        import tree_sitter_cpp as ts_cpp
        from tree_sitter import Language, Parser
    except ImportError:
        logger.debug(
            "call_graph: tree-sitter C++ grammar not installed; "
            "returning empty graph",
        )
        return FileCallGraph()

    try:
        parser = Parser(Language(ts_cpp.language()))
        tree = parser.parse(content.encode("utf-8", errors="replace"))
    except Exception as e:                              # noqa: BLE001
        logger.debug("call_graph: C++ parse failed (%s)", e)
        return FileCallGraph()

    walker = _CppCallGraph()
    walker.walk(tree.root_node)
    return walker.graph


class _CppCallGraph(_CCallGraph):
    """C++ walker. Reuses C base for includes, field expressions,
    pointer-call indirection, and ANSI declarator name extraction;
    adds class/struct/namespace/qualified-id handling."""

    # Class-body constructs.
    _CLASS_SPECIFIER = "class_specifier"
    _STRUCT_SPECIFIER = "struct_specifier"
    _FIELD_DECLARATION_LIST = "field_declaration_list"
    _BASE_CLASS_CLAUSE = "base_class_clause"
    _NAMESPACE_DEFINITION = "namespace_definition"

    # Qualified names.
    _QUALIFIED_IDENTIFIER = "qualified_identifier"
    _NAMESPACE_IDENTIFIER = "namespace_identifier"
    _TEMPLATE_TYPE = "template_type"
    _TEMPLATE_FUNCTION = "template_function"
    _TEMPLATE_DECLARATION = "template_declaration"

    # Special name shapes.
    _DESTRUCTOR_NAME = "destructor_name"
    _OPERATOR_NAME = "operator_name"
    _TYPE_IDENTIFIER = "type_identifier"

    # tree-sitter-cpp emits the keyword ``this`` as its own node type
    # named literally ``"this"``. It appears as the operand inside
    # ``field_expression`` for ``this->member`` / ``this.member``.
    _THIS = "this"

    # In-class method declaration: ``field_declaration`` wraps a
    # ``function_declarator``. Tracking these populates
    # ``ClassDef.methods`` even when the body lives out-of-line.
    _FIELD_DECLARATION = "field_declaration"

    def __init__(self) -> None:
        super().__init__()
        self._class_stack: List[ClassDef] = []
        # Namespace nesting stack. Each entry is a segment name
        # (e.g. ``ns`` for ``namespace ns { ... }``; ``a``, ``b``
        # for ``namespace a::b { ... }``). The dotted join feeds
        # ``graph.package_name`` for resolver canonicalisation —
        # parity with Java/C#/PHP/Ruby/Go.
        self._ns_stack: List[str] = []

    # ------------------------------------------------------------------
    # Walk dispatch
    # ------------------------------------------------------------------

    def walk(self, node) -> None:
        t = node.type
        if t == self._PREPROC_INCLUDE:
            self._visit_include(node)
            return
        if t == self._NAMESPACE_DEFINITION:
            self._visit_namespace_definition(node)
            return
        if t in (self._CLASS_SPECIFIER, self._STRUCT_SPECIFIER):
            self._visit_class_specifier(node)
            return  # children are visited inside _visit_class_specifier
        if t == self._FUNCTION_DEFINITION:
            self._visit_function_definition(node)
            return
        if t == self._CALL_EXPRESSION:
            self._visit_call(node)
            # Fall through — nested calls in arg list still walked.
        if t == "field_initializer":
            self._visit_field_initializer(node)
            # Fall through — nested calls inside the argument_list
            # (e.g. ``Base(helper())``) still need to be walked.
        for child in node.children:
            self.walk(child)

    # ------------------------------------------------------------------
    # Namespace
    # ------------------------------------------------------------------

    def _visit_namespace_definition(self, node) -> None:
        """``namespace ns { ... }`` / ``namespace a::b { ... }`` —
        push namespace segments and walk the body. Anonymous
        namespaces (``namespace { ... }`` with no name) push
        nothing — the body's symbols have internal linkage but
        no qualified-name prefix in the call graph."""
        parts: List[str] = []
        for c in node.children:
            if c.type == "namespace_identifier":
                parts.append(c.text.decode("utf-8", errors="replace"))
            elif c.type == "nested_namespace_specifier":
                # ``a::b`` — multiple namespace_identifier children.
                for sub in c.children:
                    if sub.type == "namespace_identifier":
                        parts.append(
                            sub.text.decode("utf-8", errors="replace"),
                        )
        self._ns_stack.extend(parts)
        if self._ns_stack:
            self.graph.package_name = ".".join(self._ns_stack)
        try:
            for c in node.children:
                self.walk(c)
        finally:
            for _ in parts:
                self._ns_stack.pop()
            # Deepest-wins: don't decrement ``package_name`` when a
            # nested namespace closes. ``namespace outer { namespace
            # inner { ... } }`` should produce ``package_name=
            # "outer.inner"`` (the deepest scope, where the class
            # actually lives). Restoring to the outer dotted form on
            # close would lose the inner segment that's typically
            # the more useful canonical form for cross-file
            # canonicalisation. Matches Ruby's module-nesting
            # convention.

    # ------------------------------------------------------------------
    # Class / struct
    # ------------------------------------------------------------------

    def _visit_class_specifier(self, node) -> None:
        name = self._class_name(node)
        if name is None:
            # Anonymous struct/class — skip class-stack tracking but
            # still descend so inner calls aren't lost.
            for c in node.children:
                self.walk(c)
            return
        bases = self._extract_bases(node)
        cdef = ClassDef(
            name=name,
            line=node.start_point[0] + 1,
            bases=bases,
            nested=bool(self._class_stack) or bool(self._enclosing),
        )
        # Pre-pass: collect method declarations from the class body
        # before descending. This populates ``cdef.methods`` so that
        # in-class call-receiver inference works on the very first
        # call site visited; without this, the methods list would
        # only fill as inline definitions get walked, leaving early
        # calls untagged.
        self._collect_method_declarations(node, cdef)
        self.graph.classes.append(cdef)
        self._class_stack.append(cdef)
        try:
            for child in node.children:
                self.walk(child)
        finally:
            self._class_stack.pop()

    def _collect_method_declarations(self, class_node, cdef: ClassDef) -> None:
        """Scan a ``class_specifier`` / ``struct_specifier`` body for
        method *declarations* + *inline definitions*. Populates
        ``cdef.methods`` BEFORE the body walk so receiver-class
        inference works on the very first call site visited.

        Three method shapes appear inside a class body:
          * ``field_declaration`` — declared method (no body); has a
            return-type child + function_declarator child.
          * ``declaration`` — destructors / constructors (no return
            type).
          * ``function_definition`` — inline method with a body.
            This is the typical shape for header-defined methods
            and is what the original PR-527 pre-pass missed —
            inline ``helper()`` calls from a sibling method
            walked first would fail to find ``helper`` in the
            methods set and miss receiver_class tagging.
        """
        body = None
        for c in class_node.children:
            if c.type == self._FIELD_DECLARATION_LIST:
                body = c
                break
        if body is None:
            return
        for member in body.children:
            # ``template<T> T get();`` and ``template<T> void m() {}``
            # wrap the declaration / function_definition inside a
            # ``template_declaration`` node. Unwrap one level so the
            # inner declarator is reachable from the same loop.
            target = member
            if target.type == self._TEMPLATE_DECLARATION:
                for sub in target.children:
                    if sub.type in (
                        self._FIELD_DECLARATION, "declaration",
                        self._FUNCTION_DEFINITION,
                    ):
                        target = sub
                        break
                else:
                    continue
            if target.type not in (self._FIELD_DECLARATION, "declaration",
                                    self._FUNCTION_DEFINITION):
                continue
            for sub in target.children:
                if sub.type == self._FUNCTION_DECLARATOR:
                    name = self._declarator_name_cpp(sub)
                    if name:
                        cdef.methods.append(
                            (name, target.start_point[0] + 1),
                        )
                    break

    def _class_name(self, node) -> Optional[str]:
        # class_specifier: "class" type_identifier base_class_clause? body
        for c in node.children:
            if c.type == self._TYPE_IDENTIFIER:
                return c.text.decode("utf-8", errors="replace")
        return None

    def _extract_bases(self, node) -> List[str]:
        """Parse ``: public Foo, protected Bar`` into ``["Foo",
        "Bar"]``. Access specifiers are dropped; only the type names
        survive. ``Foo<T>`` (template_type) base is reduced to
        ``Foo`` — type args are erased for the same reason
        template_function callees emit the bare name."""
        bases: List[str] = []
        for c in node.children:
            if c.type != self._BASE_CLASS_CLAUSE:
                continue
            for sub in c.children:
                if not sub.is_named:
                    continue
                if sub.type == self._TYPE_IDENTIFIER:
                    bases.append(sub.text.decode("utf-8", errors="replace"))
                elif sub.type == self._QUALIFIED_IDENTIFIER:
                    parts = self._qualified_parts(sub)
                    if parts:
                        bases.append("::".join(parts))
                elif sub.type == self._TEMPLATE_TYPE:
                    inner = None
                    for ti in sub.children:
                        if ti.type == self._TYPE_IDENTIFIER:
                            inner = ti
                            break
                    if inner is not None:
                        bases.append(
                            inner.text.decode("utf-8", errors="replace"),
                        )
        return bases

    # ------------------------------------------------------------------
    # Function definitions
    # ------------------------------------------------------------------

    def _visit_function_definition(self, node) -> None:
        name = self._function_name(node)
        qualified_class = self._qualified_class_from_declarator(node)
        if name is None:
            # Couldn't resolve; still descend to catch nested calls.
            for c in node.children:
                self.walk(c)
            return

        # In-class inline method: record method on the current
        # class — UNLESS the pre-pass already captured it
        # (collect_method_declarations now picks up function_definition
        # too, so a second append here would duplicate the entry).
        if self._class_stack and qualified_class is None:
            current_class = self._class_stack[-1]
            method_line = node.start_point[0] + 1
            already = any(
                m_name == name and m_line == method_line
                for m_name, m_line in current_class.methods
            )
            if not already:
                current_class.methods.append((name, method_line))

        # Push enclosing function name. For out-of-line methods, also
        # synthesise a transient ClassDef-like context so calls inside
        # tag receiver_class correctly. The synthetic ClassDef
        # inherits the *real* class's methods list (looked up by name
        # from already-collected classes); without that inheritance,
        # bare in-class call inference (e.g. ``setup()`` inside
        # ``Widget::run``, where ``setup`` is a sibling method) can't
        # fire because the synthetic's methods list would be empty.
        # Forward references (out-of-line definition appears before
        # the class declaration) degrade to empty-methods — a real
        # but accepted gap; the lookup falls back to the body-walk
        # collecting the class later in the file, which then helps
        # any subsequent definitions.
        synthetic_class: Optional[ClassDef] = None
        if qualified_class is not None and not self._class_in_stack(qualified_class):
            real = self._lookup_class(qualified_class)
            if real is not None:
                synthetic_class = ClassDef(
                    name=qualified_class,
                    line=real.line,
                    bases=list(real.bases),
                    methods=list(real.methods),
                    nested=real.nested,
                )
            else:
                synthetic_class = ClassDef(
                    name=qualified_class, line=0, nested=False,
                )
            self._class_stack.append(synthetic_class)
        self._enclosing.append(name)
        try:
            for c in node.children:
                self.walk(c)
        finally:
            self._enclosing.pop()
            if synthetic_class is not None:
                # The synthetic class is the top of the stack iff no
                # other class_specifier pushed during the body.
                if (self._class_stack
                        and self._class_stack[-1] is synthetic_class):
                    self._class_stack.pop()

    def _class_in_stack(self, name: str) -> bool:
        return any(c.name == name for c in self._class_stack)

    def _lookup_class(self, name: str) -> Optional[ClassDef]:
        """Find a previously-recorded class by name. Returns None on
        forward references (the class hasn't been visited yet)."""
        for c in self.graph.classes:
            if c.name == name:
                return c
        return None

    def _function_name(self, fn_def_node) -> Optional[str]:
        """C++ declarators can be qualified (``Foo::bar``), template-
        parameterised, or destructors (``~Foo``). Walk through wrapping
        declarators to find the innermost name."""
        for c in fn_def_node.children:
            if not c.is_named:
                continue
            if c.type == self._FUNCTION_DECLARATOR:
                return self._declarator_name_cpp(c)
            if c.type == self._POINTER_DECLARATOR:
                inner = self._find_function_declarator(c)
                if inner is not None:
                    return self._declarator_name_cpp(inner)
        return None

    def _declarator_name_cpp(self, fn_declarator_node) -> Optional[str]:
        """Like the C version but accepts qualified_identifier
        (returns just the trailing name), destructor_name, and
        operator_name."""
        for c in fn_declarator_node.children:
            if not c.is_named:
                continue
            if c.type == self._IDENTIFIER:
                return c.text.decode("utf-8", errors="replace")
            if c.type == self._FIELD_IDENTIFIER:
                return c.text.decode("utf-8", errors="replace")
            if c.type == self._QUALIFIED_IDENTIFIER:
                parts = self._qualified_parts(c)
                if parts:
                    return parts[-1]
            if c.type == self._DESTRUCTOR_NAME:
                return c.text.decode("utf-8", errors="replace")
            if c.type == self._OPERATOR_NAME:
                return c.text.decode("utf-8", errors="replace")
            if c.type == self._PARENTHESIZED_DECLARATOR:
                inner = self._first_named_child(c)
                if inner is not None:
                    if inner.type == self._IDENTIFIER:
                        return inner.text.decode("utf-8", errors="replace")
                    if inner.type == self._QUALIFIED_IDENTIFIER:
                        parts = self._qualified_parts(inner)
                        if parts:
                            return parts[-1]
        return None

    def _qualified_class_from_declarator(self, fn_def_node) -> Optional[str]:
        """If the function's declarator is ``Foo::bar`` (out-of-line
        method), return ``"Foo"``. Otherwise None."""
        for c in fn_def_node.children:
            if not c.is_named:
                continue
            if c.type == self._FUNCTION_DECLARATOR:
                return self._qualified_class_from_fn_declarator(c)
            if c.type == self._POINTER_DECLARATOR:
                inner = self._find_function_declarator(c)
                if inner is not None:
                    return self._qualified_class_from_fn_declarator(inner)
        return None

    def _qualified_class_from_fn_declarator(self, fn_declarator_node) -> Optional[str]:
        for c in fn_declarator_node.children:
            if not c.is_named:
                continue
            if c.type == self._QUALIFIED_IDENTIFIER:
                parts = self._qualified_parts(c)
                if len(parts) >= 2:
                    # ``A::B::method`` → out-of-line method of ``B``.
                    return parts[-2]
        return None

    # ------------------------------------------------------------------
    # Qualified-identifier parsing
    # ------------------------------------------------------------------

    def _qualified_parts(self, qualified_node) -> List[str]:
        """``Foo::bar`` → ``["Foo", "bar"]``;
        ``ns::sub::fn`` → ``["ns", "sub", "fn"]``.

        Tree-sitter-cpp models this recursively: ``qualified_identifier``
        has ``namespace_identifier`` + nested ``qualified_identifier``
        or terminal ``identifier`` / ``destructor_name`` /
        ``field_identifier`` / ``template_function``."""
        parts: List[str] = []
        cur = qualified_node
        while cur is not None and cur.type == self._QUALIFIED_IDENTIFIER:
            # Pre-order children: namespace_identifier, then nested.
            head = None
            tail = None
            for c in cur.children:
                if not c.is_named:
                    continue
                if head is None:
                    head = c
                else:
                    tail = c
                    break
            if head is None:
                return parts
            parts.append(self._name_token(head))
            cur = tail
        if cur is None:
            return [p for p in parts if p]
        # Terminal at the right-hand side.
        last = self._name_token(cur)
        if last:
            parts.append(last)
        return [p for p in parts if p]

    def _name_token(self, node) -> str:
        """Extract a printable name from any of the leaf-name node
        types tree-sitter-cpp uses inside qualified expressions."""
        if node.type in (
            self._IDENTIFIER, self._NAMESPACE_IDENTIFIER,
            self._TYPE_IDENTIFIER, self._FIELD_IDENTIFIER,
            self._DESTRUCTOR_NAME, self._OPERATOR_NAME,
        ):
            return node.text.decode("utf-8", errors="replace")
        if node.type in (self._TEMPLATE_TYPE, self._TEMPLATE_FUNCTION):
            # ``vector<int>`` / ``f<T>`` — emit the bare name; drop
            # template args (out of scope this revision).
            for c in node.children:
                if not c.is_named:
                    continue
                if c.type in (self._IDENTIFIER, self._TYPE_IDENTIFIER):
                    return c.text.decode("utf-8", errors="replace")
            return ""
        return ""

    # ------------------------------------------------------------------
    # Calls (override to set receiver_class + handle qualified callees)
    # ------------------------------------------------------------------

    def _callee_chain(self, node) -> Tuple[Optional[List[str]], bool]:
        # Extension: qualified_identifier as a callee.
        if node.type == self._QUALIFIED_IDENTIFIER:
            parts = self._qualified_parts(node)
            return (parts if parts else None), False
        if node.type == self._FIELD_EXPRESSION:
            # Override C base: field_expression in C++ may root on
            # ``this`` (own node type) rather than an identifier.
            return self._field_chain_cpp(node), False
        if node.type == self._TEMPLATE_FUNCTION:
            # ``get<int>()`` — callee is template_function wrapping
            # an identifier + template_argument_list. Emit just the
            # identifier; downstream tools match on the bare name,
            # template args are erased.
            for c in node.children:
                if c.type == self._IDENTIFIER:
                    return [c.text.decode("utf-8", errors="replace")], False
            return None, False
        return super()._callee_chain(node)

    def _field_chain_cpp(self, node) -> Optional[List[str]]:
        """C++ ``a.b.c`` / ``a->b->c`` / ``this->member`` resolution.

        Same as the C base's ``_field_chain`` but accepts ``this`` as
        a terminal (rendered as the literal string ``"this"`` in the
        chain), and handles a qualified_identifier at the root
        (``ns::var.field`` is legal C++)."""
        parts: List[str] = []
        cur = node
        while cur is not None and cur.type == self._FIELD_EXPRESSION:
            # The field side is either a plain ``field_identifier``
            # (``a.b``) or a ``template_method`` wrapping one
            # (``a.b<T>()``). For the template case, recover the
            # inner field_identifier — template args are dropped.
            field_node = None
            for c in cur.children:
                if c.type == self._FIELD_IDENTIFIER:
                    field_node = c
                elif c.type == "template_method":
                    for sub in c.children:
                        if sub.type == self._FIELD_IDENTIFIER:
                            field_node = sub
                            break
                elif c.type == "dependent_name":
                    # ``c.template put<int>()`` — dependent-name
                    # disambiguation. Wraps ``template_method``
                    # which wraps the field_identifier. Same
                    # erasure: drop template args, keep the name.
                    for sub in c.children:
                        if sub.type == "template_method":
                            for inner in sub.children:
                                if inner.type == self._FIELD_IDENTIFIER:
                                    field_node = inner
                                    break
                            break
                        if sub.type == self._FIELD_IDENTIFIER:
                            field_node = sub
                            break
            if field_node is None:
                return None
            parts.append(field_node.text.decode("utf-8", errors="replace"))
            operand = None
            for c in cur.children:
                if c.is_named and c.type not in (
                    self._FIELD_IDENTIFIER, "template_method",
                ):
                    operand = c
                    break
            cur = operand
        if cur is None:
            return None
        if cur.type == self._IDENTIFIER:
            parts.append(cur.text.decode("utf-8", errors="replace"))
            return list(reversed(parts))
        if cur.type == self._THIS:
            parts.append("this")
            return list(reversed(parts))
        if cur.type == self._QUALIFIED_IDENTIFIER:
            head = self._qualified_parts(cur)
            if not head:
                return None
            return head + list(reversed(parts))
        if cur.type == "compound_literal_expression":
            # ``Foo{}.method()`` / ``vector<int>{}.size()`` — the
            # operand is an unnamed temporary of type Foo. Recover
            # the type name for the chain head so a target named
            # ``Foo.method`` still matches; type args are erased
            # (same as template_function callee handling). Loses
            # namespace prefix (we'd need symbol resolution to
            # know it).
            type_name = self._compound_literal_type_name(cur)
            if type_name is not None:
                parts.append(type_name)
                return list(reversed(parts))
            return None
        return None

    def _compound_literal_type_name(self, node) -> Optional[str]:
        """Pull the type's bare name from a compound_literal_expression.
        Handles plain ``Foo{}`` (type_identifier) and templated
        ``vector<int>{}`` (template_type → type_identifier)."""
        for c in node.children:
            if c.type == self._TYPE_IDENTIFIER:
                return c.text.decode("utf-8", errors="replace")
            if c.type == self._TEMPLATE_TYPE:
                for sub in c.children:
                    if sub.type == self._TYPE_IDENTIFIER:
                        return sub.text.decode("utf-8", errors="replace")
        return None

    def _visit_call(self, node) -> None:
        callee_node = None
        for c in node.children:
            if c.type == "argument_list":
                break
            if c.is_named:
                callee_node = c
                break
        if callee_node is None:
            return

        chain, is_fn_pointer = self._callee_chain(callee_node)
        if chain is None:
            return

        if is_fn_pointer:
            self.graph.indirection.add(INDIRECTION_FN_POINTER)

        caller = self._enclosing[-1] if self._enclosing else None
        receiver_class = self._infer_receiver_class(chain)

        self.graph.calls.append(CallSite(
            line=node.start_point[0] + 1,
            chain=chain,
            caller=caller,
            receiver_class=receiver_class,
        ))

    def _visit_field_initializer(self, node) -> None:
        """Constructor initialiser list entry: ``Base(x)`` or
        ``member_(0)``. The field_identifier child names either:
          * a base class (delegating constructor call) — semantically
            a call to ``Base::Base``;
          * a data member (initialiser with value, not a call).
        Without symbol-table access we can't distinguish, so emit
        both as CallSite chains. Downstream resolver narrows via
        the class context — a target named ``Base`` lookup matches
        the base-constructor case; targets named after the member
        get a benign no-op (member name isn't in any class's
        methods list, so reachability returns NOT_CALLED).

        Bare member-init ``m_(0)`` is over-reporting but contained.
        Base-constructor delegation is the load-bearing case for
        SCA reachability against subclass-of-known-base sinks.
        """
        name_node = None
        for c in node.children:
            if c.type == self._FIELD_IDENTIFIER:
                name_node = c
                break
            if c.type == "template_method":
                # ``Base<T>(args)`` — template form of init list entry.
                # Drop template args; recover the inner field_identifier.
                for sub in c.children:
                    if sub.type == self._FIELD_IDENTIFIER:
                        name_node = sub
                        break
                if name_node is not None:
                    break
        if name_node is None:
            return
        name = name_node.text.decode("utf-8", errors="replace")
        caller = self._enclosing[-1] if self._enclosing else None
        # No receiver_class tag — initialiser-list entries dispatch
        # on the literal name (base class or member), not on the
        # enclosing class's method set.
        self.graph.calls.append(CallSite(
            line=node.start_point[0] + 1,
            chain=[name],
            caller=caller,
            receiver_class=None,
        ))

    def _infer_receiver_class(self, chain: List[str]) -> Optional[str]:
        """Tag ``receiver_class`` when the callee shape pins it.

        Rules (deliberately narrow to avoid wrong tags):
          * ``this->member`` (chain == ["this", X]) → current class
          * Inside class body, bare ``X()`` where X is in the
            class's method list → current class
          * Out-of-line methods (synthetic class on stack) — same
            rules apply

        We do NOT tag ``obj.method()`` calls (chain length >= 2 with
        non-``this`` root) — the receiver type isn't statically
        resolvable from this walk.
        """
        if not self._class_stack:
            return None
        top = self._class_stack[-1]
        if top.nested:
            # Mirrors Python walker's conservatism for nested classes.
            return None
        if len(chain) == 2 and chain[0] == "this":
            return top.name
        if len(chain) == 1:
            method_names = {m[0] for m in top.methods}
            if chain[0] in method_names:
                return top.name
        return None


__all__ = [
    "CallSite",
    "FileCallGraph",
    "INDIRECTION_BRACKET_DISPATCH",
    "INDIRECTION_DUNDER_IMPORT",
    "INDIRECTION_DYNAMIC_IMPORT",
    "INDIRECTION_EVAL",
    "INDIRECTION_FN_POINTER",
    "INDIRECTION_GETATTR",
    "INDIRECTION_IMPORTLIB",
    "INDIRECTION_REFLECT",
    "INDIRECTION_WILDCARD_IMPORT",
    "extract_call_graph_c",
    "extract_call_graph_cpp",
    "extract_call_graph_csharp",
    "extract_call_graph_go",
    "extract_call_graph_java",
    "extract_call_graph_javascript",
    "extract_call_graph_php",
    "extract_call_graph_python",
    "extract_call_graph_ruby",
    "extract_call_graph_rust",
]
