"""Module-local Python call graph — Phase 12 of the sanitizer-cut arc.

Sub-arc C's substrate. Given a Python source file, produce a frozen
graph whose nodes are the file's function / method definitions and
whose edges are intra-module call relationships. Phase 13 will
compute per-function taint summaries keyed by these nodes; Phase 14
will consult those summaries when an intra-procedural CFG sees a
:class:`core.analysis.cfg_builder.CallSite` whose name resolves to
a function in this module.

Scope:

* **Single file.** Cross-module / cross-package resolution is out of
  scope by design — a CallSite with chain ``["mod", "f"]`` is
  dropped from the edge set rather than resolved against the
  package tree.
* **Static names only.** Dynamic dispatch — ``getattr(o, "x")()``,
  ``HANDLERS[k]()``, ``eval(...)`` — is invisible to this layer.
  Functions reachable only via such mechanisms get no incoming
  edge and the downstream Phase 14 gate will refuse to use their
  summaries (correct: we can't prove they're called from where
  the taint enters).
* **Best-effort decorators / lambdas.** A lambda assigned to a name
  (``compute = lambda x: ...``) becomes a node named ``compute``.
  Lambdas in expression position with no binding name are
  ignored. Decorated functions appear under their bare name — the
  decorator's name does NOT become an edge.

Naming convention:

* Module-level functions: unqualified name (``"foo"``).
* Methods of classes: qualified ``"ClassName.method"`` — including
  ``__init__``. A ``self.method()`` call resolves to the method
  on the class enclosing the caller, when statically determinable.
* Nested functions inside another function or method: qualified
  ``"outer.inner"`` (for module-level outer) or
  ``"Class.outer.inner"`` (method outer). Reaching a nested
  function from outside its enclosing scope is rare in static
  analysis terms; the names exist for completeness but typically
  have no incoming edges from outside.

Module entry:

* A synthetic entry node named ``"<module>"`` represents module-
  level code. All module-level function definitions and any
  module-level calls flow from this entry. Phase 13's summary
  computation treats ``<module>`` specially (no summary; it's a
  caller, not a callee). Phase 14 won't dispatch into ``<module>``
  — it's purely a graph-protocol convenience so dominator queries
  work over the whole module.

Public surface:

* :class:`PyCallGraphNode` — frozen, hashable; identity is the
  qualified name + lineno.
* :class:`PyModuleCallGraph` — implements
  :class:`core.analysis.dominators.Graph`; exposes ``find(name)``
  for callee resolution and ``function_ast(name)`` for Phase 13's
  CFG-building.
* :func:`build_python_module_callgraph` — entry point.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from collections.abc import Iterable


# Sentinel name for the synthetic module entry. Chosen to be
# syntactically illegal as a Python identifier so it can't collide
# with a real function.
MODULE_ENTRY_NAME = "<module>"


@dataclass(frozen=True)
class PyCallGraphNode:
    """One function / method in a module-local call graph.

    Equality / hash are the frozen-dataclass defaults over all
    fields. In practice ``(name, lineno)`` identifies a node — the
    remaining fields are derived from the def found there.
    (Duplicate qualified names at different lines can occur when a
    module conditionally redefines a function; we treat those as
    distinct nodes so taint summaries don't fight.)
    """
    name: str               # qualified — "foo", "C.method", "outer.inner"
    lineno: int             # 1-indexed start line of the def
    end_lineno: int = 0     # 1-indexed end line; 0 when unknown
    params: tuple[str, ...] = ()
    is_method: bool = False
    class_name: str | None = None
    is_module_entry: bool = False

    def __repr__(self) -> str:                              # pragma: no cover
        suf = "(entry)" if self.is_module_entry else f"L{self.lineno}"
        return f"PyCallGraphNode({self.name!r}, {suf})"


@dataclass(frozen=True)
class PyModuleCallGraph:
    """Module-local call graph for one Python file.

    Implements :class:`core.analysis.dominators.Graph`. Plus two
    consumer-side accessors:

    * :meth:`find(name)` — qualified name → node, or None. For a
      conditionally-redefined name this is the LAST definition
      (Python's runtime winner for sequential module-level defs);
      :meth:`find_all` returns every variant.
    * :meth:`function_ast(name)` — qualified name →
      ``ast.FunctionDef`` / ``ast.AsyncFunctionDef`` / ``ast.Lambda``,
      or None. Phase 13's per-function CFG builder reads this. For
      redefined names this is the last variant's AST;
      :meth:`function_asts` returns all.

    Conditional redefinitions (``if X: def f() / else: def f()``)
    produce DISTINCT nodes — both appear in :meth:`nodes`, call
    edges to the name fan out to every variant (sound
    over-approximation), and calls made inside each variant's body
    attribute to that variant's own node.
    """
    file_path: str
    entry_node: PyCallGraphNode
    _nodes: tuple[PyCallGraphNode, ...]
    _adjacency: dict[PyCallGraphNode, tuple[PyCallGraphNode, ...]]
    _by_name: dict[str, PyCallGraphNode] = field(default_factory=dict)
    # Mutable side-channel for ast access. NOT part of node identity;
    # frozen dataclass equality still works because dicts compare by
    # content. Kept private; access via :meth:`function_ast`.
    _ast_by_name: dict[str, ast.AST] = field(default_factory=dict)
    # All variants per qualified name, in definition order. Singleton
    # tuples for the (overwhelmingly common) unredefined case.
    _variants_by_name: dict[str, tuple[PyCallGraphNode, ...]] = field(
        default_factory=dict)
    _asts_by_node: dict[tuple[str, int], ast.AST] = field(
        default_factory=dict)
    # Module-scope names whose runtime binding may differ from their
    # def: a non-def module-level assignment to a def's name
    # (``def esc(…): …`` then ``esc = str``), or a ``global``
    # declaration of it anywhere in the module (a sibling function
    # can rewrite the slot before the analysed call runs). Name-keyed
    # summary consumers must treat these identities as unknown — the
    # written name no longer proves which body executes.
    rebound_names: frozenset[str] = frozenset()
    # Module-scope roots whose binding is repo-controlled (see
    # :func:`module_shadowed_identity_roots` — non-import rebinds
    # plus import aliases binding a different source) — consumers
    # must never let a WRITTEN dotted name whose root is here match a
    # trusted external identity (catalog sanitizer, chain stamp).
    distrusted_roots: frozenset[str] = frozenset()
    # The non-import subset (:func:`module_distrusted_roots`): the
    # decorator gate refuses these outright but resolves import
    # aliases through :attr:`import_map` instead — ``from functools
    # import lru_cache`` is a trusted identity, ``lru_cache = str``
    # is not.
    nonimport_distrusted_roots: frozenset[str] = frozenset()
    # Module-scope import bindings (root → dotted source) for
    # resolving written names to trusted identities.
    import_map: dict[str, str] = field(default_factory=dict)
    # True when a dynamic route (star-import, exec/eval, sys.modules,
    # escaping globals()/vars()) makes the WHOLE module's name
    # resolution unprovable — every summary degrades to unknown and
    # every catalog identity is refused (see module_dynamic_namespace).
    namespace_unprovable: bool = False

    _scope_bindings: dict[ast.AST, frozenset[str]] = field(default_factory=dict)

    def binding_names(self, function: ast.AST) -> frozenset[str]:
        """Identities bound in this function or its enclosing function frames."""
        names = self._scope_bindings.get(function)
        return names if names is not None else local_binding_names(function)

    @property
    def entry(self) -> PyCallGraphNode:
        return self.entry_node

    def nodes(self) -> Iterable[PyCallGraphNode]:
        return self._nodes

    def successors(
        self, node: PyCallGraphNode,
    ) -> Iterable[PyCallGraphNode]:
        return self._adjacency.get(node, ())

    def find(self, name: str) -> PyCallGraphNode | None:
        """Look up a node by its qualified name."""
        return self._by_name.get(name)

    def function_ast(self, name: str) -> ast.AST | None:
        """Phase 13 hook — the AST subtree for ``name``. Returns
        None for the module entry, for unknown names, and for
        functions whose AST wasn't preserved (e.g. a lambda whose
        binding was lost)."""
        return self._ast_by_name.get(name)

    def find_all(self, name: str) -> tuple[PyCallGraphNode, ...]:
        """Every definition of ``name``, in source order. Empty tuple
        for unknown names; a singleton for the common unredefined
        case."""
        return self._variants_by_name.get(name, ())

    def function_asts(self, name: str) -> tuple[ast.AST, ...]:
        """The AST of every definition of ``name``, in source order.
        Consumers analysing behaviour must consider ALL variants —
        a conditionally-redefined function's runtime body depends on
        module-import-time state."""
        out = []
        for node in self._variants_by_name.get(name, ()):
            a = self._asts_by_node.get((node.name, node.lineno))
            if a is not None:
                out.append(a)
        return tuple(out)


# ---------------------------------------------------------------------------
# Function / method discovery
# ---------------------------------------------------------------------------


@dataclass
class _FunctionRecord:
    """Mutable bookkeeping for one function discovered during the
    AST walk. Materialised into a :class:`PyCallGraphNode` once
    the walk completes."""
    qualified_name: str
    lineno: int
    end_lineno: int
    params: tuple[str, ...]
    is_method: bool
    class_name: str | None
    ast_node: ast.AST
    # Names this function's own scope binds (params, assignments,
    # nested defs, imports, …) — computed lazily via
    # :meth:`local_bindings`; the bare-name callee arm refuses to
    # resolve through them (shadow guard).
    _local_bindings: frozenset[str] | None = None

    def local_bindings(self) -> frozenset[str]:
        if self._local_bindings is None:
            self._local_bindings = local_binding_names(self.ast_node)
        return self._local_bindings


def _function_params(
    fn: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda,
) -> tuple[str, ...]:
    """Ordered param names. Same convention as
    :func:`core.analysis.cfg_builder._function_params`: posonly,
    positional, ``*args``, kwonly, ``**kwargs``."""
    args = fn.args
    names: list[str] = [a.arg for a in args.posonlyargs]
    names.extend(a.arg for a in args.args)
    if args.vararg is not None:
        names.append(args.vararg.arg)
    names.extend(a.arg for a in args.kwonlyargs)
    if args.kwarg is not None:
        names.append(args.kwarg.arg)
    return tuple(names)


def _end_lineno(node: ast.AST) -> int:
    end = getattr(node, "end_lineno", None)
    if end is not None:
        return end
    out = getattr(node, "lineno", 0)
    for child in ast.walk(node):
        ln = getattr(child, "end_lineno", None) or getattr(child, "lineno", 0)
        if ln and ln > out:
            out = ln
    return out


def _collect_functions(tree: ast.AST) -> list[_FunctionRecord]:
    """Walk ``tree`` collecting every named function-like
    definition. Recursion handles nested functions and methods.

    ``ast.Lambda`` is harvested ONLY when bound to a single
    ``ast.Assign`` LHS — those become nodes named after the LHS.
    Anonymous lambdas in expression position are skipped (no
    static name to resolve from a call site).
    """
    out: list[_FunctionRecord] = []
    # Walk with an explicit stack so we can carry the enclosing
    # qualified-prefix and class-name context downward.
    stack: list[tuple[ast.AST, str, str | None]] = [(tree, "", None)]
    # (subtree_root, prefix, current_class_name)
    while stack:
        node, prefix, class_name = stack.pop()
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.ClassDef):
                inner_prefix = (
                    f"{prefix}.{child.name}" if prefix else child.name
                )
                # Class body is walked with class_name set; nested
                # functions become methods named "ClassName.method".
                stack.append((child, inner_prefix, inner_prefix))
                continue
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qualified = (
                    f"{prefix}.{child.name}" if prefix else child.name
                )
                # Methods: class_name is set when this def is at the
                # immediate body of a class. Nested functions inside
                # methods inherit class_name=None — they're not
                # bound to the receiver. class_name carries the full
                # dotted class prefix (inner classes get
                # "Outer.Inner", identical to prefix), so the
                # prefix == class_name comparison identifies
                # class-body defs; the endswith comparison is a
                # belt-and-braces guard over the same dotted form.
                is_method = (
                    class_name is not None
                    and (prefix == class_name
                         or prefix.endswith("." + class_name))
                )
                out.append(_FunctionRecord(
                    qualified_name=qualified,
                    lineno=child.lineno,
                    end_lineno=_end_lineno(child),
                    params=_function_params(child),
                    is_method=is_method,
                    class_name=class_name if is_method else None,
                    ast_node=child,
                ))
                # Descend; nested defs lose class_name (they're not
                # methods of any class — they live inside the method's
                # body).
                stack.append((child, qualified, None))
                continue
            if isinstance(child, ast.Assign):
                # ``name = lambda ...:`` — emit a node for ``name``.
                # Skip multi-target / tuple-unpack cases — too much
                # ambiguity for a useful binding.
                if (
                    len(child.targets) == 1
                    and isinstance(child.targets[0], ast.Name)
                    and isinstance(child.value, ast.Lambda)
                ):
                    name_node = child.targets[0]
                    lam = child.value
                    qualified = (
                        f"{prefix}.{name_node.id}" if prefix else name_node.id
                    )
                    out.append(_FunctionRecord(
                        qualified_name=qualified,
                        lineno=lam.lineno,
                        end_lineno=_end_lineno(lam),
                        params=_function_params(lam),
                        is_method=False,
                        class_name=None,
                        ast_node=lam,
                    ))
                # Don't descend into Assign — no further definitions
                # of interest live in an assignment expression.
                continue
            # Recurse into compound statements (If, Try, With, For,
            # While, Module, etc.) so conditionally-defined functions
            # are still discovered.
            stack.append((child, prefix, class_name))
    return out


# ---------------------------------------------------------------------------
# Local-binding discovery — the shadow guard for name-keyed joins
# ---------------------------------------------------------------------------


def _definition_header_expressions(node: ast.AST) -> Iterable[ast.AST]:
    """Expressions evaluated outside a definition's body scope.

    Annotations are deliberately excluded: their evaluation depends on the
    Python version and future imports, unlike decorators and defaults.
    """
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        yield from node.decorator_list
    if isinstance(node, ast.ClassDef):
        yield from node.bases
        yield from (keyword.value for keyword in node.keywords)
    elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
        yield from node.args.defaults
        yield from (value for value in node.args.kw_defaults if value is not None)


def local_binding_names(fn_ast: ast.AST) -> frozenset[str]:
    """Every name the function's OWN scope binds, flow-insensitively.

    The summary/binding joins downstream (``taint_summaries``'s
    callee join, ``interproc``'s synthetic bindings, this module's
    bare-name callee resolution) are keyed by NAME against the
    module-level table. A local binding of that name (``esc = str``,
    a parameter named ``esc``, a nested ``def esc``, a walrus, a
    ``for``/``with``/``except``/import target) makes the runtime
    callee a different object than the table entry — a hostile repo
    collides the key and mints a clean-sanitizer wrapper the enforced
    sanitizer-cut consumes. Joins must refuse when the name has ANY
    local definition: an ambiguous binding can only lose suppression
    power, never gain it.

    Scope rules:

    * Parameters, assignment/augmented/annotated targets (including
      tuple/list/star destructuring), walrus targets, ``for`` /
      ``async for`` targets, ``with … as`` targets, ``except … as``
      names, import aliases, ``match`` capture names, and the NAMES
      of nested function/class definitions all bind locally.
    * Nested function/class BODIES bind their own scopes and are not
      descended into — but their decorators and default expressions
      evaluate in THIS scope, so walruses there are collected.
    * Comprehension for-targets are NOT collected: comprehensions
      have their own scope, so a target there never rebinds the
      function's names (a walrus inside a comprehension DOES — it is
      an ordinary ``NamedExpr`` in the walk and is collected).
    """
    out: set[str] = set()
    args = getattr(fn_ast, "args", None)
    if args is not None:
        for a in (*args.posonlyargs, *args.args, *args.kwonlyargs):
            out.add(a.arg)
        if args.vararg is not None:
            out.add(args.vararg.arg)
        if args.kwarg is not None:
            out.add(args.kwarg.arg)

    def _add_target(t: ast.AST) -> None:
        if isinstance(t, ast.Name):
            out.add(t.id)
        elif isinstance(t, ast.Starred):
            _add_target(t.value)
        elif isinstance(t, (ast.Tuple, ast.List)):
            for e in t.elts:
                _add_target(e)
        # Attribute / Subscript targets bind no bare name.

    def _walk(node: ast.AST) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            if not isinstance(node, ast.Lambda):
                out.add(node.name)
            for expr in _definition_header_expressions(node):
                _walk(expr)
            return
        if isinstance(node, ast.Assign):
            for t in node.targets:
                _add_target(t)
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
            _add_target(node.target)
        elif isinstance(node, ast.NamedExpr):
            _add_target(node.target)
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            _add_target(node.target)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if item.optional_vars is not None:
                    _add_target(item.optional_vars)
        elif isinstance(node, ast.ExceptHandler):
            if node.name:
                out.add(node.name)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                if alias.asname:
                    out.add(alias.asname)
                elif alias.name != "*":
                    out.add(alias.name.split(".", 1)[0])
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)):
            if node.name:
                out.add(node.name)
        elif isinstance(node, ast.MatchMapping):
            if node.rest:
                out.add(node.rest)
        for child in ast.iter_child_nodes(node):
            _walk(child)

    if isinstance(fn_ast, (ast.FunctionDef, ast.AsyncFunctionDef)):
        for statement in fn_ast.body:
            _walk(statement)
    elif isinstance(fn_ast, ast.Lambda):
        _walk(fn_ast.body)
    else:
        _walk(fn_ast)
    return frozenset(out)


def function_scope_bindings(tree: ast.Module) -> dict[ast.AST, frozenset[str]]:
    """Bound identities visible in each function, including closure frames.

    Class namespaces do not become method closure frames. Explicit globals
    bypass enclosing function frames, including for nested descendants.
    Definition headers retain their enclosing scope rather than their body.
    """
    scopes: dict[ast.AST, frozenset[str]] = {}
    pending: list[tuple[ast.AST, frozenset[str]]] = [(tree, frozenset())]
    while pending:
        node, enclosing = pending.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            globals_: set[str] = set()
            body = node.body if not isinstance(node, ast.Lambda) else [node.body]
            statements: list[ast.AST] = list(body)
            while statements:
                statement = statements.pop()
                if isinstance(statement, ast.Global):
                    globals_.update(statement.names)
                elif not isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef,
                                                ast.ClassDef, ast.Lambda)):
                    statements.extend(ast.iter_child_nodes(statement))
            visible = (enclosing | local_binding_names(node)) - globals_
            scopes[node] = visible
            pending.extend((statement, visible) for statement in body)
            pending.extend((expr, enclosing) for expr in _definition_header_expressions(node))
        elif isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            targets = frozenset(
                target.id for generator in node.generators
                for target in ast.walk(generator.target) if isinstance(target, ast.Name)
            )
            comprehension = enclosing | targets
            for index, generator in enumerate(node.generators):
                pending.append((generator.iter, enclosing if index == 0 else comprehension))
                pending.extend((condition, comprehension) for condition in generator.ifs)
            values = (node.key, node.value) if isinstance(node, ast.DictComp) else (node.elt,)
            pending.extend((value, comprehension) for value in values)
        else:
            # In particular, class bodies retain the enclosing function
            # environment without contributing class-local assignments.
            pending.extend((child, enclosing) for child in ast.iter_child_nodes(node))
    return scopes


def _module_rebound_names(tree: ast.Module) -> frozenset[str]:
    """Module-scope names whose runtime binding is not proven to be
    their def — see :attr:`PyModuleCallGraph.rebound_names`.

    Two channels, both flow-insensitive (order between the def and
    the rebind does not matter — either order leaves the name's
    runtime identity unprovable to a name-keyed consumer):

    * A non-def binding statement at module scope naming the same
      name as a ``def``/lambda-def elsewhere at module scope
      (``esc = str``, an import alias, a ``for`` target, …). The
      single-``Name``-target lambda assignment is exempt — it IS the
      def :func:`_collect_functions` harvests.
    * A ``global`` declaration of the name anywhere in the module: a
      sibling function that runs at any point before the analysed
      call can rewrite the module slot.
    * A module-scope CLASS sharing a module-scope function def's name
      (either order — flow-insensitive): the runtime binding is
      whichever ran last, so the name proves neither body.
    """
    # Non-def bindings at module scope: same boundary walk as
    # local_binding_names (stops at def/class bodies) but WITHOUT
    # recording the def/class names themselves — those are the defs,
    # not rebinds — and skipping harvested lambda-assign statements.
    # def/class names are collected separately so the class ∩ def
    # collision can join the poison set without every ordinary class
    # poisoning its own methods.
    nondef: set[str] = set()
    def_names: set[str] = set()
    class_names: set[str] = set()

    def _add_target(t: ast.AST) -> None:
        if isinstance(t, ast.Name):
            nondef.add(t.id)
        elif isinstance(t, ast.Starred):
            _add_target(t.value)
        elif isinstance(t, (ast.Tuple, ast.List)):
            for e in t.elts:
                _add_target(e)

    def _walk(node: ast.AST) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            def_names.add(node.name)
            for expr in _definition_header_expressions(node):
                _walk(expr)
            return
        if isinstance(node, ast.ClassDef):
            class_names.add(node.name)
            for expr in _definition_header_expressions(node):
                _walk(expr)
            return
        if isinstance(node, ast.Lambda):
            for expr in _definition_header_expressions(node):
                _walk(expr)
            return
        if isinstance(node, ast.Assign):
            if (len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name)
                    and isinstance(node.value, ast.Lambda)):
                # The lambda-def shape — a function record, not a
                # rebind of one (but it IS a def name for the
                # class-collision check).
                def_names.add(node.targets[0].id)
                for expr in _definition_header_expressions(node.value):
                    _walk(expr)
                return
            for t in node.targets:
                _add_target(t)
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
            _add_target(node.target)
        elif isinstance(node, ast.NamedExpr):
            _add_target(node.target)
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            _add_target(node.target)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if item.optional_vars is not None:
                    _add_target(item.optional_vars)
        elif isinstance(node, ast.ExceptHandler):
            if node.name:
                nondef.add(node.name)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                if alias.asname:
                    nondef.add(alias.asname)
                elif alias.name != "*":
                    nondef.add(alias.name.split(".", 1)[0])
        for child in ast.iter_child_nodes(node):
            _walk(child)

    _walk(tree)

    # ``global`` declarations anywhere in the module (function bodies
    # included — that is the point).
    global_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Global):
            global_names.update(node.names)

    return frozenset(nondef | global_names | (class_names & def_names))


def module_import_map(tree: ast.Module) -> dict[str, str]:
    """Module-scope import bindings: bound root name → dotted source.

    ``import a.b`` binds ``a`` → ``a``; ``import a.b as c`` binds
    ``c`` → ``a.b``; ``from m import n as k`` binds ``k`` → ``m.n``.
    Relative imports resolve outside the module's own vocabulary and
    map to a ``<relative>``-prefixed source that can never match a
    trusted dotted name. Later bindings win (runtime order)."""
    out: dict[str, str] = {}

    def _walk(node: ast.AST) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef,
                                  ast.ClassDef, ast.Lambda)):
                continue
            if isinstance(child, ast.Import):
                for alias in child.names:
                    root = alias.name.split(".", 1)[0]
                    if alias.asname:
                        out[alias.asname] = alias.name
                    else:
                        out[root] = root
            elif isinstance(child, ast.ImportFrom):
                module = child.module or ""
                prefix = "<relative>." * child.level + module
                for alias in child.names:
                    if alias.name == "*":
                        continue
                    bound = alias.asname or alias.name
                    src = f"{prefix}.{alias.name}" if prefix else alias.name
                    out[bound] = src
            _walk(child)

    _walk(tree)
    return out


def module_distrusted_roots(tree: ast.Module) -> frozenset[str]:
    """Module-scope names whose binding is REPO-CONTROLLED rather than
    the same-named external module / builtin.

    The catalog matcher and the decorator allowlist trust WRITTEN
    names (``html.escape``, ``@staticmethod``); a hostile module can
    rebind the root of such a name and keep the spelling. Distrusted:

    * every module-scope def / class / lambda-def name (a def named
      ``html`` or ``staticmethod`` is the repo's object);
    * every non-import module-scope binding (assignments including
      destructuring, walrus, ``for``/``with``/``except`` targets);
    * names declared ``global`` anywhere in the module (any sibling
      can rewrite the slot);
    Import bindings are NOT in this set — they resolve exactly
    through :func:`module_import_map` (a ``from functools import
    lru_cache`` alias is a trusted identity, not a rebind); consumers
    that check WRITTEN dotted identities against external catalogs
    need :func:`module_shadowed_identity_roots`, which unions in the
    aliases that bind a different source.

    Trusted absences: an unbound root (resolves to builtins or fails
    at runtime — it cannot be the repo's object) and the plain
    self-import (``import html``, ``import html.parser``)."""
    out: set[str] = set()

    def _add_target(t: ast.AST) -> None:
        if isinstance(t, ast.Name):
            out.add(t.id)
        elif isinstance(t, ast.Starred):
            _add_target(t.value)
        elif isinstance(t, (ast.Tuple, ast.List)):
            for e in t.elts:
                _add_target(e)

    def _walk(node: ast.AST) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                              ast.ClassDef)):
            out.add(node.name)
            for expr in _definition_header_expressions(node):
                _walk(expr)
            return
        if isinstance(node, ast.Lambda):
            for expr in _definition_header_expressions(node):
                _walk(expr)
            return
        if isinstance(node, ast.Assign):
            for t in node.targets:
                _add_target(t)
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
            _add_target(node.target)
        elif isinstance(node, ast.NamedExpr):
            _add_target(node.target)
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            _add_target(node.target)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if item.optional_vars is not None:
                    _add_target(item.optional_vars)
        elif isinstance(node, ast.ExceptHandler):
            if node.name:
                out.add(node.name)
        for child in ast.iter_child_nodes(node):
            _walk(child)

    _walk(tree)

    for node in ast.walk(tree):
        if isinstance(node, ast.Global):
            out.update(node.names)

    return frozenset(out)


def module_dynamic_namespace(
    tree: ast.Module,
) -> tuple[bool, frozenset[str]]:
    """Dynamic module-namespace rebinding routes → ``(whole_module,
    poisoned_names)``.

    The static walkers above see BINDING STATEMENTS; Python also
    rebinds module names through routes with no binding syntax at
    all, and a hostile repo used every one of them to keep a clean
    written identity over a raw runtime callee:

    * ``from x import *`` — every name in the module is now
      potentially the star module's object → the WHOLE module's
      name-resolution confidence is void.
    * ``exec`` / ``eval`` at module-reachable scope (module body,
      class body — both run at import), or anywhere with an explicit
      globals argument — arbitrary rebinds → whole module.
    * exposed ``builtins`` / ``__builtins__`` namespaces (aliases and
      local imports included) — replacing a builtin decorator can invalidate
      an otherwise trusted method body; escaping/read-only namespace access
      is conservatively uncertain, like ``sys.modules`` below;
    * exposed ``__import__`` / ``importlib`` loaders (including imported
      aliases) — shared modules can be obtained and mutated without an
      ordinary import binding to follow;
    * any reachable ``sys.modules`` (aliased imports included) — a
      ``setattr(sys.modules[__name__], …)`` rebinds by attribute,
      and aliasing makes name-level tracking unsound → whole module.
    * ``globals()`` / ``vars()`` / module-scope ``locals()``:
      a constant-key subscript STORE/DELETE poisons exactly that
      name; a LOAD used as a direct or reflective attribute/item store receiver
      also poisons that name; plain lookup reads stay unpoisoned. Every other use
      (non-constant key store, aliasing the dict, ``.update(…)``,
      passing it on) → whole module. A function/class local lookup used as
      an object mutation receiver removes whole-module trust: its key need
      not identify the global import name. Bare function-local ``locals()``
      mapping writes and inert lookup reads keep their existing treatment.

    Consumers abstain: a poisoned name (or every name, when
    whole_module) loses join/catalog trust — suppression can only be
    lost, never gained.
    """
    whole = False
    names: set[str] = set()

    # Parent map for positional analysis of globals()/vars() calls.
    parents: dict[ast.AST, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node

    # Function-local variable annotations never execute or survive for
    # later evaluation. Keep targets/RHS and module/class behavior intact.
    local_annotation_nodes: set[ast.AST] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.AnnAssign):
            continue
        owner = parents.get(node)
        while owner is not None and not isinstance(
                owner, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Module)):
            owner = parents.get(owner)
        if isinstance(owner, (ast.FunctionDef, ast.AsyncFunctionDef)):
            local_annotation_nodes.update(ast.walk(node.annotation))

    # Builtins are process-wide mutable namespace objects, including when
    # imported inside a function. Once exposed, an alias can replace builtin
    # decorators or callable names without any ordinary module assignment.
    builtin_namespace_names = {"__builtins__"}
    dynamic_import_names = {"__import__"}
    reflective_write_names = {"setattr", "delattr"}
    reflective_read_names = {"getattr"}
    object_namespace_names = {"vars"}
    mapping_copy_names = {"dict"}
    sequence_copy_names = {"list", "tuple"}
    iterator_wrapper_names = {"iter", "reversed"}
    iterator_advance_names = {"next"}
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            bindings = module_import_map(ast.Module(body=[node], type_ignores=[]))
            dynamic_import_names.update(
                alias for alias, target in bindings.items()
                if target == "importlib" or target.startswith("importlib.")
            )
            reflective_write_names.update(
                alias for alias, target in bindings.items()
                if target in {"builtins.setattr", "builtins.delattr"}
            )
            reflective_read_names.update(
                alias for alias, target in bindings.items() if target == "builtins.getattr"
            )
            object_namespace_names.update(
                alias for alias, target in bindings.items() if target == "builtins.vars"
            )
            mapping_copy_names.update(
                alias for alias, target in bindings.items() if target == "builtins.dict"
            )
            sequence_copy_names.update(
                alias for alias, target in bindings.items()
                if target in {"builtins.list", "builtins.tuple"}
            )
            iterator_wrapper_names.update(
                alias for alias, target in bindings.items()
                if target in {"builtins.iter", "builtins.reversed"}
            )
            iterator_advance_names.update(
                alias for alias, target in bindings.items() if target == "builtins.next"
            )
        if isinstance(node, ast.Import):
            builtin_namespace_names.update(
                alias.asname or alias.name for alias in node.names
                if alias.name == "builtins"
            )
        elif isinstance(node, ast.ImportFrom) and node.module == "builtins":
            builtin_namespace_names.update(
                alias.asname or alias.name for alias in node.names
                if alias.name == "__dict__"
            )
            dynamic_import_names.update(
                alias.asname or alias.name for alias in node.names
                if alias.name == "__import__"
            )

    imap = module_import_map(tree)
    import_roots = set(imap)
    sys_aliases = {r for r, src in imap.items() if src == "sys"}
    modules_aliases = {
        r for r, src in imap.items()
        if src == "sys.modules" or src.startswith("sys.modules.")
    }

    # Importing the registry inside a function does not confine it to
    # that function: the object still exposes every loaded module.
    # Scope/name ambiguity only removes namespace trust.
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            import_roots.update(alias.asname or alias.name.split(".", 1)[0]
                                for alias in node.names)
            sys_aliases.update(alias.asname or alias.name for alias in node.names
                               if alias.name == "sys")
        elif isinstance(node, ast.ImportFrom):
            import_roots.update(alias.asname or alias.name for alias in node.names
                                if alias.name != "*")
            if node.module == "sys":
                modules_aliases.update(alias.asname or alias.name for alias in node.names
                                       if alias.name == "modules")

    def _module_reachable(node: ast.AST) -> bool:
        child = node
        cur = parents.get(child)
        while cur is not None:
            if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # Defaults and decorators run in the enclosing scope;
                # only statements in the body wait for a function call.
                if any(child is statement for statement in cur.body):
                    return False
            elif isinstance(cur, ast.Lambda) and child is cur.body:
                return False
            child = cur
            cur = parents.get(cur)
        return True

    def class_local_namespace(node: ast.AST) -> bool:
        child = node
        cur = parents.get(child)
        while cur is not None:
            if isinstance(cur, ast.ClassDef) and any(child is statement for statement in cur.body):
                return True
            child = cur
            cur = parents.get(cur)
        return False

    saved_namespace_dict_values: set[str] = set()
    namespace_dict_value_cache: dict[ast.AST, bool] = {}

    def literal_member_values(value: ast.AST) -> tuple[ast.AST, ...] | None:
        sliced = False
        while isinstance(value, ast.Subscript) and isinstance(value.slice, ast.Slice):
            sliced = True
            value = value.value
        if sliced and not isinstance(value, (ast.Tuple, ast.List)):
            return None
        if not isinstance(value, (ast.Dict, ast.Tuple, ast.List)):
            return None
        members: list[ast.AST] = []
        pending = [value]
        while pending:
            container = pending.pop()
            if isinstance(container, ast.Dict):
                for key, item in zip(container.keys, container.values):
                    if key is None and isinstance(item, ast.Dict):
                        pending.append(item)
                    else:
                        # An expanded namespace may supply shared member objects.
                        members.append(item)
            else:
                for item in container.elts:
                    if isinstance(item, ast.Starred):
                        source = item.value
                        while isinstance(source, ast.Subscript) and isinstance(source.slice, ast.Slice):
                            source = source.value
                        if isinstance(source, (ast.Tuple, ast.List)):
                            pending.append(source)
                        else:
                            members.append(item.value)
                    else:
                        members.append(item)
        return tuple(members)

    def explicit_namespace_dict_value(value: ast.AST) -> bool:
        if isinstance(value, ast.Attribute) and value.attr == "__dict__":
            return True
        if isinstance(value, ast.Call) and isinstance(value.func, ast.Name) and not value.keywords:
            if value.func.id in object_namespace_names and len(value.args) == 1:
                return True
            if (value.func.id in reflective_read_names and len(value.args) in {2, 3}
                    and isinstance(value.args[1], ast.Constant)
                    and value.args[1].value == "__dict__"):
                return True
        return False

    def literal_sequence_values(value: ast.AST) -> tuple[ast.AST, ...] | None:
        sequence = value
        while isinstance(sequence, ast.Subscript) and isinstance(sequence.slice, ast.Slice):
            sequence = sequence.value
        if not isinstance(sequence, (ast.Tuple, ast.List)):
            return None
        return literal_member_values(value)

    def explicit_pair_values(value: ast.AST) -> tuple[ast.AST, ...] | None:
        pairs = literal_sequence_values(value)
        if pairs is None or not all(
                isinstance(pair, (ast.Tuple, ast.List)) and len(pair.elts) == 2
                and not any(isinstance(item, ast.Starred) for item in pair.elts)
                for pair in pairs):
            return None
        return tuple(pair.elts[1] for pair in pairs)

    literal_selection_cache: dict[ast.AST, ast.AST | None] = {}

    def selected_literal_value(value: ast.AST) -> ast.AST | None:
        pending = [(value, False)]
        while pending:
            cursor, expanded = pending.pop()
            if cursor in literal_selection_cache:
                continue
            if isinstance(cursor, (ast.Dict, ast.Tuple, ast.List)):
                literal_selection_cache[cursor] = cursor
                continue
            if isinstance(cursor, ast.NamedExpr):
                if expanded:
                    literal_selection_cache[cursor] = literal_selection_cache[cursor.value]
                else:
                    pending.append((cursor, True))
                    pending.append((cursor.value, False))
                continue
            if not isinstance(cursor, ast.Subscript) or isinstance(cursor.slice, ast.Slice):
                literal_selection_cache[cursor] = None
                continue
            if not expanded:
                pending.append((cursor, True))
                pending.append((cursor.value, False))
                continue
            container = literal_selection_cache[cursor.value]
            key = cursor.slice
            selected = None
            if (isinstance(container, (ast.Tuple, ast.List))
                    and not any(isinstance(item, ast.Starred) for item in container.elts)):
                index = None
                if isinstance(key, ast.Constant) and type(key.value) is int:
                    index = key.value
                elif (isinstance(key, ast.UnaryOp) and isinstance(key.op, ast.USub)
                      and isinstance(key.operand, ast.Constant) and type(key.operand.value) is int):
                    index = -key.operand.value
                if index is not None and -len(container.elts) <= index < len(container.elts):
                    selected = container.elts[index]
            elif (isinstance(container, ast.Dict) and isinstance(key, ast.Constant)
                  and isinstance(key.value, str)
                  and all(isinstance(item, ast.Constant) and isinstance(item.value, str)
                          for item in container.keys)):
                for item, candidate in zip(container.keys, container.values):
                    if item.value == key.value:
                        selected = candidate
            literal_selection_cache[cursor] = selected
        return literal_selection_cache[value]

    def literal_dictionary_keys(value: ast.AST) -> tuple[ast.AST, ...] | None:
        dictionary = selected_literal_value(value)
        if isinstance(dictionary, ast.Dict):
            return tuple(key for key in dictionary.keys if key is not None)
        return None

    def literal_dictionary_view_values(value: ast.AST) -> tuple[ast.AST, ...] | None:
        if (not isinstance(value, ast.Call) or not isinstance(value.func, ast.Attribute)
                or value.args or value.keywords or value.func.attr not in {"keys", "values"}):
            return None
        dictionary = selected_literal_value(value.func.value)
        if not isinstance(dictionary, ast.Dict):
            return None
        if value.func.attr == "keys":
            return literal_dictionary_keys(dictionary)
        return literal_member_values(dictionary)

    sequence_container_cache: dict[ast.AST, bool] = {}

    def potential_sequence_container(value: ast.AST) -> bool:
        path = []
        cursor = value
        while cursor not in sequence_container_cache:
            path.append(cursor)
            if isinstance(cursor, (ast.Tuple, ast.List)):
                result = True
                break
            if (isinstance(cursor, ast.Call) and isinstance(cursor.func, ast.Name)
                    and cursor.func.id in sequence_copy_names
                    and len(cursor.args) == 1 and not cursor.keywords):
                result = True
                break
            if isinstance(cursor, ast.NamedExpr):
                cursor = cursor.value
            elif isinstance(cursor, ast.Subscript) and isinstance(cursor.slice, ast.Slice):
                cursor = cursor.value
            elif (isinstance(cursor, ast.Call) and isinstance(cursor.func, ast.Attribute)
                  and cursor.func.attr == "copy" and not cursor.args and not cursor.keywords):
                cursor = cursor.func.value
            else:
                result = False
                break
        else:
            result = sequence_container_cache[cursor]
        for node in path:
            sequence_container_cache[node] = result
        return result

    sequence_iteration_cache: dict[ast.AST, tuple[bool, tuple[ast.AST, ...]] | None] = {}

    def sequence_iteration_values(value: ast.AST) -> tuple[ast.AST, ...] | None:
        members: list[ast.AST] = []
        pending = [value]
        seen: set[ast.AST] = set()
        recognised = False
        while pending:
            cursor = pending.pop()
            if cursor in seen:
                continue
            seen.add(cursor)
            if cursor not in sequence_iteration_cache:
                sequence_values = literal_sequence_values(cursor)
                dictionary_keys = literal_dictionary_keys(cursor)
                view_values = literal_dictionary_view_values(cursor)
                values = (sequence_values if sequence_values is not None else
                          dictionary_keys if dictionary_keys is not None else view_values)
                if values is not None:
                    sequence_iteration_cache[cursor] = (True, values)
                else:
                    children = ()
                    if isinstance(cursor, ast.NamedExpr):
                        children = (cursor.value,)
                    elif isinstance(cursor, ast.IfExp):
                        children = (cursor.body, cursor.orelse)
                    elif isinstance(cursor, ast.BoolOp):
                        children = tuple(cursor.values)
                    elif (isinstance(cursor, ast.Subscript) and isinstance(cursor.slice, ast.Slice)
                          and potential_sequence_container(cursor.value)):
                        children = (cursor.value,)
                    elif isinstance(cursor, ast.Subscript) and not isinstance(cursor.slice, ast.Slice):
                        selected = selected_literal_value(cursor)
                        if selected is not None:
                            children = (selected,)
                    elif (isinstance(cursor, ast.Call) and isinstance(cursor.func, ast.Name)
                          and (cursor.func.id in sequence_copy_names
                               or cursor.func.id in iterator_wrapper_names)
                          and len(cursor.args) == 1 and not cursor.keywords):
                        children = (cursor.args[0],)
                    elif (isinstance(cursor, ast.Call) and isinstance(cursor.func, ast.Attribute)
                          and cursor.func.attr == "copy" and not cursor.args and not cursor.keywords):
                        children = (cursor.func.value,)
                    elif (isinstance(cursor, ast.Call) and isinstance(cursor.func, ast.Attribute)
                          and cursor.func.attr in {"get", "__getitem__"}
                          and isinstance(selected_literal_value(cursor.func.value),
                                         (ast.Dict, ast.Tuple, ast.List))):
                        children = literal_member_result_values(cursor) or ()
                    # Keep graph links rather than duplicating transitive members.
                    sequence_iteration_cache[cursor] = (False, children) if children else None
            descriptor = sequence_iteration_cache[cursor]
            if descriptor is None:
                continue
            direct_members, sources = descriptor
            if direct_members:
                recognised = True
                members.extend(sources)
            else:
                pending.extend(sources)
        return tuple(members) if recognised else None

    def container_member_sources(value: ast.AST) -> tuple[ast.AST, ...] | None:
        members: list[ast.AST] = []
        pending = [(value, False)]
        recognised = False
        while pending:
            container, copied = pending.pop()
            literal_members = (literal_member_values(container)
                               if not isinstance(container, ast.Dict) else None)
            if isinstance(container, ast.Dict):
                recognised = True
                for key, item in zip(container.keys, container.values):
                    if key is None:
                        pending.append((item, False))
                    else:
                        members.append(item)
            elif literal_members is not None:
                recognised = True
                members.extend(literal_members)
            elif (isinstance(container, ast.Subscript) and isinstance(container.slice, ast.Slice)
                  and potential_sequence_container(container.value)):
                sequence_values = sequence_iteration_values(container)
                if sequence_values is not None:
                    recognised = True
                    members.extend(sequence_values)
                if not copied:
                    members.append(container)
            elif isinstance(container, ast.Subscript) and not isinstance(container.slice, ast.Slice):
                selected = selected_literal_value(container)
                if selected is not None:
                    recognised = True
                    pending.append((selected, copied))
                if not copied:
                    # Selection adds candidates without erasing old kind evidence.
                    members.append(container)
            elif isinstance(container, ast.NamedExpr):
                pending.append((container.value, copied))
            elif isinstance(container, ast.IfExp):
                pending.extend((branch, copied) for branch in (container.body, container.orelse))
            elif isinstance(container, ast.BoolOp):
                pending.extend((branch, copied) for branch in container.values)
            elif (isinstance(container, ast.Call) and isinstance(container.func, ast.Attribute)
                  and container.func.attr == "copy" and not container.args and not container.keywords):
                pending.append((container.func.value, True))
            elif (isinstance(container, ast.Call) and isinstance(container.func, ast.Name)
                  and (container.func.id in mapping_copy_names or container.func.id in sequence_copy_names)
                  and len(container.args) == 1 and not container.keywords):
                if container.func.id in sequence_copy_names:
                    sequence_values = sequence_iteration_values(container.args[0])
                    if sequence_values is not None:
                        recognised = True
                        members.extend(sequence_values)
                if container.func.id in mapping_copy_names:
                    pair_values = explicit_pair_values(container.args[0])
                    if pair_values is not None:
                        recognised = True
                        members.extend(pair_values)
                    # Constructor-name ambiguity retains both old possibilities.
                    pending.append((container.args[0], True))
                elif not copied:
                    members.append(container)
            elif (isinstance(container, ast.Call) and isinstance(container.func, ast.Name)
                  and container.func.id in mapping_copy_names and not container.args
                  and len(container.keywords) == 1 and container.keywords[0].arg is None):
                pending.append((container.keywords[0].value, True))
            elif isinstance(container, ast.BinOp) and isinstance(container.op, ast.BitOr):
                for source, empty in ((container.left, container.right), (container.right, container.left)):
                    if isinstance(empty, ast.Dict) and not empty.keys:
                        pending.append((source, True))
                        break
                else:
                    if not copied:
                        members.append(container)
            elif explicit_namespace_dict_value(container):
                members.append(container)
                recognised |= copied
            elif not copied:
                # Preserve existing object possibilities from ordinary branches;
                # opaque copy calls do not establish their argument's identity.
                members.append(container)
        return tuple(members) if recognised else None

    def iterator_advance_sources(value: ast.AST) -> tuple[ast.AST, ...] | None:
        if not isinstance(value, ast.Call) or value.keywords:
            return None
        if (isinstance(value.func, ast.Name) and value.func.id in iterator_advance_names
                and len(value.args) in {1, 2}):
            iterator = value.args[0]
            defaults = tuple(value.args[1:])
        elif (isinstance(value.func, ast.Attribute) and value.func.attr == "__next__"
              and not value.args):
            iterator = value.func.value
            defaults = ()
        else:
            return None
        pending = [iterator]
        seen = set()
        members = []
        known_members = False
        while pending:
            cursor = pending.pop()
            if cursor in seen:
                continue
            seen.add(cursor)
            if isinstance(cursor, ast.NamedExpr):
                pending.append(cursor.value)
            elif isinstance(cursor, ast.Subscript):
                selected = selected_literal_value(cursor)
                if selected is not None:
                    pending.append(selected)
            elif isinstance(cursor, ast.IfExp):
                pending.extend((cursor.body, cursor.orelse))
            elif isinstance(cursor, ast.BoolOp):
                pending.extend(cursor.values)
            elif (isinstance(cursor, ast.Call) and isinstance(cursor.func, ast.Name)
                  and cursor.func.id in iterator_wrapper_names
                  and len(cursor.args) == 1 and not cursor.keywords):
                sources = sequence_iteration_values(cursor)
                if sources is not None:
                    known_members = True
                    members.extend(sources)
            elif (isinstance(cursor, ast.Call) and isinstance(cursor.func, ast.Attribute)
                  and cursor.func.attr in {"get", "__getitem__"}):
                sources = literal_member_result_values(cursor)
                if sources is not None:
                    pending.extend(sources)
        if not known_members and not defaults:
            return None
        return (*members, *defaults)

    def literal_member_result_values(value: ast.AST) -> tuple[ast.AST, ...] | None:
        advancement = iterator_advance_sources(value)
        if advancement is not None:
            return advancement
        if isinstance(value, ast.Subscript):
            if isinstance(value.slice, ast.Slice):
                # A sequence slice returns a container, not an element.
                return None
            return container_member_sources(value.value)
        if (isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute)
                and not value.keywords):
            receiver = value.func.value
            if ((value.func.attr == "get" and not isinstance(receiver, (ast.Tuple, ast.List))
                 and len(value.args) in {1, 2})
                    or (value.func.attr == "__getitem__" and len(value.args) == 1)):
                members = container_member_sources(receiver)
                if members is not None:
                    return (*members, *value.args[1:])
        return None

    def possible_namespace_dict_value(value: ast.AST) -> bool:
        pending_values = [(value, False)]
        while pending_values:
            cursor, expanded = pending_values.pop()
            if cursor in namespace_dict_value_cache:
                continue
            if explicit_namespace_dict_value(cursor):
                namespace_dict_value_cache[cursor] = True
                continue
            literal_members = literal_member_result_values(cursor)
            if literal_members is not None:
                children = literal_members
            elif isinstance(cursor, ast.NamedExpr):
                children = (cursor.value,)
            elif isinstance(cursor, ast.IfExp):
                children = (cursor.body, cursor.orelse)
            elif isinstance(cursor, ast.BoolOp):
                children = tuple(cursor.values)
            else:
                children = ()
            if not children:
                namespace_dict_value_cache[cursor] = False
            elif expanded:
                namespace_dict_value_cache[cursor] = any(
                    namespace_dict_value_cache[child] for child in children
                )
            else:
                pending_values.append((cursor, True))
                pending_values.extend((child, False) for child in children)
        return namespace_dict_value_cache[value]

    namespace_copy_cache: dict[ast.AST, ast.AST | None] = {}

    def namespace_copy_receiver(value: ast.AST) -> ast.AST | None:
        path = []
        cursor = value
        source = None
        while cursor not in namespace_copy_cache:
            path.append(cursor)
            next_source = None
            if (isinstance(cursor, ast.Call) and isinstance(cursor.func, ast.Attribute)
                    and cursor.func.attr == "copy" and not cursor.args and not cursor.keywords):
                next_source = cursor.func.value
            elif (isinstance(cursor, ast.Call) and isinstance(cursor.func, ast.Name)
                  and cursor.func.id in mapping_copy_names):
                if len(cursor.args) == 1 and not cursor.keywords:
                    next_source = cursor.args[0]
                elif (not cursor.args and len(cursor.keywords) == 1
                      and cursor.keywords[0].arg is None):
                    next_source = cursor.keywords[0].value
            elif isinstance(cursor, ast.BinOp) and isinstance(cursor.op, ast.BitOr):
                for candidate, empty in ((cursor.left, cursor.right), (cursor.right, cursor.left)):
                    if isinstance(empty, ast.Dict) and not empty.keys:
                        next_source = candidate
                        break
            if next_source is None:
                break
            if possible_namespace_dict_value(next_source):
                source = next_source
                break
            cursor = next_source
        else:
            source = namespace_copy_cache[cursor]
        for node in path:
            namespace_copy_cache[node] = source
        return source

    def namespace_dict_member_receiver(member: ast.AST) -> ast.AST | None:
        if (isinstance(member, ast.Attribute)
                and member.attr in {"update", "clear", "pop", "popitem", "setdefault",
                                    "__setitem__", "__delitem__", "__ior__", "__init__"}):
            receiver = member.value
            if isinstance(receiver, ast.Attribute) and receiver.attr == "__dict__":
                return receiver.value
            if isinstance(receiver, ast.Name) and receiver.id in saved_namespace_dict_values:
                return receiver
        return None

    def namespace_dict_receiver(node: ast.AST) -> ast.AST | None:
        return namespace_dict_member_receiver(node.func) if isinstance(node, ast.Call) else None

    def reflective_receiver(node: ast.AST) -> ast.AST | None:
        if not isinstance(node, ast.Call):
            return None
        if isinstance(node.func, ast.Name) and node.func.id in reflective_write_names and node.args:
            return node.args[0]
        if isinstance(node.func, ast.Attribute) and node.func.attr in {"__setattr__", "__delattr__"}:
            return node.func.value
        return None

    def direct_callee(node: ast.AST) -> bool:
        parent = parents.get(node)
        return isinstance(parent, ast.Call) and parent.func is node

    def escaped_dictionary_mutator_receiver(node: ast.AST) -> ast.AST | None:
        if (isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load)
                and not direct_callee(node)):
            return namespace_dict_member_receiver(node)
        return None

    def escaped_setter_receiver(node: ast.AST) -> ast.AST | None:
        if (isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load)
                and node.attr in {"__setattr__", "__delattr__"}
                and not direct_callee(node)):
            return node.value
        return None

    # Keep direct saved values of known imports visible to the
    # existing object-mutation checks. This is deliberately one step only.
    original_import_roots = frozenset(import_roots)
    saved_import_values: set[str] = set()
    import_value_cache: dict[ast.AST, bool] = {}

    def possible_import_value(value: ast.AST) -> bool:
        pending_values = [(value, False)]
        while pending_values:
            cursor, expanded = pending_values.pop()
            if cursor in import_value_cache:
                continue
            if isinstance(cursor, ast.Name):
                import_value_cache[cursor] = cursor.id in original_import_roots
                continue
            if (isinstance(cursor, ast.Subscript) and isinstance(cursor.value, ast.Call)
                    and isinstance(cursor.value.func, ast.Name)
                    and cursor.value.func.id == "globals"
                    and not cursor.value.args and not cursor.value.keywords):
                key = cursor.slice
                import_value_cache[cursor] = (isinstance(key, ast.Constant)
                                               and isinstance(key.value, str)
                                               and key.value in original_import_roots)
                continue
            literal_members = literal_member_result_values(cursor)
            copied_namespace = (namespace_copy_receiver(cursor.value)
                                if isinstance(cursor, ast.Subscript) else None)
            if copied_namespace is not None:
                children = (copied_namespace,)
            elif isinstance(cursor, (ast.Attribute, ast.Subscript, ast.NamedExpr)):
                children = (cursor.value,)
            elif isinstance(cursor, ast.IfExp):
                children = (cursor.body, cursor.orelse)
            elif isinstance(cursor, ast.BoolOp):
                children = tuple(cursor.values)
            elif (isinstance(cursor, ast.Call) and isinstance(cursor.func, ast.Name)
                  and cursor.func.id in reflective_read_names and not cursor.keywords
                  and len(cursor.args) in {2, 3}
                  and isinstance(cursor.args[1], ast.Constant)
                  and isinstance(cursor.args[1].value, str)):
                children = (cursor.args[0], *cursor.args[2:])
            elif (isinstance(cursor, ast.Call) and isinstance(cursor.func, ast.Name)
                  and cursor.func.id in object_namespace_names
                  and len(cursor.args) == 1 and not cursor.keywords):
                children = (cursor.args[0],)
            elif (isinstance(cursor, ast.Call) and isinstance(cursor.func, ast.Attribute)
                  and not cursor.keywords
                  and ((cursor.func.attr == "get" and len(cursor.args) in {1, 2})
                       or (cursor.func.attr == "__getitem__" and len(cursor.args) == 1))
                  and (possible_namespace_dict_value(cursor.func.value)
                       or namespace_copy_receiver(cursor.func.value) is not None)):
                receiver = namespace_copy_receiver(cursor.func.value)
                children = ((receiver if receiver is not None else cursor.func.value),
                            *cursor.args[1:])
            else:
                children = ()
            if literal_members is not None:
                # Partial projections add possibilities; they must not erase
                # an existing copy source or ordinary receiver possibility.
                children = (*children, *literal_members)
            if not children:
                import_value_cache[cursor] = False
            elif expanded:
                import_value_cache[cursor] = any(import_value_cache[child] for child in children)
            else:
                pending_values.append((cursor, True))
                pending_values.extend((child, False) for child in children)
        return import_value_cache[value]

    for statement in ast.walk(tree):
        if statement in local_annotation_nodes:
            continue
        if isinstance(statement, ast.Assign):
            targets = statement.targets
            value = statement.value
        elif isinstance(statement, ast.AnnAssign) and statement.value is not None:
            targets = [statement.target]
            value = statement.value
        elif isinstance(statement, ast.NamedExpr):
            targets = [statement.target]
            value = statement.value
        elif (isinstance(statement, ast.For)
              or (isinstance(statement, ast.comprehension)
                  and (not statement.is_async
                       or isinstance(statement.iter, (ast.Tuple, ast.List))))):
            targets = [statement.target]
            value = statement.iter
        else:
            continue
        if isinstance(statement, (ast.For, ast.comprehension)):
            if isinstance(statement.iter, (ast.Tuple, ast.List)):
                items = []
                for item in statement.iter.elts:
                    if not isinstance(item, ast.Starred):
                        items.append(item)
                    elif not (isinstance(statement, ast.comprehension) and statement.is_async):
                        items.extend(sequence_iteration_values(item.value) or ())
            else:
                items = sequence_iteration_values(statement.iter) or ()
            pending = [(statement.target, item) for item in items]
        else:
            pending = [(target, value) for target in targets]
        while pending:
            target, value = pending.pop()
            if isinstance(target, (ast.Tuple, ast.List)):
                if (isinstance(value, (ast.Tuple, ast.List))
                        and len(target.elts) == len(value.elts)
                        and not any(isinstance(item, ast.Starred)
                                    for item in (*target.elts, *value.elts))):
                    pending.extend(zip(target.elts, value.elts))
                elif (not isinstance(value, (ast.Tuple, ast.List))
                      and len(target.elts) == 1 and isinstance(target.elts[0], ast.Name)):
                    members = sequence_iteration_values(value)
                    if members is not None:
                        pending.extend((target.elts[0], member) for member in members)
                continue
            if not isinstance(target, ast.Name):
                continue
            if possible_import_value(value):
                saved_import_values.add(target.id)
                if possible_namespace_dict_value(value):
                    saved_namespace_dict_values.add(target.id)
    import_roots.update(saved_import_values)

    def imported_mutation_receiver(receiver: ast.AST | None) -> bool:
        if receiver is None:
            return False
        root = receiver
        while isinstance(root, (ast.Attribute, ast.Subscript)):
            if (isinstance(root, ast.Subscript) and isinstance(root.value, ast.Call)
                    and isinstance(root.value.func, ast.Name)
                    and root.value.func.id in {"globals", "vars", "locals"}
                    and not root.value.args and not root.value.keywords):
                # Preserve the namespace walk's more precise named-root policy.
                return False
            root = root.value
        return ((isinstance(root, ast.Name) and root.id in import_roots)
                or possible_import_value(receiver))

    for node in ast.walk(tree):
        if node in local_annotation_nodes:
            continue
        if isinstance(node, (ast.Attribute, ast.Subscript)) \
                and isinstance(node.ctx, (ast.Store, ast.Del)):
            parent = parents.get(node)
            annotation_only = (isinstance(parent, ast.AnnAssign)
                               and parent.target is node and parent.value is None)
            if not annotation_only and imported_mutation_receiver(node.value):
                # Direct imported-object mutations can rewrite a shared
                # callable namespace without rebinding its import name.
                whole = True
        if isinstance(node, ast.ImportFrom):
            if any(alias.name == "*" for alias in node.names):
                whole = True
        elif isinstance(node, ast.Attribute):
            if (node.attr == "modules"
                    and isinstance(node.value, ast.Name)
                    and node.value.id in sys_aliases):
                whole = True
            for receiver in (escaped_setter_receiver(node),
                             escaped_dictionary_mutator_receiver(node)):
                if imported_mutation_receiver(receiver):
                    whole = True
        elif isinstance(node, ast.Name):
            if (node.id in modules_aliases or node.id in builtin_namespace_names
                    or (isinstance(node.ctx, ast.Load) and node.id in dynamic_import_names)):
                # A loader exposes shared modules without an ordinary
                # import binding whose later member stores we can follow.
                whole = True
            if (isinstance(node.ctx, ast.Load) and node.id in reflective_write_names
                    and not direct_callee(node)):
                whole = True  # A saved setter can later receive an unknown object.
        elif isinstance(node, ast.Call):
            func = node.func
            for receiver in (namespace_dict_receiver(node), reflective_receiver(node)):
                if imported_mutation_receiver(receiver):
                    # These calls can replace imported members with
                    # no Store node or rebinding of the import name.
                    whole = True
            if not isinstance(func, ast.Name):
                continue
            fname = func.id
            if fname in ("exec", "eval"):
                if len(node.args) >= 2 or _module_reachable(node):
                    whole = True
                continue
            if fname not in ("globals", "vars", "locals"):
                continue
            function_locals = fname == "locals" and not _module_reachable(node)
            parent = parents.get(node)
            if function_locals and not (
                    isinstance(parent, ast.Subscript) and parent.value is node
                    and isinstance(parent.ctx, ast.Load)):
                # Local mapping bindings cannot rebind module names.
                continue
            if (isinstance(parent, ast.Subscript)
                    and parent.value is node):
                if isinstance(parent.ctx, ast.Load):
                    # A lookup can be the receiver of an ordinary or
                    # reflective store, although the lookup itself is a Load.
                    cursor: ast.AST = parent
                    receiver_write = False
                    while True:
                        container = parents.get(cursor)
                        if (isinstance(container, ast.Attribute) and container.value is cursor
                                and (escaped_setter_receiver(container) is not None
                                     or escaped_dictionary_mutator_receiver(container) is not None)):
                            receiver_write = True
                            break
                        if (isinstance(container, ast.Call) and container.func is cursor
                                and namespace_dict_receiver(container) is not None):
                            receiver_write = True
                            break
                        if isinstance(container, ast.Call):
                            receiver = reflective_receiver(container)
                            if (receiver is cursor
                                    or (receiver is not None and container.func is cursor)):
                                receiver_write = True
                                break
                        if not isinstance(container, (ast.Attribute, ast.Subscript)) \
                                or container.value is not cursor:
                            break
                        if isinstance(container.ctx, (ast.Store, ast.Del)):
                            receiver_write = True
                            break
                        cursor = container
                    if not receiver_write:
                        continue
                if function_locals or (
                        fname in {"locals", "vars"} and not node.args and not node.keywords
                        and isinstance(parent.ctx, ast.Load)
                        and (not _module_reachable(node) or class_local_namespace(node))):
                    # A local alias can refer to a shared imported object;
                    # its lookup key does not name the module-global root.
                    whole = True
                    continue
                if fname == "vars" and (node.args or node.keywords):
                    # vars(obj) exposes obj's namespace; its lookup key
                    # does not identify a module-global root to poison.
                    whole = True
                    continue
                key = parent.slice
                if (isinstance(key, ast.Constant)
                        and isinstance(key.value, str)):
                    names.add(key.value.split(".", 1)[0])
                    continue
                whole = True                     # computed-key write
                continue
            # Aliased, updated, or escaping namespace dict.
            whole = True

    return whole, frozenset(names)


def module_shadowed_identity_roots(tree: ast.Module) -> frozenset[str]:
    """Roots a WRITTEN dotted identity must never be trusted through:
    every non-import rebind (:func:`module_distrusted_roots`) plus
    import aliases binding a DIFFERENT source (``import fakelib as
    html``, ``from fakelib import html``). The sanitizer-catalog
    guard and the summary chain stamps consume this set."""
    return module_distrusted_roots(tree) | frozenset(
        root for root, src in module_import_map(tree).items()
        if src != root
    )


# ---------------------------------------------------------------------------
# Call resolution
# ---------------------------------------------------------------------------


def _attribute_chain(node: ast.AST) -> list[str] | None:
    """``foo.bar.baz`` (``ast.Attribute`` rooted on ``ast.Name``) →
    ``["foo", "bar", "baz"]``. ``ast.Name("f")`` → ``["f"]``.
    Anything else (subscript root, call root, parenthesised
    lambda, etc.) → None."""
    parts: list[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        parts.reverse()
        return parts
    return None


def _enclosing_function_chain(
    call_node: ast.Call,
    function_records: list[_FunctionRecord],
) -> _FunctionRecord | None:
    """Find the function whose line range contains the call's line
    and whose span is smallest (so a nested method wins over its
    enclosing class scope)."""
    line = call_node.lineno
    candidates = [
        fr for fr in function_records
        if fr.lineno <= line <= fr.end_lineno
    ]
    if not candidates:
        return None
    candidates.sort(key=lambda fr: fr.end_lineno - fr.lineno)
    return candidates[0]


def _resolve_callee(
    chain: list[str],
    caller: _FunctionRecord | None,
    function_records_by_name: dict[str, list[_FunctionRecord]],
    class_methods: dict[str, set[str]],
) -> str | None:
    """Resolve a call's attribute chain to a callee's qualified
    name in this module, or None.

    Resolution rules (deliberately conservative — drop the edge
    rather than guess):

    * ``["f"]`` — match a module-level function named ``f``.
      If a nested function named ``f`` exists with the caller as
      its enclosing scope, that wins.
    * ``["self", "m"]`` — the caller must be a method; resolve to
      ``{caller.class_name}.m`` if defined.
    * ``["cls", "m"]`` — same as ``self`` for classmethod-style
      calls; the convention is followed even if @classmethod
      isn't recorded.
    * ``["ClassName"]`` — constructor invocation; resolve to
      ``ClassName.__init__`` when defined, else drop.
    * ``["ClassName", "m"]`` — class-qualified static-style call;
      resolve to ``ClassName.m`` when defined.
    * Anything longer or with an unknown root — drop (cross-module
      or dynamic).

    Shadow guard: when the CALLER's own scope binds the chain's root
    name (``esc = str``, a param named ``esc``, a walrus, an import
    alias), the runtime callee is the local binding, not the module
    table's entry — resolving through the table would attribute the
    call to a function it provably may not reach (the downstream
    taint summaries then certify forged clean-sanitizer wrappers).
    The one exception is the nested-def preference below: a nested
    ``def esc`` IS the local binding, so resolving to it is exact.
    """
    if not chain:
        return None
    # Single name — bare function or class name.
    if len(chain) == 1:
        name = chain[0]
        # Prefer a nested function defined under the caller.
        if caller is not None:
            nested = f"{caller.qualified_name}.{name}"
            if nested in function_records_by_name:
                return nested
        if caller is not None and name in caller.local_bindings():
            # Locally rebound (and not the nested def handled above)
            # — the module-level entry is not the runtime callee.
            return None
        if name in function_records_by_name:
            return name
        # Class construction — ClassName() → ClassName.__init__
        init = f"{name}.__init__"
        if init in function_records_by_name:
            return init
        return None
    # ``self.m`` / ``cls.m``
    if len(chain) == 2 and chain[0] in ("self", "cls"):
        if caller is None or caller.class_name is None:
            return None
        candidate = f"{caller.class_name}.{chain[1]}"
        if candidate in function_records_by_name:
            return candidate
        return None
    # ``Class.m`` — module-level class methods, static-style.
    if len(chain) == 2:
        if caller is not None and chain[0] in caller.local_bindings():
            # A local named like the class shadows it for this call.
            return None
        cls = chain[0]
        if cls in class_methods and chain[1] in class_methods[cls]:
            return f"{cls}.{chain[1]}"
        return None
    # Longer chains: cross-module / nested attribute. Drop.
    return None


def _collect_calls(tree: ast.AST) -> list[tuple[ast.Call, list[str]]]:
    """Every ``ast.Call`` whose function position has a resolvable
    static name chain, paired with that chain. Calls without a
    recoverable chain (lambda invoke, subscript, etc.) are skipped."""
    out: list[tuple[ast.Call, list[str]]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        chain = _attribute_chain(node.func)
        if chain is None:
            continue
        out.append((node, chain))
    return out


# ---------------------------------------------------------------------------
# Module-entry edges — top-level (module-level) code calls
# ---------------------------------------------------------------------------


def _module_level_calls(
    tree: ast.Module,
    function_records: list[_FunctionRecord],
) -> list[tuple[ast.Call, list[str]]]:
    """Calls that live at module level (outside any
    ``FunctionDef`` / ``AsyncFunctionDef`` / ``ClassDef`` body).
    These attach to the synthetic module-entry node."""
    fn_ranges = [(fr.lineno, fr.end_lineno) for fr in function_records]

    def _inside_function(line: int) -> bool:
        return any(start <= line <= end for start, end in fn_ranges)

    out: list[tuple[ast.Call, list[str]]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if _inside_function(node.lineno):
            continue
        chain = _attribute_chain(node.func)
        if chain is None:
            continue
        out.append((node, chain))
    return out


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def build_python_module_callgraph(
    source: str | Path,
) -> PyModuleCallGraph | None:
    """Build a module-local call graph for one Python source file.

    ``source`` is a :class:`Path` (read from disk) or a ``str`` of
    source code (parsed directly — useful for tests). Returns
    None when the source can't be parsed.

    A successfully-built graph always has at least the synthetic
    module-entry node, even when the file defines no functions.
    """
    if isinstance(source, Path):
        file_path = str(source)
        # errors="replace": a non-UTF-8 target file must degrade to
        # the parse-failure None path (or parse what it can), not
        # raise UnicodeDecodeError into the caller — the resolver's
        # blanket except would silently drop the file's summaries,
        # and new callers would crash outright.
        source_text = source.read_text(encoding="utf-8",
                                       errors="replace")
    else:
        file_path = "<string>"
        source_text = source
    try:
        tree = ast.parse(source_text)
    except SyntaxError:
        return None
    if not isinstance(tree, ast.Module):
        return None

    fn_records = _collect_functions(tree)
    scope_bindings = function_scope_bindings(tree)
    for record in fn_records:
        record._local_bindings = scope_bindings.get(record.ast_node)
    by_name: dict[str, list[_FunctionRecord]] = {}
    for fr in fn_records:
        by_name.setdefault(fr.qualified_name, []).append(fr)
    class_methods: dict[str, set[str]] = {}
    for fr in fn_records:
        if fr.is_method and fr.class_name is not None:
            method_short = fr.qualified_name.split(".", 1)[1]
            class_methods.setdefault(fr.class_name, set()).add(method_short)

    # Build nodes.
    entry = PyCallGraphNode(
        name=MODULE_ENTRY_NAME, lineno=0, end_lineno=0,
        params=(), is_method=False, class_name=None,
        is_module_entry=True,
    )
    # Nodes are keyed by (qualified_name, lineno) so conditional
    # redefinitions materialise as DISTINCT nodes — a name-keyed dict
    # silently dropped every variant but the last, which (a) lost the
    # earlier body from the graph entirely and (b) mis-attributed the
    # earlier body's outgoing calls to the later variant's node.
    fn_node_by_key: dict[tuple[str, int], PyCallGraphNode] = {}
    variants_by_name: dict[str, list[PyCallGraphNode]] = {}
    for fr in fn_records:
        node = PyCallGraphNode(
            name=fr.qualified_name,
            lineno=fr.lineno,
            end_lineno=fr.end_lineno,
            params=fr.params,
            is_method=fr.is_method,
            class_name=fr.class_name,
        )
        fn_node_by_key[(fr.qualified_name, fr.lineno)] = node
        variants_by_name.setdefault(fr.qualified_name, []).append(node)
    # Name-keyed views: last definition wins (Python's runtime
    # semantics for sequential module-level defs) — the variant
    # tuples carry the rest.
    fn_nodes: dict[str, PyCallGraphNode] = {
        name: nodes[-1] for name, nodes in variants_by_name.items()
    }
    all_nodes_by_name: dict[str, PyCallGraphNode] = {
        MODULE_ENTRY_NAME: entry,
        **fn_nodes,
    }
    ast_by_name: dict[str, ast.AST] = {
        fr.qualified_name: fr.ast_node for fr in fn_records
    }
    asts_by_node: dict[tuple[str, int], ast.AST] = {
        (fr.qualified_name, fr.lineno): fr.ast_node for fr in fn_records
    }

    # Build edges. Two sources:
    # 1. Module-level calls — edges from ``<module>`` to each
    #    resolvable callee.
    # 2. In-function calls — edges from the caller's node to each
    #    resolvable callee.
    adjacency: dict[PyCallGraphNode, set[PyCallGraphNode]] = {}

    def _add_edge(src: PyCallGraphNode, dst: PyCallGraphNode) -> None:
        adjacency.setdefault(src, set()).add(dst)

    # Module entry also implicitly "calls" every module-level function
    # (so dominator queries treat them as reachable). This is the
    # synthetic equivalent of a Python import importing the module:
    # the module body runs and defines the top-level fns. Methods of
    # classes are reachable transitively via their class's
    # construction — but we don't model that here, so methods are
    # only reachable via call edges from other functions.
    for fr in fn_records:
        if fr.is_method:
            continue
        if "." in fr.qualified_name:
            continue        # nested under another function — not top-level
        _add_edge(entry, fn_node_by_key[(fr.qualified_name, fr.lineno)])

    # Module-level calls. A call to a conditionally-redefined name
    # fans out to EVERY variant — which body runs depends on
    # module-import-time state, so the sound graph reaches both.
    for call, chain in _module_level_calls(tree, fn_records):
        callee = _resolve_callee(chain, None, by_name, class_methods)
        if callee is not None:
            for dst in variants_by_name.get(callee, ()):
                _add_edge(entry, dst)

    # Per-function calls. The CALLER side binds exactly (each
    # variant's body attributes to its own node); the CALLEE side
    # fans out across variants, same as above.
    all_calls = _collect_calls(tree)
    for call, chain in all_calls:
        caller_record = _enclosing_function_chain(call, fn_records)
        if caller_record is None:
            continue            # module-level — handled above
        callee_name = _resolve_callee(
            chain, caller_record, by_name, class_methods,
        )
        if callee_name is None:
            continue
        src_node = fn_node_by_key.get(
            (caller_record.qualified_name, caller_record.lineno),
        )
        if src_node is None:
            continue
        for dst_node in variants_by_name.get(callee_name, ()):
            _add_edge(src_node, dst_node)

    # Materialise immutable adjacency. Sort deterministically by
    # (name, lineno) so test snapshots are stable.
    final_adj: dict[PyCallGraphNode, tuple[PyCallGraphNode, ...]] = {}
    for src, dsts in adjacency.items():
        final_adj[src] = tuple(sorted(dsts, key=lambda n: (n.name, n.lineno)))

    ordered_nodes: list[PyCallGraphNode] = [entry] + sorted(
        fn_node_by_key.values(), key=lambda n: (n.lineno, n.name),
    )

    # Rebound-identity poison set: only roots that actually name a
    # collected function (or its enclosing class prefix) matter to
    # summary consumers, so intersect the module-scope rebinds down
    # to them.
    fn_roots = {fr.qualified_name.split(".", 1)[0] for fr in fn_records}
    dyn_whole, dyn_names = module_dynamic_namespace(tree)
    rebound = frozenset(
        (_module_rebound_names(tree) | dyn_names) & fn_roots,
    )

    return PyModuleCallGraph(
        file_path=file_path,
        entry_node=entry,
        _nodes=tuple(ordered_nodes),
        _adjacency=final_adj,
        _by_name=all_nodes_by_name,
        _ast_by_name=ast_by_name,
        _variants_by_name={
            name: tuple(nodes) for name, nodes in variants_by_name.items()
        },
        _asts_by_node=asts_by_node,
        rebound_names=rebound,
        distrusted_roots=(
            module_shadowed_identity_roots(tree) | dyn_names
        ),
        nonimport_distrusted_roots=(
            module_distrusted_roots(tree) | dyn_names
        ),
        import_map=module_import_map(tree),
        namespace_unprovable=dyn_whole,
        _scope_bindings=scope_bindings,
    )


__all__ = [
    "MODULE_ENTRY_NAME",
    "PyCallGraphNode",
    "PyModuleCallGraph",
    "build_python_module_callgraph",
    "local_binding_names",
    "function_scope_bindings",
    "module_distrusted_roots",
    "module_import_map",
    "module_dynamic_namespace",
    "module_shadowed_identity_roots",
]
