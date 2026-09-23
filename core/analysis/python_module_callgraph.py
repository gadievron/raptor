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
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                out.add(child.name)
                # Decorators and defaults evaluate in THIS scope.
                for expr in (*child.decorator_list,
                             *child.args.defaults,
                             *(d for d in child.args.kw_defaults
                               if d is not None)):
                    _walk(expr)
                continue
            if isinstance(child, ast.ClassDef):
                out.add(child.name)
                for expr in (*child.decorator_list, *child.bases,
                             *(kw.value for kw in child.keywords)):
                    _walk(expr)
                continue
            if isinstance(child, ast.Lambda):
                for expr in (*child.args.defaults,
                             *(d for d in child.args.kw_defaults
                               if d is not None)):
                    _walk(expr)
                continue
            if isinstance(child, ast.Assign):
                for t in child.targets:
                    _add_target(t)
            elif isinstance(child, (ast.AnnAssign, ast.AugAssign)):
                _add_target(child.target)
            elif isinstance(child, ast.NamedExpr):
                _add_target(child.target)
            elif isinstance(child, (ast.For, ast.AsyncFor)):
                _add_target(child.target)
            elif isinstance(child, (ast.With, ast.AsyncWith)):
                for item in child.items:
                    if item.optional_vars is not None:
                        _add_target(item.optional_vars)
            elif isinstance(child, ast.ExceptHandler):
                if child.name:
                    out.add(child.name)
            elif isinstance(child, (ast.Import, ast.ImportFrom)):
                for alias in child.names:
                    if alias.asname:
                        out.add(alias.asname)
                    elif alias.name != "*":
                        out.add(alias.name.split(".", 1)[0])
            elif isinstance(child, (ast.MatchAs, ast.MatchStar)):
                if child.name:
                    out.add(child.name)
            elif isinstance(child, ast.MatchMapping):
                if child.rest:
                    out.add(child.rest)
            _walk(child)

    _walk(fn_ast)
    return frozenset(out)


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
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                def_names.add(child.name)
                continue
            if isinstance(child, ast.ClassDef):
                class_names.add(child.name)
                continue
            if isinstance(child, ast.Lambda):
                continue
            if isinstance(child, ast.Assign):
                if (len(child.targets) == 1
                        and isinstance(child.targets[0], ast.Name)
                        and isinstance(child.value, ast.Lambda)):
                    # The lambda-def shape — a function record, not a
                    # rebind of one (but it IS a def name for the
                    # class-collision check).
                    def_names.add(child.targets[0].id)
                    continue
                for t in child.targets:
                    _add_target(t)
            elif isinstance(child, (ast.AnnAssign, ast.AugAssign)):
                _add_target(child.target)
            elif isinstance(child, ast.NamedExpr):
                _add_target(child.target)
            elif isinstance(child, (ast.For, ast.AsyncFor)):
                _add_target(child.target)
            elif isinstance(child, (ast.With, ast.AsyncWith)):
                for item in child.items:
                    if item.optional_vars is not None:
                        _add_target(item.optional_vars)
            elif isinstance(child, ast.ExceptHandler):
                if child.name:
                    nondef.add(child.name)
            elif isinstance(child, (ast.Import, ast.ImportFrom)):
                for alias in child.names:
                    if alias.asname:
                        nondef.add(alias.asname)
                    elif alias.name != "*":
                        nondef.add(alias.name.split(".", 1)[0])
            _walk(child)

    _walk(tree)

    # ``global`` declarations anywhere in the module (function bodies
    # included — that is the point).
    global_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Global):
            global_names.update(node.names)

    return frozenset(nondef | global_names | (class_names & def_names))


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
    rebound = frozenset(
        _module_rebound_names(tree) & fn_roots,
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
    )


__all__ = [
    "MODULE_ENTRY_NAME",
    "PyCallGraphNode",
    "PyModuleCallGraph",
    "build_python_module_callgraph",
    "local_binding_names",
]
