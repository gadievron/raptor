"""Module-local Python call graph — Phase 12 of the sanitizer-cut arc.

Sub-arc C's substrate. Given a Python source file, produce a frozen
graph whose nodes are the file's function / method definitions and
whose edges are intra-module call relationships. Phase 13 will
compute per-function taint summaries keyed by these nodes; Phase 14
will consult those summaries when an intra-procedural CFG sees a
:class:`core.inventory.cfg_builder.CallSite` whose name resolves to
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
  :class:`core.inventory.dominators.Graph`; exposes ``find(name)``
  for callee resolution and ``function_ast(name)`` for Phase 13's
  CFG-building.
* :func:`build_python_module_callgraph` — entry point.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import (
    Dict,
    Iterable,
    List,
    Optional,
    Set,
    Tuple,
    Union,
)


# Sentinel name for the synthetic module entry. Chosen to be
# syntactically illegal as a Python identifier so it can't collide
# with a real function.
MODULE_ENTRY_NAME = "<module>"


@dataclass(frozen=True)
class PyCallGraphNode:
    """One function / method in a module-local call graph.

    Equality / hash are over ``(name, lineno)`` — two functions
    with the same qualified name at the same line are the same
    node. (Duplicate qualified names at different lines can occur
    when a module conditionally redefines a function; we treat
    those as distinct nodes so taint summaries don't fight.)
    """
    name: str               # qualified — "foo", "C.method", "outer.inner"
    lineno: int             # 1-indexed start line of the def
    end_lineno: int = 0     # 1-indexed end line; 0 when unknown
    params: Tuple[str, ...] = ()
    is_method: bool = False
    class_name: Optional[str] = None
    is_module_entry: bool = False

    def __repr__(self) -> str:                              # pragma: no cover
        suf = "(entry)" if self.is_module_entry else f"L{self.lineno}"
        return f"PyCallGraphNode({self.name!r}, {suf})"


@dataclass(frozen=True)
class PyModuleCallGraph:
    """Module-local call graph for one Python file.

    Implements :class:`core.inventory.dominators.Graph`. Plus two
    consumer-side accessors:

    * :meth:`find(name)` — qualified name → node, or None.
    * :meth:`function_ast(name)` — qualified name →
      ``ast.FunctionDef`` / ``ast.AsyncFunctionDef`` / ``ast.Lambda``,
      or None. Phase 13's per-function CFG builder reads this.
    """
    file_path: str
    entry_node: PyCallGraphNode
    _nodes: Tuple[PyCallGraphNode, ...]
    _adjacency: Dict[PyCallGraphNode, Tuple[PyCallGraphNode, ...]]
    _by_name: Dict[str, PyCallGraphNode] = field(default_factory=dict)
    # Mutable side-channel for ast access. NOT part of node identity;
    # frozen dataclass equality still works because dicts compare by
    # content. Kept private; access via :meth:`function_ast`.
    _ast_by_name: Dict[str, ast.AST] = field(default_factory=dict)

    @property
    def entry(self) -> PyCallGraphNode:
        return self.entry_node

    def nodes(self) -> Iterable[PyCallGraphNode]:
        return self._nodes

    def successors(
        self, node: PyCallGraphNode,
    ) -> Iterable[PyCallGraphNode]:
        return self._adjacency.get(node, ())

    def find(self, name: str) -> Optional[PyCallGraphNode]:
        """Look up a node by its qualified name."""
        return self._by_name.get(name)

    def function_ast(self, name: str) -> Optional[ast.AST]:
        """Phase 13 hook — the AST subtree for ``name``. Returns
        None for the module entry, for unknown names, and for
        functions whose AST wasn't preserved (e.g. a lambda whose
        binding was lost)."""
        return self._ast_by_name.get(name)


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
    params: Tuple[str, ...]
    is_method: bool
    class_name: Optional[str]
    ast_node: ast.AST


def _function_params(
    fn: Union[ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda],
) -> Tuple[str, ...]:
    """Ordered param names. Same convention as
    :func:`core.inventory.cfg_builder._function_params`: posonly,
    positional, ``*args``, kwonly, ``**kwargs``."""
    args = fn.args
    names: List[str] = []
    for a in args.posonlyargs:
        names.append(a.arg)
    for a in args.args:
        names.append(a.arg)
    if args.vararg is not None:
        names.append(args.vararg.arg)
    for a in args.kwonlyargs:
        names.append(a.arg)
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


def _collect_functions(tree: ast.AST) -> List[_FunctionRecord]:
    """Walk ``tree`` collecting every named function-like
    definition. Recursion handles nested functions and methods.

    ``ast.Lambda`` is harvested ONLY when bound to a single
    ``ast.Assign`` LHS — those become nodes named after the LHS.
    Anonymous lambdas in expression position are skipped (no
    static name to resolve from a call site).
    """
    out: List[_FunctionRecord] = []
    # Walk with an explicit stack so we can carry the enclosing
    # qualified-prefix and class-name context downward.
    stack: List[Tuple[ast.AST, str, Optional[str]]] = [(tree, "", None)]
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
                stack.append((child, inner_prefix, child.name))
                continue
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qualified = (
                    f"{prefix}.{child.name}" if prefix else child.name
                )
                # Methods: class_name is set when this def is at the
                # immediate body of a class. Nested functions inside
                # methods inherit class_name=None — they're not
                # bound to the receiver.
                is_method = (
                    class_name is not None
                    and prefix == class_name
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
# Call resolution
# ---------------------------------------------------------------------------


def _attribute_chain(node: ast.AST) -> Optional[List[str]]:
    """``foo.bar.baz`` (``ast.Attribute`` rooted on ``ast.Name``) →
    ``["foo", "bar", "baz"]``. ``ast.Name("f")`` → ``["f"]``.
    Anything else (subscript root, call root, parenthesised
    lambda, etc.) → None."""
    parts: List[str] = []
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
    function_records: List[_FunctionRecord],
) -> Optional[_FunctionRecord]:
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
    chain: List[str],
    caller: Optional[_FunctionRecord],
    function_records_by_name: Dict[str, _FunctionRecord],
    class_methods: Dict[str, Set[str]],
) -> Optional[str]:
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
        cls = chain[0]
        if cls in class_methods and chain[1] in class_methods[cls]:
            return f"{cls}.{chain[1]}"
        return None
    # Longer chains: cross-module / nested attribute. Drop.
    return None


def _collect_calls(tree: ast.AST) -> List[Tuple[ast.Call, List[str]]]:
    """Every ``ast.Call`` whose function position has a resolvable
    static name chain, paired with that chain. Calls without a
    recoverable chain (lambda invoke, subscript, etc.) are skipped."""
    out: List[Tuple[ast.Call, List[str]]] = []
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
    function_records: List[_FunctionRecord],
) -> List[Tuple[ast.Call, List[str]]]:
    """Calls that live at module level (outside any
    ``FunctionDef`` / ``AsyncFunctionDef`` / ``ClassDef`` body).
    These attach to the synthetic module-entry node."""
    fn_ranges = [(fr.lineno, fr.end_lineno) for fr in function_records]

    def _inside_function(line: int) -> bool:
        return any(start <= line <= end for start, end in fn_ranges)

    out: List[Tuple[ast.Call, List[str]]] = []
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
    source: Union[str, Path],
) -> Optional[PyModuleCallGraph]:
    """Build a module-local call graph for one Python source file.

    ``source`` is a :class:`Path` (read from disk) or a ``str`` of
    source code (parsed directly — useful for tests). Returns
    None when the source can't be parsed.

    A successfully-built graph always has at least the synthetic
    module-entry node, even when the file defines no functions.
    """
    if isinstance(source, Path):
        file_path = str(source)
        source_text = source.read_text(encoding="utf-8")
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
    by_name: Dict[str, _FunctionRecord] = {
        fr.qualified_name: fr for fr in fn_records
    }
    class_methods: Dict[str, Set[str]] = {}
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
    fn_nodes: Dict[str, PyCallGraphNode] = {}
    for fr in fn_records:
        fn_nodes[fr.qualified_name] = PyCallGraphNode(
            name=fr.qualified_name,
            lineno=fr.lineno,
            end_lineno=fr.end_lineno,
            params=fr.params,
            is_method=fr.is_method,
            class_name=fr.class_name,
        )
    all_nodes_by_name: Dict[str, PyCallGraphNode] = {
        MODULE_ENTRY_NAME: entry,
        **fn_nodes,
    }
    ast_by_name: Dict[str, ast.AST] = {
        fr.qualified_name: fr.ast_node for fr in fn_records
    }

    # Build edges. Two sources:
    # 1. Module-level calls — edges from ``<module>`` to each
    #    resolvable callee.
    # 2. In-function calls — edges from the caller's node to each
    #    resolvable callee.
    adjacency: Dict[PyCallGraphNode, Set[PyCallGraphNode]] = {}

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
        _add_edge(entry, fn_nodes[fr.qualified_name])

    # Module-level calls.
    for call, chain in _module_level_calls(tree, fn_records):
        callee = _resolve_callee(chain, None, by_name, class_methods)
        if callee is not None and callee in fn_nodes:
            _add_edge(entry, fn_nodes[callee])

    # Per-function calls.
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
        src_node = fn_nodes.get(caller_record.qualified_name)
        dst_node = fn_nodes.get(callee_name)
        if src_node is None or dst_node is None:
            continue
        _add_edge(src_node, dst_node)

    # Materialise immutable adjacency. Sort deterministically by
    # (name, lineno) so test snapshots are stable.
    final_adj: Dict[PyCallGraphNode, Tuple[PyCallGraphNode, ...]] = {}
    for src, dsts in adjacency.items():
        final_adj[src] = tuple(sorted(dsts, key=lambda n: (n.name, n.lineno)))

    ordered_nodes: List[PyCallGraphNode] = [entry] + sorted(
        fn_nodes.values(), key=lambda n: (n.lineno, n.name),
    )

    return PyModuleCallGraph(
        file_path=file_path,
        entry_node=entry,
        _nodes=tuple(ordered_nodes),
        _adjacency=final_adj,
        _by_name=all_nodes_by_name,
        _ast_by_name=ast_by_name,
    )


__all__ = [
    "MODULE_ENTRY_NAME",
    "PyCallGraphNode",
    "PyModuleCallGraph",
    "build_python_module_callgraph",
]
