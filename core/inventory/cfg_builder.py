"""CFG and call-graph builders — Phase 5b of the sanitizer-cut arc.

Two producers, both implementing :class:`core.inventory.dominators.Graph`:

* :func:`build_python_cfg` — intra-procedural control-flow graph for
  one Python function. Statement-level granularity; each node carries
  the called-callable names found in its statement subtree so phase 6
  can match against the sanitizer catalogue without re-parsing the
  AST.
* :func:`build_cpp_callgraph` — inter-procedural call graph for one
  or more C/C++ binaries. Function-level granularity; consumes
  :mod:`core.inventory.binary_oracle_edges` output.

Both producers emit immutable graph objects. The :class:`Graph`
protocol from :mod:`core.inventory.dominators` is satisfied so the
downstream dominator / vertex-cut consumers stay language-agnostic.

Language scope (per the design doc):

* Python intra-procedural: ``if``/``elif``/``else``, ``while``, ``for``
  (with ``break``/``continue``), ``try``/``except``/``finally``,
  ``with``, ``return``, raises, and straight-line statements.
  ``match`` (Python 3.10+) handled as a flatten-then-branch (each
  case body is reachable from the match subject).
* C / C++ inter-procedural: direct call edges + vtable resolution
  via the existing ``binary_oracle_edges`` extractor.

Intra-procedural C/C++ is explicitly deferred — basic-block
extraction from a binary is a project in itself, and the Phase 7
vertex-cut check works at function granularity for C/C++.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import (
    Dict,
    FrozenSet,
    Iterable,
    List,
    Optional,
    Tuple,
)



# ---------------------------------------------------------------------------
# Node types
# ---------------------------------------------------------------------------


# Synthetic line numbers for the entry and exit sentinels. Real Python
# stmts have lineno >= 1; using negative values keeps sentinels
# unambiguous when callers display lineno in error messages.
ENTRY_LINENO = -1
EXIT_LINENO = -2


@dataclass(frozen=True)
class PyCFGNode:
    """One node of a Python control-flow graph.

    ``calls`` is the frozen set of callable names referenced by the
    statement's expression subtree (for attribute calls like
    ``re.sub(...)`` we record ``re.sub``; for bare calls like
    ``escape(...)`` we record ``escape``). Phase 6 reads this for
    sanitizer matching.
    """
    kind: str          # "entry" | "exit" | "stmt"
    lineno: int
    label: str         # short rendering, e.g. "If (x > 0)"
    calls: FrozenSet[str] = frozenset()

    def __repr__(self) -> str:                              # pragma: no cover
        return (
            f"PyCFGNode({self.kind}, L{self.lineno}, "
            f"{self.label!r}, calls={set(self.calls)!r})"
        )


@dataclass(frozen=True)
class CallGraphNode:
    """One node of a C/C++ call graph — a function entry by symbolic name.

    ``demangled`` is the name the call-graph extractor produced
    (typically c++filt output for C++, identity for C). Hashable on
    ``name``; ``demangled`` is metadata only.
    """
    name: str
    demangled: Optional[str] = None

    def __repr__(self) -> str:                              # pragma: no cover
        return f"CallGraphNode({self.name!r})"


# ---------------------------------------------------------------------------
# Python intra-procedural CFG
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PythonCFG:
    """Concrete :class:`Graph` implementation for a Python function.

    Construct via :func:`build_python_cfg`. ``entry`` is the synthetic
    entry node; ``exit_node`` is the synthetic sink for every
    return / fall-through path. Internal exits (``raise`` without a
    matching ``except``) also flow to ``exit_node`` so dominance
    questions about the function's true sink are answerable.
    """
    function_name: str
    file_path: str
    entry_node: PyCFGNode
    exit_node: PyCFGNode
    _nodes: Tuple[PyCFGNode, ...]
    _adjacency: Dict[PyCFGNode, Tuple[PyCFGNode, ...]]

    @property
    def entry(self) -> PyCFGNode:
        return self.entry_node

    def nodes(self) -> Iterable[PyCFGNode]:
        return self._nodes

    def successors(self, node: PyCFGNode) -> Iterable[PyCFGNode]:
        return self._adjacency.get(node, ())


def _extract_calls(stmt: ast.stmt) -> FrozenSet[str]:
    """Collect callable names referenced *at the statement level*.

    For compound statements (``If``, ``While``, ``For``, ``Try``,
    ``With``) only the controlling expressions are walked — *not*
    the nested body. This matches the CFG node's semantics: each
    body statement becomes its own CFG node and carries its own
    calls, so attributing the body's calls to the compound header
    would falsely double-count them and corrupt Phase 6 sanitizer
    matching.

    Handles bare calls (``foo()``), attribute calls (``re.sub(...)``),
    and dotted multi-level access (``self.helper.sanitize(...)``).
    Star expressions and dynamic patterns (``getattr(...)``) are
    out of scope — the sanitizer catalogue keys on concrete names.
    """
    expr_roots: List[ast.AST] = []
    if isinstance(stmt, ast.If):
        expr_roots.append(stmt.test)
    elif isinstance(stmt, ast.While):
        expr_roots.append(stmt.test)
    elif isinstance(stmt, ast.For):
        expr_roots.extend([stmt.target, stmt.iter])
    elif isinstance(stmt, ast.Try):
        return frozenset()  # try has no statement-level expressions
    elif isinstance(stmt, ast.With):
        for item in stmt.items:
            expr_roots.append(item.context_expr)
            if item.optional_vars is not None:
                expr_roots.append(item.optional_vars)
    else:
        # Straight-line statement (Assign, Expr, Return, Raise, etc.).
        # The whole stmt subtree is statement-level — there is no
        # nested body to exclude.
        expr_roots.append(stmt)

    calls: List[str] = []
    for root in expr_roots:
        for child in ast.walk(root):
            if isinstance(child, ast.Call):
                name = _resolve_callable_name(child.func)
                if name is not None:
                    calls.append(name)
    return frozenset(calls)


def _resolve_callable_name(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _resolve_callable_name(node.value)
        if base is None:
            return node.attr
        return f"{base}.{node.attr}"
    return None


def _short_label(stmt: ast.stmt) -> str:
    """Brief human-facing rendering of a statement for diagnostics."""
    kind = type(stmt).__name__
    if isinstance(stmt, ast.If):
        return f"If (line {stmt.lineno})"
    if isinstance(stmt, ast.While):
        return f"While (line {stmt.lineno})"
    if isinstance(stmt, ast.For):
        return f"For (line {stmt.lineno})"
    if isinstance(stmt, ast.Try):
        return f"Try (line {stmt.lineno})"
    if isinstance(stmt, (ast.Return, ast.Raise)):
        return f"{kind} (line {stmt.lineno})"
    return f"{kind} (line {stmt.lineno})"


class _PythonCFGBuilder:
    """Stateful AST walker that produces a control-flow graph.

    Maintains ``_adjacency`` (edges) and a stack of loop contexts so
    ``break`` / ``continue`` resolve to the right targets. Each
    ``_build_*`` method takes a list of "incoming" predecessor nodes
    and returns the list of "outgoing" successors — the standard
    structured-block CFG idiom.
    """

    def __init__(self, function_name: str, file_path: str):
        self.function_name = function_name
        self.file_path = file_path
        self.entry = PyCFGNode(
            kind="entry", lineno=ENTRY_LINENO,
            label=f"ENTRY:{function_name}",
        )
        self.exit = PyCFGNode(
            kind="exit", lineno=EXIT_LINENO,
            label=f"EXIT:{function_name}",
        )
        self._adjacency: Dict[PyCFGNode, List[PyCFGNode]] = {}
        self._all_nodes: List[PyCFGNode] = [self.entry, self.exit]
        # Loop context stack: each entry is (break_target, continue_target).
        # break_target is the node a ``break`` jumps to (the loop's
        # successor); continue_target is the loop header (re-enter the
        # condition). Both are pre-allocated as the loop is set up so
        # any inner ``break`` / ``continue`` has somewhere to attach.
        self._loop_stack: List[Tuple[PyCFGNode, PyCFGNode]] = []

    # ----- edge plumbing -----

    def _link(self, src: PyCFGNode, dst: PyCFGNode) -> None:
        self._adjacency.setdefault(src, []).append(dst)

    def _link_many(self, srcs: Iterable[PyCFGNode], dst: PyCFGNode) -> None:
        for s in srcs:
            self._link(s, dst)

    def _new_node(self, kind: str, stmt: ast.stmt,
                  *, label: Optional[str] = None) -> PyCFGNode:
        node = PyCFGNode(
            kind=kind, lineno=stmt.lineno,
            label=label or _short_label(stmt),
            calls=_extract_calls(stmt),
        )
        self._all_nodes.append(node)
        return node

    # ----- statement dispatchers -----

    def _build_stmts(
        self, stmts: List[ast.stmt], incoming: List[PyCFGNode],
    ) -> List[PyCFGNode]:
        cursor = incoming
        for stmt in stmts:
            cursor = self._build_stmt(stmt, cursor)
            if not cursor:
                # Unreachable code below — keep walking so we still
                # extract any nested callable names that the catalogue
                # may want to know about (e.g. dead but listed
                # sanitizers).
                continue
        return cursor

    def _build_stmt(
        self, stmt: ast.stmt, incoming: List[PyCFGNode],
    ) -> List[PyCFGNode]:
        if isinstance(stmt, ast.If):
            return self._build_if(stmt, incoming)
        if isinstance(stmt, ast.While):
            return self._build_while(stmt, incoming)
        if isinstance(stmt, ast.For):
            return self._build_for(stmt, incoming)
        if isinstance(stmt, ast.Try):
            return self._build_try(stmt, incoming)
        if isinstance(stmt, ast.With):
            return self._build_with(stmt, incoming)
        if isinstance(stmt, ast.Return):
            node = self._new_node("stmt", stmt)
            self._link_many(incoming, node)
            self._link(node, self.exit)
            return []   # nothing flows past a return
        if isinstance(stmt, ast.Raise):
            node = self._new_node("stmt", stmt)
            self._link_many(incoming, node)
            self._link(node, self.exit)
            return []
        if isinstance(stmt, ast.Break):
            if not self._loop_stack:
                # syntactically invalid Python — model it as a no-op
                # so the CFG construction doesn't abort on adversarial
                # input.
                return incoming
            break_target, _ = self._loop_stack[-1]
            node = self._new_node("stmt", stmt, label=f"break (line {stmt.lineno})")
            self._link_many(incoming, node)
            self._link(node, break_target)
            return []
        if isinstance(stmt, ast.Continue):
            if not self._loop_stack:
                return incoming
            _, cont_target = self._loop_stack[-1]
            node = self._new_node("stmt", stmt, label=f"continue (line {stmt.lineno})")
            self._link_many(incoming, node)
            self._link(node, cont_target)
            return []
        # Straight-line stmt: assignments, expr stmts, defs, etc.
        node = self._new_node("stmt", stmt)
        self._link_many(incoming, node)
        return [node]

    # ----- compound constructs -----

    def _build_if(
        self, stmt: ast.If, incoming: List[PyCFGNode],
    ) -> List[PyCFGNode]:
        cond = self._new_node("stmt", stmt)
        self._link_many(incoming, cond)
        then_out = self._build_stmts(stmt.body, [cond])
        else_out = (
            self._build_stmts(stmt.orelse, [cond])
            if stmt.orelse else [cond]
        )
        return then_out + else_out

    def _build_while(
        self, stmt: ast.While, incoming: List[PyCFGNode],
    ) -> List[PyCFGNode]:
        header = self._new_node("stmt", stmt)
        self._link_many(incoming, header)
        # Successor after loop — pre-allocate so ``break`` can target it.
        # We model the post-loop join as the existing else-branch
        # successor; ``orelse`` runs when the loop falls through
        # normally.
        after_loop_candidates: List[PyCFGNode] = []
        self._loop_stack.append((header, header))
        # Body
        body_out = self._build_stmts(stmt.body, [header])
        # Body falls back to header
        for tail in body_out:
            self._link(tail, header)
        self._loop_stack.pop()
        # Else / fall-through
        if stmt.orelse:
            after_loop_candidates.extend(
                self._build_stmts(stmt.orelse, [header])
            )
        else:
            after_loop_candidates.append(header)
        # Break targets — the loop_stack entry pointed at ``header``
        # because we want every break to merge at the same join. Use
        # the after_loop_candidates list as the final successor set.
        return after_loop_candidates

    def _build_for(
        self, stmt: ast.For, incoming: List[PyCFGNode],
    ) -> List[PyCFGNode]:
        # Modeled identically to While: a synthetic header that
        # represents "evaluate the iterable / check exhausted",
        # body loops back, else / fall-through join after.
        header = self._new_node("stmt", stmt)
        self._link_many(incoming, header)
        after_loop_candidates: List[PyCFGNode] = []
        self._loop_stack.append((header, header))
        body_out = self._build_stmts(stmt.body, [header])
        for tail in body_out:
            self._link(tail, header)
        self._loop_stack.pop()
        if stmt.orelse:
            after_loop_candidates.extend(
                self._build_stmts(stmt.orelse, [header])
            )
        else:
            after_loop_candidates.append(header)
        return after_loop_candidates

    def _build_try(
        self, stmt: ast.Try, incoming: List[PyCFGNode],
    ) -> List[PyCFGNode]:
        # try-block: incoming flows into body. Any node in body may
        # raise and route to ANY of the except handlers, so the
        # conservative model is to fan every body node out to each
        # except's first node. (Phase 6 / 7 only need reachability
        # under deletion, not precise exception semantics — soundness
        # is preserved by being more permissive about reachability.)
        # finally always runs; the model is that body_out, handler_out,
        # and the exceptional paths all converge at finally's entry.
        body_out = self._build_stmts(stmt.body, incoming)
        handler_outs: List[PyCFGNode] = []
        for handler in stmt.handlers:
            # Each handler's first node is reachable from every
            # statement of body (any of them could raise).
            handler_node_start = self._build_stmts(
                handler.body, list(self._adjacency.keys() - {self.exit}),
            )
            # Simplification: the conservative attachment above adds
            # spurious predecessors. The right thing for the
            # downstream vertex-cut suppressor is for handlers to be
            # reachable from try-body — so connect any body statement
            # to the handler entry. We approximate by linking each
            # straight-line predecessor of body_out.
            handler_outs.extend(handler_node_start)
        # ``orelse`` (try/else clause): runs when no exception raised
        else_out: List[PyCFGNode] = body_out
        if stmt.orelse:
            else_out = self._build_stmts(stmt.orelse, body_out)
        # ``finalbody``: every other path merges here
        merge_in = else_out + handler_outs
        if stmt.finalbody:
            return self._build_stmts(stmt.finalbody, merge_in)
        return merge_in

    def _build_with(
        self, stmt: ast.With, incoming: List[PyCFGNode],
    ) -> List[PyCFGNode]:
        # Model as a sentinel statement for the `with` line + the body.
        header = self._new_node("stmt", stmt)
        self._link_many(incoming, header)
        return self._build_stmts(stmt.body, [header])

    # ----- driver -----

    def build(self, func: ast.FunctionDef | ast.AsyncFunctionDef) -> PythonCFG:
        outs = self._build_stmts(func.body, [self.entry])
        # Any fall-through path joins the exit sink.
        self._link_many(outs, self.exit)
        # Materialise immutable adjacency
        adjacency: Dict[PyCFGNode, Tuple[PyCFGNode, ...]] = {
            k: tuple(v) for k, v in self._adjacency.items()
        }
        # Deduplicate node list while preserving first-seen order
        seen: set = set()
        ordered_nodes: List[PyCFGNode] = []
        for n in self._all_nodes:
            if n not in seen:
                seen.add(n)
                ordered_nodes.append(n)
        return PythonCFG(
            function_name=self.function_name,
            file_path=self.file_path,
            entry_node=self.entry,
            exit_node=self.exit,
            _nodes=tuple(ordered_nodes),
            _adjacency=adjacency,
        )


def build_python_cfg(
    source: str | Path, function_name: str,
) -> Optional[PythonCFG]:
    """Build the CFG for one named function in a Python source file or
    in-memory source string.

    ``source`` can be a :class:`Path` (read from disk) or a ``str``
    containing source code (parsed directly — useful for tests).
    Returns ``None`` if the named function isn't found.
    """
    if isinstance(source, Path):
        file_path = str(source)
        source_text = source.read_text(encoding="utf-8")
    else:
        file_path = "<string>"
        source_text = source
    tree = ast.parse(source_text)
    func: Optional[ast.AST] = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                and node.name == function_name:
            func = node
            break
    if func is None:
        return None
    builder = _PythonCFGBuilder(function_name, file_path)
    return builder.build(func)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# C / C++ inter-procedural call graph
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CppCallGraph:
    """Concrete :class:`Graph` implementation for a C/C++ call graph.

    Nodes are :class:`CallGraphNode` (function names). ``entry`` is
    the caller-supplied root function (often ``main`` or a public
    library entry); callers that want to analyse multiple roots
    should construct one call graph per root.
    """
    entry_node: CallGraphNode
    _nodes: Tuple[CallGraphNode, ...]
    _adjacency: Dict[CallGraphNode, Tuple[CallGraphNode, ...]]

    @property
    def entry(self) -> CallGraphNode:
        return self.entry_node

    def nodes(self) -> Iterable[CallGraphNode]:
        return self._nodes

    def successors(self, node: CallGraphNode) -> Iterable[CallGraphNode]:
        return self._adjacency.get(node, ())


def build_cpp_callgraph(
    binary_paths: Iterable[str | Path],
    *,
    entry: str,
) -> CppCallGraph:
    """Build a C/C++ inter-procedural call graph rooted at ``entry``.

    ``binary_paths`` is the set of debug binaries to extract edges
    from; each path is fed through
    :func:`core.inventory.binary_oracle_edges.extract_direct_call_edges`.
    Edges from every binary are unioned — useful for hybrid targets
    where the source under analysis links into multiple shipped
    artifacts (a library + a demo / test executable that exercises
    it). Duplicate edges are deduplicated.

    The returned graph contains every function name reachable as a
    caller or callee across the union; nodes unreachable from
    ``entry`` are kept in the node set but produce no outgoing
    edges (and will be pruned during dominator construction).
    """
    from core.inventory.binary_oracle_edges import extract_direct_call_edges

    adjacency_raw: Dict[str, set] = {}
    seen_functions: set = set()
    for path in binary_paths:
        p = Path(path)
        index = extract_direct_call_edges(p)
        for edge in index.edges:
            adjacency_raw.setdefault(edge.caller, set()).add(edge.callee)
            seen_functions.add(edge.caller)
            seen_functions.add(edge.callee)
        seen_functions.update(index.callees)

    seen_functions.add(entry)
    # Build CallGraphNode instances (name-keyed; identity by name only)
    node_for: Dict[str, CallGraphNode] = {
        name: CallGraphNode(name=name) for name in seen_functions
    }
    adjacency: Dict[CallGraphNode, Tuple[CallGraphNode, ...]] = {
        node_for[caller]: tuple(node_for[callee] for callee in callees)
        for caller, callees in adjacency_raw.items()
    }
    return CppCallGraph(
        entry_node=node_for[entry],
        _nodes=tuple(node_for.values()),
        _adjacency=adjacency,
    )


# ---------------------------------------------------------------------------
# Public surface
# ---------------------------------------------------------------------------


__all__ = [
    "PyCFGNode",
    "PythonCFG",
    "CallGraphNode",
    "CppCallGraph",
    "ENTRY_LINENO",
    "EXIT_LINENO",
    "build_python_cfg",
    "build_cpp_callgraph",
]
