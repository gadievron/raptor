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
    Set,
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
class CallSite:
    """One call expression nested in a CFG node's statement-level
    expressions — phase 1 of the value-binding arc.

    ``name`` is the resolved dotted callable name (``html.escape``,
    ``werkzeug.security.safe_join``). Same resolver as the legacy
    ``calls`` frozenset on :class:`PyCFGNode`.

    ``arg_names`` is the frozenset of *bare-name* argument
    identifiers passed positionally or by keyword. Conservatively
    underestimates: nested calls, subscripts, binops, lambdas, and
    constants contribute nothing. Attributes contribute their base
    name (``foo(obj.attr)`` → ``{"obj"}``). The undercount is
    deliberate — :func:`evaluate_finding` gate condition 2 fires when
    ``input_symbols ∩ tainted`` is non-empty, so over-counting would
    over-suppress.

    ``assigned_names`` is the frozenset of LHS names this call's
    return value flows to. Non-empty only when the call IS the
    direct RHS of an ``Assign`` / ``AugAssign`` / ``AnnAssign``;
    nested calls (``y = wrap(f(x))`` — the inner ``f(x)``) have
    empty ``assigned_names`` because their return value flows
    into ``wrap``, not into ``y``.

    ``lineno`` is the source line of the call expression itself,
    which can differ from the enclosing statement's lineno when a
    multi-line expression wraps.

    ``col_offset`` is the 0-based column of the call expression.
    Paired with ``lineno`` it uniquely identifies a call even when
    two calls share a source line (``f(a) if g(b) else None``), so
    inter-procedural binding can attach to the right call's argument
    list rather than relying on ``ast.walk`` order. Defaults to ``0``
    for producers that don't track columns.
    """
    name: str
    arg_names: FrozenSet[str]
    assigned_names: FrozenSet[str]
    lineno: int
    col_offset: int = 0


@dataclass(frozen=True)
class PyCFGNode:
    """One node of a Python control-flow graph.

    ``calls`` is the frozen set of callable names referenced by the
    statement's expression subtree (for attribute calls like
    ``re.sub(...)`` we record ``re.sub``; for bare calls like
    ``escape(...)`` we record ``escape``). Phase 6 reads this for
    sanitizer matching.

    ``defs`` is the frozenset of names this statement assigns
    (``Name`` in ``Store`` context anywhere in the statement-level
    expressions, plus the ``LHS`` of augmented and annotated
    assignments). Comprehension-local targets are deliberately
    excluded — they don't leak to the enclosing function's symbol
    table.

    ``uses`` is the frozenset of names this statement reads
    (``Name`` in ``Load`` context). Comprehension-local names are
    likewise excluded.

    ``call_sites`` is the per-statement record of every nested
    :class:`CallSite`. Ordered by source position so chained calls
    are observable: ``y = wrap(html.escape(x))`` produces
    ``call_sites == (html.escape@arg_names={x}, wrap@arg_names={})``
    with ``wrap`` carrying ``assigned_names={y}``.

    The legacy ``calls`` field is preserved for back-compat with
    phase 5–7 callers; ``{cs.name for cs in call_sites}`` will agree
    with it.
    """
    kind: str          # "entry" | "exit" | "stmt"
    lineno: int
    label: str         # short rendering, e.g. "If (x > 0)"
    calls: FrozenSet[str] = frozenset()
    defs: FrozenSet[str] = frozenset()
    uses: FrozenSet[str] = frozenset()
    call_sites: Tuple[CallSite, ...] = ()

    def __repr__(self) -> str:                              # pragma: no cover
        return (
            f"PyCFGNode({self.kind}, L{self.lineno}, "
            f"{self.label!r}, calls={set(self.calls)!r}, "
            f"defs={set(self.defs)!r}, uses={set(self.uses)!r})"
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

    ``params`` is the ordered tuple of parameter names declared by
    the function (positional, keyword-only, ``*args``, ``**kwargs``).
    Phase 2's reaching-defs reads this to treat the entry as virtually
    defining each parameter so a body use of a parameter resolves
    to the entry as its reaching definer. Empty when the function
    takes no arguments.
    """
    function_name: str
    file_path: str
    entry_node: PyCFGNode
    exit_node: PyCFGNode
    _nodes: Tuple[PyCFGNode, ...]
    _adjacency: Dict[PyCFGNode, Tuple[PyCFGNode, ...]]
    params: Tuple[str, ...] = ()

    @property
    def entry(self) -> PyCFGNode:
        return self.entry_node

    def nodes(self) -> Iterable[PyCFGNode]:
        return self._nodes

    def successors(self, node: PyCFGNode) -> Iterable[PyCFGNode]:
        return self._adjacency.get(node, ())


_COMPREHENSION_TYPES = (
    ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp,
)


def _statement_expr_roots(stmt: ast.stmt) -> List[ast.AST]:
    """Per-stmt-kind list of expressions that belong to *this* CFG
    node, excluding nested compound bodies (which become their own
    nodes).

    Centralised so :func:`_extract_statement_payload` and any future
    symbol-aware extractor stay in lockstep on what "statement-level"
    means.
    """
    if isinstance(stmt, ast.If):
        return [stmt.test]
    if isinstance(stmt, ast.While):
        return [stmt.test]
    if isinstance(stmt, ast.For):
        return [stmt.target, stmt.iter]
    if isinstance(stmt, ast.Try):
        return []  # try has no statement-level expressions
    if isinstance(stmt, ast.With):
        roots: List[ast.AST] = []
        for item in stmt.items:
            roots.append(item.context_expr)
            if item.optional_vars is not None:
                roots.append(item.optional_vars)
        return roots
    # Straight-line statement: the whole subtree is statement-level.
    return [stmt]


def _resolve_callable_name(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _resolve_callable_name(node.value)
        if base is None:
            return node.attr
        return f"{base}.{node.attr}"
    return None


def _arg_surface_names(call: ast.Call) -> FrozenSet[str]:
    """Conservative bare-name extraction for one call's arguments.

    Only direct ``Name`` args and the base ``Name`` of direct
    ``Attribute`` args are counted. Nested ``Call``, ``Subscript``,
    ``BinOp``, ``Lambda``, ``Constant`` contribute nothing — their
    "value" isn't a bare symbol, so the gate condition
    ``input_symbols ∩ tainted`` would over-suppress if we
    treated their internal names as inputs to the outer call.
    """
    names: Set[str] = set()
    for arg in list(call.args) + [kw.value for kw in call.keywords]:
        if isinstance(arg, ast.Name) and isinstance(arg.ctx, ast.Load):
            names.add(arg.id)
        elif isinstance(arg, ast.Attribute):
            base: ast.AST = arg
            while isinstance(base, ast.Attribute):
                base = base.value
            if isinstance(base, ast.Name) and isinstance(base.ctx, ast.Load):
                names.add(base.id)
    return frozenset(names)


def _assign_target_names(target: ast.AST) -> FrozenSet[str]:
    """Collect ``Store``-context bare names from one assignment target.

    Handles ``Name``, ``Tuple``, ``List``. ``Subscript`` and
    ``Attribute`` targets mutate a base name without rebinding it;
    their base name is recorded as a def via :func:`_walk_symbols`
    (the LHS subtree is walked there too) rather than here, because
    here we are computing "names the call's return flows to" — a
    subscript or attribute target doesn't capture the return as a
    fresh name.
    """
    names: Set[str] = set()
    for child in ast.walk(target):
        if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store):
            names.add(child.id)
    return frozenset(names)


def _statement_assigned_map(stmt: ast.stmt) -> Dict[int, FrozenSet[str]]:
    """Map ``id(call_node) → assigned LHS names`` for calls whose
    return value is captured into a fresh LHS name at this stmt.

    Covers ``Assign`` (any LHS shape), ``AugAssign`` (target is
    always a ``Name`` / ``Subscript`` / ``Attribute``; only ``Name``
    rebinds), ``AnnAssign`` with a value. ``y, z = f(), g()`` pairs
    each Tuple LHS element with the same-position Tuple RHS Call.
    Nested calls and non-call RHS expressions get no entry.
    """
    result: Dict[int, FrozenSet[str]] = {}
    if isinstance(stmt, ast.Assign):
        lhs_names: Set[str] = set()
        for target in stmt.targets:
            lhs_names |= _assign_target_names(target)
        all_lhs = frozenset(lhs_names)
        if isinstance(stmt.value, ast.Call):
            result[id(stmt.value)] = all_lhs
        elif isinstance(stmt.value, ast.Tuple):
            # Best-effort position-matched attribution for paired
            # Tuple LHS / Tuple RHS. Mixed shapes fall back to "all
            # LHS names" for each Call element.
            tuple_targets = [
                t for t in stmt.targets if isinstance(t, ast.Tuple)
            ]
            if tuple_targets and len(tuple_targets[0].elts) == len(stmt.value.elts):
                for lhs_elt, rhs_elt in zip(
                    tuple_targets[0].elts, stmt.value.elts,
                ):
                    if isinstance(rhs_elt, ast.Call):
                        result[id(rhs_elt)] = _assign_target_names(lhs_elt)
            else:
                for rhs_elt in stmt.value.elts:
                    if isinstance(rhs_elt, ast.Call):
                        result[id(rhs_elt)] = all_lhs
    elif isinstance(stmt, ast.AugAssign):
        if isinstance(stmt.target, ast.Name) and isinstance(
            stmt.value, ast.Call,
        ):
            result[id(stmt.value)] = frozenset({stmt.target.id})
    elif isinstance(stmt, ast.AnnAssign):
        if (
            isinstance(stmt.target, ast.Name)
            and stmt.value is not None
            and isinstance(stmt.value, ast.Call)
        ):
            result[id(stmt.value)] = frozenset({stmt.target.id})
    return result


def _walk_symbols(
    root: ast.AST,
) -> Tuple[FrozenSet[str], FrozenSet[str]]:
    """Walk one statement-level expression subtree, returning
    ``(defs, uses)``.

    Comprehension scopes are handled correctly: a comp's generator
    targets are comp-local and do NOT leak into the enclosing
    function's def set. Names referenced inside the comp that match
    a comp-local target are likewise excluded from uses. The first
    generator's ``iter`` is evaluated in the enclosing scope (the
    standard Python semantic), so its loads count for the
    enclosing function.
    """
    defs: Set[str] = set()
    uses: Set[str] = set()

    def _walk(node: ast.AST, comp_local: FrozenSet[str]) -> None:
        if isinstance(node, _COMPREHENSION_TYPES):
            new_locals: Set[str] = set(comp_local)
            for gen in node.generators:
                for n in ast.walk(gen.target):
                    if isinstance(n, ast.Name):
                        new_locals.add(n.id)
            local_scope = frozenset(new_locals)
            first = True
            for gen in node.generators:
                if first:
                    _walk(gen.iter, comp_local)
                    first = False
                else:
                    _walk(gen.iter, local_scope)
                for if_ in gen.ifs:
                    _walk(if_, local_scope)
            if isinstance(node, ast.DictComp):
                _walk(node.key, local_scope)
                _walk(node.value, local_scope)
            else:
                _walk(node.elt, local_scope)
            return
        if isinstance(node, ast.Lambda):
            # Lambda params are lambda-local; the body's free names
            # are loads in the enclosing scope. Add params to
            # comp_local for the body walk.
            lambda_locals = set(comp_local)
            for arg in node.args.args:
                lambda_locals.add(arg.arg)
            for arg in node.args.posonlyargs:
                lambda_locals.add(arg.arg)
            for arg in node.args.kwonlyargs:
                lambda_locals.add(arg.arg)
            if node.args.vararg is not None:
                lambda_locals.add(node.args.vararg.arg)
            if node.args.kwarg is not None:
                lambda_locals.add(node.args.kwarg.arg)
            _walk(node.body, frozenset(lambda_locals))
            return
        if isinstance(node, ast.Name):
            if node.id in comp_local:
                return
            if isinstance(node.ctx, (ast.Store, ast.Del)):
                defs.add(node.id)
            elif isinstance(node.ctx, ast.Load):
                uses.add(node.id)
            return
        if isinstance(node, ast.NamedExpr):
            # Walrus ``(y := expr)``: target is a def, expr is a use.
            if isinstance(node.target, ast.Name):
                if node.target.id not in comp_local:
                    defs.add(node.target.id)
            _walk(node.value, comp_local)
            return
        for child in ast.iter_child_nodes(node):
            _walk(child, comp_local)

    _walk(root, frozenset())
    return frozenset(defs), frozenset(uses)


def _extract_statement_payload(
    stmt: ast.stmt,
) -> Tuple[
    FrozenSet[str],          # calls (legacy)
    FrozenSet[str],          # defs
    FrozenSet[str],          # uses
    Tuple[CallSite, ...],    # call_sites
]:
    """Single pass producing every per-node symbol artefact.

    Statement-level expression discipline (compound stmts walk only
    their controlling expressions, not bodies) is shared with
    :func:`_statement_expr_roots`. The legacy ``calls`` frozenset is
    derived from ``call_sites`` so the two views never disagree.
    """
    expr_roots = _statement_expr_roots(stmt)
    assigned_map = _statement_assigned_map(stmt)

    # call_sites in source order
    site_records: List[Tuple[int, int, CallSite]] = []
    for root in expr_roots:
        for child in ast.walk(root):
            if not isinstance(child, ast.Call):
                continue
            name = _resolve_callable_name(child.func)
            if name is None:
                continue
            site = CallSite(
                name=name,
                arg_names=_arg_surface_names(child),
                assigned_names=assigned_map.get(id(child), frozenset()),
                lineno=child.lineno,
                col_offset=getattr(child, "col_offset", 0),
            )
            site_records.append((
                child.lineno, getattr(child, "col_offset", 0), site,
            ))
    site_records.sort(key=lambda t: (t[0], t[1]))
    call_sites = tuple(s for _, _, s in site_records)
    calls = frozenset(s.name for s in call_sites)

    # defs / uses across all expression roots, then add per-stmt
    # special-case defs that aren't captured by Store-ctx Name walk:
    #   For.target — already Store-ctx, picked up by _walk_symbols
    #   With.items[].optional_vars — already Store-ctx
    #   AnnAssign.target without value — Store-ctx
    defs: Set[str] = set()
    uses: Set[str] = set()
    for root in expr_roots:
        d, u = _walk_symbols(root)
        defs |= d
        uses |= u
    # AugAssign target is both def and use even when AST gives it
    # Store ctx (the read of the prior value is implicit).
    if isinstance(stmt, ast.AugAssign) and isinstance(stmt.target, ast.Name):
        uses.add(stmt.target.id)

    return calls, frozenset(defs), frozenset(uses), call_sites


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
        calls, defs, uses, call_sites = _extract_statement_payload(stmt)
        node = PyCFGNode(
            kind=kind, lineno=stmt.lineno,
            label=label or _short_label(stmt),
            calls=calls,
            defs=defs,
            uses=uses,
            call_sites=call_sites,
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
            params=_function_params(func),
        )


def _function_params(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
) -> Tuple[str, ...]:
    """Ordered tuple of bare parameter names declared by ``func``.

    Positional-only, then positional-or-keyword, then ``*vararg``,
    then keyword-only, then ``**kwarg`` — same order Python uses
    when binding. Defaults / annotations are ignored. Used by Phase
    2's reaching-defs to treat the entry as virtually defining each
    parameter so body uses resolve to the entry node.
    """
    args = func.args
    names: List[str] = []
    for arg in args.posonlyargs:
        names.append(arg.arg)
    for arg in args.args:
        names.append(arg.arg)
    if args.vararg is not None:
        names.append(args.vararg.arg)
    for arg in args.kwonlyargs:
        names.append(arg.arg)
    if args.kwarg is not None:
        names.append(args.kwarg.arg)
    return tuple(names)


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
    "CallSite",
    "PyCFGNode",
    "PythonCFG",
    "CallGraphNode",
    "CppCallGraph",
    "ENTRY_LINENO",
    "EXIT_LINENO",
    "build_python_cfg",
    "build_cpp_callgraph",
]
