"""CFG and call-graph builders — Phase 5b of the sanitizer-cut arc.

Two producers, both implementing :class:`core.analysis.dominators.Graph`:

* :func:`build_python_cfg` — intra-procedural control-flow graph for
  one Python function. Statement-level granularity; each node carries
  the called-callable names found in its statement subtree so phase 6
  can match against the sanitizer catalogue without re-parsing the
  AST.
* :func:`build_cpp_callgraph` — inter-procedural call graph for one
  or more C/C++ binaries. Function-level granularity; consumes
  :mod:`core.analysis.binary_oracle_edges` output.

Both producers emit immutable graph objects. The :class:`Graph`
protocol from :mod:`core.analysis.dominators` is satisfied so the
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
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable



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
    arg_names: frozenset[str]
    assigned_names: frozenset[str]
    lineno: int
    col_offset: int = 0
    # Names referenced ANYWHERE inside the argument subtrees —
    # receivers of nested calls (``print(bar.toCharArray())`` →
    # ``{"bar"}``), operands of concatenations (``println("x" + a)``
    # → ``{"a"}``). SINK-ARG RESOLUTION FALLBACK ONLY: this set must
    # never feed gate condition 2 (``input_symbols ∩ tainted``) —
    # arg_names' deliberate undercount is the soundness guard there,
    # and widening it would over-suppress. Producers that don't track
    # deep names leave the default; the sink resolver uses it only
    # when it contains exactly one name.
    arg_deep_names: frozenset[str] = frozenset()


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

    ``may_escape`` is the aliasing-conservatism bit shared with the
    C/C++ and Java node contracts. A Python statement that stores to
    a name the function declared ``global`` or ``nonlocal`` is NOT a
    clean local rebinding: any callee (or, for ``nonlocal``, any
    sibling closure) can rewrite the same binding between this
    statement and a later read, so the value gate must not treat the
    stored value's identity as proven at the sink.
    ``evaluate_finding`` downgrades ``SUPPRESS → CANDIDATE_ONLY``
    when a ``may_escape`` node sits on a source→sink path.
    """
    kind: str          # "entry" | "exit" | "stmt"
    lineno: int
    label: str         # short rendering, e.g. "If (x > 0)"
    calls: frozenset[str] = frozenset()
    defs: frozenset[str] = frozenset()
    uses: frozenset[str] = frozenset()
    call_sites: tuple[CallSite, ...] = ()
    may_escape: bool = False

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
    demangled: str | None = None

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
    _nodes: tuple[PyCFGNode, ...]
    _adjacency: dict[PyCFGNode, tuple[PyCFGNode, ...]]
    params: tuple[str, ...] = ()
    # Names whose WRITTEN identity a consumer must not trust: the
    # function's own bound names (params, assignments, local imports,
    # nested defs, …) plus the module's repo-controlled roots
    # (module-scope defs/assignments/globals and import aliases that
    # bind a different source — ``import fakelib as html``). The
    # sanitizer-cut catalog matcher degrades any binding whose
    # callable root is in this set: the runtime callee is the repo's
    # object, not the catalog identity the spelling suggests. Empty
    # for hand-built CFGs (consumers treat absence as no distrust).
    shadowed_roots: frozenset[str] = frozenset()
    # True when a dynamic route (star-import, exec/eval, sys.modules,
    # escaping globals()/vars()) makes the WHOLE module's name
    # resolution unprovable — the catalog guard refuses every written
    # identity in the function (suppression can only be lost).
    namespace_unprovable: bool = False

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


# ``ast.TryStar`` (``except*``) is 3.11+; same guard shape as the
# smt_barrier dominance walk so the two legs stay coherent — an
# ``except*`` handler group models exactly like ``except`` for
# reachability-under-deletion purposes (re-raising handlers still
# converge on the same merge points).
_TRY_STMTS: tuple[type, ...] = (
    (ast.Try, ast.TryStar) if hasattr(ast, "TryStar") else (ast.Try,)
)


def _statement_expr_roots(stmt: ast.stmt) -> list[ast.AST]:
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
    if isinstance(stmt, (ast.For, ast.AsyncFor)):
        return [stmt.target, stmt.iter]
    if isinstance(stmt, _TRY_STMTS):
        return []  # try has no statement-level expressions
    if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef,
                         ast.ClassDef)):
        # Nested def/class: the BODY is not statement-level code of
        # the enclosing function — flattening it attributed a
        # sanitizer inside a never-called nested def to a node that
        # sits unconditionally on the path, and leaked nested locals
        # / class-body names into defs. Only the parts evaluated AT
        # the definition site in the enclosing scope are roots:
        # decorators, parameter defaults, class bases / keywords.
        roots: list[ast.AST] = list(stmt.decorator_list)
        if isinstance(stmt, ast.ClassDef):
            roots.extend(stmt.bases)
            roots.extend(kw.value for kw in stmt.keywords)
        else:
            roots.extend(stmt.args.defaults)
            roots.extend(
                d for d in stmt.args.kw_defaults if d is not None
            )
        return roots
    if hasattr(ast, "Match") and isinstance(stmt, ast.Match):
        # Only the subject is statement-level; case bodies become
        # their own nodes. Without this the subject node inherits the
        # case bodies' calls — a sanitizer call inside a case would be
        # attributed to the subject, so the vertex cut removes the
        # subject and severs the no-match fall-through with it.
        return [stmt.subject]
    if isinstance(stmt, (ast.With, ast.AsyncWith)):
        roots = []
        for item in stmt.items:
            roots.append(item.context_expr)
            if item.optional_vars is not None:
                roots.append(item.optional_vars)
        return roots
    # Straight-line statement: the whole subtree is statement-level.
    return [stmt]


def _resolve_callable_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _resolve_callable_name(node.value)
        if base is None:
            return node.attr
        return f"{base}.{node.attr}"
    return None


def _arg_surface_names(call: ast.Call) -> frozenset[str]:
    """Conservative bare-name extraction for one call's arguments.

    Only direct ``Name`` args and the base ``Name`` of direct
    ``Attribute`` args are counted. Nested ``Call``, ``Subscript``,
    ``BinOp``, ``Lambda``, ``Constant`` contribute nothing — their
    "value" isn't a bare symbol, so the gate condition
    ``input_symbols ∩ tainted`` would over-suppress if we
    treated their internal names as inputs to the outer call.
    """
    names: set[str] = set()
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


def _assign_target_names(target: ast.AST) -> frozenset[str]:
    """Collect ``Store``-context bare names from one assignment target.

    Handles ``Name``, ``Tuple``, ``List``. ``Subscript`` and
    ``Attribute`` targets mutate a base name without rebinding it;
    their base name is recorded as a def via :func:`_walk_symbols`
    (the LHS subtree is walked there too) rather than here, because
    here we are computing "names the call's return flows to" — a
    subscript or attribute target doesn't capture the return as a
    fresh name.
    """
    names: set[str] = set()
    for child in ast.walk(target):
        if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store):
            names.add(child.id)
    return frozenset(names)


def _statement_assigned_map(stmt: ast.stmt) -> dict[int, frozenset[str]]:
    """Map ``id(call_node) → assigned LHS names`` for calls whose
    return value is captured into a fresh LHS name at this stmt.

    Covers ``Assign`` (any LHS shape), ``AugAssign`` (target is
    always a ``Name`` / ``Subscript`` / ``Attribute``; only ``Name``
    rebinds), ``AnnAssign`` with a value. ``y, z = f(), g()`` pairs
    each Tuple LHS element with the same-position Tuple RHS Call.
    Nested calls and non-call RHS expressions get no entry.
    """
    result: dict[int, frozenset[str]] = {}
    if isinstance(stmt, ast.Assign):
        lhs_names: set[str] = set()
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
                    strict=True,
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
) -> tuple[frozenset[str], frozenset[str]]:
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
    defs: set[str] = set()
    uses: set[str] = set()

    def _walk(node: ast.AST, comp_local: frozenset[str]) -> None:
        if isinstance(node, _COMPREHENSION_TYPES):
            new_locals: set[str] = set(comp_local)
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


def _iter_eager_calls(root: ast.AST):
    """Every ``ast.Call`` in ``root`` whose execution is NOT deferred.

    Lambda bodies and generator-expression payloads run when the
    lambda is CALLED / the generator is CONSUMED — not at this
    statement. Attributing their calls to the statement node puts a
    possibly-never-executed sanitizer unconditionally on the path
    (the same false-suppression hazard as flattening nested ``def``
    bodies, which :func:`_statement_expr_roots` already excludes).
    Only the parts evaluated eagerly at the statement descend: a
    lambda's parameter defaults, and a genexp's FIRST iterable (the
    standard Python semantic). List/set/dict comprehensions evaluate
    eagerly and descend in full.
    """
    stack: list[ast.AST] = [root]
    while stack:
        node = stack.pop()
        if isinstance(node, ast.Lambda):
            stack.extend(node.args.defaults)
            stack.extend(
                d for d in node.args.kw_defaults if d is not None
            )
            continue
        if isinstance(node, ast.GeneratorExp):
            if node.generators:
                stack.append(node.generators[0].iter)
            continue
        if isinstance(node, ast.Call):
            yield node
        stack.extend(ast.iter_child_nodes(node))


def _extract_statement_payload(
    stmt: ast.stmt,
) -> tuple[
    frozenset[str],          # calls (legacy)
    frozenset[str],          # defs
    frozenset[str],          # uses
    tuple[CallSite, ...],    # call_sites
]:
    """Single pass producing every per-node symbol artefact.

    Statement-level expression discipline (compound stmts walk only
    their controlling expressions, not bodies) is shared with
    :func:`_statement_expr_roots`; deferred-execution bodies (lambda,
    genexp) are excluded from call extraction by
    :func:`_iter_eager_calls`. The legacy ``calls`` frozenset is
    derived from ``call_sites`` so the two views never disagree.
    """
    expr_roots = _statement_expr_roots(stmt)
    assigned_map = _statement_assigned_map(stmt)

    # call_sites in source order
    site_records: list[tuple[int, int, CallSite]] = []
    for root in expr_roots:
        for child in _iter_eager_calls(root):
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
    defs: set[str] = set()
    uses: set[str] = set()
    for root in expr_roots:
        d, u = _walk_symbols(root)
        defs |= d
        uses |= u
    # AugAssign target is both def and use even when AST gives it
    # Store ctx (the read of the prior value is implicit).
    if isinstance(stmt, ast.AugAssign) and isinstance(stmt.target, ast.Name):
        uses.add(stmt.target.id)

    return calls, frozenset(defs), frozenset(uses), call_sites


# Label paren-content length cap: long conditions truncate rather than
# bloat every node repr; downstream reference extraction only loses
# names past the cut (a condition-text consumer degrades to fewer
# matched guards — the not-covered direction).
_LABEL_EXPR_MAX = 120


def _expr_text(expr: ast.AST) -> str | None:
    """Unparsed source of ``expr``, truncated; None when unparsing
    fails (synthetic/malformed nodes)."""
    try:
        text = ast.unparse(expr)
    except Exception:  # noqa: BLE001 — label rendering must never abort a build
        return None
    text = " ".join(text.split())
    return text[:_LABEL_EXPR_MAX]


def _short_label(stmt: ast.stmt) -> str:
    """Brief human-facing rendering of a statement for diagnostics.

    Conditional headers embed their CONDITION text — ``If (x > 0)`` —
    not just the line number: cfg_conditions/lifecycle_collector parse
    the paren content of ``If``/``While``/``For`` labels as the guard
    expression (same contract as the C/C++ and Java builders), and
    :class:`PyCFGNode` documents that shape. A positional-only label
    would hand those consumers ``line N`` as the guard text.
    """
    kind = type(stmt).__name__
    if isinstance(stmt, (ast.If, ast.While)):
        cond = _expr_text(stmt.test)
        if cond is not None:
            return f"{kind} ({cond})"
        return f"{kind} (line {stmt.lineno})"
    if isinstance(stmt, ast.For):
        target = _expr_text(stmt.target)
        it = _expr_text(stmt.iter)
        if target is not None and it is not None:
            return f"For ({target} in {it})"
        return f"For (line {stmt.lineno})"
    if isinstance(stmt, ast.Try):
        return f"Try (line {stmt.lineno})"
    return f"{kind} (line {stmt.lineno})"


def _pattern_irrefutable(pattern: ast.pattern) -> bool:
    """True when ``pattern`` matches ANY subject value.

    ``case _:`` and bare captures (``case x:``) are ``MatchAs`` with
    ``pattern=None``; ``case <p> as x`` is irrefutable iff ``<p>`` is;
    a ``MatchOr`` is irrefutable when any alternative is. Everything
    else (literals, classes, sequences, mappings) can fail to match.
    """
    if isinstance(pattern, ast.MatchAs):
        return pattern.pattern is None or _pattern_irrefutable(pattern.pattern)
    if isinstance(pattern, ast.MatchOr):
        return any(_pattern_irrefutable(p) for p in pattern.patterns)
    return False


def _pattern_capture_names(pattern: ast.AST) -> frozenset[str]:
    """Names a match-case pattern BINDS on success.

    Capture names are identifier STRINGS (``MatchAs.name`` /
    ``MatchStar.name`` / ``MatchMapping.rest``), not Store-ctx
    ``ast.Name`` nodes, so no ``_walk_symbols`` layer can ever see
    them. Leaving them out of ``defs`` makes a capture rebind of a
    sanitized name (``case [*y]:``) invisible to reaching-defs — the
    value-bound gate's condition-3 exclusivity then holds falsely and
    a runtime-tainted sink suppresses.
    """
    out: set[str] = set()
    for node in ast.walk(pattern):
        if isinstance(node, (ast.MatchAs, ast.MatchStar)):
            if node.name is not None:
                out.add(node.name)
        elif isinstance(node, ast.MatchMapping):
            if node.rest is not None:
                out.add(node.rest)
    return frozenset(out)


def _match_has_irrefutable_case(stmt: ast.Match) -> bool:
    """True when some case of ``stmt`` is guaranteed to execute — an
    irrefutable pattern with no ``if`` guard. Only then does the match
    have no fall-through path."""
    return any(
        case.guard is None and _pattern_irrefutable(case.pattern)
        for case in stmt.cases
    )


class _PythonCFGBuilder:
    """Stateful AST walker that produces a control-flow graph.

    Maintains ``_adjacency`` (edges) and a stack of loop contexts so
    ``break`` / ``continue`` resolve to the right targets. Each
    ``_build_*`` method takes a list of "incoming" predecessor nodes
    and returns the list of "outgoing" successors — the standard
    structured-block CFG idiom.
    """

    def __init__(self, function_name: str, file_path: str,
                 escape_names: frozenset[str] = frozenset()) -> None:
        self.function_name = function_name
        self.file_path = file_path
        # Names this function declared ``global`` / ``nonlocal``.
        # Stores to them are not clean local rebindings — see
        # :meth:`_apply_scope_escape`.
        self._escape_names = escape_names
        self.entry = PyCFGNode(
            kind="entry", lineno=ENTRY_LINENO,
            label=f"ENTRY:{function_name}",
        )
        self.exit = PyCFGNode(
            kind="exit", lineno=EXIT_LINENO,
            label=f"EXIT:{function_name}",
        )
        self._adjacency: dict[PyCFGNode, list[PyCFGNode]] = {}
        self._all_nodes: list[PyCFGNode] = [self.entry, self.exit]
        # Loop context stack: each entry is (break_target, continue_target).
        # break_target is the node a ``break`` jumps to (the loop's
        # successor); continue_target is the loop header (re-enter the
        # condition). Both are pre-allocated as the loop is set up so
        # any inner ``break`` / ``continue`` has somewhere to attach.
        self._loop_stack: list[tuple[PyCFGNode, PyCFGNode]] = []

    # ----- edge plumbing -----

    def _link(self, src: PyCFGNode, dst: PyCFGNode) -> None:
        self._adjacency.setdefault(src, []).append(dst)

    def _link_many(self, srcs: Iterable[PyCFGNode], dst: PyCFGNode) -> None:
        for s in srcs:
            self._link(s, dst)

    def _apply_scope_escape(
        self, defs: frozenset[str], call_sites: tuple[CallSite, ...],
    ) -> tuple[bool, tuple[CallSite, ...]]:
        """Demote stores to ``global`` / ``nonlocal`` names.

        A bare-name store to such a name binds OUTSIDE the local
        frame: a callee (or sibling closure) can rewrite it between
        this statement and a later read, so granting it the clean
        local-rebinding semantics (``assigned_names`` — sanitizer-
        output identity) would let the value gate prove exclusivity
        over a binding it does not own. The def itself stays — an
        extra definer can only break an exclusivity proof, never
        grant identity (refusal direction) — but the node is stamped
        ``may_escape`` and its call sites lose the escaping names
        from ``assigned_names``.
        """
        if not (defs & self._escape_names):
            return False, call_sites
        call_sites = tuple(
            replace(cs, assigned_names=cs.assigned_names - self._escape_names)
            if cs.assigned_names & self._escape_names else cs
            for cs in call_sites
        )
        return True, call_sites

    def _new_node(self, kind: str, stmt: ast.stmt,
                  *, label: str | None = None) -> PyCFGNode:
        calls, defs, uses, call_sites = _extract_statement_payload(stmt)
        escapes, call_sites = self._apply_scope_escape(defs, call_sites)
        node = PyCFGNode(
            kind=kind, lineno=stmt.lineno,
            label=label or _short_label(stmt),
            calls=calls,
            defs=defs,
            uses=uses,
            call_sites=call_sites,
            may_escape=escapes,
        )
        self._all_nodes.append(node)
        return node

    def _join_node(self, stmt: ast.stmt, label: str) -> PyCFGNode:
        """Payload-free join sentinel for a loop's exit edge.

        Re-running the header's payload extraction here duplicated
        the header's calls/defs/uses on a SECOND node at the same
        line: a walrus in the condition (``while (y := f(x)):``)
        yielded a duplicate definer of ``y`` on the join, and a
        sanitizer call in the condition appeared on two nodes. The
        duplicate definer carries empty ``assigned_names`` so it can
        only break exclusivity (over-refusal, never suppression),
        but it pollutes reaching-defs and per-line call-site queries
        — the sentinel carries no payload at all.
        """
        node = PyCFGNode(kind="join", lineno=stmt.lineno, label=label)
        self._all_nodes.append(node)
        return node

    # ----- statement dispatchers -----

    def _build_stmts(
        self, stmts: list[ast.stmt], incoming: list[PyCFGNode],
    ) -> list[PyCFGNode]:
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
        self, stmt: ast.stmt, incoming: list[PyCFGNode],
    ) -> list[PyCFGNode]:
        if isinstance(stmt, ast.If):
            return self._build_if(stmt, incoming)
        if isinstance(stmt, ast.While):
            return self._build_while(stmt, incoming)
        if isinstance(stmt, (ast.For, ast.AsyncFor)):
            # AsyncFor shares For's field shape (target/iter/body/
            # orelse) and its zero-iteration semantics — collapsing
            # it to one straight-line node put a sanitizer inside the
            # body unconditionally on the path.
            return self._build_for(stmt, incoming)
        if isinstance(stmt, _TRY_STMTS):
            # ``except*`` groups converge like ``except`` for
            # reachability-under-deletion (see _TRY_STMTS).
            return self._build_try(stmt, incoming)
        if isinstance(stmt, (ast.With, ast.AsyncWith)):
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
        if hasattr(ast, "Match") and isinstance(stmt, ast.Match):
            return self._build_match(stmt, incoming)
        # Straight-line stmt: assignments, expr stmts, defs, etc.
        node = self._new_node("stmt", stmt)
        self._link_many(incoming, node)
        return [node]

    # ----- compound constructs -----

    def _build_if(
        self, stmt: ast.If, incoming: list[PyCFGNode],
    ) -> list[PyCFGNode]:
        cond = self._new_node("stmt", stmt)
        self._link_many(incoming, cond)
        then_out = self._build_stmts(stmt.body, [cond])
        else_out = (
            self._build_stmts(stmt.orelse, [cond])
            if stmt.orelse else [cond]
        )
        return then_out + else_out

    def _build_while(
        self, stmt: ast.While, incoming: list[PyCFGNode],
    ) -> list[PyCFGNode]:
        header = self._new_node("stmt", stmt)
        self._link_many(incoming, header)
        exit_node = self._join_node(stmt, f"while-exit (line {stmt.lineno})")
        self._loop_stack.append((exit_node, header))
        body_out = self._build_stmts(stmt.body, [header])
        for tail in body_out:
            self._link(tail, header)
        self._loop_stack.pop()
        if stmt.orelse:
            orelse_out = self._build_stmts(stmt.orelse, [header])
            for tail in orelse_out:
                self._link(tail, exit_node)
        else:
            self._link(header, exit_node)
        return [exit_node]

    def _build_for(
        self, stmt: ast.For | ast.AsyncFor, incoming: list[PyCFGNode],
    ) -> list[PyCFGNode]:
        header = self._new_node("stmt", stmt)
        self._link_many(incoming, header)
        exit_node = self._join_node(stmt, f"for-exit (line {stmt.lineno})")
        self._loop_stack.append((exit_node, header))
        body_out = self._build_stmts(stmt.body, [header])
        for tail in body_out:
            self._link(tail, header)
        self._loop_stack.pop()
        if stmt.orelse:
            orelse_out = self._build_stmts(stmt.orelse, [header])
            for tail in orelse_out:
                self._link(tail, exit_node)
        else:
            self._link(header, exit_node)
        return [exit_node]

    def _build_match(
        self, stmt: ast.Match, incoming: list[PyCFGNode],
    ) -> list[PyCFGNode]:
        subject = self._new_node("stmt", stmt, label=f"match (line {stmt.lineno})")
        self._link_many(incoming, subject)
        exits: list[PyCFGNode] = []
        for case in stmt.cases:
            # Per-case binding node between subject and body: carries
            # the pattern's capture names as defs (see
            # _pattern_capture_names — invisible to any Name walk) and
            # the guard's reads/calls. Without it a capture rebind of
            # a sanitized name never reaches reaching-defs — the
            # false-suppression direction for the value-bound gate.
            case_node = self._match_case_node(case)
            self._link(subject, case_node)
            case_out = self._build_stmts(case.body, [case_node])
            exits.extend(case_out)
        # When no case is irrefutable, execution can match NOTHING and
        # fall straight through to the post-match code — the subject
        # itself is an exit, mirroring _build_if's no-else handling.
        # Omitting this edge makes a sanitizer inside a case body look
        # like it lies on every path to a post-match sink, which is
        # the false-suppression direction for the vertex-cut consumer.
        if not _match_has_irrefutable_case(stmt):
            exits.append(subject)
        return exits

    def _match_case_node(self, case: ast.match_case) -> PyCFGNode:
        """Synthetic node for one match case: pattern capture names as
        ``defs``; pattern value reads plus the guard's reads as
        ``uses``; the guard's calls as ``calls``/``call_sites``.
        Guard call sites carry empty ``assigned_names`` — a guard
        expression binds nothing the gate may treat as a sanitizer
        output (refusal direction)."""
        defs = set(_pattern_capture_names(case.pattern))
        uses: set[str] = set()
        for sub in ast.walk(case.pattern):
            if isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Load):
                uses.add(sub.id)
        site_records: list[CallSite] = []
        if case.guard is not None:
            guard_defs, guard_uses = _walk_symbols(case.guard)
            defs |= guard_defs  # a walrus in a guard binds too
            uses |= guard_uses
            for child in _iter_eager_calls(case.guard):
                name = _resolve_callable_name(child.func)
                if name is None:
                    continue
                site_records.append(CallSite(
                    name=name,
                    arg_names=_arg_surface_names(child),
                    assigned_names=frozenset(),
                    lineno=child.lineno,
                    col_offset=getattr(child, "col_offset", 0),
                ))
        frozen_defs = frozenset(defs)
        escapes, sites = self._apply_scope_escape(
            frozen_defs, tuple(site_records),
        )
        node = PyCFGNode(
            kind="stmt",
            lineno=case.pattern.lineno,
            label=f"case (line {case.pattern.lineno})",
            calls=frozenset(cs.name for cs in sites),
            defs=frozen_defs,
            uses=frozenset(uses),
            call_sites=sites,
            may_escape=escapes,
        )
        self._all_nodes.append(node)
        return node

    def _build_try(
        self, stmt: ast.Try | ast.TryStar, incoming: list[PyCFGNode],
    ) -> list[PyCFGNode]:
        # try-block: incoming flows into body. Any node in body may
        # raise and route to ANY of the except handlers, so the
        # conservative model is to fan every body node out to each
        # except's first node. (Phase 6 / 7 only need reachability
        # under deletion, not precise exception semantics — soundness
        # is preserved by being more permissive about reachability.)
        # finally always runs; the model is that body_out, handler_out,
        # and the exceptional paths all converge at finally's entry.
        body_out = self._build_stmts(stmt.body, incoming)
        handler_outs: list[PyCFGNode] = []
        for handler in stmt.handlers:
            # Handler ENTRY node: carries the ``except E as name``
            # binding as a def. ``ExceptHandler.name`` is an
            # identifier STRING (no Store-ctx Name node), so no
            # ``_walk_symbols`` walk can ever see it — leaving it out
            # of ``defs`` makes a handler rebind of a sanitized name
            # invisible to reaching-defs, the same hole the match-case
            # capture nodes and the Java leg's catch entry close.
            # Def-only (never ``assigned_names``): refusal direction.
            handler_defs = (
                frozenset({handler.name}) if handler.name else frozenset()
            )
            entry_node = PyCFGNode(
                kind="stmt",
                lineno=handler.lineno,
                label=f"except (line {handler.lineno})",
                defs=handler_defs,
                may_escape=bool(handler_defs & self._escape_names),
            )
            self._all_nodes.append(entry_node)
            # Each handler's entry is reachable from every statement
            # of body (any of them could raise).
            self._link_many(
                list(self._adjacency.keys() - {self.exit}), entry_node,
            )
            handler_node_start = self._build_stmts(
                handler.body, [entry_node],
            )
            # Simplification: the conservative attachment above adds
            # spurious predecessors. The right thing for the
            # downstream vertex-cut suppressor is for handlers to be
            # reachable from try-body — so connect any body statement
            # to the handler entry. We approximate by linking each
            # straight-line predecessor of body_out.
            handler_outs.extend(handler_node_start)
        # ``orelse`` (try/else clause): runs when no exception raised
        else_out: list[PyCFGNode] = body_out
        if stmt.orelse:
            else_out = self._build_stmts(stmt.orelse, body_out)
        # ``finalbody``: every other path merges here
        merge_in = else_out + handler_outs
        if stmt.finalbody:
            return self._build_stmts(stmt.finalbody, merge_in)
        return merge_in

    def _build_with(
        self, stmt: ast.With | ast.AsyncWith, incoming: list[PyCFGNode],
    ) -> list[PyCFGNode]:
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
        adjacency: dict[PyCFGNode, tuple[PyCFGNode, ...]] = {
            k: tuple(v) for k, v in self._adjacency.items()
        }
        # Deduplicate node list while preserving first-seen order
        seen: set = set()
        ordered_nodes: list[PyCFGNode] = []
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
) -> tuple[str, ...]:
    """Ordered tuple of bare parameter names declared by ``func``.

    Positional-only, then positional-or-keyword, then ``*vararg``,
    then keyword-only, then ``**kwarg`` — same order Python uses
    when binding. Defaults / annotations are ignored. Used by Phase
    2's reaching-defs to treat the entry as virtually defining each
    parameter so body uses resolve to the entry node.
    """
    args = func.args
    names: list[str] = [arg.arg for arg in args.posonlyargs]
    names.extend(arg.arg for arg in args.args)
    if args.vararg is not None:
        names.append(args.vararg.arg)
    names.extend(arg.arg for arg in args.kwonlyargs)
    if args.kwarg is not None:
        names.append(args.kwarg.arg)
    return tuple(names)


def _scope_escape_names(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
) -> frozenset[str]:
    """Names whose local bindings in ``func`` are rewritable from
    outside straight-line reaching-defs.

    Two channels:

    * ``func``'s own ``global`` / ``nonlocal`` declarations —
      compile-time properties of the WHOLE scope (a ``global x``
      inside an ``if`` branch still binds every ``x`` store in the
      function). The walk covers the body but stops at nested scopes
      for THIS channel: a nested def's ``global`` binds the module
      frame, not this one.
    * ``nonlocal`` declarations in defs NESTED under ``func`` (any
      depth): ``nonlocal t`` targets an ENCLOSING function frame, so
      calling the closure rewrites ``func``'s ``t`` behind
      reaching-defs' back — ``t = escape(x); def f(): nonlocal t;
      t = x; f(); sink(t)`` kills the sanitized def invisibly.
      Over-approximate (the nonlocal may target an intermediate
      nested frame): an extra escape name only ever breaks an
      exclusivity proof, never grants one.

    Lambdas and comprehensions cannot contain statements.
    """
    out: set[str] = set()
    stack: list[ast.AST] = list(func.body)
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.ClassDef)):
            continue
        if isinstance(node, (ast.Global, ast.Nonlocal)):
            out.update(node.names)
            continue
        stack.extend(ast.iter_child_nodes(node))
    # Nested-scope channel: every Nonlocal anywhere under func (the
    # boundary walk above already covered func's own statements; this
    # full walk adds the nested defs').
    for node in ast.walk(func):
        if isinstance(node, ast.Nonlocal):
            out.update(node.names)
    return frozenset(out)


def build_python_cfg(
    source: str | Path, function_name: str,
) -> PythonCFG | None:
    """Build the CFG for one named function in a Python source file or
    in-memory source string.

    ``source`` can be a :class:`Path` (read from disk) or a ``str``
    containing source code (parsed directly — useful for tests).
    Returns ``None`` if the named function isn't found.
    """
    if isinstance(source, Path):
        file_path = str(source)
        try:
            source_text = source.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            # Hostile / binary bytes on the direct-Path API: refuse
            # (None) like the not-found path — decoding with
            # replacement could mangle literals downstream consumers
            # read as values.
            return None
    else:
        file_path = "<string>"
        source_text = source
    tree = ast.parse(source_text)
    func: ast.AST | None = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                and node.name == function_name:
            func = node
            break
    if func is None:
        return None
    builder = _PythonCFGBuilder(
        function_name, file_path,
        escape_names=_scope_escape_names(func),  # type: ignore[arg-type]
    )
    cfg = builder.build(func)  # type: ignore[arg-type]
    if cfg is None:
        return None
    # Stamp the untrusted-identity roots (see PythonCFG.shadowed_roots)
    # — computed here because only this entry point sees the whole
    # module tree. Local import so the callgraph substrate module
    # never becomes an import-time dependency of CFG construction for
    # non-Python callers.
    from core.analysis.python_module_callgraph import (
        local_binding_names,
        module_dynamic_namespace,
        module_shadowed_identity_roots,
    )
    dyn_whole, dyn_names = module_dynamic_namespace(tree)
    return replace(
        cfg,
        shadowed_roots=(
            local_binding_names(func)
            | module_shadowed_identity_roots(tree)
            | dyn_names
        ),
        namespace_unprovable=dyn_whole,
    )


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
    _nodes: tuple[CallGraphNode, ...]
    _adjacency: dict[CallGraphNode, tuple[CallGraphNode, ...]]

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
    :func:`core.analysis.binary_oracle_edges.extract_direct_call_edges`.
    Edges from every binary are unioned — useful for hybrid targets
    where the source under analysis links into multiple shipped
    artifacts (a library + a demo / test executable that exercises
    it). Duplicate edges are deduplicated.

    The returned graph contains every function name reachable as a
    caller or callee across the union; nodes unreachable from
    ``entry`` are kept in the node set but produce no outgoing
    edges (and will be pruned during dominator construction).
    """
    from core.analysis.binary_oracle_edges import extract_direct_call_edges

    adjacency_raw: dict[str, set] = {}
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
    node_for: dict[str, CallGraphNode] = {
        name: CallGraphNode(name=name) for name in seen_functions
    }
    adjacency: dict[CallGraphNode, tuple[CallGraphNode, ...]] = {
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
    "ENTRY_LINENO",
    "EXIT_LINENO",
    "CallGraphNode",
    "CallSite",
    "CppCallGraph",
    "PyCFGNode",
    "PythonCFG",
    "build_cpp_callgraph",
    "build_python_cfg",
]
