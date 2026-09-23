"""C / C++ intra-procedural CFG builder — Phase 9 of the sanitizer-cut arc.

Sub-arc B's substrate. Mirrors :mod:`core.analysis.cfg_builder`'s
public shape so :func:`core.dataflow.sanitizer_catalog.match_sanitizers_in_cfg`,
:func:`core.analysis.dataflow.reaching_defs`, and (eventually, in
Phase 11) :func:`core.analysis.sanitizer_cut.evaluate_finding` can
consume the C/C++ CFG with the same interface as the Python one.

Substrate: tree-sitter (`tree-sitter-c`, `tree-sitter-cpp`).

Scope — control-flow constructs handled:

* straight-line statements (``expression_statement``, ``declaration``)
* ``if`` / ``else`` (``if_statement``)
* ``while`` (``while_statement``), ``for`` (``for_statement``),
  ``do ... while`` (``do_statement``) — with ``break`` / ``continue``
* ``switch`` (``switch_statement``) — each ``case_statement`` /
  ``default`` is a branch target; fallthrough is modelled by linking
  consecutive cases when no ``break`` separates them
* ``goto`` + ``labeled_statement`` — conservative: a ``goto LBL;``
  links to every ``labeled_statement`` named ``LBL`` reachable in
  the function (which, syntactically, is at most one — but the
  walker keeps the same defensive structure regardless)
* ``return`` (``return_statement``)
* ternary ``?:`` and short-circuit ``&&`` / ``||`` — emitted as one
  node per enclosing statement; their operand expressions
  contribute to the statement's ``defs`` / ``uses`` / ``call_sites``
  but do not get their own CFG nodes in Phase 9. Splitting each
  operand into its own node (so a sanitizer in the RHS of
  ``a && escape(x)`` is independently attributable) is documented
  as a Phase 10/11 refinement and deferred — none of the canonical
  fixtures need it. CAUTION on the collapse's direction: attributing
  a possibly-skipped operand's sanitizer to a node that sits
  unconditionally on the path is the FALSE-SUPPRESSION direction for
  a suppression gate, not a safe over-approximation. What keeps it
  sound today is the assigned_names discipline — collapsed call
  sites carry empty ``assigned_names``, so the value-bound gate's
  condition 3 never binds them and the verdict degrades to
  candidate_only instead of suppress.

What this module deliberately does NOT do:

* Macro expansion (we walk pre-preprocessor source — by design)
* Pointer / alias tracking — Phase 10's ``may_escape`` policy
* Inter-procedural call resolution — Phase 14's sub-arc C analog
* C++ template instantiation — out of scope; templates parse fine
  but only the syntactic form is recorded

Public surface:

* :class:`CPPCFGNode` — analog of :class:`core.analysis.cfg_builder.PyCFGNode`
* :class:`CPPCFG` — analog of :class:`core.analysis.cfg_builder.PythonCFG`,
  implements :class:`core.analysis.dominators.Graph`
* :func:`build_cpp_intraproc_cfg` — entry point
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import (
    Any,
)
from collections.abc import Iterable

from core.analysis.cfg_node_tables import CPP_TABLES as _NODE_TABLES
from core.analysis.cfg_builder import (
    ENTRY_LINENO,
    EXIT_LINENO,
    CallSite,
)
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tree_sitter import Node


# ---------------------------------------------------------------------------
# Node types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CPPCFGNode:
    """One node of a C / C++ control-flow graph.

    Shape mirrors :class:`core.analysis.cfg_builder.PyCFGNode` so the
    same downstream consumers (reaching-defs, sanitizer-catalog,
    evaluate_finding) can read it with no language-specific branches.

    ``defs`` covers names this node assigns: the declarator name on
    ``declaration`` and ``init_declarator``, the LHS of
    ``assignment_expression`` (including compound forms ``+=``,
    ``-=``, etc.), and the induction variable of a C-style ``for``'s
    initialiser. Compound-statement targets (struct field writes,
    array element writes) yield the BASE name only — Phase 10's
    ``may_escape`` flag below covers the indirection case.

    ``uses`` covers identifiers read in ``Load`` position. Compound
    field-access reads (``obj.attr``, ``obj->attr``) contribute the
    base name only, same as ``_arg_surface_names`` in the Python
    builder.

    ``call_sites`` is the per-statement record of every nested
    ``call_expression`` in source order. The walker produces
    :class:`CallSite` instances reusing the same dataclass from
    :mod:`core.analysis.cfg_builder` so cross-language consumers
    don't need a discriminator.

    ``calls`` is the dotted-callable-name set kept for back-compat
    with the legacy chokepoint paths (matches the structure of
    ``PyCFGNode.calls``). ``{cs.name for cs in call_sites}`` agrees
    with it.

    ``may_escape`` is Phase 10's conservative-aliasing bit. True iff
    the statement involves any syntactic indirection — pointer
    dereference (``*p``), address-of (``&x``), subscript (``a[i]``),
    arrow field access (``obj->field``), or a call to a bulk-copy
    function in :data:`_BULK_COPY_FUNCS` (``memcpy``, ``strcpy``,
    etc. — they write through a destination pointer the gate can't
    track), or a bare-name store to a symbol that is NOT a declared
    local/parameter of the function (a file-scope global / static /
    class member assigned by unqualified name — any callee can
    rewrite it between this statement and a later read, so the
    stored value's identity at the sink is unprovable).
    evaluate_finding downgrades ``SUPPRESS → CANDIDATE_ONLY`` when
    any node on a source→sink path is ``may_escape``. PyCFGNode
    carries the same flag for ``global`` / ``nonlocal`` stores.
    """
    kind: str          # "entry" | "exit" | "stmt"
    lineno: int
    label: str
    calls: frozenset[str] = frozenset()
    defs: frozenset[str] = frozenset()
    uses: frozenset[str] = frozenset()
    call_sites: tuple[CallSite, ...] = ()
    may_escape: bool = False

    def __repr__(self) -> str:                              # pragma: no cover
        return (
            f"CPPCFGNode({self.kind}, L{self.lineno}, "
            f"{self.label!r}, calls={set(self.calls)!r}, "
            f"defs={set(self.defs)!r}, uses={set(self.uses)!r})"
        )


@dataclass(frozen=True)
class CPPCFG:
    """Concrete :class:`core.analysis.dominators.Graph` for a C / C++
    function.

    Construct via :func:`build_cpp_intraproc_cfg`. ``params`` is the
    ordered tuple of parameter names declared by the function
    signature (positional only — C/C++ has no keyword args). Phase 2's
    reaching-defs reads this to treat the entry as virtually defining
    each parameter so a body use of a parameter resolves to the
    entry as its reaching definer.

    ``language`` is ``"c"`` or ``"cpp"`` — recorded so downstream
    consumers (Phase 11's evaluate_finding) can pick language-specific
    sanitizer catalogs without re-detecting.
    """
    function_name: str
    file_path: str
    language: str
    entry_node: CPPCFGNode
    exit_node: CPPCFGNode
    _nodes: tuple[CPPCFGNode, ...]
    _adjacency: dict[CPPCFGNode, tuple[CPPCFGNode, ...]]
    params: tuple[str, ...] = ()

    @property
    def entry(self) -> CPPCFGNode:
        return self.entry_node

    def nodes(self) -> Iterable[CPPCFGNode]:
        return self._nodes

    def successors(self, node: CPPCFGNode) -> Iterable[CPPCFGNode]:
        return self._adjacency.get(node, ())


# ---------------------------------------------------------------------------
# Tree-sitter wiring
# ---------------------------------------------------------------------------


def _get_parser(language: str):
    """Lazy-load the tree-sitter parser for ``language``. Returns
    ``None`` if the grammar isn't installed (mirrors
    :func:`core.inventory.call_graph.extract_call_graph_c`'s
    degrade-cleanly contract)."""
    try:
        if language == "c":
            import tree_sitter_c as ts_lang
        elif language == "cpp":
            import tree_sitter_cpp as ts_lang
        else:
            return None
        # Reuse the call_graph parser cache so we don't re-allocate
        # libtree-sitter C state per call across batched runs.
        from core.inventory.call_graph import _get_ts_parser
        return _get_ts_parser(ts_lang.language)
    except ImportError:
        return None


# Phase 10 — bulk-copy / string-build functions whose presence
# stamps may_escape on the enclosing statement. They write through a
# destination pointer the value-bound gate can't follow. Conservative
# inclusion: anything that copies bytes into a caller-supplied buffer
# qualifies. Names are matched against the resolved callable name
# (``_resolve_callable_name`` returns the bare basename for non-dotted
# calls — ``memcpy``, not ``std::memcpy``; ``std::memcpy`` will appear
# as ``std.memcpy`` after the dotted-collapse, which the catalogue
# also includes).
_BULK_COPY_FUNCS = frozenset({
    # memory
    "memcpy", "memmove", "memset", "bzero",
    "std.memcpy", "std.memmove", "std.memset",
    # string copy / cat
    "strcpy", "strncpy", "strlcpy",
    "strcat", "strncat", "strlcat",
    "stpcpy", "stpncpy",
    # formatted writes into a buffer
    "sprintf", "snprintf", "vsprintf", "vsnprintf",
    "wcscpy", "wcsncpy", "wcscat", "wcsncat",
    "swprintf", "vswprintf",
})


# Node-type constants — keep in one place so the dispatcher in
# :class:`_CPPCFGBuilder` doesn't bury magic strings. Tree-sitter-c
# and tree-sitter-cpp agree on these names; C++-only nodes (templates,
# lambdas, namespace) parse but aren't handled specially in Phase 9.

_FN_DEFINITION = "function_definition"
_COMPOUND_STMT = "compound_statement"

_IF = "if_statement"
_WHILE = "while_statement"
_FOR = "for_statement"
_DO = "do_statement"
_SWITCH = "switch_statement"
_CASE = "case_statement"
_BREAK = "break_statement"
_CONTINUE = "continue_statement"
_RETURN = "return_statement"
_GOTO = "goto_statement"
_LABELED = "labeled_statement"

_EXPR_STMT = "expression_statement"
_DECLARATION = "declaration"
_INIT_DECLARATOR = "init_declarator"
_ASSIGNMENT = "assignment_expression"
_CALL_EXPR = "call_expression"
_FIELD_EXPR = "field_expression"
_IDENT = "identifier"
_TYPE_IDENT = "type_identifier"
_FIELD_IDENT = "field_identifier"
_FN_DECLARATOR = "function_declarator"
_POINTER_DECLARATOR = "pointer_declarator"
_PARENTHESIZED_DECLARATOR = "parenthesized_declarator"
_PARAM_LIST = "parameter_list"
_PARAM_DECL = "parameter_declaration"

# Phase 10 — node types whose presence in a statement stamps
# ``may_escape`` on the enclosing CFG node. Each represents a
# syntactic indirection the value-bound gate can't follow:
#
# * ``pointer_expression`` — both ``*p`` (deref) and ``&x``
#   (address-of). The operator child distinguishes them but both
#   qualify: deref reads through an unknown alias, address-of hands
#   the callee a handle to mutate the named symbol.
# * ``subscript_expression`` — ``a[i]`` in load OR store position.
#   The same array element can be read by any other index expression
#   we can't symbolically equate.
# * ``field_expression`` is only flagged when the operator is ``->``
#   (arrow access through a pointer). Plain ``obj.field`` is a value
#   access through the named base; no indirection. The walker reads
#   the operator child to distinguish.
_INDIRECTION_NODE_TYPES = frozenset({
    "pointer_expression",
    "subscript_expression",
})

# C++ lambda (tree-sitter-cpp; the C grammar never produces it). A
# lambda is BOTH deferred execution (its body's calls are excluded
# from the statement payload — see _walk_subtree_for_call_sites) and
# an alias hazard: a by-reference capture lets the body rebind
# enclosing locals whenever the lambda later runs, invisibly to
# reaching-defs. The enclosing statement therefore stamps
# ``may_escape`` — the gate demotes SUPPRESS → CANDIDATE_ONLY.
_LAMBDA_EXPR = "lambda_expression"


# ---------------------------------------------------------------------------
# Statement payload extraction — defs, uses, call_sites per CFG node
# ---------------------------------------------------------------------------


def _node_text(n) -> str:
    return n.text.decode("utf-8", errors="replace") if n is not None else ""


def _innermost_ident(n: Node) -> str | None:
    """Leftmost identifier under ``n`` — pierces pointer declarators,
    parenthesised declarators, field expressions. Returns the bare
    base name only; field selectors aren't recorded."""
    if n is None:
        return None
    if n.type == _IDENT:
        return _node_text(n)
    if n.type == _FIELD_EXPR:
        # ``a.b.c`` → base ``a``; matches Python builder's behaviour
        arg = n.child_by_field_name("argument")
        if arg is not None:
            return _innermost_ident(arg)
    for child in n.children:
        r = _innermost_ident(child)
        if r is not None:
            return r
    return None


def _resolve_callable_name(callee: Node) -> str | None:
    """Dotted-or-arrow callable name from a ``call_expression``'s
    ``function`` field. ``foo`` → ``"foo"``; ``obj.method`` →
    ``"obj.method"``; ``obj->method`` → ``"obj.method"`` (arrow
    collapsed to dot — same convention as the call-graph extractor
    so the sanitizer catalogue keys match)."""
    if callee is None:
        return None
    if callee.type == _IDENT:
        return _node_text(callee)
    if callee.type == _FIELD_EXPR:
        arg = callee.child_by_field_name("argument")
        field = callee.child_by_field_name("field")
        base = _resolve_callable_name(arg) if arg is not None else None
        fname = _node_text(field) if field is not None else None
        if base is not None and fname is not None:
            return f"{base}.{fname}"
        if fname is not None:
            return fname
    # parenthesized_expression wrapping a callee
    for child in callee.children:
        if child.is_named:
            r = _resolve_callable_name(child)
            if r is not None:
                return r
    return None


def _arg_surface_names(call_node: Node) -> frozenset[str]:
    """Conservative bare-name extraction for one call's arguments.

    Mirrors :func:`core.analysis.cfg_builder._arg_surface_names`:
    only direct identifiers and the base of a field expression
    count. Nested calls, subscripts, casts, binary expressions, and
    literals contribute nothing — same under-count rationale (the
    gate's condition 2 over-suppresses if we over-count).
    """
    args = call_node.child_by_field_name("arguments")
    if args is None:
        return frozenset()
    names: set[str] = set()
    for child in args.children:
        if not child.is_named:
            continue
        # Strip cast_expression / parenthesized_expression wrappers
        unwrapped = _unwrap_value_expr(child)
        if unwrapped.type == _IDENT:
            names.add(_node_text(unwrapped))
        elif unwrapped.type == _FIELD_EXPR:
            base = _innermost_ident(unwrapped)
            if base is not None:
                names.add(base)
    return frozenset(names)


def _unwrap_value_expr(n):
    """Strip syntactic noise that wraps a value expression without
    changing its symbol identity: casts and parens. The walker uses
    this so ``(char *)x`` and ``x`` are equivalent for surface-name
    extraction."""
    cur = n
    while True:
        t = cur.type
        if t == "cast_expression":
            val = cur.child_by_field_name("value")
            if val is None:
                return cur
            cur = val
            continue
        if t == "parenthesized_expression":
            inner = None
            for c in cur.children:
                if c.is_named:
                    inner = c
                    break
            if inner is None:
                return cur
            cur = inner
            continue
        return cur


def _walk_subtree_for_uses(n, *, exclude: set | None = None) -> frozenset[str]:
    """Every identifier appearing in load position inside ``n``,
    excluding identifiers that are the callee position of a
    ``call_expression`` (those become call_sites, not uses) and
    declarator-position identifiers (those become defs).

    ``exclude`` is a set of (start_byte, end_byte) tuples that
    identify identifiers already attributed elsewhere — typically
    the LHS of an init_declarator / assignment_expression so its
    name doesn't double as both def and use.
    """
    if exclude is None:
        exclude = set()
    out: set[str] = set()
    stack = [n]
    while stack:
        cur = stack.pop()
        t = cur.type
        if t == _CALL_EXPR:
            # Callee itself isn't a "use" of a value (it's a call);
            # descend into arguments only.
            args = cur.child_by_field_name("arguments")
            if args is not None:
                stack.extend(c for c in args.children if c.is_named)
            continue
        if t == _IDENT:
            key = (cur.start_byte, cur.end_byte)
            if key not in exclude:
                out.add(_node_text(cur))
            continue
        if t == _FIELD_EXPR:
            # Base name only.
            arg = cur.child_by_field_name("argument")
            if arg is not None:
                stack.append(arg)
            continue
        stack.extend(c for c in cur.children if c.is_named)
    return frozenset(out)


def _walk_subtree_for_call_sites(
    n, *, assigned_for_root: frozenset[str] = frozenset(),
) -> tuple[CallSite, ...]:
    """Every ``call_expression`` inside ``n`` as :class:`CallSite`
    records, in source order.

    ``assigned_for_root`` is the LHS name(s) the OUTERMOST call's
    return flows into — populated by the caller when ``n`` is the
    direct RHS of an init_declarator / assignment. Nested calls
    (``wrap(escape(x))`` — the inner ``escape(x)``) carry empty
    ``assigned_names`` because their return value flows into
    ``wrap``, not into the statement's LHS. This matches the
    Python builder's semantics.
    """
    # Sort key is ``end_byte`` so inner calls (smaller end_byte —
    # their closing paren comes before the outer's) appear before
    # outer calls. Matches the PyCFG convention: ``call_sites[-1]``
    # is the syntactic OUTERMOST call. The Phase 11 resolver's
    # outermost-pick uses ``call_sites[-1]``; both languages now
    # agree.
    out: list[tuple[int, int, CallSite]] = []
    root_id = id(_unwrap_value_expr(n)) if n is not None else None

    def visit(node: Node) -> None:
        t = node.type
        if t == _LAMBDA_EXPR:
            # Deferred execution: the body runs when the lambda is
            # CALLED, not at this statement — attributing its calls
            # here would put a possibly-never-executed sanitizer
            # unconditionally on the path (false-suppression
            # direction). The enclosing node is stamped may_escape
            # instead (see _subtree_has_indirection).
            return
        if t == _CALL_EXPR:
            callee = node.child_by_field_name("function")
            name = _resolve_callable_name(callee)
            args = _arg_surface_names(node)
            is_root = id(_unwrap_value_expr(node)) == root_id or \
                id(node) == root_id
            assigned = assigned_for_root if is_root else frozenset()
            if name is not None:
                cs = CallSite(
                    name=name,
                    arg_names=args,
                    assigned_names=assigned,
                    lineno=node.start_point[0] + 1,
                    col_offset=node.start_point[1],
                )
                out.append((node.end_byte, id(node), cs))
            arg_list = node.child_by_field_name("arguments")
            if arg_list is not None:
                for c in arg_list.children:
                    if c.is_named:
                        visit(c)
            return
        for c in node.children:
            if c.is_named:
                visit(c)

    if n is not None:
        visit(n)
    out.sort(key=lambda t: (t[0], t[1]))
    return tuple(cs for _, _, cs in out)


def _walk_subtree_for_calls(n) -> frozenset[str]:
    """Set of dotted callable names referenced anywhere in ``n``.
    Equivalent to ``{cs.name for cs in
    _walk_subtree_for_call_sites(n)}`` but without the position
    plumbing; used to populate the back-compat ``calls`` field.
    Lambda bodies are excluded — deferred execution, same rule as
    the call-site walker."""
    out: set[str] = set()
    stack = [n] if n is not None else []
    while stack:
        cur = stack.pop()
        if cur.type == _LAMBDA_EXPR:
            continue
        if cur.type == _CALL_EXPR:
            callee = cur.child_by_field_name("function")
            name = _resolve_callable_name(callee)
            if name is not None:
                out.add(name)
        stack.extend(c for c in cur.children if c.is_named)
    return frozenset(out)


def _subtree_has_indirection(n) -> bool:
    """Phase 10 — True iff any descendant of ``n`` is one of:

    * ``pointer_expression`` (``*p`` or ``&x``)
    * ``subscript_expression`` (``a[i]``)
    * ``field_expression`` with operator ``->``
    * ``call_expression`` whose resolved callee is in
      :data:`_BULK_COPY_FUNCS` (``memcpy`` etc.)

    Used by the statement-payload extractors to set
    :attr:`CPPCFGNode.may_escape`. Recursion is depth-first; we
    don't short-circuit because the cost is bounded by statement
    size (tens of nodes) and the call-site walk has to happen
    anyway for bulk-copy detection.
    """
    if n is None:
        return False
    stack = [n]
    while stack:
        cur = stack.pop()
        t = cur.type
        if t in _INDIRECTION_NODE_TYPES or t == _LAMBDA_EXPR:
            return True
        if t == _FIELD_EXPR:
            op = cur.child_by_field_name("operator")
            if op is not None and _node_text(op) == "->":
                return True
        if t == _CALL_EXPR:
            callee = cur.child_by_field_name("function")
            name = _resolve_callable_name(callee)
            if name is not None and name in _BULK_COPY_FUNCS:
                return True
        stack.extend(c for c in cur.children if c.is_named)
    return False


def _payload_from_declaration(decl) -> tuple[frozenset[str], frozenset[str],
                                              frozenset[str], tuple[CallSite, ...]]:
    """``int x = f(y);`` and ``int x;`` etc.

    Returns ``(calls, defs, uses, call_sites)``. Init declarators
    contribute their LHS as a def and their RHS as the surface for
    uses / call_sites. Plain declarations contribute only defs.
    """
    defs: set[str] = set()
    uses_acc: set[str] = set()
    calls_acc: set[str] = set()
    cs_acc: list[CallSite] = []
    for child in decl.children:
        if not child.is_named:
            continue
        if child.type == _INIT_DECLARATOR:
            tgt = child.child_by_field_name("declarator")
            tgt_name = _innermost_ident(tgt) if tgt is not None else None
            if tgt_name is not None:
                defs.add(tgt_name)
            val = child.child_by_field_name("value")
            if val is not None:
                assigned = frozenset({tgt_name}) if tgt_name else frozenset()
                cs_acc.extend(
                    _walk_subtree_for_call_sites(
                        val, assigned_for_root=assigned,
                    )
                )
                calls_acc |= _walk_subtree_for_calls(val)
                uses_acc |= _walk_subtree_for_uses(val)
                # Embedded stores in the INITIALIZER (``char *z =
                # (y = x);``) — see _embedded_store_names.
                defs |= _embedded_store_names(val)
        elif child.type in (
            _IDENT, _POINTER_DECLARATOR,
            "array_declarator", "function_declarator",
        ):
            name = _innermost_ident(child)
            if name is not None:
                defs.add(name)
        # type_identifier etc. — not a name event
    return (frozenset(calls_acc), frozenset(defs), frozenset(uses_acc),
            tuple(cs_acc))


def _payload_from_assignment(
    expr: Node, local_scopes: _LocalNameScopes | None = None,
) -> tuple[frozenset[str], frozenset[str],
           frozenset[str], tuple[CallSite, ...]]:
    """``x = f(y);`` / ``x += f(y);`` — defs={x}, RHS feeds uses + call_sites.

    Compound LHSes (``a.b = ...``, ``arr[i] = ...``) contribute the
    base name only as a def. Phase 10's ``may_escape`` policy
    handles the through-indirection write semantics.

    ``assigned_names`` (sanitizer-output identity) is granted only
    for a plain-identifier ``=`` LHS a declared local/param
    declarator positionally vouches for (``local_scopes``). A
    compound LHS mutates through the base name without rebinding it,
    and a bare-name store no in-scope preceding declarator vouches
    for resolves to a file-scope global / static / class member —
    a binding any callee can rewrite between this statement and a
    later read, so the value gate must not treat it as a clean local
    rebinding (the enclosing node is additionally stamped
    ``may_escape`` by the builder)."""
    lhs = expr.child_by_field_name("left")
    rhs = expr.child_by_field_name("right")
    op_node = expr.child_by_field_name("operator")
    op = _node_text(op_node) if op_node is not None else "="
    lhs_name = _innermost_ident(lhs) if lhs is not None else None
    defs = frozenset({lhs_name}) if lhs_name is not None else frozenset()
    uses_acc: set[str] = set()
    calls_acc: set[str] = set()
    cs_acc: list[CallSite] = []
    # Compound assignment (``+=``, ``-=``, ...) reads the LHS too.
    if op != "=" and lhs_name is not None:
        uses_acc.add(lhs_name)
    if rhs is not None:
        clean_lhs = (lhs is not None and lhs.type == _IDENT
                     and op == "=" and local_scopes is not None
                     and local_scopes.vouches(lhs_name, lhs.start_byte))
        assigned = defs if clean_lhs else frozenset()
        cs_acc.extend(
            _walk_subtree_for_call_sites(rhs, assigned_for_root=assigned)
        )
        calls_acc |= _walk_subtree_for_calls(rhs)
        uses_acc |= _walk_subtree_for_uses(rhs)
        # Embedded stores in the RHS (``z = (y = x);``) — defs only,
        # never assigned_names; see _embedded_store_names.
        defs = defs | _embedded_store_names(rhs)
    # The LHS may also contain uses — e.g. ``arr[i] = ...`` reads
    # ``arr`` and ``i``. Walk it but exclude the bare LHS target.
    if lhs is not None and lhs.type != _IDENT:
        uses_acc |= _walk_subtree_for_uses(lhs)
    return (frozenset(calls_acc), defs, frozenset(uses_acc), tuple(cs_acc))


def _embedded_store_names(n) -> frozenset[str]:
    """Store-side base names of assignments and updates EMBEDDED in
    an expression subtree (a condition, a for-step, a call argument).

    ``if ((p = malloc(n)))`` / ``while ((c = getc(f)) != EOF)`` write
    their LHS; a payload with ``defs=∅`` makes that definer invisible
    to reaching-defs, so the value-bound gate's condition-3
    exclusivity holds falsely on a live re-taint. Recording the def
    only (never ``assigned_names``) is the refusal direction: an
    extra definer can break an exclusivity proof but never grants
    sanitizer-output identity.
    """
    return frozenset(name for name, _ in _embedded_store_sites(n))


def _embedded_store_sites(n) -> tuple[tuple[str, int], ...]:
    """``(name, store_byte)`` pairs for the same stores
    :func:`_embedded_store_names` collects — positional so the scope
    oracle can bind each store site to a preceding in-scope
    declarator rather than function-wide name presence."""
    if n is None:
        return ()
    out: list[tuple[str, int]] = []
    stack = [n]
    while stack:
        cur = stack.pop()
        if cur.type == _ASSIGNMENT:
            name = _innermost_ident(cur.child_by_field_name("left"))
            if name is not None:
                out.append((name, cur.start_byte))
        elif cur.type == "update_expression":
            arg = cur.child_by_field_name("argument")
            name = _innermost_ident(arg) if arg is not None else None
            if name is not None:
                out.append((name, cur.start_byte))
        stack.extend(c for c in cur.children if c.is_named)
    return tuple(out)


def _payload_from_subtree(n) -> tuple[frozenset[str], frozenset[str],
                                       frozenset[str], tuple[CallSite, ...]]:
    """Fall-through payload extractor for expression-only statements:
    ``return f(x);``, ``if (cond)``, plain expression statements,
    switch subjects, etc. Defs cover only stores EMBEDDED in the
    expression (assignment-in-condition, ``i++`` in a for-step — see
    :func:`_embedded_store_names`); every identifier feeds uses;
    every call_expression feeds call_sites + calls.
    """
    if n is None:
        return (frozenset(), frozenset(), frozenset(), ())
    return (
        _walk_subtree_for_calls(n),
        _embedded_store_names(n),
        _walk_subtree_for_uses(n),
        _walk_subtree_for_call_sites(n),
    )


# ---------------------------------------------------------------------------
# Function discovery + parameter extraction
# ---------------------------------------------------------------------------


def _find_function_definition(root, function_name: str):
    """First ``function_definition`` whose declarator's innermost
    identifier matches ``function_name``. ``None`` if not found.

    The walker descends into ``namespace_definition`` and
    ``class_specifier`` for C++ but does NOT join the namespace /
    class prefix onto the function name — ``Foo::bar`` matches a
    request for ``bar``. Multi-definition disambiguation is the
    caller's problem (Phase 11 will pass ``at_line`` like Phase 5
    does for Python)."""
    stack = [root]
    while stack:
        cur = stack.pop()
        if cur.type == _FN_DEFINITION:
            name = _function_name(cur)
            if name == function_name:
                return cur
        stack.extend(child for child in cur.children if child.is_named)
    return None


def _function_name(fn_def: Node) -> str | None:
    """Pull the function identifier from a ``function_definition``.

    Walks through pointer / parenthesised declarator wrappers until
    a ``function_declarator`` is found, then returns its innermost
    identifier. For C++ ``operator+`` and similar, the operator-name
    node is returned via ``_node_text`` — this matches what
    ``call_graph.extract_call_graph_cpp`` keys on, so the sanitizer
    catalogue's name lookup behaves consistently."""
    decl = fn_def.child_by_field_name("declarator")
    while decl is not None:
        if decl.type == _FN_DECLARATOR:
            inner = decl.child_by_field_name("declarator")
            if inner is None:
                return None
            return _innermost_ident(inner) or _node_text(inner)
        decl = decl.child_by_field_name("declarator")
    return None


def _function_params(fn_def: Node) -> tuple[str, ...]:
    """Ordered tuple of parameter names declared in the function's
    signature. C-style ``void`` and unnamed parameters yield no
    entry — they have no symbol to bind in the body."""
    decl = fn_def.child_by_field_name("declarator")
    fn_decl = None
    while decl is not None:
        if decl.type == _FN_DECLARATOR:
            fn_decl = decl
            break
        decl = decl.child_by_field_name("declarator")
    if fn_decl is None:
        return ()
    params = fn_decl.child_by_field_name("parameters")
    if params is None:
        return ()
    names: list[str] = []
    for child in params.children:
        if not child.is_named:
            continue
        if child.type != _PARAM_DECL:
            # ``variadic_parameter`` (``...``) or ``optional_parameter``
            # carry no bindable name in the body.
            continue
        pdecl = child.child_by_field_name("declarator")
        if pdecl is None:
            continue
        name = _innermost_ident(pdecl)
        if name is not None:
            names.append(name)
    return tuple(names)


# Nested scopes whose declarations are not locals of the enclosing
# function. A lambda's parameters/locals belong to the lambda frame;
# treating them as function locals would grant bare-name stores to
# same-named globals local-grade semantics. Nested class/struct/union
# bodies (C++ local classes) likewise bind their own members and
# method locals — without the barrier a local class's declarations
# leaked into the outer function's local set.
# Single-homed in cfg_node_tables (grammar-validated by its closure
# test — a dead / renamed node name fails CI instead of silently
# disarming the barrier).
_LOCAL_SCOPE_BARRIERS = _NODE_TABLES.scope_barriers

# Constructs that bound a declarator's vouch window: a declaration
# inside one of these is out of scope past its end. Missing a member
# here widens a window toward the function end (suppression-ward),
# so the set errs inclusive — an over-narrow window only refuses.
# Single-homed in cfg_node_tables (grammar-validated).
_LOCAL_SCOPE_BOUNDS = _NODE_TABLES.scope_bounds

# Storage-class specifiers whose block-scope declarations do NOT bind
# a function-local object: ``extern`` declares the GLOBAL itself
# (block-scope extern is a declaration, never a definition), and
# ``static`` / ``thread_local`` name storage shared across calls (or
# threads' reentrancy) that an interleaved call can rewrite — none may
# earn local-grade rebinding semantics.
_NONLOCAL_STORAGE_CLASSES = frozenset({
    "extern", "static", "thread_local", "__thread",
})

# Declarator wrappers whose innermost identifier is the declared name.
_DECLARATOR_TYPES = frozenset({
    _IDENT, _POINTER_DECLARATOR, "array_declarator",
    "function_declarator", "reference_declarator",
    "parenthesized_declarator",
})


class _LocalNameScopes:
    """Positional scope oracle over a function's declared
    locals/params.

    Each declared name carries vouch windows ``[declarator_start,
    enclosing_scope_end)``: a bare-name store earns local-grade
    semantics only when some window of its name contains the store's
    byte offset. Flat per-function name membership was steerable — a
    dead block-scoped declarator anywhere in the function (after the
    sink, in unreachable code) re-armed local-grade semantics for
    every same-named global store. Binding the store site to a
    declarator that PRECEDES it inside a live scope closes that;
    C/C++'s declare-before-use rule for locals means the positional
    check never refuses a genuinely local store."""

    __slots__ = ("_windows",)

    def __init__(
        self, windows: dict[str, tuple[tuple[int, int], ...]],
    ) -> None:
        self._windows = windows

    def vouches(self, name: str, store_byte: int) -> bool:
        return any(
            lo <= store_byte < hi
            for lo, hi in self._windows.get(name, ())
        )


_EMPTY_LOCAL_SCOPES = _LocalNameScopes({})


def _declaration_storage_nonlocal(decl: Node) -> bool:
    """True when a block-scope ``declaration`` carries a storage-class
    specifier that binds outside the local frame (see
    :data:`_NONLOCAL_STORAGE_CLASSES`)."""
    return any(
        c.type == "storage_class_specifier"
        and _node_text(c) in _NONLOCAL_STORAGE_CLASSES
        for c in decl.children
    )


def _declared_local_scopes(fn_def: Node) -> _LocalNameScopes:
    """Positional oracle for every name ``fn_def`` binds as a local or
    parameter: formal parameters, block-scope declarations (including
    ``for`` inits and C++ condition declarations), range-``for``
    declarators, catch parameters, and structured bindings.

    This is the scope oracle behind the value gate's locals-are-
    unaliasable premise: an identifier-LHS store that no in-scope
    PRECEDING declarator vouches for resolves to a file-scope global
    / static / class member — a binding any callee can rewrite
    between the store and a later read — so it must not earn
    local-grade rebinding semantics.
    """
    windows: dict[str, list[tuple[int, int]]] = {}

    def add(name: str, decl_byte: int, bound_end: int) -> None:
        windows.setdefault(name, []).append((decl_byte, bound_end))

    for p in _function_params(fn_def):
        add(p, fn_def.start_byte, fn_def.end_byte)
    body = fn_def.child_by_field_name("body")
    if body is None:
        return _LocalNameScopes(
            {k: tuple(v) for k, v in windows.items()})
    stack: list[tuple[Node, int]] = [(body, body.end_byte)]
    while stack:
        cur, bound = stack.pop()
        t = cur.type
        if t in _LOCAL_SCOPE_BARRIERS:
            continue
        if t in _LOCAL_SCOPE_BOUNDS:
            bound = min(bound, cur.end_byte)
        if t == _DECLARATION:
            if _declaration_storage_nonlocal(cur):
                # ``extern char *g;`` in a function body declares the
                # GLOBAL g — registering it as a local handed every
                # subsequent bare store to g local-grade semantics.
                # static / thread_local are storage shared across
                # calls: demoted too (fail closed — the value remains
                # rewritable under reentrancy).
                continue
            for child in cur.children:
                if not child.is_named:
                    continue
                if child.type == _INIT_DECLARATOR:
                    tgt = child.child_by_field_name("declarator")
                    if tgt is not None and tgt.type == \
                            "structured_binding_declarator":
                        for c in tgt.children:
                            if c.type == _IDENT:
                                add(_node_text(c), cur.start_byte, bound)
                        continue
                    name = _innermost_ident(tgt) if tgt is not None else None
                    if name is not None:
                        add(name, cur.start_byte, bound)
                elif child.type in _DECLARATOR_TYPES:
                    name = _innermost_ident(child)
                    if name is not None:
                        add(name, cur.start_byte, bound)
        elif t == _PARAM_DECL:
            # Catch-clause parameters (C++). Lambda parameters are
            # excluded by the scope barrier above.
            pdecl = cur.child_by_field_name("declarator")
            name = _innermost_ident(pdecl) if pdecl is not None else None
            if name is not None:
                add(name, cur.start_byte, bound)
        elif t == "for_range_loop":
            tgt = cur.child_by_field_name("declarator")
            name = _innermost_ident(tgt) if tgt is not None else None
            if name is not None:
                add(name, cur.start_byte, bound)
        stack.extend(
            (c, bound) for c in cur.children if c.is_named)
    return _LocalNameScopes({k: tuple(v) for k, v in windows.items()})


# ---------------------------------------------------------------------------
# CFG builder
# ---------------------------------------------------------------------------


class _CPPCFGBuilder:
    """Stateful walker. Same shape as
    :class:`core.analysis.cfg_builder._PythonCFGBuilder`: each
    ``_build_*`` takes an incoming-predecessor list and returns the
    outgoing-successor list, the structured-block CFG idiom."""

    def __init__(self, function_name: str, file_path: str, language: str,
                 local_scopes: _LocalNameScopes = _EMPTY_LOCAL_SCOPES,
                 ) -> None:
        self.function_name = function_name
        self.file_path = file_path
        self.language = language
        # Positional scope oracle over the function's declared
        # locals/params. The fail-closed default (empty) demotes
        # EVERY bare-name store to may_escape — refusal direction.
        self._local_scopes = local_scopes
        self.entry = CPPCFGNode(
            kind="entry", lineno=ENTRY_LINENO,
            label=f"ENTRY:{function_name}",
        )
        self.exit = CPPCFGNode(
            kind="exit", lineno=EXIT_LINENO,
            label=f"EXIT:{function_name}",
        )
        self._adjacency: dict[CPPCFGNode, list[CPPCFGNode]] = {}
        self._all_nodes: list[CPPCFGNode] = [self.entry, self.exit]
        # Loop context stack: (break_target, continue_target).
        self._loop_stack: list[tuple[CPPCFGNode, CPPCFGNode]] = []
        # switch context stack: (break_target, fallthrough-from-prev-case)
        # The break target is the join AFTER the switch.
        self._switch_stack: list[CPPCFGNode] = []
        # Unified break-target stack tracks nesting order so break
        # targets the innermost enclosing loop or switch.
        self._break_stack: list[CPPCFGNode] = []
        # Goto resolution: collect (goto_node, label_text) for a
        # post-pass once all labels are known. Conservative: every
        # labeled_statement with a matching label receives an edge
        # from the goto.
        self._gotos: list[tuple[CPPCFGNode, str]] = []
        self._labels: dict[str, CPPCFGNode] = {}
        # Unique-id counter for nodes whose (kind, lineno, label,
        # defs, uses, call_sites) would otherwise collide. Frozen
        # dataclasses hash on all fields; two empty straight-line
        # nodes on the same line (e.g. an empty ``case`` label) would
        # otherwise collapse into one and corrupt the adjacency.
        self._dedupe_counter = 0

    # ----- edge plumbing -----

    def _link(self, src: CPPCFGNode, dst: CPPCFGNode) -> None:
        self._adjacency.setdefault(src, []).append(dst)

    def _link_many(self, srcs: Iterable[CPPCFGNode], dst: CPPCFGNode) -> None:
        for s in srcs:
            self._link(s, dst)

    def _make_node(
        self, *, kind: str, lineno: int, label: str,
        calls: frozenset[str] = frozenset(),
        defs: frozenset[str] = frozenset(),
        uses: frozenset[str] = frozenset(),
        call_sites: tuple[CallSite, ...] = (),
        may_escape: bool = False,
    ) -> CPPCFGNode:
        # Append a tie-breaker tag only when a node with identical
        # structural identity already exists — cheap, keeps repr
        # readable for the common case.
        node = CPPCFGNode(
            kind=kind, lineno=lineno, label=label,
            calls=calls, defs=defs, uses=uses, call_sites=call_sites,
            may_escape=may_escape,
        )
        if node in self._adjacency or node in self._all_nodes:
            self._dedupe_counter += 1
            tag = f" #{self._dedupe_counter}"
            node = CPPCFGNode(
                kind=kind, lineno=lineno, label=label + tag,
                calls=calls, defs=defs, uses=uses, call_sites=call_sites,
                may_escape=may_escape,
            )
        self._all_nodes.append(node)
        return node

    # ----- statement dispatch -----

    def _escapes(self, n) -> bool:
        """Alias-conservatism stamp for one payload subtree: the
        Phase 10 syntactic indirections plus any embedded/direct
        store no in-scope preceding declarator vouches for — a
        bare-name global / static / member write any interleaved
        call can rewrite (the value gate demotes SUPPRESS →
        CANDIDATE_ONLY on may_escape paths)."""
        if _subtree_has_indirection(n):
            return True
        return any(
            not self._local_scopes.vouches(name, byte)
            for name, byte in _embedded_store_sites(n)
        )

    def _short_label(self, n) -> str:
        # Use just the first 60 chars of the source span for the label.
        text = _node_text(n).split("\n", 1)[0].strip()
        return text[:60] + ("…" if len(text) > 60 else "")

    def _build_stmts(
        self, body, incoming: list[CPPCFGNode],
    ) -> list[CPPCFGNode]:
        """Walk a ``compound_statement`` body, a list of pre-extracted
        statement nodes (switch's case-body grouping), or a single
        statement (a bare ``if (...) break;`` consequence without
        braces). In the single-statement case we route directly to
        :meth:`_build_stmt` — otherwise the inner children would be
        descended into and the statement-as-a-whole semantics lost
        (e.g. ``break_statement`` has no named children, so iterating
        them yields nothing and the break is silently dropped)."""
        if isinstance(body, list):
            stmts = body
        elif body.type == _COMPOUND_STMT:
            stmts = [c for c in body.children if c.is_named]
        else:
            return self._build_stmt(body, incoming)
        cursor = incoming
        for stmt in stmts:
            cursor = self._build_stmt(stmt, cursor)
        return cursor

    def _build_stmt(
        self, stmt, incoming: list[CPPCFGNode],
    ) -> list[CPPCFGNode]:
        t = stmt.type
        if t == _IF:
            return self._build_if(stmt, incoming)
        if t == _WHILE:
            return self._build_while(stmt, incoming)
        if t == _FOR:
            return self._build_for(stmt, incoming)
        if t == _DO:
            return self._build_do(stmt, incoming)
        if t == _SWITCH:
            return self._build_switch(stmt, incoming)
        if t == _RETURN:
            node = self._straight_node(stmt)
            self._link_many(incoming, node)
            self._link(node, self.exit)
            return []
        if t == _BREAK:
            return self._build_break(stmt, incoming)
        if t == _CONTINUE:
            return self._build_continue(stmt, incoming)
        if t == _GOTO:
            return self._build_goto(stmt, incoming)
        if t == _LABELED:
            return self._build_labeled(stmt, incoming)
        if t == _COMPOUND_STMT:
            return self._build_stmts(stmt, incoming)
        if t == _CASE:
            # Bare ``case`` outside a switch — shouldn't happen in
            # well-formed C, but model as a no-op straight-line stmt.
            node = self._straight_node(stmt)
            self._link_many(incoming, node)
            return [node]
        # Straight-line: expression_statement, declaration, etc.
        node = self._straight_node(stmt)
        self._link_many(incoming, node)
        return [node]

    def _straight_node(self, stmt: Node) -> CPPCFGNode:
        """Compute payload and emit a stmt node. Routes to the
        specialised extractor based on ``stmt.type``."""
        t = stmt.type
        if t == _DECLARATION:
            calls, defs, uses, css = _payload_from_declaration(stmt)
        elif t == _EXPR_STMT:
            # ``expression_statement`` is a one-child wrapper.
            inner = None
            for c in stmt.children:
                if c.is_named:
                    inner = c
                    break
            if inner is not None and inner.type == _ASSIGNMENT:
                calls, defs, uses, css = _payload_from_assignment(
                    inner, self._local_scopes)
            else:
                calls, defs, uses, css = _payload_from_subtree(inner)
        else:
            calls, defs, uses, css = _payload_from_subtree(stmt)
        return self._make_node(
            kind="stmt", lineno=stmt.start_point[0] + 1,
            label=self._short_label(stmt),
            calls=calls, defs=defs, uses=uses, call_sites=css,
            may_escape=self._escapes(stmt),
        )

    # ----- compound constructs -----

    def _build_if(self, stmt: Node, incoming):
        cond = stmt.child_by_field_name("condition")
        calls, defs, uses, css = _payload_from_subtree(cond)
        cond_node = self._make_node(
            kind="stmt", lineno=stmt.start_point[0] + 1,
            label="if " + self._short_label(cond) if cond is not None else "if",
            calls=calls, defs=defs, uses=uses, call_sites=css,
            may_escape=self._escapes(cond),
        )
        self._link_many(incoming, cond_node)
        then_body = stmt.child_by_field_name("consequence")
        else_body = stmt.child_by_field_name("alternative")
        then_out = self._build_stmts(then_body, [cond_node]) \
            if then_body is not None else [cond_node]
        # tree-sitter wraps ``else`` content in an alternative field
        # that points either at the else-body compound_statement or
        # at an ``else_clause`` node — handle both shapes.
        if else_body is None:
            else_out: list[CPPCFGNode] = [cond_node]
        elif else_body.type == "else_clause":
            # else_clause's first named child is the body / nested if
            inner = None
            for c in else_body.children:
                if c.is_named:
                    inner = c
                    break
            else_out = self._build_stmt(inner, [cond_node]) \
                if inner is not None else [cond_node]
        else:
            else_out = self._build_stmts(else_body, [cond_node])
        return then_out + else_out

    def _build_while(self, stmt: Node, incoming):
        cond = stmt.child_by_field_name("condition")
        calls, defs, uses, css = _payload_from_subtree(cond)
        header = self._make_node(
            kind="stmt", lineno=stmt.start_point[0] + 1,
            label="while " + self._short_label(cond) if cond is not None else "while",
            calls=calls, defs=defs, uses=uses, call_sites=css,
            may_escape=self._escapes(cond),
        )
        self._link_many(incoming, header)
        after_loop: list[CPPCFGNode] = [header]
        self._loop_stack.append((header, header))
        self._break_stack.append(header)
        body = stmt.child_by_field_name("body")
        body_out = self._build_stmts(body, [header]) if body is not None else []
        for tail in body_out:
            self._link(tail, header)
        self._break_stack.pop()
        self._loop_stack.pop()
        return after_loop

    def _build_for(self, stmt: Node, incoming):
        # ``for (init; cond; step) body`` — model as init → header →
        # body → step → header, with header → after on exit.
        init = stmt.child_by_field_name("initializer")
        cond = stmt.child_by_field_name("condition")
        step = stmt.child_by_field_name("update")
        body = stmt.child_by_field_name("body")
        cursor = incoming
        if init is not None:
            init_node = self._straight_node(init)
            self._link_many(cursor, init_node)
            cursor = [init_node]
        # Header (condition test).
        if cond is not None:
            calls, defs, uses, css = _payload_from_subtree(cond)
            header = self._make_node(
                kind="stmt", lineno=stmt.start_point[0] + 1,
                label="for " + self._short_label(cond),
                calls=calls, defs=defs, uses=uses, call_sites=css,
                may_escape=self._escapes(cond),
            )
        else:
            # ``for(;;)`` infinite loop header
            header = self._make_node(
                kind="stmt", lineno=stmt.start_point[0] + 1,
                label="for(;;)",
            )
        self._link_many(cursor, header)
        # Step node — continue jumps here; step then jumps to header.
        if step is not None:
            calls_s, defs_s, uses_s, css_s = _payload_from_subtree(step)
            step_node = self._make_node(
                kind="stmt", lineno=step.start_point[0] + 1,
                label="step " + self._short_label(step),
                calls=calls_s, defs=defs_s, uses=uses_s, call_sites=css_s,
                may_escape=self._escapes(step),
            )
            self._link(step_node, header)
        else:
            step_node = header   # continue == loop back to header
        self._loop_stack.append((header, step_node))
        self._break_stack.append(header)
        body_out = self._build_stmts(body, [header]) if body is not None else []
        for tail in body_out:
            self._link(tail, step_node)
        self._break_stack.pop()
        self._loop_stack.pop()
        return [header]

    def _build_do(self, stmt: Node, incoming):
        # ``do body while (cond);`` — body runs at least once, cond
        # is at the tail.
        body = stmt.child_by_field_name("body")
        cond = stmt.child_by_field_name("condition")
        # body entry has the same predecessors as the do statement.
        # tail node = the condition test; body falls through to it.
        if cond is not None:
            calls, defs, uses, css = _payload_from_subtree(cond)
            tail = self._make_node(
                kind="stmt", lineno=cond.start_point[0] + 1,
                label="while " + self._short_label(cond),
                calls=calls, defs=defs, uses=uses, call_sites=css,
                may_escape=self._escapes(cond),
            )
        else:
            tail = self._make_node(
                kind="stmt", lineno=stmt.end_point[0] + 1,
                label="while (...)",
            )
        # Pre-allocate the body entry as a sentinel so break/continue
        # have something to point at. We use the first body node as
        # the loop "header" for continue.
        self._loop_stack.append((tail, tail))
        self._break_stack.append(tail)
        # Tail loops back to body entry.  _build_stmts links incoming →
        # first body node(s), so we snapshot incoming's successors before
        # and diff after to recover the body entry set.
        pre_succs = {n: set(self._adjacency.get(n, ())) for n in incoming}
        body_out = self._build_stmts(body, incoming) if body is not None else list(incoming)
        # Body falls through to tail (the condition test)
        self._link_many(body_out, tail)
        body_entry = set()
        for n in incoming:
            body_entry |= set(self._adjacency.get(n, ())) - pre_succs.get(n, set())
        for entry in body_entry:
            self._link(tail, entry)
        self._break_stack.pop()
        self._loop_stack.pop()
        return [tail]

    def _build_switch(self, stmt: Node, incoming):
        subj = stmt.child_by_field_name("condition")
        calls, defs, uses, css = _payload_from_subtree(subj)
        header = self._make_node(
            kind="stmt", lineno=stmt.start_point[0] + 1,
            label="switch " + (self._short_label(subj) if subj is not None else ""),
            calls=calls, defs=defs, uses=uses, call_sites=css,
            may_escape=self._escapes(subj),
        )
        self._link_many(incoming, header)
        # Join node — every break in the switch body links here; the
        # switch's overall successor is this join.
        join = self._make_node(
            kind="stmt", lineno=stmt.end_point[0] + 1,
            label="switch-join",
        )
        self._switch_stack.append(join)
        self._break_stack.append(join)
        body = stmt.child_by_field_name("body")
        # Walk the body's children, grouping consecutive stmts by
        # case label. Each case_statement becomes a "branch" entry
        # from the header. Fallthrough = predecessors of stmt N+1
        # include stmt N when there's no break.
        case_groups: list[list[Any]] = []   # list of (stmt nodes)
        case_entries: list[list[Any]] = []  # case label statements
        if body is not None:
            current_group: list[Any] = []
            current_labels: list[Any] = []
            for child in body.children:
                if not child.is_named:
                    continue
                if child.type == _CASE:
                    # Close out current group, start a new one
                    if current_group or current_labels:
                        case_groups.append(current_group)
                        case_entries.append(current_labels)
                    # tree-sitter nests body stmts inside case_statement
                    value_node = child.child_by_field_name("value")
                    current_group = [
                        c for c in child.children
                        if c.is_named and c != value_node
                    ]
                    current_labels = [child]
                else:
                    current_group.append(child)
            if current_group or current_labels:
                case_groups.append(current_group)
                case_entries.append(current_labels)
        # Now build each case.
        prev_out: list[CPPCFGNode] = []
        outs: list[CPPCFGNode] = []
        for labels, group in zip(case_entries, case_groups, strict=True):
            # case label node(s) — model as one node per label.
            entry: list[CPPCFGNode] = [header] + prev_out
            for label_stmt in labels:
                ln = self._make_node(
                    kind="stmt",
                    lineno=label_stmt.start_point[0] + 1,
                    label=self._short_label(label_stmt),
                )
                self._link_many(entry, ln)
                entry = [ln]
            # Body
            group_out = self._build_stmts(group, entry)
            prev_out = group_out
            outs.extend(group_out)
        # Cases that fall through past the last labeled stmt without
        # break join the switch's successor.
        for tail in outs:
            self._link(tail, join)
        # If the switch has no default, header can also reach join
        # (no case matched).
        has_default = any(
            any(_node_text(c).strip().startswith("default")
                for c in labels if c.type == _CASE)
            for labels in case_entries
        )
        if not has_default:
            self._link(header, join)
        self._break_stack.pop()
        self._switch_stack.pop()
        return [join]

    def _build_break(self, stmt: Node, incoming):
        node = self._make_node(
            kind="stmt", lineno=stmt.start_point[0] + 1, label="break",
        )
        self._link_many(incoming, node)
        if self._break_stack:
            self._link(node, self._break_stack[-1])
        return []

    def _build_continue(self, stmt: Node, incoming):
        node = self._make_node(
            kind="stmt", lineno=stmt.start_point[0] + 1, label="continue",
        )
        self._link_many(incoming, node)
        if self._loop_stack:
            self._link(node, self._loop_stack[-1][1])
        return []

    def _build_goto(self, stmt: Node, incoming):
        label_node = stmt.child_by_field_name("label")
        label_name = _node_text(label_node) if label_node is not None else ""
        node = self._make_node(
            kind="stmt", lineno=stmt.start_point[0] + 1,
            label=f"goto {label_name}",
        )
        self._link_many(incoming, node)
        # Resolve in the post-pass; record now.
        self._gotos.append((node, label_name))
        return []

    def _build_labeled(self, stmt: Node, incoming):
        # ``label:`` followed by a stmt. Emit a sentinel for the
        # label that goto can target; descend into the inner stmt.
        label_node = stmt.child_by_field_name("label")
        label_name = _node_text(label_node) if label_node is not None else ""
        ln = self._make_node(
            kind="stmt", lineno=stmt.start_point[0] + 1,
            label=f"{label_name}:",
        )
        self._link_many(incoming, ln)
        self._labels.setdefault(label_name, ln)
        # Inner stmt — tree-sitter exposes it as the next named child.
        inner: Any | None = None
        for c in stmt.children:
            if c.is_named and c is not label_node:
                inner = c
                break
        if inner is None:
            return [ln]
        return self._build_stmt(inner, [ln])

    # ----- driver -----

    def build(self, fn_def: Node) -> CPPCFG:
        self._local_scopes = _declared_local_scopes(fn_def)
        body = fn_def.child_by_field_name("body")
        if body is None:
            # Pure declaration — no body. Just hook entry → exit.
            self._link(self.entry, self.exit)
        else:
            outs = self._build_stmts(body, [self.entry])
            self._link_many(outs, self.exit)
        # Resolve goto targets now that every label is known.
        for goto_node, label_name in self._gotos:
            target = self._labels.get(label_name)
            if target is not None:
                self._link(goto_node, target)
            else:
                # Unknown label — goto becomes a no-op flowing to exit
                # so the function isn't a sink-trap for analysis.
                self._link(goto_node, self.exit)
        adjacency: dict[CPPCFGNode, tuple[CPPCFGNode, ...]] = {
            k: tuple(v) for k, v in self._adjacency.items()
        }
        seen: set = set()
        ordered: list[CPPCFGNode] = []
        for n in self._all_nodes:
            if n not in seen:
                seen.add(n)
                ordered.append(n)
        return CPPCFG(
            function_name=self.function_name,
            file_path=self.file_path,
            language=self.language,
            entry_node=self.entry,
            exit_node=self.exit,
            _nodes=tuple(ordered),
            _adjacency=adjacency,
            params=_function_params(fn_def),
        )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def build_cpp_intraproc_cfg(
    source: str | Path, function_name: str, *, language: str = "c",
) -> CPPCFG | None:
    """Build the CFG for one named C/C++ function.

    ``source`` is a :class:`Path` (read from disk) or a ``str`` of
    source code. ``language`` is ``"c"`` or ``"cpp"`` — picks the
    tree-sitter grammar.

    Returns ``None`` when:

    * The tree-sitter grammar for ``language`` isn't installed.
    * The source has unrecoverable parse errors before any function
      definition is found.
    * No function in the file matches ``function_name``.

    Partial parse errors (a malformed statement inside an otherwise-
    parseable function) do NOT return None — tree-sitter's error
    recovery yields ``ERROR`` subtrees that the walker treats as
    opaque straight-line statements. This matches the inventory
    walks' degrade-cleanly contract.
    """
    if language not in ("c", "cpp"):
        return None
    parser = _get_parser(language)
    if parser is None:
        return None
    if isinstance(source, Path):
        file_path = str(source)
        source_text = source.read_text(encoding="utf-8")
    else:
        file_path = "<string>"
        source_text = source
    # parse_origin: a budget-abandoned parse must name this file on
    # the run's analysis-gap trail.
    from core.run.gaps import parse_origin
    with parse_origin(file_path):
        tree = parser.parse(source_text.encode("utf-8", errors="replace"))
    fn_def = _find_function_definition(tree.root_node, function_name)
    if fn_def is None:
        return None
    builder = _CPPCFGBuilder(function_name, file_path, language)
    return builder.build(fn_def)
