"""C / C++ intra-procedural CFG builder — Phase 9 of the sanitizer-cut arc.

Sub-arc B's substrate. Mirrors :mod:`core.inventory.cfg_builder`'s
public shape so :func:`core.dataflow.sanitizer_catalog.match_sanitizers_in_cfg`,
:func:`core.inventory.dataflow.reaching_defs`, and (eventually, in
Phase 11) :func:`core.inventory.sanitizer_cut.evaluate_finding` can
consume the C/C++ CFG with the same interface as the Python one.

Substrate: tree-sitter (`tree-sitter-c`, `tree-sitter-cpp`). The
Phase 8 decision doc at ``docs/phase-8-substrate-spike/DECISION.md``
explains why.

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
  fixtures need it, and the conservative collapse over-suppresses
  rather than under-suppresses (a sanitizer in any short-circuit
  operand still appears in ``call_sites``).

What this module deliberately does NOT do:

* Macro expansion (we walk pre-preprocessor source — by design)
* Pointer / alias tracking — Phase 10's ``may_escape`` policy
* Inter-procedural call resolution — Phase 14's sub-arc C analog
* C++ template instantiation — out of scope; templates parse fine
  but only the syntactic form is recorded

Public surface:

* :class:`CPPCFGNode` — analog of :class:`core.inventory.cfg_builder.PyCFGNode`
* :class:`CPPCFG` — analog of :class:`core.inventory.cfg_builder.PythonCFG`,
  implements :class:`core.inventory.dominators.Graph`
* :func:`build_cpp_intraproc_cfg` — entry point
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import (
    Any,
    Dict,
    FrozenSet,
    Iterable,
    List,
    Optional,
    Set,
    Tuple,
)

from core.inventory.cfg_builder import (
    ENTRY_LINENO,
    EXIT_LINENO,
    CallSite,
)


# ---------------------------------------------------------------------------
# Node types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CPPCFGNode:
    """One node of a C / C++ control-flow graph.

    Shape mirrors :class:`core.inventory.cfg_builder.PyCFGNode` so the
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
    :mod:`core.inventory.cfg_builder` so cross-language consumers
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
    track). evaluate_finding downgrades ``SUPPRESS → CANDIDATE_ONLY``
    when any node on a source→sink path is ``may_escape``. The flag
    is non-load-bearing for Python (PyCFGNode lacks the attribute and
    ``getattr(..., "may_escape", False)`` keeps the Python path
    bit-identical).
    """
    kind: str          # "entry" | "exit" | "stmt"
    lineno: int
    label: str
    calls: FrozenSet[str] = frozenset()
    defs: FrozenSet[str] = frozenset()
    uses: FrozenSet[str] = frozenset()
    call_sites: Tuple[CallSite, ...] = ()
    may_escape: bool = False

    def __repr__(self) -> str:                              # pragma: no cover
        return (
            f"CPPCFGNode({self.kind}, L{self.lineno}, "
            f"{self.label!r}, calls={set(self.calls)!r}, "
            f"defs={set(self.defs)!r}, uses={set(self.uses)!r})"
        )


@dataclass(frozen=True)
class CPPCFG:
    """Concrete :class:`core.inventory.dominators.Graph` for a C / C++
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
    _nodes: Tuple[CPPCFGNode, ...]
    _adjacency: Dict[CPPCFGNode, Tuple[CPPCFGNode, ...]]
    params: Tuple[str, ...] = ()

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


# ---------------------------------------------------------------------------
# Statement payload extraction — defs, uses, call_sites per CFG node
# ---------------------------------------------------------------------------


def _node_text(n) -> str:
    return n.text.decode("utf-8", errors="replace") if n is not None else ""


def _innermost_ident(n) -> Optional[str]:
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


def _resolve_callable_name(callee) -> Optional[str]:
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


def _arg_surface_names(call_node) -> FrozenSet[str]:
    """Conservative bare-name extraction for one call's arguments.

    Mirrors :func:`core.inventory.cfg_builder._arg_surface_names`:
    only direct identifiers and the base of a field expression
    count. Nested calls, subscripts, casts, binary expressions, and
    literals contribute nothing — same under-count rationale (the
    gate's condition 2 over-suppresses if we over-count).
    """
    args = call_node.child_by_field_name("arguments")
    if args is None:
        return frozenset()
    names: Set[str] = set()
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


def _walk_subtree_for_uses(n, *, exclude: Optional[set] = None) -> FrozenSet[str]:
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
    out: Set[str] = set()
    stack = [n]
    while stack:
        cur = stack.pop()
        t = cur.type
        if t == _CALL_EXPR:
            # Callee itself isn't a "use" of a value (it's a call);
            # descend into arguments only.
            args = cur.child_by_field_name("arguments")
            if args is not None:
                for c in args.children:
                    if c.is_named:
                        stack.append(c)
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
        for c in cur.children:
            if c.is_named:
                stack.append(c)
    return frozenset(out)


def _walk_subtree_for_call_sites(
    n, *, assigned_for_root: FrozenSet[str] = frozenset(),
) -> Tuple[CallSite, ...]:
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
    out: List[Tuple[int, int, CallSite]] = []
    root_id = id(_unwrap_value_expr(n)) if n is not None else None

    def visit(node) -> None:
        t = node.type
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


def _walk_subtree_for_calls(n) -> FrozenSet[str]:
    """Set of dotted callable names referenced anywhere in ``n``.
    Equivalent to ``{cs.name for cs in
    _walk_subtree_for_call_sites(n)}`` but without the position
    plumbing; used to populate the back-compat ``calls`` field."""
    out: Set[str] = set()
    stack = [n] if n is not None else []
    while stack:
        cur = stack.pop()
        if cur.type == _CALL_EXPR:
            callee = cur.child_by_field_name("function")
            name = _resolve_callable_name(callee)
            if name is not None:
                out.add(name)
        for c in cur.children:
            if c.is_named:
                stack.append(c)
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
        if t in _INDIRECTION_NODE_TYPES:
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
        for c in cur.children:
            if c.is_named:
                stack.append(c)
    return False


def _payload_from_declaration(decl) -> Tuple[FrozenSet[str], FrozenSet[str],
                                              FrozenSet[str], Tuple[CallSite, ...]]:
    """``int x = f(y);`` and ``int x;`` etc.

    Returns ``(calls, defs, uses, call_sites)``. Init declarators
    contribute their LHS as a def and their RHS as the surface for
    uses / call_sites. Plain declarations contribute only defs.
    """
    defs: Set[str] = set()
    uses_acc: Set[str] = set()
    calls_acc: Set[str] = set()
    cs_acc: List[CallSite] = []
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
        elif child.type == _IDENT or child.type == _POINTER_DECLARATOR:
            # ``int x;`` — declarator with no initialiser
            name = _innermost_ident(child)
            if name is not None:
                defs.add(name)
        # type_identifier etc. — not a name event
    return (frozenset(calls_acc), frozenset(defs), frozenset(uses_acc),
            tuple(cs_acc))


def _payload_from_assignment(expr) -> Tuple[FrozenSet[str], FrozenSet[str],
                                             FrozenSet[str], Tuple[CallSite, ...]]:
    """``x = f(y);`` / ``x += f(y);`` — defs={x}, RHS feeds uses + call_sites.

    Compound LHSes (``a.b = ...``, ``arr[i] = ...``) contribute the
    base name only as a def. Phase 10's ``may_escape`` policy
    handles the through-indirection write semantics."""
    lhs = expr.child_by_field_name("left")
    rhs = expr.child_by_field_name("right")
    op_node = expr.child_by_field_name("operator")
    op = _node_text(op_node) if op_node is not None else "="
    lhs_name = _innermost_ident(lhs) if lhs is not None else None
    defs = frozenset({lhs_name}) if lhs_name is not None else frozenset()
    uses_acc: Set[str] = set()
    calls_acc: Set[str] = set()
    cs_acc: List[CallSite] = []
    # Compound assignment (``+=``, ``-=``, ...) reads the LHS too.
    if op != "=" and lhs_name is not None:
        uses_acc.add(lhs_name)
    if rhs is not None:
        assigned = defs if op == "=" else frozenset()
        cs_acc.extend(
            _walk_subtree_for_call_sites(rhs, assigned_for_root=assigned)
        )
        calls_acc |= _walk_subtree_for_calls(rhs)
        uses_acc |= _walk_subtree_for_uses(rhs)
    # The LHS may also contain uses — e.g. ``arr[i] = ...`` reads
    # ``arr`` and ``i``. Walk it but exclude the bare LHS target.
    if lhs is not None and lhs.type != _IDENT:
        uses_acc |= _walk_subtree_for_uses(lhs)
    return (frozenset(calls_acc), defs, frozenset(uses_acc), tuple(cs_acc))


def _payload_from_subtree(n) -> Tuple[FrozenSet[str], FrozenSet[str],
                                       FrozenSet[str], Tuple[CallSite, ...]]:
    """Fall-through payload extractor for expression-only statements:
    ``return f(x);``, ``if (cond)``, plain expression statements,
    switch subjects, etc. No defs (no LHS); every identifier feeds
    uses; every call_expression feeds call_sites + calls.
    """
    if n is None:
        return (frozenset(), frozenset(), frozenset(), ())
    return (
        _walk_subtree_for_calls(n),
        frozenset(),
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
        for child in cur.children:
            if child.is_named:
                stack.append(child)
    return None


def _function_name(fn_def) -> Optional[str]:
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


def _function_params(fn_def) -> Tuple[str, ...]:
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
    names: List[str] = []
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


# ---------------------------------------------------------------------------
# CFG builder
# ---------------------------------------------------------------------------


class _CPPCFGBuilder:
    """Stateful walker. Same shape as
    :class:`core.inventory.cfg_builder._PythonCFGBuilder`: each
    ``_build_*`` takes an incoming-predecessor list and returns the
    outgoing-successor list, the structured-block CFG idiom."""

    def __init__(self, function_name: str, file_path: str, language: str):
        self.function_name = function_name
        self.file_path = file_path
        self.language = language
        self.entry = CPPCFGNode(
            kind="entry", lineno=ENTRY_LINENO,
            label=f"ENTRY:{function_name}",
        )
        self.exit = CPPCFGNode(
            kind="exit", lineno=EXIT_LINENO,
            label=f"EXIT:{function_name}",
        )
        self._adjacency: Dict[CPPCFGNode, List[CPPCFGNode]] = {}
        self._all_nodes: List[CPPCFGNode] = [self.entry, self.exit]
        # Loop context stack: (break_target, continue_target).
        self._loop_stack: List[Tuple[CPPCFGNode, CPPCFGNode]] = []
        # switch context stack: (break_target, fallthrough-from-prev-case)
        # The break target is the join AFTER the switch.
        self._switch_stack: List[CPPCFGNode] = []
        # Goto resolution: collect (goto_node, label_text) for a
        # post-pass once all labels are known. Conservative: every
        # labeled_statement with a matching label receives an edge
        # from the goto.
        self._gotos: List[Tuple[CPPCFGNode, str]] = []
        self._labels: Dict[str, CPPCFGNode] = {}
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
        calls: FrozenSet[str] = frozenset(),
        defs: FrozenSet[str] = frozenset(),
        uses: FrozenSet[str] = frozenset(),
        call_sites: Tuple[CallSite, ...] = (),
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

    def _short_label(self, n) -> str:
        # Use just the first 60 chars of the source span for the label.
        text = _node_text(n).split("\n", 1)[0].strip()
        return text[:60] + ("…" if len(text) > 60 else "")

    def _build_stmts(
        self, body, incoming: List[CPPCFGNode],
    ) -> List[CPPCFGNode]:
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
        self, stmt, incoming: List[CPPCFGNode],
    ) -> List[CPPCFGNode]:
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

    def _straight_node(self, stmt) -> CPPCFGNode:
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
                calls, defs, uses, css = _payload_from_assignment(inner)
            else:
                calls, defs, uses, css = _payload_from_subtree(inner)
        else:
            calls, defs, uses, css = _payload_from_subtree(stmt)
        return self._make_node(
            kind="stmt", lineno=stmt.start_point[0] + 1,
            label=self._short_label(stmt),
            calls=calls, defs=defs, uses=uses, call_sites=css,
            may_escape=_subtree_has_indirection(stmt),
        )

    # ----- compound constructs -----

    def _build_if(self, stmt, incoming):
        cond = stmt.child_by_field_name("condition")
        calls, defs, uses, css = _payload_from_subtree(cond)
        cond_node = self._make_node(
            kind="stmt", lineno=stmt.start_point[0] + 1,
            label="if " + self._short_label(cond) if cond is not None else "if",
            calls=calls, defs=defs, uses=uses, call_sites=css,
            may_escape=_subtree_has_indirection(cond),
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
            else_out: List[CPPCFGNode] = [cond_node]
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

    def _build_while(self, stmt, incoming):
        cond = stmt.child_by_field_name("condition")
        calls, defs, uses, css = _payload_from_subtree(cond)
        header = self._make_node(
            kind="stmt", lineno=stmt.start_point[0] + 1,
            label="while " + self._short_label(cond) if cond is not None else "while",
            calls=calls, defs=defs, uses=uses, call_sites=css,
            may_escape=_subtree_has_indirection(cond),
        )
        self._link_many(incoming, header)
        after_loop: List[CPPCFGNode] = [header]
        self._loop_stack.append((header, header))
        body = stmt.child_by_field_name("body")
        body_out = self._build_stmts(body, [header]) if body is not None else []
        for tail in body_out:
            self._link(tail, header)
        self._loop_stack.pop()
        return after_loop

    def _build_for(self, stmt, incoming):
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
                may_escape=_subtree_has_indirection(cond),
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
                may_escape=_subtree_has_indirection(step),
            )
            self._link(step_node, header)
        else:
            step_node = header   # continue == loop back to header
        self._loop_stack.append((header, step_node))
        body_out = self._build_stmts(body, [header]) if body is not None else []
        for tail in body_out:
            self._link(tail, step_node)
        self._loop_stack.pop()
        return [header]

    def _build_do(self, stmt, incoming):
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
                may_escape=_subtree_has_indirection(cond),
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
        body_out = self._build_stmts(body, incoming) if body is not None else list(incoming)
        # Body falls through to tail (the cond test)
        self._link_many(body_out, tail)
        # Tail loops back to body entry. We don't have a direct
        # handle on body entry; the first stmt in body had `incoming`
        # as predecessor. Link tail → all predecessor-successors of
        # body — i.e. re-walk the body starting from tail. To keep
        # this finite, we explicitly add the edge tail → first body
        # node by linking tail to whatever incoming was used for body.
        # Simplest correct model: tail → header == body's first node.
        # We approximate by linking tail to every node whose only
        # predecessor was in incoming. For straight-line bodies that
        # is one node; for complex bodies (e.g. nested if) the
        # over-approximation is permissive and the vertex-cut still
        # works correctly.
        body_entry_candidates = [
            n for n, _ in self._adjacency.items()
            if any(succ for succ in self._adjacency.get(n, ())
                   if succ in body_out)
        ]
        for cand in body_entry_candidates:
            self._link(tail, cand)
        self._loop_stack.pop()
        return [tail]

    def _build_switch(self, stmt, incoming):
        subj = stmt.child_by_field_name("condition")
        calls, defs, uses, css = _payload_from_subtree(subj)
        header = self._make_node(
            kind="stmt", lineno=stmt.start_point[0] + 1,
            label="switch " + (self._short_label(subj) if subj is not None else ""),
            calls=calls, defs=defs, uses=uses, call_sites=css,
            may_escape=_subtree_has_indirection(subj),
        )
        self._link_many(incoming, header)
        # Join node — every break in the switch body links here; the
        # switch's overall successor is this join.
        join = self._make_node(
            kind="stmt", lineno=stmt.end_point[0] + 1,
            label="switch-join",
        )
        self._switch_stack.append(join)
        body = stmt.child_by_field_name("body")
        # Walk the body's children, grouping consecutive stmts by
        # case label. Each case_statement becomes a "branch" entry
        # from the header. Fallthrough = predecessors of stmt N+1
        # include stmt N when there's no break.
        case_groups: List[List[Any]] = []   # list of (stmt nodes)
        case_entries: List[List[Any]] = []  # case label statements
        if body is not None:
            current_group: List[Any] = []
            current_labels: List[Any] = []
            for child in body.children:
                if not child.is_named:
                    continue
                if child.type == _CASE:
                    # Close out current group, start a new one
                    if current_group or current_labels:
                        case_groups.append(current_group)
                        case_entries.append(current_labels)
                    current_group = []
                    current_labels = [child]
                else:
                    current_group.append(child)
            if current_group or current_labels:
                case_groups.append(current_group)
                case_entries.append(current_labels)
        # Now build each case.
        prev_out: List[CPPCFGNode] = []
        outs: List[CPPCFGNode] = []
        for labels, group in zip(case_entries, case_groups):
            # case label node(s) — model as one node per label.
            entry: List[CPPCFGNode] = [header] + prev_out
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
        self._switch_stack.pop()
        return [join]

    def _build_break(self, stmt, incoming):
        node = self._make_node(
            kind="stmt", lineno=stmt.start_point[0] + 1, label="break",
        )
        self._link_many(incoming, node)
        # Prefer the switch break target if we're inside one; otherwise
        # the loop break target.
        if self._switch_stack:
            self._link(node, self._switch_stack[-1])
        elif self._loop_stack:
            self._link(node, self._loop_stack[-1][0])
        return []

    def _build_continue(self, stmt, incoming):
        node = self._make_node(
            kind="stmt", lineno=stmt.start_point[0] + 1, label="continue",
        )
        self._link_many(incoming, node)
        if self._loop_stack:
            self._link(node, self._loop_stack[-1][1])
        return []

    def _build_goto(self, stmt, incoming):
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

    def _build_labeled(self, stmt, incoming):
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
        inner: Optional[Any] = None
        for c in stmt.children:
            if c.is_named and c is not label_node:
                inner = c
                break
        if inner is None:
            return [ln]
        return self._build_stmt(inner, [ln])

    # ----- driver -----

    def build(self, fn_def) -> CPPCFG:
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
        adjacency: Dict[CPPCFGNode, Tuple[CPPCFGNode, ...]] = {
            k: tuple(v) for k, v in self._adjacency.items()
        }
        seen: set = set()
        ordered: List[CPPCFGNode] = []
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
) -> Optional[CPPCFG]:
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
    tree = parser.parse(source_text.encode("utf-8", errors="replace"))
    fn_def = _find_function_definition(tree.root_node, function_name)
    if fn_def is None:
        return None
    builder = _CPPCFGBuilder(function_name, file_path, language)
    return builder.build(fn_def)
