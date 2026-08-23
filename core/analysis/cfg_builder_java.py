"""Java intra-procedural CFG builder — the Java leg of the sanitizer-cut arc.

Mirrors :mod:`core.analysis.cfg_builder_cpp`'s contract: a
:class:`JavaCFG` satisfying :class:`core.analysis.dominators.Graph`,
with per-statement nodes carrying ``defs`` / ``uses`` /
``call_sites`` / ``may_escape`` so
:func:`core.analysis.sanitizer_cut.evaluate_finding` consumes it with
no language branches.

Soundness posture (the vertex cut's failure direction is MISSING
edges — a real path absent from the model can make the cut look
complete while execution bypasses it):

* Constructs whose control flow the builder cannot faithfully
  enumerate cause the whole build to REFUSE (return ``None``):
  lambdas, method references, anonymous / local classes,
  pattern-matching ``switch`` labels (``case Integer i when …``),
  ``yield``, and ``switch`` used in VALUE position (its result
  feeding an expression). The resolver surfaces the refusal as a
  :class:`~core.analysis.finding_resolver.ResolutionFailure`, so the
  finding survives to the LLM — never a silent wrong graph.
* Statement-position ``switch`` IS modelled: classic groups with
  fall-through (the tail of group N flows into group N+1 unless a
  jump terminates it — a missing fall-through edge is the
  false-suppression direction), arrow rules without fall-through,
  ``break`` targeting the switch's join node (not the enclosing
  loop), and a missing ``default`` adding the condition → join edge.
  When the discriminant and every case label fold to compile-time
  constants (:mod:`core.analysis.const_fold_java` over the built
  graph's reaching definitions), the condition's edges to the
  non-selected groups are PRUNED — proof-backed dead-branch removal,
  the switch analog of the dead-branch ternary. Any refusal along
  the way keeps every edge (sound over-approximation) and is
  recorded in :attr:`JavaCFG.build_notes`.
* ``try`` / ``catch`` / ``finally`` is modelled with LIBERAL edges:
  every statement in a ``try`` body gets an edge to every catch
  handler's entry (any statement may throw). Extra edges only add
  paths, which can only make suppression harder — conservative.
* Labeled ``break`` / ``continue`` refuse the build (rare, and a
  mis-targeted jump edge is a missing-path hazard); the unlabeled
  forms target the innermost loop like the C builder.

``may_escape`` (alias conservatism, mirroring the C leg's policy —
every Java object access is through a reference, so a field STORE is
the analog of C's ``->`` write):

* ``array_access`` anywhere in the statement (element aliasing);
* a field STORE (``obj.f = …`` / ``this.f = …``) — writes through a
  reference an alias may observe; plain field READS contribute the
  base name as a use and are not an escape (same as C's ``.`` rule);
* ``System.arraycopy`` calls (the bulk-copy analog).

Callable names are emitted FQN-RESOLVED against the file's explicit
imports so the sanitizer catalog can key on fully-qualified names:
``Encode.forHtml(x)`` under ``import org.owasp.encoder.Encode``
surfaces as ``org.owasp.encoder.Encode.forHtml``. Wildcard imports
resolve nothing (conservative — an unresolved name cannot match the
catalog, so it can never suppress). The chained singleton idiom
``ESAPI.encoder().encodeForHTML(x)`` surfaces with an explicit call
marker: ``org.owasp.esapi.ESAPI.encoder().encodeForHTML`` — only that
exact static-chain shape matches; an instance call
``enc.encodeForHTML(x)`` stays unresolved (no type inference, so no
suppression through it).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import (
    Any,
)
from collections.abc import Iterable, Mapping

from core.analysis.cfg_builder import (
    ENTRY_LINENO,
    EXIT_LINENO,
    CallSite,
)
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tree_sitter import Node

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Node / graph types — same contract as CPPCFGNode / CPPCFG
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class JavaCFGNode:
    """One node of a Java method's control-flow graph. Field contract
    identical to :class:`core.analysis.cfg_builder_cpp.CPPCFGNode`."""
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
            f"JavaCFGNode({self.kind}, L{self.lineno}, "
            f"{self.label!r}, defs={set(self.defs)!r}, "
            f"uses={set(self.uses)!r})"
        )


@dataclass(frozen=True)
class JavaCFG:
    """Concrete Graph for one Java method / constructor."""
    function_name: str
    file_path: str
    language: str
    entry_node: JavaCFGNode
    exit_node: JavaCFGNode
    _nodes: tuple[JavaCFGNode, ...]
    _adjacency: dict[JavaCFGNode, tuple[JavaCFGNode, ...]]
    params: tuple[str, ...] = ()
    # Mechanism telemetry: which optional modelling steps fired
    # ("switch:constant-resolved", "switch:all-branches", …). Additive
    # — consumers must tolerate an empty tuple.
    build_notes: tuple[str, ...] = ()

    @property
    def entry(self) -> JavaCFGNode:
        return self.entry_node

    def nodes(self) -> Iterable[JavaCFGNode]:
        return self._nodes

    def successors(self, node: JavaCFGNode) -> Iterable[JavaCFGNode]:
        return self._adjacency.get(node, ())


# ---------------------------------------------------------------------------
# Tree-sitter wiring
# ---------------------------------------------------------------------------


def _get_parser():
    """Lazy-load the tree-sitter Java parser; ``None`` when the
    grammar isn't installed (degrade-cleanly, same as the C leg)."""
    try:
        import tree_sitter_java as ts_lang
        from core.inventory.call_graph import _get_ts_parser
        return _get_ts_parser(ts_lang.language)
    except ImportError:
        return None


_METHOD_DECL = "method_declaration"
_CTOR_DECL = "constructor_declaration"
_BLOCK = "block"
_CTOR_BODY = "constructor_body"

_IF = "if_statement"
_WHILE = "while_statement"
_FOR = "for_statement"
_ENHANCED_FOR = "enhanced_for_statement"
_DO = "do_statement"
_RETURN = "return_statement"
_BREAK = "break_statement"
_CONTINUE = "continue_statement"
_THROW = "throw_statement"
_TRY = "try_statement"
_TRY_WITH_RES = "try_with_resources_statement"
_SYNCHRONIZED = "synchronized_statement"
_LABELED = "labeled_statement"

_EXPR_STMT = "expression_statement"
_LOCAL_VAR_DECL = "local_variable_declaration"
_VAR_DECLARATOR = "variable_declarator"
_ASSIGNMENT = "assignment_expression"
_UPDATE = "update_expression"
_METHOD_INVOCATION = "method_invocation"
_OBJECT_CREATION = "object_creation_expression"
_FIELD_ACCESS = "field_access"
_ARRAY_ACCESS = "array_access"
_IDENT = "identifier"
_CAST = "cast_expression"
_PARENS = "parenthesized_expression"

# Constructs the builder REFUSES (soundness: their control/data flow
# can't be faithfully modelled intra-procedurally). switch stays in
# this set so a switch nested in VALUE position (inside any
# expression payload) refuses via _subtree_has_refused; statement-
# position switch is dispatched to _build_switch BEFORE this check.
_REFUSED_NODE_TYPES = frozenset({
    "lambda_expression",
    "method_reference",
    "switch_expression",
    "switch_statement",
    "class_declaration",         # local class inside a method body
    "anonymous_class_body",      # older grammar name
})

_SWITCH_TYPES = ("switch_expression", "switch_statement")
_SWITCH_GROUP = "switch_block_statement_group"
_SWITCH_RULE = "switch_rule"
_SWITCH_LABEL = "switch_label"
_YIELD = "yield_statement"

# Bulk-copy analog: writes through a destination reference the value
# gate can't follow.
_BULK_COPY_CALLS = frozenset({"System.arraycopy"})


# ---------------------------------------------------------------------------
# Import table — FQN resolution for callable names
# ---------------------------------------------------------------------------


def _node_text(n) -> str:
    return n.text.decode("utf-8", errors="replace") if n is not None else ""


def build_import_map(root) -> tuple[Mapping[str, str], Mapping[str, str]]:
    """Parse the compilation unit's import declarations.

    Returns ``(type_imports, static_imports)``:

    * ``type_imports``:   simple class name → FQN
      (``Encode`` → ``org.owasp.encoder.Encode``)
    * ``static_imports``: simple member name → FQN
      (``forHtml`` → ``org.owasp.encoder.Encode.forHtml``)

    Wildcard imports are skipped — an unresolvable simple name stays
    unresolved and can never match a catalog FQN (conservative).
    """
    types: dict[str, str] = {}
    statics: dict[str, str] = {}
    for child in root.children:
        if child.type != "import_declaration":
            continue
        is_static = any(
            (not c.is_named) and _node_text(c) == "static"
            for c in child.children
        )
        has_wildcard = any(c.type == "asterisk" for c in child.children)
        if has_wildcard:
            continue
        scoped = next(
            (c for c in child.children if c.type == "scoped_identifier"),
            None,
        )
        if scoped is None:
            continue
        fqn = _node_text(scoped)
        simple = fqn.rsplit(".", 1)[-1]
        if is_static:
            statics[simple] = fqn
        else:
            types[simple] = fqn
    return types, statics


# ---------------------------------------------------------------------------
# Expression helpers
# ---------------------------------------------------------------------------


def _unwrap_value_expr(n):
    """Strip casts and parens without changing symbol identity."""
    cur = n
    while cur is not None:
        if cur.type == _CAST:
            val = cur.child_by_field_name("value")
            if val is None:
                return cur
            cur = val
            continue
        if cur.type == _PARENS:
            inner = next((c for c in cur.children if c.is_named), None)
            if inner is None:
                return cur
            cur = inner
            continue
        return cur
    return n


def _base_ident(n: Node) -> str | None:
    """Leftmost identifier: ``a.b.c`` → ``a``; ``arr[i]`` → ``arr``."""
    if n is None:
        return None
    if n.type == _IDENT:
        return _node_text(n)
    if n.type == _FIELD_ACCESS:
        return _base_ident(n.child_by_field_name("object"))
    if n.type == _ARRAY_ACCESS:
        return _base_ident(n.child_by_field_name("array"))
    for c in n.children:
        if c.is_named:
            r = _base_ident(c)
            if r is not None:
                return r
    return None


def _dotted_chain(n: Node) -> str | None:
    """Render an identifier / field_access chain as a dotted string.
    ``org.owasp.esapi.ESAPI`` (parsed as nested field_access) →
    ``"org.owasp.esapi.ESAPI"``. Anything else → None."""
    if n is None:
        return None
    if n.type == _IDENT:
        return _node_text(n)
    if n.type == _FIELD_ACCESS:
        obj = _dotted_chain(n.child_by_field_name("object"))
        field = n.child_by_field_name("field")
        if obj is not None and field is not None:
            return f"{obj}.{_node_text(field)}"
    return None


class _NameResolver:
    """FQN-resolves callable names against the file's imports."""

    def __init__(self, type_imports: Mapping[str, str],
                 static_imports: Mapping[str, str]) -> None:
        self.types = dict(type_imports)
        self.statics = dict(static_imports)

    def _resolve_chain(self, chain: str) -> str:
        head, _, rest = chain.partition(".")
        fqn = self.types.get(head)
        if fqn is not None:
            return f"{fqn}.{rest}" if rest else fqn
        return chain

    def callable_name(self, invocation: Node) -> str | None:
        """Resolved dotted name for one ``method_invocation`` (or
        ``object_creation_expression`` → ``new <Type>``)."""
        if invocation.type == _OBJECT_CREATION:
            ty = invocation.child_by_field_name("type")
            ty_text = _node_text(ty) if ty is not None else None
            if not ty_text:
                return None
            return "new " + self.types.get(ty_text, ty_text)
        name_node = invocation.child_by_field_name("name")
        if name_node is None:
            return None
        simple = _node_text(name_node)
        obj = invocation.child_by_field_name("object")
        if obj is None:
            # Bare call — resolves only via a static import.
            fqn = self.statics.get(simple)
            return fqn if fqn is not None else simple
        obj = _unwrap_value_expr(obj)
        if obj.type == _METHOD_INVOCATION:
            # Chained call: mark the receiver as a CALL explicitly so
            # only the exact static-chain idiom can match a catalog
            # key (``…ESAPI.encoder().encodeForHTML``).
            inner = self.callable_name(obj)
            if inner is None:
                return None
            return f"{inner}().{simple}"
        if obj.type == _OBJECT_CREATION:
            # Instance-creation receiver (``new Helper().m(...)``):
            # carries the explicit call marker so it can never collide
            # with a static-chain catalog key, and so the wrapper
            # binder can match the exact idiom.
            inner = self.callable_name(obj)
            if inner is None:
                return None
            return f"{inner}().{simple}"
        chain = _dotted_chain(obj)
        if chain is None:
            return None
        return f"{self._resolve_chain(chain)}.{simple}"


def _arg_surface_names(invocation: Node) -> frozenset[str]:
    """Bare-name surface of a call's arguments — identifiers and the
    base of field / array accesses; nested calls, literals, binary
    expressions contribute nothing (same under-count rationale as the
    C leg)."""
    args = invocation.child_by_field_name("arguments")
    if args is None:
        return frozenset()
    names: set[str] = set()
    for child in args.children:
        if not child.is_named:
            continue
        unwrapped = _unwrap_value_expr(child)
        if unwrapped.type == _IDENT:
            names.add(_node_text(unwrapped))
        elif unwrapped.type in (_FIELD_ACCESS, _ARRAY_ACCESS):
            base = _base_ident(unwrapped)
            if base is not None:
                names.add(base)
    return frozenset(names)


def _arg_deep_names(invocation: Node, resolver) -> frozenset[str]:
    """Names referenced anywhere inside the call's argument subtrees —
    the sink-arg fallback surface (see CallSite.arg_deep_names).
    Reuses the load-position walker, so callee names are excluded and
    static-class receivers don't count as value uses."""
    args = invocation.child_by_field_name("arguments")
    if args is None:
        return frozenset()
    names: set[str] = set()
    for child in args.children:
        if child.is_named:
            names |= _walk_uses(child, resolver)
    return frozenset(names)


def _walk_uses(n, resolver, *, exclude: set | None = None) -> frozenset[str]:
    """Identifiers in load position: callee names are excluded (they
    become call sites), field/array accesses contribute their base."""
    if exclude is None:
        exclude = set()
    out: set[str] = set()
    stack = [n] if n is not None else []
    while stack:
        cur = stack.pop()
        t = cur.type
        if t in (_METHOD_INVOCATION, _OBJECT_CREATION):
            obj = cur.child_by_field_name("object")
            if obj is not None:
                obj_u = _unwrap_value_expr(obj)
                # A static-class receiver (import-resolved or dotted
                # package chain) is a namespace, not a value use; a
                # plain-variable / chained receiver is a value use.
                if obj_u.type == _IDENT and _node_text(obj_u) not in resolver.types:
                    out.add(_node_text(obj_u))
                elif obj_u.type in (_METHOD_INVOCATION, _OBJECT_CREATION):
                    # A chained-call or instance-creation receiver can
                    # carry value uses in ITS argument subtrees
                    # (``new Helper(x).m(y)``) — walk it. Conservative
                    # direction: more uses = more visible taint.
                    stack.append(obj_u)
            args = cur.child_by_field_name("arguments")
            if args is not None:
                stack.extend(c for c in args.children if c.is_named)
            continue
        if t == _IDENT:
            key = (cur.start_byte, cur.end_byte)
            if key not in exclude:
                out.add(_node_text(cur))
            continue
        if t == _FIELD_ACCESS:
            base = _base_ident(cur)
            if base is not None and base not in resolver.types:
                out.add(base)
            continue
        stack.extend(c for c in cur.children if c.is_named)
    return frozenset(out)


def _walk_call_sites(
    n, resolver, *, assigned_for_root: frozenset[str] = frozenset(),
) -> tuple[CallSite, ...]:
    """Every call in ``n`` as :class:`CallSite`, sorted so
    ``call_sites[-1]`` is the syntactic outermost (end-byte order,
    matching both existing builders)."""
    out: list[tuple[int, int, CallSite]] = []
    root_id = id(_unwrap_value_expr(n)) if n is not None else None

    def visit(node: Node) -> None:
        if node.type in (_METHOD_INVOCATION, _OBJECT_CREATION):
            name = resolver.callable_name(node)
            is_root = id(node) == root_id or \
                id(_unwrap_value_expr(node)) == root_id
            assigned = assigned_for_root if is_root else frozenset()
            if name is not None:
                out.append((node.end_byte, id(node), CallSite(
                    name=name,
                    arg_names=_arg_surface_names(node),
                    assigned_names=assigned,
                    lineno=node.start_point[0] + 1,
                    col_offset=node.start_point[1],
                    arg_deep_names=_arg_deep_names(node, resolver),
                )))
            obj = node.child_by_field_name("object")
            if obj is not None and _unwrap_value_expr(obj).type in (
                    _METHOD_INVOCATION, _OBJECT_CREATION):
                visit(_unwrap_value_expr(obj))
            args = node.child_by_field_name("arguments")
            if args is not None:
                for c in args.children:
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


def _subtree_may_escape(n, resolver) -> bool:
    """Java escape policy: array_access anywhere; field STORE
    (assignment whose LHS is a field_access); System.arraycopy."""
    if n is None:
        return False
    stack = [n]
    while stack:
        cur = stack.pop()
        t = cur.type
        if t == _ARRAY_ACCESS:
            return True
        if t == _ASSIGNMENT:
            lhs = cur.child_by_field_name("left")
            if lhs is not None and lhs.type == _FIELD_ACCESS:
                return True
        if t == _METHOD_INVOCATION:
            name = resolver.callable_name(cur)
            if name in _BULK_COPY_CALLS:
                return True
        stack.extend(c for c in cur.children if c.is_named)
    return False


def _subtree_has_refused(n) -> bool:
    if n is None:
        return False
    stack = [n]
    while stack:
        cur = stack.pop()
        if cur.type in _REFUSED_NODE_TYPES:
            return True
        stack.extend(c for c in cur.children if c.is_named)
    return False


# ---------------------------------------------------------------------------
# Statement payloads
# ---------------------------------------------------------------------------


def _payload_from_local_var_decl(decl, resolver):
    defs: set[str] = set()
    uses: set[str] = set()
    calls: set[str] = set()
    css: list[CallSite] = []
    for child in decl.children:
        if child.type != _VAR_DECLARATOR:
            continue
        name_node = child.child_by_field_name("name")
        tgt = _node_text(name_node) if name_node is not None else None
        if tgt:
            defs.add(tgt)
        val = child.child_by_field_name("value")
        if val is not None:
            assigned = frozenset({tgt}) if tgt else frozenset()
            css.extend(_walk_call_sites(
                val, resolver, assigned_for_root=assigned))
            uses |= _walk_uses(val, resolver)
    calls = {cs.name for cs in css}
    return frozenset(calls), frozenset(defs), frozenset(uses), tuple(css)


def _payload_from_assignment(expr: Node, resolver):
    lhs = expr.child_by_field_name("left")
    rhs = expr.child_by_field_name("right")
    op_node = expr.child_by_field_name("operator")
    op = _node_text(op_node) if op_node is not None else "="
    lhs_name = _base_ident(lhs) if lhs is not None else None
    defs = frozenset({lhs_name}) if lhs_name else frozenset()
    uses: set[str] = set()
    css: list[CallSite] = []
    if op != "=" and lhs_name:
        uses.add(lhs_name)
    if rhs is not None:
        # Assignment through a field / array LHS is NOT a clean
        # rebinding of the base name — the sanitizer-output identity
        # doesn't transfer. Only a plain-identifier LHS earns
        # assigned_names (may_escape additionally covers the store).
        clean_lhs = lhs is not None and lhs.type == _IDENT and op == "="
        assigned = defs if clean_lhs else frozenset()
        css.extend(_walk_call_sites(rhs, resolver, assigned_for_root=assigned))
        uses |= _walk_uses(rhs, resolver)
    if lhs is not None and lhs.type != _IDENT:
        uses |= _walk_uses(lhs, resolver)
    calls = {cs.name for cs in css}
    return frozenset(calls), defs, frozenset(uses), tuple(css)


def _payload_from_subtree(n, resolver):
    if n is None:
        return frozenset(), frozenset(), frozenset(), ()
    css = _walk_call_sites(n, resolver)
    return (
        frozenset({cs.name for cs in css}),
        frozenset(),
        _walk_uses(n, resolver),
        css,
    )


# ---------------------------------------------------------------------------
# Method discovery
# ---------------------------------------------------------------------------


def _method_name(decl: Node) -> str | None:
    n = decl.child_by_field_name("name")
    return _node_text(n) if n is not None else None


def _method_params(decl) -> tuple[str, ...]:
    params = decl.child_by_field_name("parameters")
    if params is None:
        return ()
    out: list[str] = []
    for p in params.children:
        if p.type not in ("formal_parameter", "spread_parameter"):
            continue
        name_node = p.child_by_field_name("name")
        if name_node is None:
            # spread_parameter nests its name inside a
            # variable_declarator.
            decl = next(
                (c for c in p.children if c.type == _VAR_DECLARATOR), None)
            if decl is not None:
                name_node = decl.child_by_field_name("name")
        if name_node is not None:
            out.append(_node_text(name_node))
    return tuple(out)


def find_enclosing_method(
    source_text: str, source_line: int, sink_line: int,
) -> tuple[str | None, int]:
    """Smallest method / constructor declaration spanning
    [source_line, sink_line]. Returns ``(name, header_line)`` or
    ``(None, 0)``."""
    parser = _get_parser()
    if parser is None:
        return None, 0
    tree = parser.parse(source_text.encode("utf-8", errors="replace"))
    lo, hi = min(source_line, sink_line), max(source_line, sink_line)
    best: tuple[int, str, int] | None = None
    stack = [tree.root_node]
    while stack:
        cur = stack.pop()
        if cur.type in (_METHOD_DECL, _CTOR_DECL):
            start = cur.start_point[0] + 1
            end = cur.end_point[0] + 1
            if start <= lo and hi <= end:
                name = _method_name(cur)
                if name is not None:
                    span = end - start
                    if best is None or span < best[0]:
                        best = (span, name, start)
        stack.extend(c for c in cur.children if c.is_named)
    if best is None:
        return None, 0
    return best[1], best[2]


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------


class _RefusedConstruct(Exception):
    """Internal: body contains a construct the builder refuses."""


class _JavaCFGBuilder:
    def __init__(self, function_name: str, file_path: str,
                 resolver: _NameResolver) -> None:
        self.function_name = function_name
        self.file_path = file_path
        self.resolver = resolver
        self.entry = JavaCFGNode(
            kind="entry", lineno=ENTRY_LINENO,
            label=f"ENTRY:{function_name}",
        )
        self.exit = JavaCFGNode(
            kind="exit", lineno=EXIT_LINENO,
            label=f"EXIT:{function_name}",
        )
        self._adjacency: dict[JavaCFGNode, list[JavaCFGNode]] = {}
        self._all_nodes: list[JavaCFGNode] = [self.entry, self.exit]
        self._loop_stack: list[tuple[JavaCFGNode, JavaCFGNode]] = []
        # Unlabeled ``break`` targets: loops push their header,
        # switches push their join node — Java's break exits the
        # innermost of EITHER, unlike continue which is loop-only.
        self._break_targets: list[JavaCFGNode] = []
        # Ambient catch entries for liberal try-edge wiring.
        self._catch_entry_stack: list[list[JavaCFGNode]] = []
        self._dedupe_counter = 0
        # (cond_node, disc_ts_node, [(entry, label_nodes, is_default)],
        #  join_node) per modelled switch — consumed by the post-build
        # constant-discriminant refinement.
        self._switch_records: list[tuple] = []
        # (cond_node, cond_ts_node, catch_succ_snapshot,
        #  then_entries, else_entries, has_alt) per modelled if —
        # consumed by the post-build constant-condition refinement.
        self._if_records: list[tuple] = []
        self.build_notes: list[str] = []

    # ----- plumbing -----

    def _link(self, src, dst) -> None:
        self._adjacency.setdefault(src, []).append(dst)

    def _link_many(self, srcs, dst) -> None:
        for s in srcs:
            self._link(s, dst)

    def _make_node(self, *, lineno, label, calls=frozenset(),
                   defs=frozenset(), uses=frozenset(), call_sites=(),
                   may_escape: bool=False) -> JavaCFGNode:
        node = JavaCFGNode(
            kind="stmt", lineno=lineno, label=label, calls=calls,
            defs=defs, uses=uses, call_sites=call_sites,
            may_escape=may_escape,
        )
        if node in self._adjacency or node in self._all_nodes:
            self._dedupe_counter += 1
            node = JavaCFGNode(
                kind="stmt", lineno=lineno,
                label=f"{label} #{self._dedupe_counter}", calls=calls,
                defs=defs, uses=uses, call_sites=call_sites,
                may_escape=may_escape,
            )
        self._all_nodes.append(node)
        return node

    def _short_label(self, n) -> str:
        text = _node_text(n).split("\n", 1)[0].strip()
        return text[:60] + ("…" if len(text) > 60 else "")

    def _ambient_catch_link(self, node: JavaCFGNode) -> None:
        """Liberal try-edge: any statement inside a try body may
        transfer to each enclosing catch handler."""
        for handlers in self._catch_entry_stack:
            for h in handlers:
                self._link(node, h)

    # ----- statements -----

    def _build_stmts(self, body, incoming):
        if isinstance(body, list):
            stmts = body
        elif body.type in (_BLOCK, _CTOR_BODY):
            stmts = [c for c in body.children if c.is_named]
        else:
            return self._build_stmt(body, incoming)
        cursor = incoming
        for stmt in stmts:
            cursor = self._build_stmt(stmt, cursor)
        return cursor

    def _build_stmt(self, stmt: Node, incoming):
        t = stmt.type
        # Statement-position switch is modelled; expression_statement-
        # wrapped switch is the same statement position in older
        # grammars. Value-position switch still refuses via the
        # _REFUSED_NODE_TYPES check below / _subtree_has_refused.
        if t in _SWITCH_TYPES:
            return self._build_switch(stmt, incoming)
        if t == _EXPR_STMT:
            inner = next((c for c in stmt.children if c.is_named), None)
            if inner is not None and inner.type in _SWITCH_TYPES:
                return self._build_switch(inner, incoming)
        if t in _REFUSED_NODE_TYPES:
            raise _RefusedConstruct(t)
        if t == _IF:
            return self._build_if(stmt, incoming)
        if t == _WHILE:
            return self._build_while(stmt, incoming)
        if t == _FOR:
            return self._build_for(stmt, incoming)
        if t == _ENHANCED_FOR:
            return self._build_enhanced_for(stmt, incoming)
        if t == _DO:
            return self._build_do(stmt, incoming)
        if t in (_TRY, _TRY_WITH_RES):
            return self._build_try(stmt, incoming)
        if t == _RETURN:
            node = self._straight_node(stmt)
            self._link_many(incoming, node)
            self._ambient_catch_link(node)
            self._link(node, self.exit)
            return []
        if t == _THROW:
            node = self._straight_node(stmt)
            self._link_many(incoming, node)
            self._ambient_catch_link(node)
            self._link(node, self.exit)
            return []
        if t == _BREAK:
            return self._build_break(stmt, incoming)
        if t == _CONTINUE:
            return self._build_continue(stmt, incoming)
        if t == _LABELED:
            # Labeled statements pair with labeled break/continue —
            # refused for soundness (see module docstring).
            raise _RefusedConstruct(_LABELED)
        if t == _SYNCHRONIZED:
            body = stmt.child_by_field_name("body")
            return self._build_stmts(body, incoming) \
                if body is not None else incoming
        if t == _BLOCK:
            return self._build_stmts(stmt, incoming)
        node = self._straight_node(stmt)
        self._link_many(incoming, node)
        self._ambient_catch_link(node)
        return [node]

    def _straight_node(self, stmt: Node) -> JavaCFGNode:
        if _subtree_has_refused(stmt):
            raise _RefusedConstruct(stmt.type)
        t = stmt.type
        if t == _LOCAL_VAR_DECL:
            calls, defs, uses, css = _payload_from_local_var_decl(
                stmt, self.resolver)
        elif t == _EXPR_STMT:
            inner = next((c for c in stmt.children if c.is_named), None)
            if inner is not None and inner.type == _ASSIGNMENT:
                calls, defs, uses, css = _payload_from_assignment(
                    inner, self.resolver)
            elif inner is not None and inner.type == _UPDATE:
                tgt = _base_ident(inner)
                defs = frozenset({tgt}) if tgt else frozenset()
                uses = defs
                calls, css = frozenset(), ()
            else:
                calls, defs, uses, css = _payload_from_subtree(
                    inner, self.resolver)
        else:
            calls, defs, uses, css = _payload_from_subtree(
                stmt, self.resolver)
        return self._make_node(
            lineno=stmt.start_point[0] + 1,
            label=self._short_label(stmt),
            calls=calls, defs=defs, uses=uses, call_sites=css,
            may_escape=_subtree_may_escape(stmt, self.resolver),
        )

    def _cond_node(self, stmt: Node, prefix: str) -> JavaCFGNode:
        cond = stmt.child_by_field_name("condition")
        if _subtree_has_refused(cond):
            msg = "condition"
            raise _RefusedConstruct(msg)
        calls, defs, uses, css = _payload_from_subtree(cond, self.resolver)
        return self._make_node(
            lineno=stmt.start_point[0] + 1,
            label=f"{prefix} {self._short_label(cond)}" if cond is not None
            else prefix,
            calls=calls, defs=defs, uses=uses, call_sites=css,
            may_escape=_subtree_may_escape(cond, self.resolver),
        )

    def _build_if(self, stmt: Node, incoming):
        cond_node = self._cond_node(stmt, "if")
        self._link_many(incoming, cond_node)
        self._ambient_catch_link(cond_node)
        # Successor snapshots bracket each branch build so the
        # refinement can tell branch-entry edges apart from the
        # ambient catch edges (never prunable — the condition itself
        # may throw) and the caller-added fall-through edge.
        base_succ = tuple(self._adjacency.get(cond_node, ()))
        conseq = stmt.child_by_field_name("consequence")
        alt = stmt.child_by_field_name("alternative")
        then_out = self._build_stmts(conseq, [cond_node]) \
            if conseq is not None else [cond_node]
        after_then = tuple(self._adjacency.get(cond_node, ()))
        else_out = self._build_stmts(alt, [cond_node]) \
            if alt is not None else [cond_node]
        after_else = tuple(self._adjacency.get(cond_node, ()))
        then_entries = frozenset(after_then) - frozenset(base_succ)
        else_entries = frozenset(after_else) - frozenset(after_then)
        self._if_records.append((
            cond_node, stmt.child_by_field_name("condition"),
            frozenset(base_succ), then_entries, else_entries,
            alt is not None,
        ))
        return then_out + else_out

    def _build_while(self, stmt: Node, incoming):
        header = self._cond_node(stmt, "while")
        self._link_many(incoming, header)
        self._ambient_catch_link(header)
        after = [header]
        self._loop_stack.append((header, header))
        self._break_targets.append(header)
        body = stmt.child_by_field_name("body")
        body_out = self._build_stmts(body, [header]) \
            if body is not None else []
        for tail in body_out:
            self._link(tail, header)
        self._loop_stack.pop()
        self._break_targets.pop()
        return after

    def _build_do(self, stmt: Node, incoming):
        # ``do body while (cond)`` — a synthetic loop-head node makes
        # the second-iteration back edge representable: incoming →
        # head → body… → cond → head (back edge) and cond → after.
        # Without the head→body path via the back edge, paths where
        # taint flows on iteration ≥2 would be missing from the graph
        # — a missing path is the unsound direction for the cut.
        head = self._make_node(
            lineno=stmt.start_point[0] + 1, label="do",
        )
        self._link_many(incoming, head)
        self._ambient_catch_link(head)
        header = self._cond_node(stmt, "do-while")
        self._loop_stack.append((header, head))
        self._break_targets.append(header)
        body = stmt.child_by_field_name("body")
        body_out = self._build_stmts(body, [head]) \
            if body is not None else [head]
        self._loop_stack.pop()
        self._break_targets.pop()
        self._link_many(body_out, header)
        self._ambient_catch_link(header)
        self._link(header, head)
        return [header]

    def _build_for(self, stmt: Node, incoming):
        init = stmt.child_by_field_name("init")
        cursor = incoming
        if init is not None:
            init_node = self._straight_node(init)
            self._link_many(cursor, init_node)
            self._ambient_catch_link(init_node)
            cursor = [init_node]
        header = self._cond_node(stmt, "for")
        self._link_many(cursor, header)
        self._ambient_catch_link(header)
        update = stmt.child_by_field_name("update")
        self._loop_stack.append((header, header))
        self._break_targets.append(header)
        body = stmt.child_by_field_name("body")
        body_out = self._build_stmts(body, [header]) \
            if body is not None else []
        if update is not None:
            upd_node = self._straight_node(update)
            self._link_many(body_out, upd_node)
            self._link(upd_node, header)
        else:
            for tail in body_out:
                self._link(tail, header)
        self._loop_stack.pop()
        self._break_targets.pop()
        return [header]

    def _build_enhanced_for(self, stmt: Node, incoming):
        # ``for (T i : expr) body`` — header defines the induction
        # variable and uses the iterable.
        name_node = stmt.child_by_field_name("name")
        value = stmt.child_by_field_name("value")
        if _subtree_has_refused(value):
            msg = "enhanced_for value"
            raise _RefusedConstruct(msg)
        var = _node_text(name_node) if name_node is not None else None
        calls, _d, uses, css = _payload_from_subtree(value, self.resolver)
        header = self._make_node(
            lineno=stmt.start_point[0] + 1,
            label=f"for {var} : {self._short_label(value)}",
            calls=calls,
            defs=frozenset({var}) if var else frozenset(),
            uses=uses, call_sites=css,
            may_escape=_subtree_may_escape(value, self.resolver),
        )
        self._link_many(incoming, header)
        self._ambient_catch_link(header)
        self._loop_stack.append((header, header))
        self._break_targets.append(header)
        body = stmt.child_by_field_name("body")
        body_out = self._build_stmts(body, [header]) \
            if body is not None else []
        for tail in body_out:
            self._link(tail, header)
        self._loop_stack.pop()
        self._break_targets.pop()
        return [header]

    def _build_try(self, stmt: Node, incoming):
        catches = [c for c in stmt.children if c.type == "catch_clause"]
        finally_clause = next(
            (c for c in stmt.children if c.type == "finally_clause"), None)
        # Catch entry nodes first, so try-body statements can link.
        catch_entries: list[JavaCFGNode] = []
        for cl in catches:
            param = next(
                (c for c in cl.children if c.type == "catch_formal_parameter"),
                None,
            )
            exc_name = None
            if param is not None:
                idents = [c for c in param.children if c.type == _IDENT]
                exc_name = _node_text(idents[-1]) if idents else None
            entry = self._make_node(
                lineno=cl.start_point[0] + 1,
                label=f"catch {self._short_label(param)}",
                defs=frozenset({exc_name}) if exc_name else frozenset(),
            )
            catch_entries.append(entry)

        # Resources (try-with-resources) are declarations preceding
        # the body.
        cursor = incoming
        resources = next(
            (c for c in stmt.children if c.type == "resource_specification"),
            None,
        )
        if resources is not None:
            for res in resources.children:
                if res.type == "resource":
                    node = self._straight_node(res)
                    self._link_many(cursor, node)
                    for h in catch_entries:
                        self._link(node, h)
                    cursor = [node]

        body = stmt.child_by_field_name("body")
        self._catch_entry_stack.append(catch_entries)
        # Incoming may ALSO reach a catch (the first body statement
        # throws before executing) — liberal edge from each incoming.
        for src in cursor:
            for h in catch_entries:
                self._link(src, h)
        body_out = self._build_stmts(body, cursor) \
            if body is not None else cursor
        self._catch_entry_stack.pop()

        # Catch bodies.
        catch_outs: list[JavaCFGNode] = []
        for cl, entry in zip(catches, catch_entries):
            cbody = cl.child_by_field_name("body")
            outs = self._build_stmts(cbody, [entry]) \
                if cbody is not None else [entry]
            catch_outs.extend(outs)

        join = body_out + catch_outs
        if finally_clause is not None:
            fbody = next(
                (c for c in finally_clause.children if c.type == _BLOCK),
                None,
            )
            if fbody is not None:
                join = self._build_stmts(fbody, join)
        return join

    def _build_break(self, stmt, incoming):
        if any(c.type == _IDENT for c in stmt.children):
            msg = "labeled break"
            raise _RefusedConstruct(msg)
        node = self._straight_node(stmt)
        self._link_many(incoming, node)
        if not self._break_targets:
            self._link(node, self.exit)
            return []
        # break exits the innermost loop OR switch: for a loop the
        # header stands in for the after-set (break must NOT re-test
        # the condition, but the extra edge is only an extra path —
        # conservative); for a switch the target is its join node.
        self._link(node, self._break_targets[-1])
        return []

    def _build_continue(self, stmt, incoming):
        if any(c.type == _IDENT for c in stmt.children):
            msg = "labeled continue"
            raise _RefusedConstruct(msg)
        node = self._straight_node(stmt)
        self._link_many(incoming, node)
        if not self._loop_stack:
            self._link(node, self.exit)
            return []
        self._link(node, self._loop_stack[-1][1])
        return []

    # ----- switch -----

    def _build_switch(self, stmt: Node, incoming):
        """Statement-position switch: classic groups with fall-through
        or arrow rules without; ``break`` targets the join node. The
        condition initially links to EVERY group entry (plus the join
        when no ``default`` exists) — the post-build refinement prunes
        non-selected entries only under a full constant proof."""
        disc = stmt.child_by_field_name("condition")
        body = stmt.child_by_field_name("body")
        if disc is None or body is None:
            msg = "switch shape"
            raise _RefusedConstruct(msg)
        if _subtree_has_refused(disc):
            msg = "switch condition"
            raise _RefusedConstruct(msg)
        # A yield anywhere makes this a value-producing switch body —
        # its result flow is not modelled.
        scan = [body]
        while scan:
            cur = scan.pop()
            if cur.type == _YIELD:
                msg = "switch yield"
                raise _RefusedConstruct(msg)
            scan.extend(c for c in cur.children if c.is_named)
        groups = [c for c in body.children if c.type == _SWITCH_GROUP]
        rules = [c for c in body.children if c.type == _SWITCH_RULE]
        if groups and rules:
            msg = "mixed switch block"
            raise _RefusedConstruct(msg)
        units = groups or rules

        # Parse labels up front so a pattern label refuses before any
        # graph mutation beyond this switch.
        parsed = []
        for u in units:
            labels = [c for c in u.children if c.type == _SWITCH_LABEL]
            if not labels:
                msg = "switch label shape"
                raise _RefusedConstruct(msg)
            exprs: list = []
            is_default = False
            for lab in labels:
                named = [c for c in lab.children if c.is_named]
                if any(c.type in ("pattern", "guard", "type_pattern",
                                  "record_pattern") for c in named):
                    msg = "switch pattern label"
                    raise _RefusedConstruct(msg)
                if not named:
                    is_default = True
                else:
                    exprs.extend(named)
            parsed.append((u, labels, exprs, is_default))

        calls, defs, uses, css = _payload_from_subtree(disc, self.resolver)
        cond_node = self._make_node(
            lineno=stmt.start_point[0] + 1,
            label=f"switch {self._short_label(disc)}",
            calls=calls, defs=defs, uses=uses, call_sites=css,
            may_escape=_subtree_may_escape(disc, self.resolver),
        )
        self._link_many(incoming, cond_node)
        self._ambient_catch_link(cond_node)
        join = self._make_node(
            lineno=stmt.end_point[0] + 1, label="switch-end",
        )

        if not units:
            self._link(cond_node, join)
            return [join]

        entries: list[tuple[JavaCFGNode, tuple, bool]] = []
        has_default = False
        prev_tails: list[JavaCFGNode] | None = None
        for u, labels, exprs, is_default in parsed:
            has_default = has_default or is_default
            entry = self._make_node(
                lineno=labels[0].start_point[0] + 1,
                label=self._short_label(labels[0]),
            )
            self._link(cond_node, entry)
            self._ambient_catch_link(entry)
            if prev_tails is not None:
                # Classic fall-through: group N's live tails flow into
                # group N+1's entry. A missing fall-through edge would
                # hide the path where a re-taint after the sanitizing
                # case executes — the false-suppression direction.
                self._link_many(prev_tails, entry)
            stmts = [c for c in u.children
                     if c.is_named and c.type != _SWITCH_LABEL]
            self._break_targets.append(join)
            outs = self._build_stmts(stmts, [entry]) if stmts else [entry]
            self._break_targets.pop()
            if u.type == _SWITCH_RULE:
                self._link_many(outs, join)
                prev_tails = None
            else:
                prev_tails = outs
            entries.append((entry, tuple(exprs), is_default))
        if prev_tails is not None:
            self._link_many(prev_tails, join)
        if not has_default:
            self._link(cond_node, join)
        self._switch_records.append(
            (cond_node, disc, tuple(entries), join, has_default),
        )
        return [join]


def build_java_intraproc_cfg(
    source_text: str,
    function_name: str,
    *,
    line_hint: tuple[int, int] | None = None,
) -> JavaCFG | None:
    """Build the CFG for one Java method / constructor.

    ``line_hint`` — when given, the declaration selected is the
    smallest one with the matching name that SPANS the hint range;
    Java overloads share a name, so name-only selection could pick
    the wrong body. Falls back to the first name match when no
    spanning declaration exists.

    Returns ``None`` when the grammar is missing, the method isn't
    found, or the body contains a refused construct (lambdas, method
    references, anonymous/local classes, switch, labeled jumps) —
    the caller treats ``None`` as resolution failure, never as an
    empty-but-valid graph.
    """
    parser = _get_parser()
    if parser is None:
        return None
    tree = parser.parse(source_text.encode("utf-8", errors="replace"))
    root = tree.root_node

    candidates = []
    stack = [root]
    while stack:
        cur = stack.pop()
        if cur.type in (_METHOD_DECL, _CTOR_DECL) \
                and _method_name(cur) == function_name:
            candidates.append(cur)
        stack.extend(c for c in cur.children if c.is_named)
    if not candidates:
        return None
    decl = None
    if line_hint is not None:
        lo, hi = min(line_hint), max(line_hint)
        spanning = [
            d for d in candidates
            if d.start_point[0] + 1 <= lo and hi <= d.end_point[0] + 1
        ]
        if spanning:
            spanning.sort(key=lambda d: d.end_point[0] - d.start_point[0])
            decl = spanning[0]
    if decl is None:
        candidates.sort(key=lambda d: d.start_point[0])
        decl = candidates[0]

    body = decl.child_by_field_name("body")
    if body is None:
        return None

    type_imports, static_imports = build_import_map(root)
    resolver = _NameResolver(type_imports, static_imports)
    builder = _JavaCFGBuilder(function_name, "<memory>", resolver)
    try:
        tails = builder._build_stmts(body, [builder.entry])
    except _RefusedConstruct as rc:
        logger.debug(
            "java CFG refused for %s: unsupported construct %s",
            function_name, rc,
        )
        return None
    builder._link_many(tails, builder.exit)

    pruned: set[tuple[JavaCFGNode, JavaCFGNode]] = set()
    notes: list[str] = list(builder.build_notes)
    substrate = None
    if builder._switch_records or builder._if_records:
        try:
            substrate = _refinement_substrate(
                builder, source_text, _method_params(decl),
            )
        except Exception:  # noqa: BLE001 — refinement is an optimisation;
            logger.debug("refinement substrate failed for %s",
                         function_name, exc_info=True)
            substrate = None
    if builder._switch_records and substrate is not None:
        try:
            pruned, refine_notes = _refine_constant_switches(
                builder, substrate,
            )
            notes.extend(refine_notes)
        except Exception:  # noqa: BLE001 — refinement is an optimisation;
            # failure keeps every edge (sound) and is recorded.
            logger.debug("switch refinement failed for %s",
                         function_name, exc_info=True)
            pruned = set()
            notes.append("switch:refine-error")
    if builder._if_records and substrate is not None:
        try:
            if_pruned, if_notes = _refine_constant_ifs(
                builder, substrate, pruned,
            )
            pruned = pruned | if_pruned
            notes.extend(if_notes)
        except Exception:  # noqa: BLE001 — same posture as switches:
            # an if-refinement failure keeps the if edges (sound)
            # without disturbing any switch pruning already proven.
            logger.debug("if refinement failed for %s",
                         function_name, exc_info=True)
            notes.append("if:refine-error")

    adjacency = {
        n: tuple(d for d in dsts if (n, d) not in pruned)
        for n, dsts in builder._adjacency.items()
    }
    return JavaCFG(
        function_name=function_name,
        file_path="<memory>",
        language="java",
        entry_node=builder.entry,
        exit_node=builder.exit,
        _nodes=tuple(builder._all_nodes),
        _adjacency=adjacency,
        params=_method_params(decl),
        build_notes=tuple(notes),
    )


def _refinement_substrate(
    builder: _JavaCFGBuilder,
    source_text: str,
    params: tuple[str, ...],
) -> tuple[Any, Any, Any, Any]:
    """Shared proof substrate for the post-build branch refinements:
    (interim unpruned CFG, its reaching defs, the constant index, the
    optional table resolver). Computed once — the switch and if
    refiners must read the SAME unpruned-graph oracle (more reaching
    defs = more chances to refuse — conservative)."""
    from core.analysis.const_fold_java import JavaConstIndex
    from core.analysis.dataflow import reaching_defs

    n_lines = source_text.count("\n") + 1
    index = JavaConstIndex(source_text, (1, n_lines))
    try:
        from core.analysis.value_set_java import build_table_resolver
        table_resolver = build_table_resolver(source_text, (1, n_lines))
    except Exception:  # noqa: BLE001 — table support is optional
        table_resolver = None
    interim = JavaCFG(
        function_name=builder.function_name,
        file_path=builder.file_path,
        language="java",
        entry_node=builder.entry,
        exit_node=builder.exit,
        _nodes=tuple(builder._all_nodes),
        _adjacency={n: tuple(d) for n, d in builder._adjacency.items()},
        params=params,
    )
    rd = reaching_defs(interim)
    return interim, rd, index, table_resolver


def _refine_constant_switches(
    builder: _JavaCFGBuilder,
    substrate: tuple[Any, Any, Any, Any],
) -> tuple[set[tuple[JavaCFGNode, JavaCFGNode]], list[str]]:
    """Prune condition→group edges of switches whose discriminant and
    every case label fold to compile-time constants.

    The proof runs over the UNPRUNED graph's reaching definitions (more
    reaching defs = more chances to refuse — conservative) using the
    same definition oracle as the constant-definers gate. Anything
    short of a full proof — an unresolvable label, a discriminant that
    refuses, a duplicate match, a non int/string discriminant value —
    keeps every edge and records ``switch:all-branches``.
    """
    from core.analysis.const_fold_java import (
        REFUSE,
        fold_expr,
        fold_expr_at,
    )

    pruned: set[tuple[JavaCFGNode, JavaCFGNode]] = set()
    notes: list[str] = []
    _interim, rd, index, table_resolver = substrate

    def _refuse_names(_name: str, _depth: int):
        return REFUSE

    for cond_node, disc, entries, _join, _has_default in \
            builder._switch_records:
        label_vals: list[list] = []
        ok = True
        for _entry, exprs, _is_default in entries:
            vals = []
            for e in exprs:
                # Labels fold literal-only: Java constant-variable
                # labels (``case MY_CONST:``) refuse — resolving them
                # against field initializers is out of scope.
                v = fold_expr(e, _refuse_names)
                if v is REFUSE:
                    ok = False
                    break
                vals.append(v)
            if not ok:
                break
            label_vals.append(vals)
        if not ok:
            notes.append("switch:all-branches")
            continue
        dv = fold_expr_at(rd, cond_node, disc, index,
                          array_resolver=table_resolver)
        if dv is REFUSE or isinstance(dv, bool) or dv is None \
                or not isinstance(dv, (int, str)):
            notes.append("switch:all-branches")
            continue
        selected = None
        duplicate = False
        for (entry, _exprs, _is_default), vals in zip(entries, label_vals):
            for lv in vals:
                if type(lv) is type(dv) and lv == dv:
                    if selected is not None and selected is not entry:
                        duplicate = True
                    selected = entry
        if duplicate:
            notes.append("switch:all-branches")
            continue
        if selected is None:
            selected = next(
                (e for e, _x, d in entries if d), None,
            )
        for entry, _exprs, _is_default in entries:
            if entry is not selected:
                pruned.add((cond_node, entry))
        # No match and no default: control falls straight to the join —
        # the cond→join edge already exists (has_default is False).
        notes.append("switch:constant-resolved")
    return pruned, notes


def _refine_constant_ifs(
    builder: _JavaCFGBuilder,
    substrate: tuple[Any, Any, Any, Any],
    already_pruned: set[tuple[JavaCFGNode, JavaCFGNode]],
) -> tuple[set[tuple[JavaCFGNode, JavaCFGNode]], list[str]]:
    """Prune the dead branch of ``if`` statements whose condition
    folds to a compile-time BOOLEAN — the statement-level analog of
    the dead-branch ternary and of ``switch`` constant resolution.

    Same edge-removal semantics as the switch refiner: pruning only
    deletes condition→branch edges in the final adjacency, and the
    reaching-defs reachability restriction (core.analysis.dataflow)
    then excludes the whole dead region from the fixpoint, so its
    definitions cannot leak back through residual join edges.

    Full-proof rules (anything less keeps every edge, note
    ``if:all-branches``):

    * the condition must fold to a strict :class:`bool` under the
      VALUE-ONLY contract — the TAINT_FREE tier is not enabled, so a
      taint-free-but-unknown-valued condition reads as REFUSE and can
      never prune (an unknown value selects an unknown branch);
    * ambient catch edges (snapshotted before the branches were
      built) are never pruning candidates — condition evaluation may
      itself throw;
    * the no-else / empty-else skip edge (condition → join) is pruned
      on a True condition only when the then-branch has entry edges
      of its own AND the join target keeps at least one other
      predecessor under the pruning decided so far — a then-branch
      that never rejoins (return/throw tails) keeps the skip edge as
      a sound over-approximation rather than disconnecting the
      region downstream.
    """
    from core.analysis.const_fold_java import REFUSE, fold_expr_at

    _interim, rd, index, table_resolver = substrate
    pruned: set[tuple[JavaCFGNode, JavaCFGNode]] = set()
    notes: list[str] = []

    # Predecessor map over the adjacency as pruned SO FAR (switch
    # refinement first): the join guard must not count an edge that
    # an earlier proof already removed.
    preds: dict[JavaCFGNode, set[JavaCFGNode]] = {}
    for n, dsts in builder._adjacency.items():
        for d in dsts:
            if (n, d) in already_pruned:
                continue
            preds.setdefault(d, set()).add(n)

    for (cond_node, cond_expr, base_succ, then_entries,
         else_entries, has_alt) in builder._if_records:
        if cond_expr is None:
            notes.append("if:all-branches")
            continue
        val = fold_expr_at(rd, cond_node, cond_expr, index,
                           array_resolver=table_resolver)
        if val is REFUSE or not isinstance(val, bool):
            notes.append("if:all-branches")
            continue
        local: set[tuple[JavaCFGNode, JavaCFGNode]] = set()
        if val:
            for e in else_entries:
                local.add((cond_node, e))
            if then_entries and (not has_alt or not else_entries):
                succ_now = [
                    d for d in builder._adjacency.get(cond_node, ())
                    if (cond_node, d) not in already_pruned
                ]
                skip_edges = (
                    set(succ_now) - set(base_succ)
                    - set(then_entries) - set(else_entries)
                )
                for f in skip_edges:
                    if preds.get(f, set()) - {cond_node}:
                        local.add((cond_node, f))
        else:
            for t in then_entries:
                local.add((cond_node, t))
        if local:
            pruned |= local
            notes.append("if:constant-resolved")
        else:
            notes.append("if:all-branches")
    return pruned, notes


__all__ = [
    "JavaCFG",
    "JavaCFGNode",
    "build_import_map",
    "build_java_intraproc_cfg",
    "find_enclosing_method",
]
