"""Wrapper summaries for the Java value gate — same-class, same-file
cross-class, and depth-2 composition.

The Java analog of :mod:`core.analysis.interproc` (Phase 14, Python):
when the analysed method calls a small helper whose return value is
provably the output of a catalog sanitizer applied to its argument,
synthesise a
:class:`core.dataflow.sanitizer_catalog.SanitizerBinding` at the call
site so the four-condition value gate treats the helper call exactly
like a direct sanitizer call.

Three call forms bind (b19 shipped the first; b21 added the rest):

* bare ``helper(x)`` — a helper of the ENCLOSING class, ``private``
  or ``static`` (no dynamic dispatch);
* static ``Helper.esc(x)`` — a ``static`` method of another class
  declared in the SAME compilation unit;
* instance-creation ``new Helper().m(x)`` — an instance method of a
  same-file class, only under the trivial-construction and
  instance-state rules below. This is the OWASP Benchmark's
  ``new Test().doSomething(request, param)`` shape — measured
  same-file (private inner class) across the corpus.

Cross-class acceptance (all must hold, else a refusal decision):

* the helper class is declared in this compilation unit, its simple
  name is unambiguous in the file, and it is ``private`` or ``final``
  or nested — and NO class in the file ``extends`` it (bounded
  dispatch: nothing in scope can override the summarised method);
* the instance form additionally requires trivial construction — no
  declared constructor, or only zero-parameter constructors whose
  bodies are empty (a constructor parameter could store taint into
  instance state, so ``new Holder(x).out()`` refuses at the call
  site regardless of the constructor's body);
* instance-form bodies obey the STRICT state rule: local
  declarations plus a single trailing return only (no bare
  assignments — an undeclared assignment target could be a field),
  and no ``this`` / ``super`` / field access anywhere in the body.

Depth-2 composition: a helper whose return calls ANOTHER helper binds
only when the inner helper already earned a depth-1 (catalog-only)
summary in the same class — the composition of two proven summaries,
never general interprocedural analysis. Depth 3, recursion, and
two-helper cycles refuse structurally: pass 1 admits catalog-only
returns, pass 2 admits pass-1 callees, and nothing admits a pass-2
callee. An argument position the inner summary IGNORES (its
parameter provably never reaches the inner return — pass 1 refuses
any helper where a parameter reaches the return outside a sanitizer)
is skipped: the value is discarded, so nothing about it needs
proving.

Everything else keeps b19's refusal taxonomy: overload ambiguity,
varargs, non-straight-line bodies, reassigned locals, parameters
reaching the return outside a sanitizer, non-catalog calls (beyond
the composition rule), unknown names, and non-``+`` operators all
refuse; ``this.helper(...)`` produces no CallSite in the builder and
never binds (pinned by test — a builder change must force a
deliberate decision here); a variable receiver (``b.m(x)``) is never
indexed, so dispatch through a receiver whose dynamic type is
unknown can never bind.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from core.dataflow.sanitizer_catalog import (
    SanitizerBinding,
    sanitizer_callables_for_cwe,
)
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tree_sitter import Node

logger = logging.getLogger(__name__)

_MAX_BODY_STATEMENTS = 6
_MAX_SUBST_DEPTH = 4

_IDENT = "identifier"
_METHOD_DECL = "method_declaration"
_CTOR_DECL = "constructor_declaration"
_CLASS_DECL = "class_declaration"
_BLOCK = "block"
_RETURN = "return_statement"
_LOCAL_DECL = "local_variable_declaration"
_EXPR_STMT = "expression_statement"
_ASSIGNMENT = "assignment_expression"
_DECLARATOR = "variable_declarator"
_METHOD_INVOCATION = "method_invocation"
_OBJECT_CREATION = "object_creation_expression"
_BINARY = "binary_expression"
_STRING_LITERALS = frozenset({
    "string_literal", "character_literal", "decimal_integer_literal",
    "hex_integer_literal", "true", "false", "null_literal",
})
_STATE_NODES = frozenset({"this", "super", "field_access"})


def _parser():
    from core.analysis.cfg_builder_java import _get_parser
    return _get_parser()


def _unwrap(n):
    from core.analysis.cfg_builder_java import _unwrap_value_expr
    return _unwrap_value_expr(n)


def _text(n) -> str:
    return n.text.decode("utf-8", errors="replace") if n is not None else ""


@dataclass(frozen=True)
class WrapperSummary:
    """Summary for one qualifying helper: which parameter positions
    flow to the return exclusively through catalog sanitizers (a
    position missing here provably never reaches the return), and
    through which sanitizer callables. ``bare_callable`` marks
    enclosing-class helpers — the only ones a bare call can reach."""
    owner: str
    simple_name: str
    arity: int
    sanitized_positions: frozenset[int]
    sanitizer_callables: frozenset[str]
    is_static: bool
    bare_callable: bool


@dataclass
class _CallInfo:
    """One qualifying invocation at the call-site index: receiver
    form ('bare' / 'static' / 'creation' / 'creation_args') plus the
    positional argument identifiers (None for non-identifier args)."""
    form: str
    owner: str | None
    args: tuple[str | None, ...]


class _Refused(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _modifiers(decl) -> set[str]:
    mods = next((c for c in decl.children if c.type == "modifiers"), None)
    if mods is None:
        return set()
    return {_text(c) for c in mods.children}


def _param_names(decl: Node) -> tuple[str, ...] | None:
    params = decl.child_by_field_name("parameters")
    if params is None:
        return None
    out: list[str] = []
    for p in params.children:
        if not p.is_named:
            continue
        if p.type == "spread_parameter":
            return None                      # varargs: arity is fluid
        if p.type != "formal_parameter":
            return None
        name_node = p.child_by_field_name("name")
        if name_node is None:
            return None
        out.append(_text(name_node))
    return tuple(out)


def _iter_named(root):
    stack = [root]
    while stack:
        cur = stack.pop()
        yield cur
        stack.extend(c for c in cur.children if c.is_named)


def _subtree_touches_state(n) -> bool:
    return any(cur.type in _STATE_NODES for cur in _iter_named(n))


def _straight_line_locals(body, params: tuple[str, ...],
                          *, strict_state: bool):
    """Return ``(locals_map, return_expr)`` for a straight-line body,
    or raise :class:`_Refused`. ``strict_state`` (cross-class
    instance helpers) forbids bare assignments entirely — an
    undeclared assignment target could be a field."""
    stmts = [c for c in body.children if c.is_named]
    if len(stmts) > _MAX_BODY_STATEMENTS:
        msg = "body exceeds statement cap"
        raise _Refused(msg)
    if not stmts or stmts[-1].type != _RETURN:
        msg = "body does not end in a single return"
        raise _Refused(msg)
    if strict_state and _subtree_touches_state(body):
        msg = "instance state touched in a cross-class helper"
        raise _Refused(msg)
    locals_map: dict[str, Any] = {}
    assigned: set[str] = set()
    for stmt in stmts[:-1]:
        if stmt.type == _LOCAL_DECL:
            decls = [c for c in stmt.children if c.type == _DECLARATOR]
            if len(decls) != 1:
                msg = "multi-declarator local"
                raise _Refused(msg)
            name_node = decls[0].child_by_field_name("name")
            value = decls[0].child_by_field_name("value")
            if name_node is None or value is None:
                msg = "local without initializer"
                raise _Refused(msg)
            name = _text(name_node)
            if name in assigned or name in params:
                msg = "local reassignment / parameter shadowing"
                raise _Refused(msg)
            assigned.add(name)
            locals_map[name] = value
            continue
        if stmt.type == _EXPR_STMT:
            if strict_state:
                msg = "bare assignment in a cross-class helper body"
                raise _Refused(msg)
            inner = next((c for c in stmt.children if c.is_named), None)
            if inner is None or inner.type != _ASSIGNMENT:
                msg = "non-assignment statement in body"
                raise _Refused(msg)
            left = inner.child_by_field_name("left")
            right = inner.child_by_field_name("right")
            op = inner.child_by_field_name("operator")
            if (left is None or left.type != _IDENT or right is None
                    or _text(op) != "="):
                msg = "unsupported assignment shape in body"
                raise _Refused(msg)
            name = _text(left)
            if name in assigned or name in params:
                msg = "local reassignment / parameter shadowing"
                raise _Refused(msg)
            assigned.add(name)
            locals_map[name] = right
            continue
        msg = f"unsupported body statement: {stmt.type}"
        raise _Refused(msg)
    ret = stmts[-1]
    ret_expr = next((c for c in ret.children if c.is_named), None)
    if ret_expr is None:
        msg = "bare return"
        raise _Refused(msg)
    return locals_map, ret_expr


def _classify_return(
    expr,
    params: tuple[str, ...],
    locals_map: dict[str, Any],
    resolver,
    catalog: set[str],
    composable: dict[tuple[str, str, int], WrapperSummary],
    owner: str,
) -> tuple[frozenset[int], frozenset[str]]:
    """Positions and callables when the return is clean; raises
    :class:`_Refused` otherwise. ``composable`` holds the depth-1
    summaries a bare call may compose with (same owner only)."""
    param_pos = {p: i for i, p in enumerate(params)}
    sanitized: dict[int, set[str]] = {}

    def visit(n, inside: frozenset[str] | None, depth: int) -> None:
        if depth > _MAX_SUBST_DEPTH:
            msg = "substitution depth cap"
            raise _Refused(msg)
        n = _unwrap(n)
        if n is None:
            msg = "unparseable return fragment"
            raise _Refused(msg)
        t = n.type
        if t in _STRING_LITERALS:
            return
        if t == _IDENT:
            name = _text(n)
            if name in param_pos:
                if inside is None:
                    msg = "parameter reaches return outside a sanitizer"
                    raise _Refused(msg)
                sanitized.setdefault(param_pos[name], set()).update(inside)
                return
            if name in locals_map:
                visit(locals_map[name], inside, depth + 1)
                return
            msg = "unknown name in return expression"
            raise _Refused(msg)
        if t == _METHOD_INVOCATION:
            try:
                resolved = resolver.callable_name(n)
            except Exception:  # noqa: BLE001 — resolver over scanned source
                resolved = None
            args = n.child_by_field_name("arguments")
            named_args = [c for c in args.children if c.is_named] \
                if args is not None else []
            if resolved is not None and resolved in catalog:
                for c in named_args:
                    visit(c, frozenset({resolved}), depth + 1)
                return
            # depth-2 composition: bare call to a depth-1 summary of
            # the SAME class.
            if n.child_by_field_name("object") is None:
                key = (owner, _text(n.child_by_field_name("name")),
                       len(named_args))
                summary = composable.get(key)
                if summary is not None:
                    for i, c in enumerate(named_args):
                        if i in summary.sanitized_positions:
                            visit(c, summary.sanitizer_callables,
                                  depth + 1)
                        # else: the inner summary proves position i
                        # never reaches its return — value discarded.
                    return
            msg = "non-catalog call in return expression"
            raise _Refused(msg)
        if t == _BINARY:
            op = n.child_by_field_name("operator")
            if op is None or op.type != "+":
                msg = "non-concatenation operator in return"
                raise _Refused(msg)
            visit(n.child_by_field_name("left"), inside, depth + 1)
            visit(n.child_by_field_name("right"), inside, depth + 1)
            return
        msg = f"unsupported return construct: {t}"
        raise _Refused(msg)

    visit(expr, None, 0)
    if not sanitized:
        msg = "no parameter flows through a sanitizer"
        raise _Refused(msg)
    positions = frozenset(sanitized)
    callables = frozenset(c for cs in sanitized.values() for c in cs)
    return positions, callables


# ---------------------------------------------------------------------------
# Class inventory
# ---------------------------------------------------------------------------

@dataclass
class _ClassInfo:
    node: Any
    name: str
    modifiers: set[str]
    is_nested: bool


def _class_inventory(root) -> tuple[dict[str, list[_ClassInfo]], set[str]]:
    """All class declarations by simple name, plus the set of names
    appearing in any ``extends`` clause in the file."""
    by_name: dict[str, list[_ClassInfo]] = {}
    extended: set[str] = set()
    for n in _iter_named(root):
        if n.type != _CLASS_DECL:
            continue
        name_node = n.child_by_field_name("name")
        if name_node is None:
            continue
        parent = n.parent
        is_nested = False
        while parent is not None:
            if parent.type == _CLASS_DECL:
                is_nested = True
                break
            parent = parent.parent
        by_name.setdefault(_text(name_node), []).append(_ClassInfo(
            node=n, name=_text(name_node),
            modifiers=_modifiers(n), is_nested=is_nested,
        ))
        superclass = n.child_by_field_name("superclass")
        if superclass is not None:
            for c in _iter_named(superclass):
                if c.type in (_IDENT, "type_identifier"):
                    extended.add(_text(c))
    return by_name, extended


def _trivially_constructible(cls_node: Node) -> bool:
    """No declared constructor, or only zero-parameter constructors
    whose bodies are empty (a lone ``super();`` allowed)."""
    body = cls_node.child_by_field_name("body")
    if body is None:
        return False
    for child in body.children:
        if child.type != _CTOR_DECL:
            continue
        params = _param_names(child)
        if params is None or len(params) != 0:
            return False
        cbody = child.child_by_field_name("body")
        if cbody is None:
            return False
        for s in cbody.children:
            if s.is_named and s.type != "explicit_constructor_invocation":
                return False
    return True


def _methods_of(cls_node: Node) -> dict[tuple[str, int], list[Any]]:
    body = cls_node.child_by_field_name("body")
    out: dict[tuple[str, int], list[Any]] = {}
    if body is None:
        return out
    for child in body.children:
        if child.type != _METHOD_DECL:
            continue
        name_node = child.child_by_field_name("name")
        params = _param_names(child)
        if name_node is None or params is None:
            continue
        out.setdefault((_text(name_node), len(params)), []).append(child)
    return out


# ---------------------------------------------------------------------------
# Summary derivation
# ---------------------------------------------------------------------------

def _summarize_class(
    info: _ClassInfo,
    *,
    is_enclosing: bool,
    resolver,
    catalog: set[str],
    decisions: list[str],
) -> dict[tuple[str, str, int], WrapperSummary]:
    """Two-pass summaries for one class. Pass 1 admits catalog-only
    returns; pass 2 re-tries pass-1 refusals allowing composition
    with the pass-1 set (depth exactly 2 — cycles and recursion never
    earn a pass-1 summary, so they refuse in both passes)."""
    owner = info.name
    summaries: dict[tuple[str, str, int], WrapperSummary] = {}

    def attempt(name, arity, decls, composable) -> WrapperSummary | None:
        if len(decls) > 1:
            decisions.append(
                f"{owner}.{name}/{arity}: refused (overload ambiguity)")
            return None
        decl = decls[0]
        mods = _modifiers(decl)
        strict = not is_enclosing and "static" not in mods
        if is_enclosing and "private" not in mods and "static" not in mods:
            decisions.append(
                f"{owner}.{name}/{arity}: refused "
                "(overridable instance method)")
            return None
        if "abstract" in mods or "native" in mods:
            decisions.append(f"{owner}.{name}/{arity}: refused (no body)")
            return None
        mbody = decl.child_by_field_name("body")
        if mbody is None or mbody.type != _BLOCK:
            decisions.append(
                f"{owner}.{name}/{arity}: refused (no block body)")
            return None
        params = _param_names(decl) or ()
        try:
            locals_map, ret_expr = _straight_line_locals(
                mbody, params, strict_state=strict)
            positions, callables = _classify_return(
                ret_expr, params, locals_map, resolver, catalog,
                composable, owner)
        except _Refused as r:
            decisions.append(
                f"{owner}.{name}/{arity}: refused ({r.reason})")
            return None
        return WrapperSummary(
            owner=owner, simple_name=name, arity=arity,
            sanitized_positions=positions,
            sanitizer_callables=callables,
            is_static="static" in mods,
            bare_callable=is_enclosing,
        )

    methods = _methods_of(info.node)
    pending: list[tuple[str, int, list[Any]]] = []
    for (name, arity), decls in methods.items():
        s = attempt(name, arity, decls, composable={})
        if s is not None:
            summaries[(owner, name, arity)] = s
            decisions.append(
                f"{owner}.{name}/{arity}: sanitizes positions "
                f"{sorted(s.sanitized_positions)} via "
                f"{sorted(s.sanitizer_callables)}")
        else:
            pending.append((name, arity, decls))
    pass1 = dict(summaries)
    for name, arity, decls in pending:
        s = attempt(name, arity, decls, composable=pass1)
        if s is not None:
            summaries[(owner, name, arity)] = s
            decisions.append(
                f"{owner}.{name}/{arity}: sanitizes positions "
                f"{sorted(s.sanitized_positions)} via "
                f"{sorted(s.sanitizer_callables)} (depth-2)")
    return summaries


def derive_wrapper_summaries(
    source_text: str,
    line_hint: tuple[int, int],
    cwe: str,
    language: str,
) -> tuple[dict[tuple[str, str, int], WrapperSummary], list[str]]:
    """Summaries for qualifying helpers reachable from the method
    enclosing ``line_hint``: the enclosing class's own private/static
    helpers plus qualifying same-file helper classes. Returns
    ``(summaries, decisions)`` keyed ``(owner, name, arity)``; empty
    on any parse failure or when the CWE has no catalog sanitizers."""
    decisions: list[str] = []
    catalog = sanitizer_callables_for_cwe(cwe, language)
    if not catalog:
        return {}, ["no catalog sanitizers for this cwe/language"]
    parser = _parser()
    if parser is None:
        return {}, ["tree-sitter java unavailable"]
    try:
        from core.analysis.cfg_builder_java import (
            _NameResolver,
            build_import_map,
        )
        tree = parser.parse(source_text.encode("utf-8", errors="replace"))
    except Exception:  # noqa: BLE001 — arbitrary scanned source
        return {}, ["parse failure"]
    root = tree.root_node
    types, statics = build_import_map(root)
    resolver = _NameResolver(types, statics)

    by_name, extended = _class_inventory(root)

    lo, hi = min(line_hint), max(line_hint)
    enclosing: _ClassInfo | None = None
    best_span = None
    for infos in by_name.values():
        for info in infos:
            start = info.node.start_point[0] + 1
            end = info.node.end_point[0] + 1
            if start <= lo and hi <= end:
                span = end - start
                if best_span is None or span < best_span:
                    best_span, enclosing = span, info
    if enclosing is None:
        return {}, ["no enclosing class for the finding's lines"]

    summaries: dict[tuple[str, str, int], WrapperSummary] = {}
    summaries.update(_summarize_class(
        enclosing, is_enclosing=True, resolver=resolver,
        catalog=catalog, decisions=decisions))

    for name, infos in by_name.items():
        if len(infos) > 1:
            decisions.append(
                f"{name}: refused (ambiguous class name in file)")
            continue
        info = infos[0]
        if info is enclosing:
            continue
        cls_summaries = _summarize_class(
            info, is_enclosing=False, resolver=resolver,
            catalog=catalog, decisions=decisions)
        # Static methods dispatch exactly (``Cls.m`` names the class;
        # subclass statics hide, never override) — always bindable.
        # Instance summaries need MORE: the creation form's receiver
        # type is exact, but belt-and-braces we still require a
        # dispatch-bounded class (private / final / nested, not
        # extended in this file) plus trivial construction.
        bounded = (
            ("private" in info.modifiers
             or "final" in info.modifiers
             or info.is_nested)
            and name not in extended
        )
        if not bounded or not _trivially_constructible(info.node):
            dropped = {k for k, v in cls_summaries.items()
                       if not v.is_static}
            if dropped:
                decisions.append(
                    f"{name}: instance summaries dropped "
                    "(unbounded dispatch or non-trivial construction)")
            cls_summaries = {
                k: v for k, v in cls_summaries.items() if v.is_static
            }
        summaries.update(cls_summaries)

    for d in decisions:
        logger.debug("java wrapper summary: %s", d)
    return summaries, decisions


# ---------------------------------------------------------------------------
# Call-site index + binding synthesis
# ---------------------------------------------------------------------------

def _positional_args(node: Node) -> tuple[str | None, ...]:
    args_node = node.child_by_field_name("arguments")
    args: list[str | None] = []
    if args_node is not None:
        for c in args_node.children:
            if not c.is_named:
                continue
            u = _unwrap(c)
            args.append(
                _text(u) if u is not None and u.type == _IDENT else None)
    return tuple(args)


def _index_calls(
    source_text: str,
    simple_names: set[str],
    class_names: set[str],
) -> dict[tuple[int, int], _CallInfo]:
    """Qualifying invocations keyed by the invocation node's
    (lineno, col) — the pair :class:`CallSite` carries. Receiver
    forms beyond bare / same-file-static / zero-arg-creation are
    omitted (a variable receiver's dynamic type is unknown and never
    binds); creation WITH arguments is recorded as its own form so
    the binder refuses it explicitly rather than by absence."""
    parser = _parser()
    if parser is None:
        return {}
    try:
        tree = parser.parse(source_text.encode("utf-8", errors="replace"))
    except Exception:  # noqa: BLE001
        return {}
    out: dict[tuple[int, int], _CallInfo] = {}
    for cur in _iter_named(tree.root_node):
        if cur.type != _METHOD_INVOCATION:
            continue
        name_node = cur.child_by_field_name("name")
        if name_node is None or _text(name_node) not in simple_names:
            continue
        key = (cur.start_point[0] + 1, cur.start_point[1])
        obj = cur.child_by_field_name("object")
        if obj is None:
            out[key] = _CallInfo(
                form="bare", owner=None, args=_positional_args(cur))
            continue
        obj_u = _unwrap(obj)
        if obj_u is None:
            continue
        if obj_u.type == _IDENT and _text(obj_u) in class_names:
            out[key] = _CallInfo(
                form="static", owner=_text(obj_u),
                args=_positional_args(cur))
            continue
        if obj_u.type == _OBJECT_CREATION:
            if any(c.type == "class_body" for c in obj_u.children):
                # ``new Helper() { ... }`` declares an anonymous
                # SUBCLASS — dispatch goes to its overrides, not to
                # the summarised class. Never bind.
                continue
            ty = obj_u.child_by_field_name("type")
            ty_text = _text(ty).split("<", 1)[0].strip()
            if ty_text not in class_names:
                continue
            ctor_args = obj_u.child_by_field_name("arguments")
            n_ctor = len([c for c in ctor_args.children if c.is_named]) \
                if ctor_args is not None else 0
            out[key] = _CallInfo(
                form="creation" if n_ctor == 0 else "creation_args",
                owner=ty_text, args=_positional_args(cur))
    return out


def _simple_of(callsite_name: str) -> str:
    """Trailing simple method name of a CallSite name — handles
    ``m``, ``Helper.m``, and ``new Helper().m``."""
    return callsite_name.rsplit(".", 1)[-1]


def synthetic_wrapper_bindings_java(
    cfg,
    source_text: str,
    line_hint: tuple[int, int],
    cwe: str,
    language: str,
) -> frozenset[SanitizerBinding]:
    """Synthetic bindings for qualifying wrapper calls in ``cfg``.
    Empty frozenset on any failure — best-effort, the
    intra-procedural verdict stands."""
    summaries, _decisions = derive_wrapper_summaries(
        source_text, line_hint, cwe, language)
    if not summaries:
        return frozenset()
    simple_names = {name for (_o, name, _a) in summaries}
    class_names = {owner for (owner, _n, _a) in summaries}
    calls = _index_calls(source_text, simple_names, class_names)

    bindings: list[SanitizerBinding] = []
    for node in cfg.nodes():
        for cs in getattr(node, "call_sites", ()) or ():
            info = calls.get((cs.lineno, cs.col_offset))
            if info is None:
                continue
            if info.form == "creation_args":
                # A constructor argument could store taint into the
                # instance — never bind through it.
                continue
            arity = len(info.args)
            method_name = _simple_of(cs.name)
            if info.form == "bare":
                matching = [
                    s for s in summaries.values()
                    if s.bare_callable and s.simple_name == cs.name
                    and s.arity == arity
                ]
                if len(matching) != 1:
                    continue
                summary = matching[0]
            else:
                summary = summaries.get((info.owner, method_name, arity))
                if summary is None:
                    continue
                if info.form == "static" and not summary.is_static:
                    continue
            input_symbols = frozenset(
                info.args[i]
                for i in summary.sanitized_positions
                if i < len(info.args) and info.args[i] is not None
            )
            if not input_symbols:
                continue
            bindings.append(SanitizerBinding(
                node=node,
                callable=(
                    f"wrapper:{summary.owner}.{summary.simple_name}->"
                    + "+".join(sorted(summary.sanitizer_callables))
                ),
                input_symbols=input_symbols,
                output_symbols=cs.assigned_names,
                lineno=cs.lineno,
            ))
    return frozenset(bindings)


# ---------------------------------------------------------------------------
# Conduit summaries (b27) — helpers that provably return either a
# compile-time constant or a specific parameter UNCHANGED.
# ---------------------------------------------------------------------------
#
# A conduit is NOT a sanitizer: it forwards a value. The gate consumes
# a conduit call site as value-transparent — the taint/constancy
# question passes through to the argument (returns-param), vanishes
# (returns-constant: a compile-time constant cannot carry attacker
# data, the precedent the constant-definers gate settled), or reduces
# to the parameter side (join: constant-or-param when the selecting
# condition doesn't fold — the constant side is taint-free either
# way). Transparency preserves honesty by construction: a tainted
# argument rides through untouched and the gate's ordinary taint
# reasoning refuses the suppression.
#
# Class/method eligibility is IDENTICAL to wrapper summaries (bounded
# dispatch, trivial construction, strict instance-state rule,
# overload/varargs/anonymous-subclass refusals). The return grammar
# differs: any method call in the return refuses (including catalog
# sanitizers — a sanitizing return is wrapper-summary territory), any
# transformation of the parameter (concatenation, arithmetic) refuses,
# and a ``null`` constant refuses (the fold-hook contract uses None
# for "not a conduit call", so a null conduit would be
# indistinguishable — and null forwards no taint anyway).

CONDUIT_CONST = "const"
CONDUIT_PARAM = "param"
CONDUIT_JOIN = "join"

_TERNARY = "ternary_expression"


@dataclass(frozen=True)
class ConduitSummary:
    """Value summary for one conduit helper.

    ``kind``:

    * :data:`CONDUIT_CONST` — every execution returns
      ``const_value`` (``param_index`` is None);
    * :data:`CONDUIT_PARAM` — every execution returns parameter
      ``param_index`` unchanged (``const_value`` is None);
    * :data:`CONDUIT_JOIN` — returns either ``const_value`` or
      parameter ``param_index`` unchanged, branch statically
      unknown.
    """
    owner: str
    simple_name: str
    arity: int
    kind: str
    param_index: int | None
    const_value: Any
    is_static: bool
    bare_callable: bool


_UNASSIGNED = object()

_IF_STMT = "if_statement"
_COMMENTS = frozenset({"line_comment", "block_comment"})


def _classify_expr(expr, params: tuple[str, ...],
                   env: dict[str, Any]) -> tuple[str, int | None, Any]:
    """AbstractVal ``(kind, param_index, const_value)`` for an
    expression under the body environment, or raise :class:`_Refused`.
    ``env`` maps body-local names to AbstractVals (or
    :data:`_UNASSIGNED` for declared-uninitialized locals)."""
    from core.analysis.const_fold_java import REFUSE, fold_expr

    def resolve(name: str, _depth: int) -> Any:
        v = env.get(name)
        if isinstance(v, tuple) and v[0] == CONDUIT_CONST:
            return v[2]
        return REFUSE

    val = fold_expr(expr, resolve)
    if val is not REFUSE:
        if val is None:
            msg = "null constant return"
            raise _Refused(msg)
        return (CONDUIT_CONST, None, val)
    n = _unwrap(expr)
    if n is None:
        msg = "unparseable return fragment"
        raise _Refused(msg)
    param_pos = {p: i for i, p in enumerate(params)}
    if n.type == _IDENT:
        name = _text(n)
        if name in param_pos:
            return (CONDUIT_PARAM, param_pos[name], None)
        v = env.get(name)
        if v is None or v is _UNASSIGNED:
            msg = "unknown or unassigned name in expression"
            raise _Refused(msg)
        return v
    if n.type == _TERNARY:
        cond_val = fold_expr(n.child_by_field_name("condition"), resolve)
        if isinstance(cond_val, bool):
            branch = n.child_by_field_name(
                "consequence" if cond_val else "alternative")
            return _classify_expr(branch, params, env)
        a = _classify_expr(
            n.child_by_field_name("consequence"), params, env)
        b = _classify_expr(
            n.child_by_field_name("alternative"), params, env)
        return _merge_vals(a, b)
    msg = "parameter transformed or unsupported return construct"
    raise _Refused(msg)


def _merge_vals(a, b):
    """Join of two AbstractVals — the exact union when it fits the
    const/param/join lattice, :class:`_Refused` otherwise."""
    if a == b:
        return a
    ka, kb = a[0], b[0]
    if ka == kb == CONDUIT_CONST:
        msg = "constant-set return (branch constants differ)"
        raise _Refused(msg)
    if ka == kb == CONDUIT_PARAM:
        msg = "join of two different parameters"
        raise _Refused(msg)
    if {ka, kb} == {CONDUIT_CONST, CONDUIT_PARAM}:
        c, p = (a, b) if ka == CONDUIT_CONST else (b, a)
        return (CONDUIT_JOIN, p[1], c[2])
    # join ∪ its own constant side / its own param side stays the join
    if ka == CONDUIT_JOIN and kb == CONDUIT_CONST and b[2] == a[2] \
            and type(b[2]) is type(a[2]):
        return a
    if kb == CONDUIT_JOIN and ka == CONDUIT_CONST and a[2] == b[2] \
            and type(a[2]) is type(b[2]):
        return b
    if ka == CONDUIT_JOIN and kb == CONDUIT_PARAM and b[1] == a[1]:
        return a
    if kb == CONDUIT_JOIN and ka == CONDUIT_PARAM and a[1] == b[1]:
        return b
    msg = "unmergeable branch values"
    raise _Refused(msg)


def _single_assignment_arm(arm) -> tuple[str, Any] | None:
    """``(name, rhs)`` when an if-arm is exactly one plain assignment
    (braced or not); None otherwise."""
    node = arm
    if node is None:
        return None
    if node.type == _BLOCK:
        named = [c for c in node.children
                 if c.is_named and c.type not in _COMMENTS]
        if len(named) != 1:
            return None
        node = named[0]
    if node.type != _EXPR_STMT:
        return None
    inner = next((c for c in node.children if c.is_named), None)
    if inner is None or inner.type != _ASSIGNMENT:
        return None
    left = inner.child_by_field_name("left")
    right = inner.child_by_field_name("right")
    op = inner.child_by_field_name("operator")
    if left is None or left.type != _IDENT or right is None \
            or _text(op) != "=":
        return None
    return _text(left), right


def _walk_conduit_body(
    body,
    params: tuple[str, ...],
    *,
    strict_state: bool,
) -> tuple[str, int | None, Any]:
    """Sequential abstract interpretation of a conduit body over the
    const/param/join lattice. Exact for the accepted statement forms
    (declarations with or without initializers, plain reassignments —
    last write wins in straight line, single-assignment ``if`` /
    ``if/else`` arms with the join as the unfoldable-condition merge);
    every other statement refuses. Returns the return expression's
    AbstractVal or raises :class:`_Refused`."""
    from core.analysis.const_fold_java import REFUSE, fold_expr

    stmts = [c for c in body.children
             if c.is_named and c.type not in _COMMENTS]
    if len(stmts) > _MAX_BODY_STATEMENTS:
        msg = "body exceeds statement cap"
        raise _Refused(msg)
    if not stmts or stmts[-1].type != _RETURN:
        msg = "body does not end in a single return"
        raise _Refused(msg)
    if strict_state and _subtree_touches_state(body):
        msg = "instance state touched in a cross-class helper"
        raise _Refused(msg)
    env: dict[str, Any] = {}
    declared: set[str] = set()

    def assign(name: str, rhs) -> None:
        if name in params:
            msg = "parameter reassigned in body"
            raise _Refused(msg)
        if strict_state and name not in declared:
            msg = "bare assignment in a cross-class helper body"
            raise _Refused(msg)
        env[name] = _classify_expr(rhs, params, env)

    for stmt in stmts[:-1]:
        if stmt.type == _LOCAL_DECL:
            decls = [c for c in stmt.children if c.type == _DECLARATOR]
            if len(decls) != 1:
                msg = "multi-declarator local"
                raise _Refused(msg)
            name_node = decls[0].child_by_field_name("name")
            if name_node is None:
                msg = "declarator without a name"
                raise _Refused(msg)
            name = _text(name_node)
            if name in params:
                msg = "parameter shadowed by a local"
                raise _Refused(msg)
            declared.add(name)
            value = decls[0].child_by_field_name("value")
            if value is None:
                env[name] = _UNASSIGNED
            else:
                env[name] = _classify_expr(value, params, env)
            continue
        if stmt.type == _EXPR_STMT:
            arm = _single_assignment_arm(stmt)
            if arm is None:
                msg = "unsupported statement in body"
                raise _Refused(msg)
            assign(*arm)
            continue
        if stmt.type == _IF_STMT:
            then_arm = _single_assignment_arm(
                stmt.child_by_field_name("consequence"))
            if then_arm is None:
                msg = "unsupported if-arm in body"
                raise _Refused(msg)
            alt = stmt.child_by_field_name("alternative")
            else_arm = None
            if alt is not None:
                # the alternative field wraps the else clause; the arm
                # is its single named child (block or statement).
                inner = next(
                    (c for c in alt.children if c.is_named), alt)
                else_arm = _single_assignment_arm(
                    inner if alt.type == "else_clause" else alt)
                if else_arm is None:
                    msg = "unsupported else-arm in body"
                    raise _Refused(msg)
                if else_arm[0] != then_arm[0]:
                    msg = "if/else arms assign different names"
                    raise _Refused(msg)

            def resolve(name: str, _depth: int) -> Any:
                v = env.get(name)
                if isinstance(v, tuple) and v[0] == CONDUIT_CONST:
                    return v[2]
                return REFUSE

            cond = fold_expr(
                stmt.child_by_field_name("condition"), resolve)
            if isinstance(cond, bool):
                if cond:
                    assign(*then_arm)
                elif else_arm is not None:
                    assign(*else_arm)
                continue
            name = then_arm[0]
            then_val = _classify_expr(then_arm[1], params, env)
            if else_arm is not None:
                else_val = _classify_expr(else_arm[1], params, env)
                merged = _merge_vals(then_val, else_val)
            else:
                prior = env.get(name)
                if not isinstance(prior, tuple):
                    msg = "partially assigned local (unknown fall-through)"
                    raise _Refused(msg)
                merged = _merge_vals(then_val, prior)
            if strict_state and name not in declared:
                msg = "bare assignment in a cross-class helper body"
                raise _Refused(msg)
            if name in params:
                msg = "parameter reassigned in body"
                raise _Refused(msg)
            env[name] = merged
            continue
        msg = f"unsupported body statement: {stmt.type}"
        raise _Refused(msg)

    ret_expr = next((c for c in stmts[-1].children if c.is_named), None)
    if ret_expr is None:
        msg = "bare return"
        raise _Refused(msg)
    return _classify_expr(ret_expr, params, env)


def _summarize_class_conduits(
    info: _ClassInfo,
    *,
    is_enclosing: bool,
    decisions: list[str],
) -> dict[tuple[str, str, int], ConduitSummary]:
    """Conduit summaries for one class — same structural discipline
    as :func:`_summarize_class`, different return grammar."""
    owner = info.name
    out: dict[tuple[str, str, int], ConduitSummary] = {}
    for (name, arity), decls in _methods_of(info.node).items():
        if len(decls) > 1:
            decisions.append(
                f"{owner}.{name}/{arity}: conduit refused "
                "(overload ambiguity)")
            continue
        decl = decls[0]
        mods = _modifiers(decl)
        strict = not is_enclosing and "static" not in mods
        if is_enclosing and "private" not in mods and "static" not in mods:
            decisions.append(
                f"{owner}.{name}/{arity}: conduit refused "
                "(overridable instance method)")
            continue
        if "abstract" in mods or "native" in mods:
            decisions.append(
                f"{owner}.{name}/{arity}: conduit refused (no body)")
            continue
        mbody = decl.child_by_field_name("body")
        if mbody is None or mbody.type != _BLOCK:
            decisions.append(
                f"{owner}.{name}/{arity}: conduit refused (no block body)")
            continue
        params = _param_names(decl) or ()
        try:
            kind, p_idx, c_val = _walk_conduit_body(
                mbody, params, strict_state=strict)
        except _Refused as r:
            decisions.append(
                f"{owner}.{name}/{arity}: conduit refused ({r.reason})")
            continue
        out[(owner, name, arity)] = ConduitSummary(
            owner=owner, simple_name=name, arity=arity,
            kind=kind, param_index=p_idx, const_value=c_val,
            is_static="static" in mods, bare_callable=is_enclosing,
        )
        decisions.append(
            f"{owner}.{name}/{arity}: conduit {kind}"
            + (f" param={p_idx}" if p_idx is not None else ""))
    return out


def derive_conduit_summaries(
    source_text: str,
    line_hint: tuple[int, int],
) -> tuple[dict[tuple[str, str, int], ConduitSummary], list[str]]:
    """Conduit summaries reachable from the method enclosing
    ``line_hint`` — enclosing-class helpers plus qualifying same-file
    classes under the wrapper rules (bounded dispatch, trivial
    construction). CWE-independent: conduits carry values, not
    sanitization."""
    decisions: list[str] = []
    parser = _parser()
    if parser is None:
        return {}, ["tree-sitter java unavailable"]
    try:
        tree = parser.parse(source_text.encode("utf-8", errors="replace"))
    except Exception:  # noqa: BLE001 — arbitrary scanned source
        return {}, ["parse failure"]
    root = tree.root_node
    by_name, extended = _class_inventory(root)

    lo, hi = min(line_hint), max(line_hint)
    enclosing: _ClassInfo | None = None
    best_span = None
    for infos in by_name.values():
        for info in infos:
            start = info.node.start_point[0] + 1
            end = info.node.end_point[0] + 1
            if start <= lo and hi <= end:
                span = end - start
                if best_span is None or span < best_span:
                    best_span, enclosing = span, info
    if enclosing is None:
        return {}, ["no enclosing class for the finding's lines"]

    summaries: dict[tuple[str, str, int], ConduitSummary] = {}
    summaries.update(_summarize_class_conduits(
        enclosing, is_enclosing=True, decisions=decisions))
    for name, infos in by_name.items():
        if len(infos) > 1:
            decisions.append(
                f"{name}: conduits refused (ambiguous class name in file)")
            continue
        info = infos[0]
        if info is enclosing:
            continue
        cls = _summarize_class_conduits(
            info, is_enclosing=False, decisions=decisions)
        bounded = (
            ("private" in info.modifiers
             or "final" in info.modifiers
             or info.is_nested)
            and name not in extended
        )
        if not bounded or not _trivially_constructible(info.node):
            dropped = {k for k, v in cls.items() if not v.is_static}
            if dropped:
                decisions.append(
                    f"{name}: instance conduits dropped "
                    "(unbounded dispatch or non-trivial construction)")
            cls = {k: v for k, v in cls.items() if v.is_static}
        summaries.update(cls)
    for d in decisions:
        logger.debug("java conduit summary: %s", d)
    return summaries, decisions


def _index_conduit_calls(
    source_text: str,
    summaries: dict[tuple[str, str, int], ConduitSummary],
) -> dict[tuple[int, int], tuple[ConduitSummary, tuple[str | None, ...]]]:
    """Qualifying conduit invocations keyed by (lineno, col), resolved
    to their summary plus positional argument identifiers. Anonymous
    subclass bodies and creation-with-arguments never resolve;
    variable receivers are never indexed (unknown dynamic type)."""
    simple_names = {n for (_o, n, _a) in summaries}
    class_names = {o for (o, _n, _a) in summaries}
    parser = _parser()
    if parser is None:
        return {}
    try:
        tree = parser.parse(source_text.encode("utf-8", errors="replace"))
    except Exception:  # noqa: BLE001
        return {}
    out: dict[tuple[int, int],
              tuple[ConduitSummary, tuple[str | None, ...]]] = {}
    for cur in _iter_named(tree.root_node):
        if cur.type != _METHOD_INVOCATION:
            continue
        name_node = cur.child_by_field_name("name")
        if name_node is None or _text(name_node) not in simple_names:
            continue
        method = _text(name_node)
        args = _positional_args(cur)
        arity = len(args)
        key = (cur.start_point[0] + 1, cur.start_point[1])
        obj = cur.child_by_field_name("object")
        summary: ConduitSummary | None = None
        if obj is None:
            matching = [
                s for s in summaries.values()
                if s.bare_callable and s.simple_name == method
                and s.arity == arity
            ]
            summary = matching[0] if len(matching) == 1 else None
        else:
            obj_u = _unwrap(obj)
            if obj_u is None:
                continue
            if obj_u.type == _IDENT and _text(obj_u) in class_names:
                s = summaries.get((_text(obj_u), method, arity))
                summary = s if (s is not None and s.is_static) else None
            elif obj_u.type == _OBJECT_CREATION:
                if any(c.type == "class_body" for c in obj_u.children):
                    continue          # anonymous subclass — overrides win
                ty = _text(obj_u.child_by_field_name("type"))
                ty = ty.split("<", 1)[0].strip()
                ctor_args = obj_u.child_by_field_name("arguments")
                n_ctor = len([
                    c for c in ctor_args.children if c.is_named
                ]) if ctor_args is not None else 0
                if n_ctor != 0:
                    continue          # constructor could capture state
                summary = summaries.get((ty, method, arity))
        if summary is not None:
            out[key] = (summary, args)
    return out


def conduit_call_map(
    source_text: str,
    line_hint: tuple[int, int],
) -> dict[tuple[int, int], tuple[ConduitSummary, tuple[str | None, ...]]]:
    """(lineno, col) → (summary, arg identifiers) for every resolvable
    conduit call in the file. Empty dict on any failure."""
    summaries, _decisions = derive_conduit_summaries(source_text, line_hint)
    if not summaries:
        return {}
    return _index_conduit_calls(source_text, summaries)


class ConduitFoldResolver:
    """``conduit_resolver`` hook for the Java constant folder: a
    resolvable conduit invocation folds to its constant (const kind)
    or to the fold of its selected argument (param / join kinds; the
    join accepts only when the argument folds to exactly the constant
    side — the folder's single-value contract). Returns None for
    invocations that are not conduit calls so the folder falls
    through to its pure-call allowlist. ``hits`` counts resolutions
    for reason-string attribution."""

    def __init__(self, calls) -> None:
        self._calls = calls
        self.hits = 0

    def __call__(self, node: Node, refold, depth: int) -> Any:
        from core.analysis.const_fold_java import REFUSE

        key = (node.start_point[0] + 1, node.start_point[1])
        entry = self._calls.get(key)
        if entry is None:
            return None
        summary, _arg_idents = entry
        if summary.kind == CONDUIT_CONST:
            self.hits += 1
            return summary.const_value
        args_node = node.child_by_field_name("arguments")
        named = [c for c in (args_node.children if args_node else ())
                 if c.is_named]
        i = summary.param_index
        if i is None or i >= len(named):
            return REFUSE
        v = refold(named[i], depth)
        if v is REFUSE:
            return REFUSE
        if summary.kind == CONDUIT_JOIN:
            if v == summary.const_value and \
                    type(v) is type(summary.const_value):
                self.hits += 1
                return v
            return REFUSE
        self.hits += 1
        return v


def make_conduit_fold_resolver(
    source_text: str,
    line_hint: tuple[int, int],
) -> ConduitFoldResolver | None:
    """Fold-hook over the file's resolvable conduit calls; None when
    the file has none (the folder then skips the hook entirely)."""
    calls = conduit_call_map(source_text, line_hint)
    if not calls:
        return None
    return ConduitFoldResolver(calls)


__all__ = [
    "CONDUIT_CONST",
    "CONDUIT_JOIN",
    "CONDUIT_PARAM",
    "ConduitSummary",
    "WrapperSummary",
    "conduit_call_map",
    "derive_conduit_summaries",
    "derive_wrapper_summaries",
    "make_conduit_fold_resolver",
    "synthetic_wrapper_bindings_java",
]
