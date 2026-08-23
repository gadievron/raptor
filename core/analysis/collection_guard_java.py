"""Constant-collection membership guards for the Java value gate.

When a ``contains`` guard over a provably-constant literal collection
dominates the sink, the sink value is bounded to that finite set —
and a finite set intersects a danger model by direct per-element
membership, the exact finite-language specialisation of the
regex-intersection proof :mod:`core.dataflow.smt_barrier` runs for
charset validators (same danger models, no solver needed).

Two guard forms bind, both requiring the tested identifier to BE the
sink argument:

* exit-on-fail — ``if (!allowed.contains(x)) { return/throw; }``:
  every continuing path has ``x`` in the set;
* enclosed sink — ``if (allowed.contains(x)) { ... sink ... }``:
  the sink executes only when ``x`` is in the set.

The OWASP Benchmark's header-filter idiom is the load-bearing
NON-example: ``if (common.contains(x)) { continue; }`` passes the
values OUTSIDE the set onward — exit/skip on MATCH is exclusion, not
an allowlist, and both polarity inversions are corpus-pinned as
must-not-suppress.

Dominance is syntactic: Java has no goto and no jump INTO a block, so
a statement is dominated by an earlier sibling of any of its
ancestors within the same method. Between the guard and the sink the
tested variable must have no writer of any kind (assignment, compound
assignment, update expression, redeclaration, loop variable, catch
parameter) — writer positions are compared by byte offset, which also
covers writers nested in the guard's own branches.

Collection resolution, strictest first:

* method-local — single declarator whose initializer is a constant
  collection constructor; every other occurrence of the name in the
  method must be a ``contains`` receiver (any other appearance —
  mutator, alias, argument, return — refuses);
* same-class ``static final`` field — same initializer rule; the
  occurrence discipline extends over the whole file;
* cross-file ``static final`` field (``Utils.commonHeaders``) — the
  declaring file is located under ``source_root`` by simple name +
  package match (unambiguous or refuse, candidate cap), the field
  must be ``static final`` with a constant-collection initializer,
  and EVERY file under the root that mentions the field name must use
  it only as a ``contains`` receiver (a public static collection is
  mutable from anywhere — one ``add`` in any file refuses; scan
  capped, cap hit refuses).

Constant collection constructors: ``Arrays.asList``, ``List.of``,
``Set.of``, ``Collections.unmodifiable{List,Set}`` over one of these,
and ``new HashSet<>/ArrayList<>(...)`` wrapping one — elements must
individually fold to strings via
:func:`core.analysis.const_fold_java.fold_expr` (escape-bearing
literals refuse there, so no decode ambiguity reaches the danger
check).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tree_sitter import Node

logger = logging.getLogger(__name__)

_MAX_DECLARING_CANDIDATES = 8
_MAX_TREE_FILES = 5000
_MAX_REFERENCING_FILES = 64
_MAX_ELEMENTS = 64

_CONST_CTORS = {
    "java.util.Arrays.asList", "Arrays.asList",
    "java.util.List.of", "List.of",
    "java.util.Set.of", "Set.of",
}
_UNMODIFIABLE = {
    "java.util.Collections.unmodifiableList",
    "java.util.Collections.unmodifiableSet",
    "Collections.unmodifiableList", "Collections.unmodifiableSet",
}
_WRAPPER_TYPES = {
    "HashSet", "java.util.HashSet", "ArrayList", "java.util.ArrayList",
    "LinkedHashSet", "java.util.LinkedHashSet", "TreeSet",
    "java.util.TreeSet",
}
def _parser():
    from core.analysis.cfg_builder_java import _get_parser
    return _get_parser()


def _text(n) -> str:
    return n.text.decode("utf-8", errors="replace") if n is not None else ""


def _unwrap(n):
    from core.analysis.cfg_builder_java import _unwrap_value_expr
    return _unwrap_value_expr(n)


class _Refused(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


# ---------------------------------------------------------------------------
# AST helpers
# ---------------------------------------------------------------------------

def _iter_named(root):
    stack = [root]
    while stack:
        cur = stack.pop()
        yield cur
        stack.extend(c for c in cur.children if c.is_named)


def _enclosing_method(root, line: int):
    best = None
    best_span = None
    for n in _iter_named(root):
        if n.type != "method_declaration":
            continue
        start, end = n.start_point[0] + 1, n.end_point[0] + 1
        if start <= line <= end:
            span = end - start
            if best_span is None or span < best_span:
                best, best_span = n, span
    return best


def _line_byte_range(source_text: str, line: int) -> tuple[int, int]:
    """(first_byte, end_byte) of ``line`` — used for writer-interval
    bounds. Statement covering is decided by LINE, not byte: the
    line's first byte is indentation, which no statement node spans."""
    offset = 0
    for i, chunk in enumerate(source_text.splitlines(keepends=True), 1):
        blen = len(chunk.encode("utf-8", errors="replace"))
        if i == line:
            return offset, offset + blen
        offset += blen
    return offset, offset


def _parse_contains_condition(cond) -> tuple[bool, Any, str] | None:
    """``(negated, receiver_node, tested_identifier)`` for a condition
    that is exactly ``[!]<recv>.contains(<ident>)``; None otherwise."""
    cond = _unwrap(cond)
    if cond is None:
        return None
    negated = False
    if cond.type == "unary_expression":
        op = cond.child_by_field_name("operator")
        if _text(op) != "!":
            return None
        negated = True
        cond = _unwrap(cond.child_by_field_name("operand"))
        if cond is None:
            return None
    if cond.type != "method_invocation":
        return None
    name = cond.child_by_field_name("name")
    if _text(name) != "contains":
        return None
    recv = cond.child_by_field_name("object")
    if recv is None:
        return None
    args = cond.child_by_field_name("arguments")
    named_args = [c for c in args.children if c.is_named] if args else []
    if len(named_args) != 1:
        return None
    arg = _unwrap(named_args[0])
    if arg is None or arg.type != "identifier":
        return None
    return negated, recv, _text(arg)


def _body_only_exits(consequence) -> bool:
    """True when the guard's consequence consists solely of exit
    statements (return / throw), possibly inside one block."""
    if consequence is None:
        return False
    if consequence.type in ("return_statement", "throw_statement"):
        return True
    if consequence.type == "block":
        stmts = [c for c in consequence.children if c.is_named]
        return bool(stmts) and all(
            s.type in ("return_statement", "throw_statement") for s in stmts
        )
    return False


def _guard_dominates_sink(guard_if: Node, sink_line: int) -> bool:
    """Exit-on-fail dominance: some ancestor-of-sink statement is a
    LATER sibling of the guard in the guard's parent block (covering
    decided by line — Java statements never share structure with a
    sibling's lines except on one-liners, which refuse below)."""
    parent = guard_if.parent
    if parent is None or parent.type != "block":
        return False
    guard_end_line = guard_if.end_point[0] + 1
    for child in parent.children:
        if not child.is_named or child == guard_if:
            continue
        start = child.start_point[0] + 1
        end = child.end_point[0] + 1
        if start <= sink_line <= end:
            return start > guard_end_line
    return False


def _writers_of(method, name: str) -> list[int]:
    """Byte offsets of every construct that (re)defines ``name``."""
    out: list[int] = []
    for n in _iter_named(method):
        t = n.type
        if t == "assignment_expression":
            lhs = n.child_by_field_name("left")
            if lhs is not None and lhs.type == "identifier" \
                    and _text(lhs) == name:
                out.append(n.start_byte)
        elif t == "update_expression":
            out.extend(n.start_byte for c in n.children if c.is_named and c.type == "identifier" \
                        and _text(c) == name)
        elif t in {"variable_declarator", "enhanced_for_statement"}:
            nm = n.child_by_field_name("name")
            if nm is not None and _text(nm) == name:
                out.append(n.start_byte)
        elif t == "catch_formal_parameter":
            out.extend(n.start_byte for c in n.children if c.is_named and c.type == "identifier" \
                        and _text(c) == name)
    return out


# ---------------------------------------------------------------------------
# Constant-collection resolution
# ---------------------------------------------------------------------------

def _fold_str(node) -> str | None:
    from core.analysis.const_fold_java import _REFUSE, fold_expr
    v = fold_expr(node, lambda _name, _depth: _REFUSE)
    return v if isinstance(v, str) else None


def _const_ctor_elements(expr, resolver) -> list[str] | None:
    """Literal string elements of a constant-collection constructor
    expression, or None when the shape doesn't qualify."""
    expr = _unwrap(expr)
    if expr is None:
        return None
    if expr.type == "object_creation_expression":
        ty = expr.child_by_field_name("type")
        ty_text = _text(ty)
        # generic_type: strip type arguments for the wrapper check
        base_ty = ty_text.split("<", 1)[0].strip()
        if base_ty not in _WRAPPER_TYPES:
            return None
        args = expr.child_by_field_name("arguments")
        named = [c for c in args.children if c.is_named] if args else []
        if len(named) != 1:
            return None
        return _const_ctor_elements(named[0], resolver)
    if expr.type != "method_invocation":
        return None
    try:
        callee = resolver.callable_name(expr)
    except Exception:  # noqa: BLE001 — resolver over scanned source
        return None
    if callee in _UNMODIFIABLE:
        args = expr.child_by_field_name("arguments")
        named = [c for c in args.children if c.is_named] if args else []
        if len(named) != 1:
            return None
        return _const_ctor_elements(named[0], resolver)
    if callee not in _CONST_CTORS:
        return None
    args = expr.child_by_field_name("arguments")
    named = [c for c in args.children if c.is_named] if args else []
    if not named or len(named) > _MAX_ELEMENTS:
        return None
    out: list[str] = []
    for a in named:
        v = _fold_str(a)
        if v is None:
            return None
        out.append(v)
    return out


def _occurrences_contains_only(scope, name: str, *,
                               declarator_ok: bool = True) -> bool:
    """Every identifier occurrence of ``name`` in ``scope`` is either
    its declarator or the receiver of a ``contains`` invocation."""
    for n in _iter_named(scope):
        if n.type != "identifier" or _text(n) != name:
            continue
        p = n.parent
        if declarator_ok and p is not None and p.type == "variable_declarator" \
                and p.child_by_field_name("name") == n:
            continue
        # receiver of <name>.contains(...)
        if p is not None and p.type == "method_invocation" \
                and p.child_by_field_name("object") == n \
                and _text(p.child_by_field_name("name")) == "contains":
            continue
        # the name inside a field_access chain (Utils.NAME) is handled
        # by the chain resolver, not here
        if p is not None and p.type == "field_access":
            continue
        return False
    return True


def _resolve_local_collection(method, name: str, resolver) -> list[str]:
    decl_elems: list[str] | None = None
    for n in _iter_named(method):
        if n.type != "variable_declarator":
            continue
        nm = n.child_by_field_name("name")
        if nm is None or _text(nm) != name:
            continue
        if decl_elems is not None:
            msg = "collection declared more than once"
            raise _Refused(msg)
        value = n.child_by_field_name("value")
        if value is None:
            msg = "collection declared without initializer"
            raise _Refused(msg)
        decl_elems = _const_ctor_elements(value, resolver)
        if decl_elems is None:
            msg = (
                "collection initializer is not a constant "
                           "literal constructor"
            )
            raise _Refused(msg)
    if decl_elems is None:
        msg = "no local declaration for the collection"
        raise _Refused(msg)
    if not _occurrences_contains_only(method, name):
        msg = (
            "collection name used beyond contains() — "
                       "possible mutation or aliasing"
        )
        raise _Refused(msg)
    return decl_elems


def _resolve_static_field(root, name: str, resolver) -> list[str]:
    """``static final`` field with a constant initializer, occurrence
    discipline over the whole file."""
    found: list[str] | None = None
    for n in _iter_named(root):
        if n.type != "field_declaration":
            continue
        decls = [c for c in n.children if c.type == "variable_declarator"]
        for d in decls:
            nm = d.child_by_field_name("name")
            if nm is None or _text(nm) != name:
                continue
            mods = next(
                (c for c in n.children if c.type == "modifiers"), None)
            mod_texts = {_text(c) for c in mods.children} if mods else set()
            if "static" not in mod_texts or "final" not in mod_texts:
                msg = "field is not static final"
                raise _Refused(msg)
            if found is not None:
                msg = "field declared more than once"
                raise _Refused(msg)
            value = d.child_by_field_name("value")
            elems = _const_ctor_elements(value, resolver) \
                if value is not None else None
            if elems is None:
                msg = (
                    "field initializer is not a constant "
                               "literal constructor"
                )
                raise _Refused(msg)
            found = elems
    if found is None:
        msg = "no static final field of that name"
        raise _Refused(msg)
    if not _occurrences_contains_only(root, name):
        msg = "field name used beyond contains() in its file"
        raise _Refused(msg)
    return found


def _package_of(root) -> str:
    for n in root.children:
        if n.type == "package_declaration":
            return _text(n).replace("package", "").strip().rstrip(";").strip()
    return ""


def _resolve_cross_file(chain: str, field: str, source_root: Path,
                        parser) -> list[str]:
    """Resolve ``chain.field`` (chain = dotted type FQN or simple
    class name) to a constant literal set under the coordinator's
    discipline: unambiguous declaring file, static final, constant
    initializer, and no file under the root uses the field for
    anything but ``contains``."""
    simple = chain.rsplit(".", 1)[-1]
    package = chain.rsplit(".", 1)[0] if "." in chain else ""
    candidates = []
    n_seen = 0
    for f in source_root.rglob(f"{simple}.java"):
        n_seen += 1
        if n_seen > _MAX_DECLARING_CANDIDATES:
            msg = "too many declaring-file candidates"
            raise _Refused(msg)
        candidates.append(f)
    declaring = None
    declaring_root = None
    for f in candidates:
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
            tree = parser.parse(text.encode("utf-8", errors="replace"))
        except (OSError, ValueError):
            continue
        pkg = _package_of(tree.root_node)
        if package and pkg != package:
            continue
        if declaring is not None:
            msg = (
                "ambiguous declaring file for the collection "
                           "class"
            )
            raise _Refused(msg)
        declaring, declaring_root = f, tree.root_node
    if declaring is None or declaring_root is None:
        msg = "declaring file for the collection class not found"
        raise _Refused(msg)

    from core.analysis.cfg_builder_java import _NameResolver, build_import_map
    types, statics = build_import_map(declaring_root)
    resolver = _NameResolver(types, statics)
    elems = _resolve_static_field(declaring_root, field, resolver)

    # Mutation-anywhere scan: a static collection is writable from any
    # file that can see it. Occurrences elsewhere must be contains
    # receivers only.
    n_files = 0
    n_refs = 0
    for f in source_root.rglob("*.java"):
        n_files += 1
        if n_files > _MAX_TREE_FILES:
            msg = "source tree too large to verify immutability"
            raise _Refused(msg)
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            msg = "unreadable file during immutability scan"
            raise _Refused(msg)
        if field not in text:
            continue
        n_refs += 1
        if n_refs > _MAX_REFERENCING_FILES:
            msg = "too many files reference the collection"
            raise _Refused(msg)
        if f == declaring:
            continue
        try:
            tree = parser.parse(text.encode("utf-8", errors="replace"))
        except ValueError:
            msg = "unparseable file during immutability scan"
            raise _Refused(msg)
        for n in _iter_named(tree.root_node):
            if n.type != "identifier" or _text(n) != field:
                continue
            p = n.parent
            # accepted shape: <chain>.<field> as the object of a
            # contains() call — i.e. this identifier is the field
            # member of a field_access whose grandparent invocation
            # is contains, or is directly a contains receiver.
            if p is not None and p.type == "field_access" \
                    and p.child_by_field_name("field") == n:
                gp = p.parent
                if gp is not None and gp.type == "method_invocation" \
                        and gp.child_by_field_name("object") == p \
                        and _text(gp.child_by_field_name("name")) \
                        == "contains":
                    continue
            if p is not None and p.type == "method_invocation" \
                    and p.child_by_field_name("object") == n \
                    and _text(p.child_by_field_name("name")) == "contains":
                continue
            msg = f"{f.name} uses the collection beyond contains()"
            raise _Refused(msg)
    return elems


# ---------------------------------------------------------------------------
# Danger check
# ---------------------------------------------------------------------------

def _literals_clear_danger(elems: list[str], cwe: str) -> str | None:
    """Reason fragment when every literal clears every danger model of
    the CWE's sink classes; None otherwise (including unknown class)."""
    from core.dataflow.sanitizer_catalog import sink_classes_for_cwe
    from core.dataflow.smt_barrier import danger_chars_for
    classes = sink_classes_for_cwe(cwe)
    if not classes:
        return None
    for sink_class in classes:
        danger = danger_chars_for(sink_class)
        if danger is None:
            return None
        for lit in elems:
            if any(ch in lit for ch in danger):
                logger.debug(
                    "collection guard: literal %r carries a %s danger "
                    "char — guard insufficient", lit, sink_class)
                return None
    return (f"all {len(elems)} literal(s) clear the "
            f"{sorted(classes)} danger model(s)")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def collection_guard_reason(
    source_text: str,
    sink_line: int,
    sink_arg: str,
    cwe: str,
    *,
    source_root: str | None = None,
    decisions: list[str] | None = None,
) -> str | None:
    """Suppression reason when a dominating constant-collection
    membership guard bounds ``sink_arg`` at ``sink_line`` to a finite
    literal set that clears the CWE's danger models. None = no signal
    (never an error)."""
    if decisions is None:
        decisions = []
    parser = _parser()
    if parser is None:
        return None
    try:
        tree = parser.parse(source_text.encode("utf-8", errors="replace"))
    except Exception:  # noqa: BLE001 — arbitrary scanned source
        return None
    root = tree.root_node
    method = _enclosing_method(root, sink_line)
    if method is None:
        decisions.append("no enclosing method")
        return None
    _sink_line_start, sink_line_end = _line_byte_range(
        source_text, sink_line)

    from core.analysis.cfg_builder_java import _NameResolver, build_import_map
    types, statics = build_import_map(root)
    resolver = _NameResolver(types, statics)

    for n in _iter_named(method):
        if n.type != "if_statement":
            continue
        parsed = _parse_contains_condition(n.child_by_field_name("condition"))
        if parsed is None:
            continue
        negated, recv, tested = parsed
        if tested != sink_arg:
            decisions.append(
                f"guard at line {n.start_point[0] + 1} tests {tested!r}, "
                f"not the sink argument")
            continue
        consequence = n.child_by_field_name("consequence")
        guard_end_line = n.end_point[0] + 1
        if negated:
            if not _body_only_exits(consequence):
                decisions.append("negated guard body is not exit-only")
                continue
            if sink_line <= guard_end_line:
                decisions.append(
                    "sink shares lines with the guard — one-liner "
                    "shapes refuse")
                continue
            if not _guard_dominates_sink(n, sink_line):
                decisions.append("guard does not dominate the sink")
                continue
        else:
            # enclosed form: the sink line strictly inside the
            # consequence's line span (and never in an else branch —
            # the else spans different lines of the same statement,
            # checked explicitly). The sink line must also sit BELOW
            # the condition's last line: with line-granular sink
            # coordinates, a sink "on the guard's line" could be the
            # condition's own contains() call or a one-liner body —
            # corpus-caught, refuse both (one-line enclosed forms are
            # a conservative loss, not a soundness need).
            cond = n.child_by_field_name("condition")
            cond_end_line = (cond.end_point[0] + 1) if cond is not None \
                else guard_end_line
            if sink_line <= cond_end_line:
                decisions.append(
                    "sink shares lines with the guard condition — "
                    "refused")
                continue
            if consequence is None or not (
                consequence.start_point[0] + 1 <= sink_line
                <= consequence.end_point[0] + 1
            ):
                decisions.append(
                    "positive guard does not enclose the sink — "
                    "exclusion shapes never bind")
                continue
            alt = n.child_by_field_name("alternative")
            if alt is not None and (
                alt.start_point[0] + 1 <= sink_line
                <= alt.end_point[0] + 1
            ):
                decisions.append("sink sits in the guard's else branch")
                continue
        # Writer interval: from the guard's start to the END of the
        # sink line — a same-line writer after the sink call refuses
        # too (conservative direction).
        interval = (n.start_byte, sink_line_end)
        writers = _writers_of(method, sink_arg)
        if any(interval[0] < w < interval[1] for w in writers):
            decisions.append(
                f"{sink_arg!r} is written between guard and sink")
            continue

        recv_u = _unwrap(recv)
        try:
            if recv_u is not None and recv_u.type == "identifier":
                name = _text(recv_u)
                try:
                    elems = _resolve_local_collection(method, name, resolver)
                except _Refused:
                    elems = _resolve_static_field(root, name, resolver)
            elif recv_u is not None and recv_u.type in (
                    "field_access", "scoped_identifier"):
                chain_text = _text(recv_u)
                head, _, field = chain_text.rpartition(".")
                if not head or not field:
                    msg = "unresolvable collection chain"
                    raise _Refused(msg)
                resolved_head = resolver._resolve_chain(head)
                if source_root is None:
                    msg = "cross-file collection needs a source root"
                    raise _Refused(msg)
                elems = _resolve_cross_file(
                    resolved_head, field, Path(source_root), parser)
            else:
                msg = "unsupported collection receiver shape"
                raise _Refused(msg)
        except _Refused as r:
            decisions.append(f"collection resolution refused: {r.reason}")
            continue

        cleared = _literals_clear_danger(elems, cwe)
        if cleared is None:
            decisions.append(
                "a literal carries a danger char (or unknown class) — "
                "guard insufficient")
            continue
        for d in decisions:
            logger.debug("collection guard: %s", d)
        return (
            f"collection-membership guard: {sink_arg!r} bounded to "
            f"{len(elems)} literal(s) by the dominating contains-guard "
            f"at line {n.start_point[0] + 1}; {cleared}"
        )
    for d in decisions:
        logger.debug("collection guard: %s", d)
    return None


__all__ = ["collection_guard_reason"]
