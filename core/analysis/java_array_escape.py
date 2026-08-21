"""Element-sensitive local-array tracking for the Java value gate.

The b13 leg stamps ``may_escape`` on ANY statement containing an
``array_access``, and the value gate downgrades a held suppression to
``candidate_only`` whenever a ``may_escape`` node sits on a
source→sink path. That blanket rule is sound but blunt: the OWASP
Benchmark's dominant safe idiom writes a sanitizer's output (or a
constant) into a LOCAL array element and reads the same element back
— ``String[] a = new String[2]; a[0] = Encode.forHtml(x);
out.println(a[0]);`` — which lands in ``candidate_only`` twice over
(the element store carries no ``assigned_names``, and the statement
is ``may_escape``).

This module answers two questions from the source text alone,
refusal-first:

1. **Tracking** — is a given array name a LOCAL array whose reference
   provably never escapes the method and whose every element access
   uses a decimal-integer-literal index? The rule is deliberately
   syntactic and total: the ONLY permitted appearances of a tracked
   name are (a) its single declaration initialised with a fresh
   ``new T[...]`` / ``{...}`` initializer and (b) as the base of a
   simple ``name[<int-literal>]`` access. ANY other occurrence —
   call argument, alias assignment (either direction), ``return``,
   field store, enhanced-for iterable, nested/complex access,
   non-literal index, compound element write (``a[0] += x`` /
   ``a[0]++``) — untracks the name. Java locals cannot be aliased
   except through such occurrences, so a tracked array's elements
   behave like unaliased locals keyed by (name, index).

2. **Element-exclusive sanitizer definitions** — for a tracked array
   element, is EVERY write to that element (flow-insensitively, over
   the whole method span) an assignment whose RHS is exactly one
   catalog-sanitizer call? Flow-insensitivity here is the SOUND
   choice, not a shortcut: base-name reaching-defs cannot be trusted
   for element reasoning because a write to ``a[1]`` kills a prior
   write to ``a[0]`` in the base-name lattice — exactly the inversion
   that would false-suppress ``a[0] = tainted; a[1] = sanitize(x);
   sink(a[0])``. Requiring every write to the read element to be a
   sanitizer output makes the conclusion independent of which write
   reaches. (An element never written reads as Java's ``null``
   default — not attacker data.)

The per-line escape classification (:meth:`LocalArrayIndex.exempt_line`)
additionally lets the gate keep a suppression whose only
``may_escape`` trigger is a tracked-array access: tracked arrays
cannot alias the scalar the value gate already proved exclusively
sanitizer-defined. Lines carrying a field store, ``System.arraycopy``,
an untracked-array access, or NO classified trigger at all (the
multi-line-statement case, where the trigger sits on a later physical
line than the node's lineno) are never exempt.

Like :mod:`core.analysis.const_fold_java`, this module re-parses the
file with tree-sitter and any internal failure reads as "not tracked"
/ "not exempt" — the refusal direction.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


_INT_LITERAL = "decimal_integer_literal"
_ARRAY_ACCESS = "array_access"
_ASSIGNMENT = "assignment_expression"
_UPDATE = "update_expression"
_DECLARATOR = "variable_declarator"
_IDENT = "identifier"
_FIELD_ACCESS = "field_access"
_METHOD_INVOCATION = "method_invocation"
_FRESH_INITIALIZERS = frozenset({
    "array_creation_expression",
    "array_initializer",
})


def _parser():
    from core.analysis.cfg_builder_java import _get_parser
    return _get_parser()


def _unwrap(n):
    from core.analysis.cfg_builder_java import _unwrap_value_expr
    return _unwrap_value_expr(n)


def _text(n) -> str:
    return n.text.decode("utf-8", errors="replace") if n is not None else ""


@dataclass
class _ElementWrite:
    lineno: int
    rhs: Any                      # tree-sitter node (may be None)


@dataclass
class LocalArrayIndex:
    """Per-method-span index of local-array facts. Construct via
    :func:`build_local_array_index`; ``ok`` is False when parsing
    failed (every query then refuses)."""

    ok: bool = False
    _fresh: Set[str] = field(default_factory=set)
    # Names whose single sink-line whole-array occurrence was exempted
    # (see build_local_array_index's sink_exempt).
    _whole_pass_names: Set[str] = field(default_factory=set)
    _violated: Set[str] = field(default_factory=set)
    _global_refuse: bool = False
    _writes: Dict[Tuple[str, int], List[_ElementWrite]] = field(
        default_factory=dict)
    # (lineno, base_name) -> set of int indices read there
    _reads_at: Dict[Tuple[int, str], Set[int]] = field(default_factory=dict)
    # (lineno, lhs_name) -> (array_name, index); dropped on multi-writer
    _scalar_copies: Dict[Tuple[int, str], Tuple[str, int]] = field(
        default_factory=dict)
    # (lineno, lhs_name) -> writer count (declarators + assignments)
    _lhs_writers: Dict[Tuple[int, str], int] = field(default_factory=dict)
    # lineno -> escape-trigger classification flags
    _line_flags: Dict[int, Set[str]] = field(default_factory=dict)
    # per-line array bases touched, finalized into _line_flags
    _line_bases: Dict[int, Set[str]] = field(default_factory=dict)
    _resolver: Any = None

    # ----- queries ---------------------------------------------------

    def whole_pass_ok(self, name: str) -> bool:
        """True when the name's only escape was the exempted sink
        argument occurrence."""
        return name in self._whole_pass_names and self.tracked(name)

    def tracked(self, name: str) -> bool:
        """True iff ``name`` is a local, fresh-initialised, never-
        escaping array with literal-index-only accesses."""
        if not self.ok or self._global_refuse:
            return False
        return name in self._fresh and name not in self._violated

    def element_writes(self, name: str, index: int) -> List[_ElementWrite]:
        return list(self._writes.get((name, index), ()))

    def element_reads_at(self, lineno: int, name: str) -> Optional[Set[int]]:
        """Indices of ``name`` read on ``lineno``; None when the line
        carries no recorded element read of that name."""
        got = self._reads_at.get((lineno, name))
        return set(got) if got else None

    def scalar_copy(self, lineno: int, lhs: str) -> Optional[Tuple[str, int]]:
        """``(array, index)`` when the ONLY write of ``lhs`` on
        ``lineno`` is ``lhs = array[index]``; None otherwise (including
        the same-line-multi-writer hazard: ``if (c) bar = a[0]; else
        bar = x;`` shares one lineno, so the entry is dropped)."""
        if self._lhs_writers.get((lineno, lhs), 0) != 1:
            return None
        return self._scalar_copies.get((lineno, lhs))

    def exempt_line(self, lineno: int) -> bool:
        """True iff every escape trigger classified on ``lineno`` is a
        tracked-array access — and at least one trigger WAS classified
        (an empty set means the trigger lives on a different physical
        line of a multi-line statement; never exempt on absence of
        evidence)."""
        if not self.ok or self._global_refuse:
            return False
        flags = set(self._line_flags.get(lineno, set()))
        for base in self._line_bases.get(lineno, set()):
            flags.add(
                "tracked_array" if self.tracked(base) else "untracked_array"
            )
        return bool(flags) and flags <= {"tracked_array"}

    def write_is_catalog_call(self, write: _ElementWrite,
                              catalog_callables: Set[str]) -> bool:
        """True iff the write's RHS is exactly one method invocation
        (casts/parens unwrapped) whose import-resolved name is in
        ``catalog_callables``."""
        if not self.ok or self._resolver is None or write.rhs is None:
            return False
        rhs = _unwrap(write.rhs)
        if rhs is None or rhs.type != _METHOD_INVOCATION:
            return False
        try:
            name = self._resolver.callable_name(rhs)
        except Exception:  # noqa: BLE001 — resolver over arbitrary source
            return False
        return name is not None and name in catalog_callables


def build_local_array_index(
    source_text: str, line_span: Tuple[int, int],
    sink_exempt: Optional[Tuple[int, str]] = None,
) -> Optional[LocalArrayIndex]:
    """Build the index over ``line_span`` (inclusive, 1-based — the
    method body's line range). None when the grammar is unavailable
    or parsing fails.

    ``sink_exempt=(lineno, name)`` permits AT MOST ONE otherwise-
    unconsumed bare occurrence of ``name`` on ``lineno`` — the sink
    call's whole-array argument — recording it in
    ``_whole_pass_names`` instead of violating. A second unconsumed
    occurrence on that line still violates (conservative)."""
    parser = _parser()
    if parser is None:
        return None
    try:
        from core.analysis.cfg_builder_java import (
            _NameResolver,
            build_import_map,
        )
        tree = parser.parse(source_text.encode("utf-8", errors="replace"))
    except Exception:  # noqa: BLE001 — arbitrary scanned source
        return None

    idx = LocalArrayIndex(ok=True)
    types, statics = build_import_map(tree.root_node)
    idx._resolver = _NameResolver(types, statics)
    lo, hi = line_span
    # Byte ranges of identifier nodes consumed by a permitted
    # appearance (declarator names, tracked-access bases).
    consumed: Set[Tuple[int, int]] = set()

    def line_of(n) -> int:
        return n.start_point[0] + 1

    def in_span(n) -> bool:
        return not (n.start_point[0] + 1 > hi or n.end_point[0] + 1 < lo)

    def flag(lineno: int, name: str) -> None:
        idx._line_flags.setdefault(lineno, set()).add(name)

    def record_access(acc, *, is_write: bool, rhs=None,
                      compound: bool = False) -> None:
        base = acc.child_by_field_name("array")
        index_node = acc.child_by_field_name("index")
        ln = line_of(acc)
        if base is None or base.type != _IDENT:
            # Nested / field-based array access — untrack the base-most
            # name; unknown shapes refuse everything.
            from core.analysis.cfg_builder_java import _base_ident
            bm = _base_ident(acc)
            if bm is None:
                idx._global_refuse = True
            else:
                idx._violated.add(bm)
                idx._line_bases.setdefault(ln, set()).add(bm)
            # Still walk the index subtree for inner accesses/uses.
            if index_node is not None:
                walk(index_node)
            return
        name = _text(base)
        consumed.add((base.start_byte, base.end_byte))
        idx._line_bases.setdefault(ln, set()).add(name)
        const_index: Optional[int] = None
        if index_node is not None and index_node.type == _INT_LITERAL:
            try:
                const_index = int(_text(index_node))
            except ValueError:
                const_index = None
        if const_index is None:
            idx._violated.add(name)
        elif compound:
            idx._violated.add(name)
        elif is_write:
            idx._writes.setdefault((name, const_index), []).append(
                _ElementWrite(lineno=ln, rhs=rhs))
        else:
            idx._reads_at.setdefault((ln, name), set()).add(const_index)
        if index_node is not None and index_node.type != _INT_LITERAL:
            walk(index_node)

    def record_declarator(decl) -> None:
        name_node = decl.child_by_field_name("name")
        value = decl.child_by_field_name("value")
        if name_node is None or name_node.type != _IDENT:
            return
        lhs = _text(name_node)
        ln = line_of(decl)
        consumed.add((name_node.start_byte, name_node.end_byte))
        key = (ln, lhs)
        idx._lhs_writers[key] = idx._lhs_writers.get(key, 0) + 1
        if value is None:
            return
        v = _unwrap(value)
        if v is not None and v.type in _FRESH_INITIALIZERS:
            # Fresh array: first fresh declaration tracks; a second
            # declaration of the same name anywhere is shadowing the
            # gate can't order — untrack.
            if lhs in idx._fresh:
                idx._violated.add(lhs)
            idx._fresh.add(lhs)
            if v.type == "array_initializer":
                for i, el in enumerate(c for c in v.children if c.is_named):
                    idx._writes.setdefault((lhs, i), []).append(
                        _ElementWrite(lineno=line_of(el), rhs=el))
                    walk(el)
            else:
                for c in v.children:
                    if c.is_named:
                        walk(c)
            return
        if v is not None and v.type == _ARRAY_ACCESS:
            b = v.child_by_field_name("array")
            ix = v.child_by_field_name("index")
            if (b is not None and b.type == _IDENT
                    and ix is not None and ix.type == _INT_LITERAL):
                try:
                    idx._scalar_copies[key] = (_text(b), int(_text(ix)))
                except ValueError:
                    pass
        walk(value)

    def record_assignment(asgn) -> None:
        left = asgn.child_by_field_name("left")
        right = asgn.child_by_field_name("right")
        op = asgn.child_by_field_name("operator")
        op_text = _text(op) if op is not None else "="
        ln = line_of(asgn)
        if left is not None and left.type == _ARRAY_ACCESS:
            record_access(left, is_write=True, rhs=right,
                          compound=(op_text != "="))
            if right is not None:
                walk(right)
            return
        if left is not None and left.type == _FIELD_ACCESS:
            flag(ln, "field_store")
            walk(left)
            if right is not None:
                walk(right)
            return
        if left is not None and left.type == _IDENT:
            lhs = _text(left)
            key = (ln, lhs)
            idx._lhs_writers[key] = idx._lhs_writers.get(key, 0) + 1
            if op_text == "=" and right is not None:
                r = _unwrap(right)
                if r is not None and r.type == _ARRAY_ACCESS:
                    b = r.child_by_field_name("array")
                    ix = r.child_by_field_name("index")
                    if (b is not None and b.type == _IDENT
                            and ix is not None and ix.type == _INT_LITERAL):
                        try:
                            idx._scalar_copies[key] = (
                                _text(b), int(_text(ix)))
                        except ValueError:
                            pass
            # A tracked array on the LHS bare (``a = other``) is a
            # re-alias: the leftover-occurrence scan catches it (the
            # LHS identifier is not consumed).
            if right is not None:
                walk(right)
            return
        # Any other LHS shape: walk everything.
        if left is not None:
            walk(left)
        if right is not None:
            walk(right)

    def walk(n) -> None:
        if n is None or not in_span(n):
            return
        t = n.type
        if t == _ASSIGNMENT:
            record_assignment(n)
            return
        if t == _DECLARATOR:
            record_declarator(n)
            return
        if t == _ARRAY_ACCESS:
            record_access(n, is_write=False)
            return
        if t == _UPDATE:
            inner = next((c for c in n.children if c.is_named), None)
            if inner is not None and inner.type == _ARRAY_ACCESS:
                record_access(inner, is_write=True, compound=True)
                return
        if t == _METHOD_INVOCATION:
            obj = n.child_by_field_name("object")
            name = n.child_by_field_name("name")
            if (obj is not None and obj.type == _IDENT
                    and _text(obj) == "System"
                    and _text(name) == "arraycopy"):
                flag(line_of(n), "arraycopy")
        for c in n.children:
            if c.is_named:
                walk(c)

    walk(tree.root_node)

    # Leftover-occurrence scan: any identifier equal to a fresh array
    # name whose byte range wasn't consumed by a permitted appearance
    # escapes the array (call arg, alias in/out, return, iterable,
    # whole-array sink pass, LHS re-alias, ...).
    if idx._fresh:
        stack = [tree.root_node]
        while stack:
            cur = stack.pop()
            if not in_span(cur):
                continue
            if cur.type == _IDENT:
                nm = _text(cur)
                if nm in idx._fresh and (
                        (cur.start_byte, cur.end_byte) not in consumed):
                    if (sink_exempt is not None
                            and nm == sink_exempt[1]
                            and cur.start_point[0] + 1 == sink_exempt[0]
                            and nm not in idx._whole_pass_names):
                        idx._whole_pass_names.add(nm)
                    else:
                        idx._violated.add(nm)
                continue
            for c in cur.children:
                if c.is_named:
                    stack.append(c)
    return idx


__all__ = [
    "LocalArrayIndex",
    "build_local_array_index",
]
