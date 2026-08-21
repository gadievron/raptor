"""Bounded constant-table resolution for the Java value gate.

Resolves ONE shape the constant folder refuses structurally: a read
from a small, provably-unmodified constant array by a
constant-foldable index —

    String[] values = {"safe0", "safe1", "safe2"};
    String bar = values[1];          // → "safe1", a constant

Array elements can alias, so :mod:`core.analysis.const_fold_java`
refuses every ``array_access``. This module supplies the missing
aliasing analysis with a refusal-first whole-file scan: a table name
qualifies only when its every appearance in the analysed span is one
of (a) its single initializing declarator with an array-literal
value, or (b) an ``array_access`` READ base. Any other appearance —
an element store (``values[i] = …``, compound or update forms), the
bare name as a call argument (the callee may mutate it), an alias
creation (``other = values``), a field/return escape, a second
declarator of the same name — disqualifies the name entirely. This
is deliberately coarser than necessary: a general bounded
interpreter must never out-clever its own aliasing model, and the
false-suppression direction is exactly a store the scan missed.

Hard bounds: array literals over ``_MAX_ELEMENTS`` refuse; elements
must fold literal-only (identifier elements refuse); the index must
fold to an in-range integer. Every refusal returns
:data:`~core.analysis.const_fold_java.REFUSE` — never a guess.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple

from core.analysis.const_fold_java import REFUSE, fold_expr

_MAX_ELEMENTS = 32

_ARRAY_ACCESS = "array_access"
_ASSIGNMENT = "assignment_expression"
_UPDATE = "update_expression"
_VAR_DECLARATOR = "variable_declarator"
_ARRAY_INIT = "array_initializer"
_ARRAY_CREATION = "array_creation_expression"
_IDENT = "identifier"


def _parser():
    from core.analysis.cfg_builder_java import _get_parser
    return _get_parser()


def _initializer_elements(value_node) -> Optional[List]:
    """Element nodes of ``{…}`` or ``new T[]{…}``; None otherwise."""
    if value_node is None:
        return None
    if value_node.type == _ARRAY_INIT:
        init = value_node
    elif value_node.type == _ARRAY_CREATION:
        init = next(
            (c for c in value_node.children if c.type == _ARRAY_INIT),
            None,
        )
        if init is None:
            return None
    else:
        return None
    return [c for c in init.children if c.is_named]


class ArrayTableIndex:
    """Per-file index of constant-table candidates (see module doc)."""

    def __init__(self, source_text: str,
                 line_span: Tuple[int, int]) -> None:
        self.ok = False
        self._elements: Dict[str, List[Any]] = {}
        self._refused: Set[str] = set()
        parser = _parser()
        if parser is None:
            return
        try:
            tree = parser.parse(source_text.encode("utf-8"))
        except Exception:  # noqa: BLE001
            return
        lo, hi = line_span
        # tree-sitter recreates Python node wrappers on every access,
        # so cross-traversal comparisons key on byte spans, never
        # object identity.
        declarator_name_spans: Set[Tuple[int, int]] = set()

        # Pass 1 — collect candidate tables.
        stack = [tree.root_node]
        while stack:
            n = stack.pop()
            if n.start_point[0] + 1 > hi or n.end_point[0] + 1 < lo:
                continue
            if n.type == _VAR_DECLARATOR:
                name_node = n.child_by_field_name("name")
                value = n.child_by_field_name("value")
                elements = _initializer_elements(value)
                if (name_node is not None and name_node.type == _IDENT
                        and elements is not None):
                    name = name_node.text.decode()
                    if name in self._elements:
                        # A second table declarator of the same name —
                        # scope/shadowing games the scan won't model.
                        self._refused.add(name)
                    elif len(elements) > _MAX_ELEMENTS:
                        self._refused.add(name)
                    else:
                        self._elements[name] = elements
                        declarator_name_spans.add(
                            (name_node.start_byte, name_node.end_byte))
            stack.extend(n.children)

        # Pass 2 — disqualify on any appearance outside the allowed
        # shapes, walking with explicit parent links.
        stack2 = [(tree.root_node, None, None)]
        while stack2:
            n, parent, grandparent = stack2.pop()
            if n.type == _IDENT:
                name = n.text.decode()
                if name in self._elements and name not in self._refused:
                    if not self._appearance_allowed(
                            n, parent, grandparent,
                            declarator_name_spans):
                        self._refused.add(name)
            for c in n.children:
                stack2.append((c, n, parent))
        self.ok = True

    @staticmethod
    def _spans_match(a, b) -> bool:
        return (a is not None and b is not None
                and a.start_byte == b.start_byte
                and a.end_byte == b.end_byte)

    def _appearance_allowed(self, ident, parent, grandparent,
                            declarator_name_spans) -> bool:
        if parent is None:
            return False
        # (a) the recorded initializing declarator's own name node
        if parent.type == _VAR_DECLARATOR \
                and (ident.start_byte, ident.end_byte) \
                in declarator_name_spans:
            return True
        # (b) the base of an array_access READ
        if parent.type == _ARRAY_ACCESS and self._spans_match(
                parent.child_by_field_name("array"), ident):
            if grandparent is not None \
                    and grandparent.type == _ASSIGNMENT \
                    and self._spans_match(
                        grandparent.child_by_field_name("left"), parent):
                return False  # element store (plain or compound)
            if grandparent is not None and grandparent.type == _UPDATE:
                return False  # values[i]++
            return True
        return False

    def elements(self, name: str) -> Optional[List[Any]]:
        """Element nodes for a qualified table; None = refused/unknown."""
        if name in self._refused:
            return None
        return self._elements.get(name)


_MAX_NESTING = 8


def make_array_resolver(table_index: ArrayTableIndex, fold):
    """Array-access hook for the constant folder.

    ``fold(node, resolve_name, depth)`` is the folder's own recursion
    (dependency-injected — this module must not import private folder
    internals). The returned resolver carries a ``hits`` attribute
    counting successful table resolutions, so callers can annotate
    their evidence records. Re-entrancy is capped: nested table reads
    in index position (``a[a[a[…]]]``) refuse past
    :data:`_MAX_NESTING` levels rather than recursing.
    """

    def resolve(node, resolve_name, depth: int) -> Any:
        if table_index is None or not table_index.ok:
            return REFUSE
        if resolve.active >= _MAX_NESTING:
            return REFUSE
        base = node.child_by_field_name("array")
        idx = node.child_by_field_name("index")
        if base is None or idx is None or base.type != _IDENT:
            return REFUSE
        elements = table_index.elements(base.text.decode())
        if elements is None:
            return REFUSE
        resolve.active += 1
        try:
            index_val = fold(idx, resolve_name, depth)
        finally:
            resolve.active -= 1
        if index_val is REFUSE or isinstance(index_val, bool) \
                or not isinstance(index_val, int):
            return REFUSE
        if not (0 <= index_val < len(elements)):
            return REFUSE
        # Elements fold literal-only: an identifier element would need
        # its own reaching-defs proof at the initializer, which this
        # bounded model does not carry.
        value = fold_expr(elements[index_val], lambda _n, _d: REFUSE)
        if value is REFUSE:
            return REFUSE
        resolve.hits += 1
        return value

    resolve.hits = 0
    resolve.active = 0
    return resolve


def build_table_resolver(source_text: str,
                         line_span: Tuple[int, int]):
    """Index + self-referential fold hook in one call.

    Returns the resolver (with ``.hits``) or ``None`` when the parser
    is unavailable / indexing failed. The hook folds index expressions
    with the SAME resolver installed, so a constant-table read may
    itself index another qualified table (nesting-capped).
    """
    index = ArrayTableIndex(source_text, line_span)
    if not index.ok:
        return None

    box: Dict[str, Any] = {}

    def _fold_hooked(node, resolve_name, _depth: int) -> Any:
        return fold_expr(node, resolve_name, box.get("r"))

    resolver = make_array_resolver(index, _fold_hooked)
    box["r"] = resolver
    return resolver




def finite_constant_value_set(
    rd,
    at_node,
    name: str,
    index,
    array_resolver=None,
    config_resolver=None,
    conduit_resolver=None,
    max_values: int = 8,
):
    """The bounded value-set of ``name`` at ``at_node`` as a frozenset
    of compile-time constants, or None.

    This is the if-equals-chain recognizer generalised to the
    reaching-definitions level (b40): the canonical shape

        String y;
        if (x.equals("a"))      { y = "v1"; }
        else if (x.equals("b")) { y = "v2"; }
        else                    { y = "d";  }
        sink(y);

    binds ``y``'s value to the finite set {"v1", "v2", "d"} regardless
    of ``x`` — every reaching definer at the sink is one of the
    chain's constant assignments. Anchoring on reaching definitions
    (rather than on the chain's syntax) is strictly MORE demanding:
    any path that leaves a non-constant definition live at the sink —
    a missing else over a tainted pre-initialisation, a branch that
    assigns from a call — surfaces that definer, which refuses the
    fold, and the whole set reads as None. Chain length is bounded by
    ``max_values`` definers; TAINT_FREE definers refuse (no value to
    run through a danger model — the caller's per-element check needs
    members, not tiers).
    """
    from core.analysis.const_fold_java import definer_fold_values

    values = definer_fold_values(
        rd, at_node, name, index,
        array_resolver=array_resolver,
        config_resolver=config_resolver,
        conduit_resolver=conduit_resolver,
        max_definers=max_values,
    )
    if values is None:
        return None
    return frozenset(values)


__all__ = ["ArrayTableIndex", "build_table_resolver",
           "finite_constant_value_set", "make_array_resolver"]
