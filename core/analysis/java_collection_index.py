"""Element-sensitive local-collection tracking for the Java value gate.

The b19 leg answered element questions for LOCAL ARRAYS; this module
extends the same refusal-first discipline to the other half of the
OWASP-style indirection population: local ``Map`` / ``List`` round
trips — ``map.put("k", v); bar = (String) map.get("k"); sink(bar)``.
Both program directions break on that hop today: the value gate cannot
pass a sanitizer/constant verdict through ``put``/``get`` (FP side,
the finding stays ``candidate_only``/``no_suppress``), and semgrep's
taint engine drops the chain at the same hop (FN side — handled
separately by rule propagators; this module is the gate side).

Tracking rules, deliberately syntactic and total (mirroring
:mod:`core.analysis.java_array_escape`):

* A collection is **tracked** when it is a local declared ONCE with a
  fresh, argument-free ``new`` of an allowlisted concrete type
  (``HashMap``/``Hashtable``/``LinkedHashMap``/``TreeMap`` →
  map-kind; ``ArrayList``/``LinkedList``/``Vector`` → list-kind; a
  copy-constructor ``new HashMap<>(other)`` imports unknown state and
  refuses), and the ONLY other appearances of its name are as the
  receiver of allowlisted accessor calls — map: ``put(<string
  literal>, v)`` / ``get(<string literal>)``; list: ``add(v)`` /
  ``add(i, v)`` / ``set(i, v)`` / ``get(i)``. ANY other occurrence —
  call argument, alias in or out, ``return``, field store, iteration,
  a non-allowlisted method (``remove``/``clear``/``putAll``/
  ``values``/...), a second declaration — untracks the name via the
  leftover-occurrence scan. Java locals cannot alias otherwise, so a
  tracked collection's contents are exactly its recorded writes.

* **Map writes are keyed by the decoded string-literal key**; a
  non-literal (or escape-carrying) key anywhere untracks the map —
  key identity would be unprovable.

* **List writes all land on one synthetic key** (:data:`ALL_ELEMENTS`)
  regardless of position: ``add``'s index is order-dependent, so the
  only sound positional statement is "every element ever written".
  A list read is therefore governed by ALL writes to the list, which
  is exactly the flow-insensitive every-write discipline the array
  leg settled (a read of an element the writes don't cover returns
  null — not attacker data).

* **Reads**: ``get`` with a literal key (map) or any single-argument
  ``get`` (list — the all-writes rule makes the index irrelevant);
  recorded per line for the sink-direct shape, and as scalar copies
  for the one-hop shape (``bar = (String) map.get("k")`` — casts and
  parens unwrapped; the same-line multi-writer hazard drops the
  entry, mirroring the array leg).

Like the array leg, any parse/shape surprise reads as "not tracked" —
the refusal direction. The fold-hook factory
(:func:`make_collection_fold_resolver`) additionally lets the Java
constant folder resolve ``get`` calls on tracked collections to a
compile-time constant when EVERY write to the consumed key folds to
the same constant; it composes with the conduit hook (both return
``None`` for calls they do not own).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tree_sitter import Node

#: Synthetic key for list elements — every write governs every read.
ALL_ELEMENTS = "*"

_MAP_TYPES = frozenset({
    "HashMap", "Hashtable", "LinkedHashMap", "TreeMap",
})
_LIST_TYPES = frozenset({
    "ArrayList", "LinkedList", "Vector",
})
_MAP_WRITE = frozenset({"put"})
_MAP_READ = frozenset({"get"})
_LIST_WRITE = frozenset({"add", "set"})
_LIST_READ = frozenset({"get"})
_LIST_REMOVE = frozenset({"remove"})
# Positional simulation cap: ops beyond this refuse (never mis-simulate).
_MAX_POSITIONAL_OPS = 32

_IDENT = "identifier"
_METHOD_INVOCATION = "method_invocation"
_OBJECT_CREATION = "object_creation_expression"
_DECLARATOR = "variable_declarator"
_ASSIGNMENT = "assignment_expression"
_STRING_LITERAL = "string_literal"


def _parser():
    from core.analysis.cfg_builder_java import _get_parser
    return _get_parser()


def _unwrap(n):
    from core.analysis.cfg_builder_java import _unwrap_value_expr
    return _unwrap_value_expr(n)


def _text(n) -> str:
    return n.text.decode("utf-8", errors="replace") if n is not None else ""


def _decoded_string_literal(n) -> str | None:
    """Decoded value of a plain string literal; None for anything
    else (escape-carrying literals refuse — mis-decoding a key would
    conflate two distinct elements)."""
    if n is None or n.type != _STRING_LITERAL:
        return None
    raw = _text(n)
    if len(raw) < 2 or "\\" in raw:
        return None
    return raw[1:-1]


@dataclass
class _ElementWrite:
    lineno: int
    rhs: Any                      # tree-sitter node (may be None)


def _int_literal(n) -> int | None:
    """Decimal int literal value, else None."""
    u = _unwrap(n)
    if u is None or u.type != "decimal_integer_literal":
        return None
    try:
        return int(_text(u))
    except ValueError:
        return None


def _block_id(n) -> int | None:
    """Start byte of the nearest enclosing block statement — the
    linearity token: positional simulation demands every op share
    one block, so recorded order IS execution order."""
    cur = n.parent
    while cur is not None:
        if cur.type == "block":
            return cur.start_byte
        cur = cur.parent
    return None


@dataclass
class LocalCollectionIndex:
    """Per-method-span index of local map/list facts. Construct via
    :func:`build_local_collection_index`; ``ok`` is False when parsing
    failed (every query then refuses)."""

    ok: bool = False
    _kind: dict[str, str] = field(default_factory=dict)    # name → map|list
    _violated: set[str] = field(default_factory=set)
    _writes: dict[tuple[str, str], list[_ElementWrite]] = field(
        default_factory=dict)
    # (lineno, base_name) -> keys read there
    _reads_at: dict[tuple[int, str], set[str]] = field(default_factory=dict)
    # (lineno, lhs_name) -> (collection_name, key); dropped on multi-writer
    _scalar_copies: dict[tuple[int, str], tuple[str, str]] = field(
        default_factory=dict)
    # (lineno, lhs_name) -> writer count (declarators + assignments)
    _lhs_writers: dict[tuple[int, str], int] = field(default_factory=dict)
    # (lineno, col) of qualifying get-invocations -> (name, key)
    _get_sites: dict[tuple[int, int], tuple[str, str]] = field(
        default_factory=dict)
    _resolver: Any = None

    # ----- queries ---------------------------------------------------

    def tracked(self, name: str) -> bool:
        """True iff ``name`` is a local, fresh-initialised,
        never-escaping collection whose every access is allowlisted
        with provable keys."""
        if not self.ok:
            return False
        return name in self._kind and name not in self._violated

    def element_writes(self, name: str, key: str) -> list[_ElementWrite]:
        return list(self._writes.get((name, key), ()))

    def element_reads_at(self, lineno: int, name: str) -> set[str] | None:
        got = self._reads_at.get((lineno, name))
        return set(got) if got else None

    def scalar_copy(self, lineno: int, lhs: str) -> tuple[str, str] | None:
        """``(collection, key)`` when the ONLY write of ``lhs`` on
        ``lineno`` is ``lhs = <cast?> coll.get(key)``; None otherwise
        (same-line multi-writer hazard drops the entry)."""
        if self._lhs_writers.get((lineno, lhs), 0) != 1:
            return None
        return self._scalar_copies.get((lineno, lhs))

    def get_site(self, lineno: int, col: int) -> tuple[str, str] | None:
        """``(collection, key)`` for a qualifying ``get`` invocation at
        that position on a TRACKED collection; None otherwise."""
        got = self._get_sites.get((lineno, col))
        if got is None or not self.tracked(got[0]):
            return None
        return got

    def write_is_catalog_call(self, write: _ElementWrite,
                              catalog_callables: set[str]) -> bool:
        """True iff the write's RHS is exactly one method invocation
        (casts/parens unwrapped) whose import-resolved name is in
        ``catalog_callables`` — byte-for-byte the array leg's rule."""
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


def _fresh_collection_kind(value) -> str | None:
    """``"map"`` / ``"list"`` when ``value`` is an argument-free fresh
    ``new`` of an allowlisted concrete type; None otherwise."""
    v = _unwrap(value)
    if v is None or v.type != _OBJECT_CREATION:
        return None
    if any(c.type == "class_body" for c in v.children):
        return None                       # anonymous subclass
    ty = _text(v.child_by_field_name("type"))
    ty = ty.split("<", 1)[0].strip().split(".")[-1]
    args = v.child_by_field_name("arguments")
    n_args = len([c for c in args.children if c.is_named]) \
        if args is not None else 0
    if n_args != 0:
        return None                       # copy-construction imports state
    if ty in _MAP_TYPES:
        return "map"
    if ty in _LIST_TYPES:
        return "list"
    return None


def build_local_collection_index(
    source_text: str, line_span: tuple[int, int],
) -> LocalCollectionIndex | None:
    """Build the index over ``line_span`` (inclusive, 1-based). None
    when the grammar is unavailable or parsing fails."""
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

    idx = LocalCollectionIndex(ok=True)
    idx._list_ops = {}
    idx._decl_block = {}
    types, statics = build_import_map(tree.root_node)
    idx._resolver = _NameResolver(types, statics)
    lo, hi = line_span
    consumed: set[tuple[int, int]] = set()

    def line_of(n: Node) -> int:
        return n.start_point[0] + 1

    def in_span(n: Node) -> bool:
        return not (n.start_point[0] + 1 > hi or n.end_point[0] + 1 < lo)

    def named_args(call: Node) -> list[Any]:
        args = call.child_by_field_name("arguments")
        return [c for c in (args.children if args is not None else ())
                if c.is_named]

    def record_accessor(call: Node) -> bool:
        """Record a qualifying accessor call; True when the receiver
        identifier was consumed (the shape is allowlisted), False when
        the caller must leave it for the leftover scan."""
        obj = call.child_by_field_name("object")
        name_node = call.child_by_field_name("name")
        if obj is None or obj.type != _IDENT or name_node is None:
            return False
        recv = _text(obj)
        kind = idx._kind.get(recv)
        if kind is None:
            return False
        method = _text(name_node)
        args = named_args(call)
        ln = line_of(call)
        col = call.start_point[1]
        if kind == "map" and method in _MAP_WRITE and len(args) == 2:
            key = _decoded_string_literal(_unwrap(args[0]))
            if key is None:
                idx._violated.add(recv)
            else:
                idx._writes.setdefault((recv, key), []).append(
                    _ElementWrite(lineno=ln, rhs=args[1]))
            consumed.add((obj.start_byte, obj.end_byte))
            return True
        if kind == "map" and method in _MAP_READ and len(args) == 1:
            key = _decoded_string_literal(_unwrap(args[0]))
            if key is None:
                idx._violated.add(recv)
            else:
                idx._reads_at.setdefault((ln, recv), set()).add(key)
                idx._get_sites[(ln, col)] = (recv, key)
            consumed.add((obj.start_byte, obj.end_byte))
            return True
        if kind == "list" and method in _LIST_WRITE and len(args) in (1, 2):
            # add(v) / add(i, v) / set(i, v): the VALUE is the last
            # argument; position is order-dependent, so every write
            # lands on the synthetic all-elements key. The op log
            # feeds the positional post-pass, which upgrades reads
            # when the whole op sequence is provably linear.
            idx._writes.setdefault((recv, ALL_ELEMENTS), []).append(
                _ElementWrite(lineno=ln, rhs=args[-1]))
            if method == "add" and len(args) == 1:
                op = ("add", None, args[0])
            elif method == "add":
                op = ("add_at", _int_literal(args[0]), args[1])
            else:
                op = ("set", _int_literal(args[0]), args[1])
            idx._list_ops.setdefault(recv, []).append(
                (ln, col, _block_id(call)) + op)
            consumed.add((obj.start_byte, obj.end_byte))
            return True
        if kind == "list" and method in _LIST_REMOVE and len(args) == 1:
            # remove(int-literal) is positionally simulatable; the
            # Object overload (remove("x")) and non-literal indices
            # are not — leave the receiver unconsumed so the leftover
            # scan untracks it (today's conservative behavior).
            i = _int_literal(args[0])
            if i is None:
                return False
            idx._list_ops.setdefault(recv, []).append(
                (ln, col, _block_id(call), "remove", i, None))
            consumed.add((obj.start_byte, obj.end_byte))
            return True
        if kind == "list" and method in _LIST_READ and len(args) == 1:
            idx._reads_at.setdefault((ln, recv), set()).add(ALL_ELEMENTS)
            idx._get_sites[(ln, col)] = (recv, ALL_ELEMENTS)
            idx._list_ops.setdefault(recv, []).append(
                (ln, col, _block_id(call), "get", _int_literal(args[0]),
                 None))
            consumed.add((obj.start_byte, obj.end_byte))
            return True
        # Non-allowlisted method on a tracked name: leave the
        # identifier unconsumed — the leftover scan untracks it.
        return False

    def maybe_scalar_copy(lineno: int, lhs: str, rhs) -> None:
        r = _unwrap(rhs)
        if r is None or r.type != _METHOD_INVOCATION:
            return
        obj = r.child_by_field_name("object")
        name_node = r.child_by_field_name("name")
        if obj is None or obj.type != _IDENT or name_node is None:
            return
        recv = _text(obj)
        kind = idx._kind.get(recv)
        if kind is None or _text(name_node) not in _MAP_READ:
            return
        args = named_args(r)
        if len(args) != 1:
            return
        if kind == "map":
            key = _decoded_string_literal(_unwrap(args[0]))
            if key is None:
                return
        else:
            key = ALL_ELEMENTS
        idx._scalar_copies[(lineno, lhs)] = (recv, key)

    def walk(n: Node) -> None:
        if n is None or not in_span(n):
            return
        t = n.type
        if t == _DECLARATOR:
            name_node = n.child_by_field_name("name")
            value = n.child_by_field_name("value")
            if name_node is not None and name_node.type == _IDENT:
                lhs = _text(name_node)
                ln = line_of(n)
                key = (ln, lhs)
                idx._lhs_writers[key] = idx._lhs_writers.get(key, 0) + 1
                kind = _fresh_collection_kind(value) if value is not None \
                    else None
                if kind is not None:
                    # Second fresh declaration of the same name is
                    # shadowing the index can't order — untrack.
                    if lhs in idx._kind:
                        idx._violated.add(lhs)
                    idx._kind[lhs] = kind
                    if kind == "list":
                        idx._decl_block[lhs] = _block_id(n)
                    consumed.add((name_node.start_byte, name_node.end_byte))
                    return           # fresh init consumed whole
                if value is not None:
                    maybe_scalar_copy(ln, lhs, value)
            if value is not None:
                walk(value)
            return
        if t == _ASSIGNMENT:
            left = n.child_by_field_name("left")
            right = n.child_by_field_name("right")
            op = n.child_by_field_name("operator")
            if (left is not None and left.type == _IDENT
                    and _text(op) == "="):
                lhs = _text(left)
                ln = line_of(n)
                key = (ln, lhs)
                idx._lhs_writers[key] = idx._lhs_writers.get(key, 0) + 1
                if right is not None:
                    maybe_scalar_copy(ln, lhs, right)
                # A tracked collection reassigned (either side) is a
                # re-alias; the leftover scan catches the bare name.
            if left is not None:
                walk(left)
            if right is not None:
                walk(right)
            return
        if t == _METHOD_INVOCATION and record_accessor(n):
            for a in named_args(n):
                walk(a)
            return
        for c in n.children:
            if c.is_named:
                walk(c)

    walk(tree.root_node)

    # Leftover-occurrence scan — any unconsumed appearance of a
    # tracked name escapes the collection.
    if idx._kind:
        stack = [tree.root_node]
        while stack:
            cur = stack.pop()
            if not in_span(cur):
                continue
            if cur.type == _IDENT:
                nm = _text(cur)
                if nm in idx._kind and (
                        (cur.start_byte, cur.end_byte) not in consumed):
                    idx._violated.add(nm)
                continue
            stack.extend(c for c in cur.children if c.is_named)

    _bind_positional(idx)
    return idx


def _bind_positional(idx: LocalCollectionIndex) -> None:
    """Upgrade list reads to positional single-write keys when the
    whole op sequence is provably linear.

    Soundness conditions (any failure refuses the WHOLE receiver —
    partial bindings never commit): the receiver is a tracked,
    unviolated list; every op and the declaration share one enclosing
    block (recorded order is execution order); every shifting op
    carries a literal in-range index; the op count is bounded. The
    simulation replays add/insert/set/remove and resolves each
    ``get(i)`` to the single element write occupying slot ``i`` at
    that point — ``remove(0); get(0)`` lands on the shifted (possibly
    tainted) element, so the vulnerable twin of the safe-selection
    idiom keeps its taint by construction."""
    for recv, ops in list(getattr(idx, "_list_ops", {}).items()):
        if recv in idx._violated or idx._kind.get(recv) != "list":
            continue
        if not ops or len(ops) > _MAX_POSITIONAL_OPS:
            continue
        decl_block = idx._decl_block.get(recv)
        if decl_block is None:
            continue
        if any(op[2] != decl_block for op in ops):
            continue
        ops = sorted(ops, key=lambda op: (op[0], op[1]))
        seq: list = []                     # slot -> _ElementWrite
        gets: dict = {}                    # (ln, col) -> _ElementWrite
        ok = True
        for ln, col, _blk, name, i, rhs in ops:
            if name == "add":
                seq.append(_ElementWrite(lineno=ln, rhs=rhs))
            elif name == "add_at":
                if i is None or not (0 <= i <= len(seq)):
                    ok = False
                    break
                seq.insert(i, _ElementWrite(lineno=ln, rhs=rhs))
            elif name == "set":
                if i is None or not (0 <= i < len(seq)):
                    ok = False
                    break
                seq[i] = _ElementWrite(lineno=ln, rhs=rhs)
            elif name == "remove":
                if i is None or not (0 <= i < len(seq)):
                    ok = False
                    break
                del seq[i]
            elif name == "get":
                if i is None or not (0 <= i < len(seq)):
                    ok = False
                    break
                gets[(ln, col)] = seq[i]
            else:                          # pragma: no cover — walker owns names
                ok = False
                break
        if not ok or not gets:
            continue
        # Commit: every get on a line must have resolved before the
        # line's read-set drops ALL_ELEMENTS (it did — any in-range
        # failure aborted the receiver above).
        lines_done: dict = {}
        for (ln, col), write in gets.items():
            key = f"pos@{ln}:{col}"
            idx._writes[(recv, key)] = [write]
            idx._get_sites[(ln, col)] = (recv, key)
            lines_done.setdefault(ln, set()).add(key)
        for ln, keys in lines_done.items():
            idx._reads_at[(ln, recv)] = set(keys)
        # Re-point scalar copies (bar = l.get(i)) to the positional
        # key when the line carries exactly one resolved get.
        for (ln, lhs), (r, key) in list(idx._scalar_copies.items()):
            if r != recv or key != ALL_ELEMENTS:
                continue
            keys = lines_done.get(ln)
            if keys is not None and len(keys) == 1:
                idx._scalar_copies[(ln, lhs)] = (recv, next(iter(keys)))


class CollectionFoldResolver:
    """Method-invocation fold hook: a ``get`` on a tracked collection
    folds to the shared constant when EVERY write to the consumed key
    folds to the same value. Returns ``None`` for invocations it does
    not own (the hook contract's fall-through), so it composes with
    the conduit hook; owned invocations return the value or REFUSE —
    never fall through. ``hits`` counts resolutions for reason-string
    attribution."""

    def __init__(self, index: LocalCollectionIndex) -> None:
        self._index = index
        self.hits = 0

    def __call__(self, node: Node, refold, depth: int) -> Any:
        from core.analysis.const_fold_java import REFUSE

        site = self._index.get_site(
            node.start_point[0] + 1, node.start_point[1])
        if site is None:
            return None
        name, key = site
        writes = self._index.element_writes(name, key)
        if not writes:
            return REFUSE          # never-written key: null, not const
        value: Any = REFUSE
        for w in writes:
            if w.rhs is None:
                return REFUSE
            v = refold(w.rhs, depth)
            if v is REFUSE or v is None:
                return REFUSE
            if value is REFUSE:
                value = v
            elif v != value or type(v) is not type(value):
                return REFUSE
        self.hits += 1
        return value


def compose_invocation_hooks(*hooks):
    """One method-invocation fold hook from several: first hook that
    claims the node (non-None) owns the verdict. ``None`` entries are
    skipped; returns None when no hook claims."""
    live = [h for h in hooks if h is not None]
    if not live:
        return None
    if len(live) == 1:
        return live[0]

    def combined(node, refold, depth: int):
        for h in live:
            got = h(node, refold, depth)
            if got is not None:
                return got
        return None

    return combined


__all__ = [
    "ALL_ELEMENTS",
    "CollectionFoldResolver",
    "LocalCollectionIndex",
    "build_local_collection_index",
    "compose_invocation_hooks",
]
