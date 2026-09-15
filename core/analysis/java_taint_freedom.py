"""Taint-free union summaries for same-class Java helpers (b42).

Two facts motivate this module, both measured on the corpora rather
than hypothesized:

* The dominant "guard-blocked" refusal class is NOT a value-predicate
  guard.  Sampling the Juliet ``no-suppress-verdict`` bucket and the
  OWASP ``replace_strip``/``unclassified`` census cells found zero
  exit-on-fail value validators; the real shapes are branch-merged
  definers whose folded values disagree (``{null, "foo"}``) and
  same-class helpers whose every branch writes a literal behind an
  un-foldable flag (the Juliet ``_21``/``_41`` source helpers).
* For the suppression question the branch selector is irrelevant: the
  union of attacker-free values is attacker-free whichever branch
  runs.  No condition folding, no dominance argument, no predicate
  reasoning — strictly weaker machinery than value folding, and sound
  for exactly the taint-freedom conclusion (never a usable value; the
  ``TAINT_FREE`` boundary pins in ``const_fold_java`` keep it out of
  every value consumer).

The helper summary derived here is *returns-taint-free*: every value
that can flow to any ``return`` of the helper folds to a compile-time
constant (``null`` included) or a proven taint-free read, under a
flow-INSENSITIVE all-writes union for locals.  Flow-insensitivity is
the soundness posture, not a shortcut: whichever write reaches a
return, it is drawn from the proven attacker-free set.

Refusals (each fixture-pinned in the precision corpus):

* parameter flow into the returned value — parameters may carry taint;
* field/``this`` reads in value position — temporal coupling (another
  method may store taint into the field);
* calls that the constant folder cannot itself discharge (pure-call
  allowlist) — no recursive helper-of-helper summaries in v1, cycles
  refuse structurally via the visiting set;
* compound assignments / update expressions to a returned local;
* ambiguous ``(name, arity)`` overloads, varargs, non-bare receivers;
* helpers with no value ``return`` at all.

Field reads in CONDITIONS never refuse: conditions only select among
branches whose union is already proven attacker-free, so the Juliet
field-flag idiom (``if (goodG2B1_private) ... else data = "foo";``)
summarizes without any reasoning about the flag.

The census's guard-shaped idioms that must NEVER suppress — the
selection-guard trap (``if (c.getName().equals("X")) v = c.getValue()``
guards WHICH tainted value is chosen, not whether it is safe) — refuse
naturally here because ``getValue()`` folds to nothing; the trap is
pinned in the corpus battery regardless.
"""

from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tree_sitter import Node


__all__ = [
    "TfHelperIndex",
    "derive_tf_helpers",
    "make_tf_helper_resolver",
]

# Node budget per helper body — helpers past this size are not the
# corpus shapes and refuse rather than risk a slow or surprising walk.
_MAX_BODY_NODES = 400
_MAX_HELPERS = 64
_MAX_DEPTH = 12


def _parser():
    from core.analysis.cfg_builder_java import _get_parser
    return _get_parser()


class TfHelperIndex:
    """Summaries for one compilation unit: ``(name, arity)`` pairs
    whose helper provably returns only attacker-free values."""

    __slots__ = ("hits", "ok", "refused", "str_members", "taint_free")

    def __init__(self) -> None:
        self.ok: bool = False
        self.taint_free: set[tuple[str, int]] = set()
        # Mutable counters: the gate attributes suppressions from
        # ``hits``; ``refused`` feeds telemetry.
        self.hits: list[str] = []
        self.refused: dict[str, int] = {}
        # b42 x b40 composition: every concrete string value observed
        # flowing toward a claimed helper's return, keyed like
        # ``taint_free``.  A summary is only a TAINT-freedom claim —
        # a value-based finding class is violated by the constant
        # itself, so the resolver must clear these members through the
        # caller's danger predicate before claiming (mirrors the
        # definer union's ``union_member_check``).
        self.str_members: dict[tuple[str, int], frozenset] = {}

    def _refuse(self, reason: str) -> None:
        self.refused[reason] = self.refused.get(reason, 0) + 1


def _iter_methods(root):
    stack = [root]
    while stack:
        n = stack.pop()
        if n.type == "method_declaration":
            yield n
        stack.extend(n.children)


def _method_key(m: Node) -> tuple[str, int] | None:
    name = m.child_by_field_name("name")
    params = m.child_by_field_name("parameters")
    if name is None or params is None:
        return None
    if any(c.type == "spread_parameter" for c in params.children):
        return None  # varargs: arity is not a dispatch key
    arity = sum(
        1 for c in params.children if c.type == "formal_parameter"
    )
    return name.text.decode(), arity


def _param_names(m: Node) -> set[str]:
    params = m.child_by_field_name("parameters")
    out: set[str] = set()
    if params is None:
        return out
    for c in params.children:
        if c.type == "formal_parameter":
            nm = c.child_by_field_name("name")
            if nm is not None:
                out.add(nm.text.decode())
    return out


def _enclosing_class_field_names(method: Node) -> set[str]:
    """Names of the fields/constants declared by the class-like body
    directly enclosing ``method``. A helper-local that shares a name
    with a field is a shadow-collision hazard for the flow-insensitive
    union (a bare read can bind the FIELD — ambient, rewritable —
    where the union sees only the local's writes), so such names
    refuse resolution outright."""
    body = method.parent
    while body is not None and body.type not in (
            "class_body", "enum_body", "interface_body",
            "annotation_type_body", "enum_body_declarations"):
        body = body.parent
    names: set[str] = set()
    if body is None:
        return names
    for member in body.children:
        if member.type not in ("field_declaration", "constant_declaration"):
            continue
        for c in member.children:
            if c.type == "variable_declarator":
                nm = c.child_by_field_name("name")
                if nm is not None:
                    names.add(nm.text.decode())
    return names


def _collect_writes_and_returns(body, scopes, field_names):
    """(writes[name] -> [rhs nodes], returns -> [expr nodes]) or
    (None, None) when the body exceeds the node budget.

    Every assignment/declarator RHS is collected regardless of the
    control flow around it — the union semantics.  Compound
    assignments and unary updates poison the name via a ``None`` RHS
    entry.  Bare declarations without initializer write nothing (Java
    definite assignment guarantees a later write before any read).

    Scope discipline: the union is only sound for LOCALS (definite
    assignment guarantees a body write precedes any read). Both
    directions are vouched through ``scopes`` (the builders'
    positional oracle):

    * store direction — a bare-name store with no in-scope preceding
      declarator writes a FIELD or outer binding whose ambient value
      the union never sees, so it poisons the name;
    * read direction — a bare-name VALUE READ outside every vouch
      window of that name binds a field or outer binding (same-class,
      inherited, or captured — no superclass resolution needed) even
      where every store is declared-local, so an un-vouched read
      poisons the name too.

    A name colliding with a directly-enclosing-class field
    (``field_names``) additionally poisons unconditionally — the
    cheap belt-and-braces for the same-class shadow shape.
    """
    writes: dict[str, list[object]] = {}
    returns: list[object] = []
    reads: list[tuple[str, int]] = []
    count = 0
    stack = [body]
    while stack:
        n = stack.pop()
        count += 1
        if count > _MAX_BODY_NODES:
            return None, None
        t = n.type
        if t == "identifier":
            if _is_value_read(n):
                reads.append((n.text.decode(), n.start_byte))
        elif t == "variable_declarator":
            nm = n.child_by_field_name("name")
            val = n.child_by_field_name("value")
            if nm is not None and val is not None:
                name = nm.text.decode()
                if name in field_names:
                    writes.setdefault(name, []).append(None)
                else:
                    writes.setdefault(name, []).append(val)
        elif t == "assignment_expression":
            lhs = n.child_by_field_name("left")
            rhs = n.child_by_field_name("right")
            if lhs is not None and lhs.type == "identifier":
                name = lhs.text.decode()
                op_txt = ""
                for c in n.children:
                    if c.type not in ("identifier",) and c.is_named is False:
                        op_txt = c.type
                        break
                if op_txt and op_txt != "=":
                    writes.setdefault(name, []).append(None)
                elif (name in field_names
                      or not scopes.vouches(name, n.start_byte)):
                    # FIELD / outer-binding store (or a store before
                    # the declarator): the ambient value is an
                    # invisible union member — poison.
                    writes.setdefault(name, []).append(None)
                else:
                    writes.setdefault(name, []).append(rhs)
        elif t == "update_expression":
            for c in n.children:
                if c.type == "identifier":
                    writes.setdefault(c.text.decode(), []).append(None)
        elif t == "return_statement":
            expr = None
            for c in n.children:
                if c.is_named:
                    expr = c
            returns.append(expr)
        stack.extend(n.children)
    # Read-direction poisoning (only names the union would otherwise
    # resolve — never-written names refuse at resolution regardless).
    for name, byte in reads:
        if name in writes and not scopes.vouches(name, byte):
            writes[name].append(None)
    return writes, returns


# Identifier positions that are NOT bare value reads: declaration /
# binding names, store targets (the store rule owns those), callee
# names, and ``obj.member`` member selectors. Over-approximating reads
# is the cheap (refuse-a-summary) direction; missing a read is the
# false-suppression direction, so anything unlisted counts as a read.
_NON_READ_PARENT_FIELDS = (
    ("variable_declarator", "name"),
    ("assignment_expression", "left"),
    ("method_invocation", "name"),
    ("field_access", "field"),
    ("method_reference", None),
    ("labeled_statement", None),
    ("break_statement", None),
    ("continue_statement", None),
    ("enhanced_for_statement", "name"),
    ("catch_formal_parameter", "name"),
    ("formal_parameter", "name"),
    ("type_pattern", "name"),
)


def _is_value_read(n: Node) -> bool:
    p = n.parent
    if p is None:
        return False
    for ptype, field in _NON_READ_PARENT_FIELDS:
        if p.type != ptype:
            continue
        if field is None or p.child_by_field_name(field) == n:
            return False
    return True


def derive_tf_helpers(source_text: str, span=None) -> TfHelperIndex:
    """Build the returns-taint-free summary set for one source file.

    ``span`` is accepted for interface symmetry with the other
    per-file indices; summaries are derived for the whole compilation
    unit because bare calls resolve unit-wide.
    """
    idx = TfHelperIndex()
    try:
        parser = _parser()
        tree = parser.parse(source_text.encode())
    except Exception:  # noqa: BLE001 — no parse, no summaries
        return idx
    from core.analysis.const_fold_java import (
        REFUSE,
        TAINT_FREE,
        fold_expr,
    )

    methods = list(_iter_methods(tree.root_node))
    if len(methods) > _MAX_HELPERS:
        idx._refuse("too-many-methods")
        return idx
    by_key: dict[tuple[str, int], list[object]] = {}
    for m in methods:
        key = _method_key(m)
        if key is None:
            continue
        by_key.setdefault(key, []).append(m)

    for key, decls in by_key.items():
        if len(decls) != 1:
            idx._refuse("ambiguous-overload")
            continue
        m = decls[0]
        body = m.child_by_field_name("body")
        if body is None:
            idx._refuse("no-body")
            continue
        params = _param_names(m)
        from core.analysis.cfg_builder_java import _declared_local_scopes
        scopes = _declared_local_scopes(m)
        field_names = _enclosing_class_field_names(m)
        writes, returns = _collect_writes_and_returns(
            body, scopes, field_names)
        if writes is None:
            idx._refuse("body-too-large")
            continue
        if not returns or any(r is None for r in returns):
            idx._refuse("no-value-return")
            continue

        strs: set[str] = set()

        def make_resolve(_writes, _params, _strs):
            def resolve(name: str, depth: int,
                        _visiting: set[str] | None = None):
                # Union resolution over ALL writes to the local.
                # Params and unwritten names refuse here; field and
                # outer-binding stores were poisoned at collection
                # (None entries), so they refuse below; cycles refuse
                # via the visiting set.
                if _visiting is None:
                    _visiting = set()
                if depth > _MAX_DEPTH or name in _params \
                        or name in _visiting:
                    return REFUSE
                rhss = _writes.get(name)
                if not rhss or any(r is None for r in rhss):
                    return REFUSE
                _visiting.add(name)
                try:
                    vals = []
                    for rhs in rhss:
                        v = fold_expr(
                            rhs,
                            lambda nm, dp: resolve(nm, dp, _visiting),
                            allow_taint_free=True,
                        )
                        if v is REFUSE:
                            return REFUSE
                        vals.append(v)
                finally:
                    _visiting.discard(name)
                # Every concrete string that can flow through this
                # local is a candidate return member — collected
                # conservatively (agreeing values too: the agreed
                # value keeps flowing toward the return).
                _strs.update(v for v in vals if isinstance(v, str))
                first = vals[0]
                for v in vals[1:]:
                    if v is not first and v != first:
                        # Non-agreeing but each attacker-free: the
                        # union conclusion — taint-free, never a
                        # usable value.
                        return TAINT_FREE
                return first
            return resolve

        resolve = make_resolve(writes, params, strs)
        refused = False
        for r in returns:
            v = fold_expr(r, resolve, allow_taint_free=True)
            if v is REFUSE:
                refused = True
                break
            if isinstance(v, str):
                strs.add(v)
        if refused:
            idx._refuse("return-not-taint-free")
            continue
        idx.taint_free.add(key)
        idx.str_members[key] = frozenset(strs)

    idx.ok = True
    return idx


def make_tf_helper_resolver(source_text: str, span=None,
                            member_check=None):
    """Invocation-hook (conduit-slot contract) claiming bare calls to
    returns-taint-free helpers.  Returns None when nothing qualifies
    (no hook installed at all — zero cost on files without helpers).

    Hook contract: ``resolver(node, refold, depth)`` returns
    ``TAINT_FREE`` for a claimed call, ``None`` for no-claim (the next
    hook or the pure-call allowlist decides).  It never returns plain
    values, so it cannot influence a value consumer even before the
    ``TAINT_FREE`` boundary pin — and under a value-only fold (tier
    off) the boundary pin converts the claim to a refusal, exactly the
    pre-b42 behavior.

    ``member_check`` (str list -> bool) is the caller's danger
    predicate over the helper's concrete string return members — the
    b40 composition: a constant can violate a value-based finding
    class on its own, so a helper with string members and no clearing
    predicate is never claimed (no danger authority means refuse).
    """
    idx = derive_tf_helpers(source_text, span)
    if not idx.ok or not idx.taint_free:
        return None
    from core.analysis.const_fold_java import TAINT_FREE

    def resolver(node: Node, _refold, depth: int):
        if node.type != "method_invocation":
            return None
        if node.child_by_field_name("object") is not None:
            return None  # bare same-class calls only (b19 precedent)
        name = node.child_by_field_name("name")
        args = node.child_by_field_name("arguments")
        if name is None or args is None:
            return None
        arity = sum(1 for c in args.children if c.is_named)
        key = (name.text.decode(), arity)
        if key not in idx.taint_free:
            return None
        members = idx.str_members.get(key) or frozenset()
        if members:
            if member_check is None or not member_check(sorted(members)):
                return None
        idx.hits.append(key[0])
        return TAINT_FREE

    resolver.hits = idx.hits  # type: ignore[attr-defined]
    resolver.index = idx      # type: ignore[attr-defined]
    return resolver
