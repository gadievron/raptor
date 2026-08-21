"""Mechanical source-wrapper summaries for Java (detection side).

The sanitizer-cut summary machinery (``java_wrapper_summaries``)
proves what a helper's return CANNOT carry; this module proves the
opposite direction for taint *sources*: a same-source-tree class
method whose return value provably derives from a known taint-source
call is a **source wrapper**, and its return value is a remote source
the engines cannot otherwise see (the taint enters through a
constructor-stored field, which the measured engines decline to
track — the FN census's helper_class_source bucket).

Emission is ADDITIVE ONLY: qualifying methods become models-as-data
``sourceModel`` rows (``core.dataflow.extension_pack``, provenance
``mechanical``) consumed by the standard CodeQL suite. A wrong row
adds a candidate finding that downstream validation adjudicates; it
can never suppress anything. Precision still matters — every
qualification is a proof over the parsed source, and anything the
proof cannot cover refuses with a named reason:

* return not straight-line derivable (branches/loops feeding it);
* the source value passes through ANY unrecognized call on the way
  to the return (a validating/sanitizing wrapper is not a raw
  source — ``wrapped_call``);
* constant or non-source returns;
* receiver fields not assigned exactly once, in a constructor, from
  a constructor parameter of a source-receiver type, and never
  reassigned anywhere in the class (``field_not_frozen``);
* same-class (name, arity) duplicates (overload ambiguity), varargs,
  abstract/interface bodies, anonymous classes.

Seed vocabulary is deliberately tiny (<= 9 names); project-specific
source APIs must arrive through learned vocabulary, never by growing
these literals.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Optional, Sequence, Tuple

# Shared parsing bones (deliberate private-name imports; the summary
# modules form one family — see java_wrapper_summaries).
from core.analysis.java_wrapper_summaries import (  # noqa: PLC2701
    _CLASS_DECL,
    _IDENT,
    _Refused,
    _class_inventory,
    _iter_named,
    _modifiers,
    _param_names,
    _parser,
    _straight_line_locals,
    _text,
)

# ── seed vocabulary ──────────────────────────────────────────────────

#: Receiver types whose listed methods return attacker-controlled
#: data. Seed set (<= 9 names total with the methods below): servlet
#: request surface only. Growth must come from learned vocabulary
#: (study/IRIS), never from editing these literals.
SOURCE_RECEIVER_TYPES: FrozenSet[str] = frozenset({
    "HttpServletRequest",
    "ServletRequest",
})

#: Methods on those receivers whose return carries remote input.
SOURCE_METHODS: FrozenSet[str] = frozenset({
    "getParameter",
    "getHeader",
    "getQueryString",
    "getParameterValues",
})

_METHOD_DECL = "method_declaration"
_CTOR_DECL = "constructor_declaration"
_FIELD_DECL = "field_declaration"
_INVOCATION = "method_invocation"
_FIELD_ACCESS = "field_access"
_ASSIGN = "assignment_expression"

_MAX_FILES_DEFAULT = 5000


# ── result model ─────────────────────────────────────────────────────


@dataclass(frozen=True)
class SourceSummary:
    """One qualifying source-wrapper method."""

    package: str
    owner: str
    name: str
    arity: int
    signature: str          # "(String)" — erased simple types
    via: str                # "param" | "field" | "compose"


@dataclass
class DeriveResult:
    summaries: List[SourceSummary] = field(default_factory=list)
    refusals: Dict[str, int] = field(default_factory=dict)

    def refuse(self, reason: str) -> None:
        self.refusals[reason] = self.refusals.get(reason, 0) + 1


# ── receiver resolution ──────────────────────────────────────────────


def _simple_type(text: str) -> str:
    """``javax.servlet.http.HttpServletRequest`` → last segment."""
    return text.rsplit(".", 1)[-1].strip()


def _param_types(decl) -> Optional[Tuple[str, ...]]:
    params = decl.child_by_field_name("parameters")
    if params is None:
        return None
    out: List[str] = []
    for p in params.children:
        if not p.is_named:
            continue
        if p.type != "formal_parameter":
            return None
        tnode = p.child_by_field_name("type")
        if tnode is None:
            return None
        out.append(_simple_type(_text(tnode)))
    return tuple(out)


def _request_typed_params(decl) -> Dict[str, str]:
    """Parameter name → simple type, for source-receiver-typed params."""
    names = _param_names(decl)
    types = _param_types(decl)
    if names is None or types is None or len(names) != len(types):
        return {}
    return {
        n: t for n, t in zip(names, types)
        if t in SOURCE_RECEIVER_TYPES
    }


def _frozen_request_fields(cls_node) -> FrozenSet[str]:
    """Field names of a source-receiver type that are assigned exactly
    once, inside a constructor, from a constructor parameter of the
    same type family, and never assigned anywhere else in the class.
    """
    declared: Dict[str, str] = {}
    body = cls_node.child_by_field_name("body")
    if body is None:
        return frozenset()
    for child in body.children:
        if child.type != _FIELD_DECL:
            continue
        tnode = child.child_by_field_name("type")
        if tnode is None or _simple_type(_text(tnode)) not in SOURCE_RECEIVER_TYPES:
            continue
        for d in child.children:
            if d.type == "variable_declarator":
                name_node = d.child_by_field_name("name")
                if d.child_by_field_name("value") is not None:
                    continue        # initialized at declaration: not ctor-frozen
                if name_node is not None:
                    declared[_text(name_node)] = _simple_type(_text(tnode))

    if not declared:
        return frozenset()

    assigns: Dict[str, List[Tuple[bool, Optional[str]]]] = {n: [] for n in declared}
    for node in _iter_named(cls_node):
        if node.type != _ASSIGN:
            continue
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None:
            continue
        if left.type == _IDENT:
            target = _text(left)
        elif left.type == _FIELD_ACCESS and _text(left).startswith("this."):
            target = _text(left)[len("this."):]
        else:
            continue
        if target not in declared:
            continue
        in_ctor = False
        ctor = node.parent
        while ctor is not None:
            if ctor.type == _CTOR_DECL:
                in_ctor = True
                break
            if ctor.type in (_METHOD_DECL, _CLASS_DECL):
                break
            ctor = ctor.parent
        rhs_ident = _text(right) if right is not None and right.type == _IDENT else None
        rhs_ok = False
        if in_ctor and rhs_ident and ctor is not None:
            ctor_params = _request_typed_params(ctor)
            rhs_ok = ctor_params.get(rhs_ident) == declared[target]
        assigns[target].append((in_ctor and rhs_ok, rhs_ident))

    frozen = set()
    for name, seen in assigns.items():
        if len(seen) == 1 and seen[0][0]:
            frozen.add(name)
    return frozenset(frozen)


# ── qualification ────────────────────────────────────────────────────


def _classify_source_return(
    expr,
    request_params: Dict[str, str],
    frozen_fields: FrozenSet[str],
    locals_map: Dict[str, Any],
    composable: Dict[Tuple[str, int], SourceSummary],
) -> str:
    """Return ``"param" | "field" | "compose"`` when *expr* provably
    carries a source value; raise :class:`_Refused` otherwise."""
    seen: set = set()
    node = expr
    while True:
        if id(node) in seen:
            raise _Refused("cyclic local chain")
        seen.add(id(node))
        if node.type == "parenthesized_expression":
            inner = next((c for c in node.children if c.is_named), None)
            if inner is None:
                raise _Refused("empty parenthesized return")
            node = inner
            continue
        if node.type == _IDENT:
            name = _text(node)
            if name in locals_map:
                node = locals_map[name]
                continue
            raise _Refused("return of non-derivable identifier")
        if node.type == _INVOCATION:
            mname = _text(node.child_by_field_name("name"))
            obj = node.child_by_field_name("object")
            args = node.child_by_field_name("arguments")
            argc = sum(1 for c in args.children if c.is_named) if args is not None else 0
            if mname in SOURCE_METHODS and obj is not None:
                if obj.type == _IDENT and (
                    _text(obj) in request_params or _text(obj) in frozen_fields
                ):
                    return "param" if _text(obj) in request_params else "field"
                if obj.type == _FIELD_ACCESS and _text(obj).startswith("this."):
                    if _text(obj)[len("this."):] in frozen_fields:
                        return "field"
                raise _Refused("source call on unproven receiver")
            if obj is None and (mname, argc) in composable:
                return "compose"
            raise _Refused("wrapped_call")
        raise _Refused(f"unsupported return shape: {node.type}")


def derive_source_summaries(java_source: str) -> DeriveResult:
    """Derive source-wrapper summaries for one compilation unit."""
    result = DeriveResult()
    parser = _parser()
    if parser is None:
        result.refuse("parser_unavailable")
        return result
    tree = parser.parse(java_source.encode("utf-8", errors="replace"))
    root = tree.root_node

    package = ""
    for n in root.children:
        if n.type == "package_declaration":
            for c in n.children:
                if c.is_named:
                    package = _text(c)
            break

    by_name, _extended = _class_inventory(root)
    for cname, infos in by_name.items():
        if len(infos) != 1:
            result.refuse("duplicate_class_name")
            continue
        cls = infos[0]
        frozen_fields = _frozen_request_fields(cls.node)
        body = cls.node.child_by_field_name("body")
        if body is None:
            continue

        methods: Dict[Tuple[str, int], List[Any]] = {}
        for m in body.children:
            if m.type != _METHOD_DECL:
                continue
            names = _param_names(m)
            mn = m.child_by_field_name("name")
            if names is None or mn is None:
                result.refuse("varargs_or_unreadable_params")
                continue
            methods.setdefault((_text(mn), len(names)), []).append(m)

        composable: Dict[Tuple[str, int], SourceSummary] = {}
        for _pass in (1, 2):
            for (mname, arity), decls in methods.items():
                if (mname, arity) in composable:
                    continue
                if len(decls) != 1:
                    result.refuse("overload_ambiguity")
                    continue
                decl = decls[0]
                mods = _modifiers(decl)
                if "abstract" in mods or "native" in mods:
                    result.refuse("no_body")
                    continue
                mbody = decl.child_by_field_name("body")
                if mbody is None:
                    result.refuse("no_body")
                    continue
                names = _param_names(decl) or ()
                types = _param_types(decl)
                if types is None:
                    result.refuse("varargs_or_unreadable_params")
                    continue
                try:
                    locals_map, ret_expr = _straight_line_locals(
                        mbody, names, strict_state=False)
                    via = _classify_source_return(
                        ret_expr, _request_typed_params(decl),
                        frozen_fields, locals_map, composable)
                except _Refused as r:
                    if _pass == 2:
                        result.refuse(r.reason)
                    continue
                summary = SourceSummary(
                    package=package,
                    owner=cname,
                    name=mname,
                    arity=arity,
                    signature="(" + ",".join(types) + ")",
                    via=via,
                )
                composable[(mname, arity)] = summary
        result.summaries.extend(composable.values())
    return result


# ── tree scan + emission rows ────────────────────────────────────────


def scan_tree(
    root: Path,
    *,
    max_files: int = _MAX_FILES_DEFAULT,
) -> Tuple[List[SourceSummary], Dict[str, int], int]:
    """Scan a source tree for source wrappers.

    Returns ``(summaries, refusal_counts, files_scanned)``. Hidden,
    build, and test trees are skipped; the file cap is loud in the
    counts (``file_cap_hit``).
    """
    skip_parts = {".git", "target", "build", "out", "node_modules", "test",
                  "tests", ".idea"}
    summaries: List[SourceSummary] = []
    refusals: Dict[str, int] = {}
    scanned = 0
    for path in sorted(Path(root).rglob("*.java")):
        if any(part in skip_parts or part.startswith(".")
               for part in path.parts):
            continue
        if scanned >= max_files:
            refusals["file_cap_hit"] = refusals.get("file_cap_hit", 0) + 1
            break
        scanned += 1
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            refusals["unreadable"] = refusals.get("unreadable", 0) + 1
            continue
        if "ServletRequest" not in text:
            continue        # cheap pre-filter: no receiver type mentioned
        r = derive_source_summaries(text)
        summaries.extend(r.summaries)
        for k, v in r.refusals.items():
            refusals[k] = refusals.get(k, 0) + v
    return summaries, refusals, scanned


def rows_from_source_summaries(summaries: Sequence[SourceSummary]):
    """Convert summaries to models-as-data source rows."""
    from core.dataflow.extension_pack import ModelRow, ROLE_SOURCE
    rows = []
    for s in summaries:
        rows.append(ModelRow(
            role=ROLE_SOURCE,
            provenance="mechanical",
            namespace=s.package,
            type_name=s.owner,
            name=s.name,
            signature=s.signature,
            access_output="ReturnValue",
            model_kind="remote",
            subtypes=False,
        ))
    return rows
