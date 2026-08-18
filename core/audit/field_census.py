"""Field-access census — the shared substrate for the lifecycle channels.

A whole-target index of struct *field* write sites and read sites, per
field, extending the :mod:`core.audit.struct_accessor_index` record
with the **rhs provenance class** of every write (``from_param``,
``from_call:<callee>``, ``from_field:<owner.field>``, ``literal_null``,
``literal_const``, ``from_var:<name>``) on the same tree-sitter parse
cache the return census rides
(:func:`core.audit.callsite_consistency.parse_source_cached`).

Consumers (the five-channel programme):

* ``ptr_lifecycle`` — alias edges (``from_field:*`` writes, local
  alias assignments), lifecycle-event joins, post-event read receipts;
* ``protocol_state`` (phase D) — the written-never-read by-product and
  unvalidated peer-write legs;
* ``lock_region`` — per-file function spans and lock context.

Dominating-guard conjunctions are NOT precomputed for every field
(cost bound): :func:`guards_for_site` builds CFG + dominators on
demand via :mod:`core.analysis.lifecycle_collector`, only for sites a
channel actually adjudicates.

Degradation: tree-sitter absent → regex-only records with
``tier="regex"``; any channel verdict that *needs* rhs-provenance or
guards must report an inconclusive census-degraded reason rather than
guessing (the consistency ``extractor-unavailable`` convention).

Prioritisation: fields of StudyItems whose ``resource_lifecycle`` /
``alloc_frees`` / ``state_transitions`` seed lists are non-empty walk
first (:func:`priority_fields_from_study_list`); hard caps
``MAX_CENSUS_FIELDS`` / ``MAX_SITES_PER_FIELD``, budget
``CENSUS_BUDGET_S``, ``skipped`` telemetry on overrun.

Output artifact: ``field-census.json`` in the run dir (mirrors
``return-census.json``).

No LLM calls, no subprocesses.
"""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .struct_accessor_index import _MIN_FIELD_LEN, _NOISE_FIELDS, _detect_lock

logger = logging.getLogger(__name__)

# Hard caps (§0 of the five-channel design).
MAX_CENSUS_FIELDS = 500
MAX_SITES_PER_FIELD = 200
CENSUS_BUDGET_S = 30.0

# Census extraction tiers.
TIER_TREE_SITTER = "tree_sitter"
TIER_REGEX = "regex"

# Languages the census walks (C-family field access shapes).
_CENSUS_LANGUAGES = frozenset({"c", "cpp"})

ARTIFACT_NAME = "field-census.json"

# ── rhs provenance classes ──────────────────────────────────────────
RHS_LITERAL_NULL = "literal_null"
RHS_LITERAL_CONST = "literal_const"
RHS_FROM_PARAM = "from_param"       # "from_param:<name>"
RHS_FROM_CALL = "from_call"         # "from_call:<callee>"
RHS_FROM_FIELD = "from_field"       # "from_field:<owner>.<field>"
RHS_FROM_VAR = "from_var"           # "from_var:<name>"
RHS_UNKNOWN = "unknown"


@dataclass
class FunctionSpan:
    """One function definition's (name, line span, source segment)."""

    name: str
    start: int
    end: int
    params: tuple[str, ...] = ()
    is_static: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "start": self.start,
            "end": self.end,
            "static": self.is_static,
        }


@dataclass
class FieldWrite:
    """One write site of a field, with rhs provenance."""

    file: str
    line: int
    function: str
    owner: str          # base identifier of the access expression
    rhs_class: str      # one of the RHS_* classes (possibly ":detail")
    code: str = ""
    lock_held: str = ""

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "file": self.file,
            "line": self.line,
            "function": self.function,
            "owner": self.owner,
            "rhs_class": self.rhs_class,
            "code": self.code[:200],
        }
        if self.lock_held:
            d["lock_held"] = self.lock_held
        return d


@dataclass
class FieldRead:
    """One read site of a field, with use context."""

    file: str
    line: int
    function: str
    owner: str
    # "invoke" | "call_arg" | "return" | "condition" |
    # "alias_assign:<local>" | "expr"
    context: str = "expr"
    code: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "line": self.line,
            "function": self.function,
            "owner": self.owner,
            "context": self.context,
            "code": self.code[:200],
        }


@dataclass
class FieldRecord:
    """All census sites for one field name."""

    field: str
    writes: list[FieldWrite] = field(default_factory=list)
    reads: list[FieldRead] = field(default_factory=list)
    tier: str = TIER_TREE_SITTER
    sites_capped: bool = False

    @property
    def owners(self) -> set[str]:
        return {w.owner for w in self.writes} | {r.owner for r in self.reads}

    def to_dict(self) -> dict[str, Any]:
        return {
            "field": self.field,
            "tier": self.tier,
            "sites_capped": self.sites_capped,
            "writes": [w.to_dict() for w in self.writes],
            "reads": [r.to_dict() for r in self.reads],
        }


@dataclass
class FieldCensus:
    """Whole-target field-access census + telemetry."""

    fields: dict[str, FieldRecord] = field(default_factory=dict)
    functions: dict[str, list[FunctionSpan]] = field(default_factory=dict)
    tier: str = TIER_TREE_SITTER
    telemetry: dict[str, Any] = field(default_factory=dict)

    @property
    def degraded(self) -> bool:
        """True when any verdict needing rhs-provenance must gate to
        an inconclusive census-degraded reason (regex tier)."""
        return self.tier != TIER_TREE_SITTER

    @property
    def capped(self) -> bool:
        return bool(
            self.telemetry.get("fields_skipped")
            or self.telemetry.get("budget_exceeded"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "tier": self.tier,
            "telemetry": self.telemetry,
            "fields": {
                name: rec.to_dict() for name, rec in self.fields.items()
            },
            "functions": {
                fp: [s.to_dict() for s in spans]
                for fp, spans in self.functions.items()
            },
        }


# ── regex tier ──────────────────────────────────────────────────────

_WRITE_RE = re.compile(r"\b(\w+)\s*->\s*(\w+)\s*=(?![=>])")
_ACCESS_RE = re.compile(r"\b(\w+)\s*->\s*(\w+)\b")
_LOCAL_ALIAS_RE = re.compile(r"\b(\w+)\s*=\s*(\w+)\s*->\s*(\w+)\s*;")
_CALL_AFTER_RE = re.compile(r"\A\s*\(")
_FUNC_DEF_RE = re.compile(
    r"^(?P<head>[A-Za-z_][\w\s\*]*?)\b(?P<name>[A-Za-z_]\w*)\s*"
    r"\((?P<params>[^;{)]*)\)\s*\{",
    re.MULTILINE,
)
_C_KEYWORDS = frozenset({
    "if", "for", "while", "switch", "return", "sizeof", "do", "else",
})
_NULL_TOKENS = frozenset({"NULL", "nullptr"})
_CONST_RE = re.compile(r"\A(?:0[xX][0-9a-fA-F]+|\d+|\".*\"|'.')\s*;?\s*\Z")
_IDENT_RE = re.compile(r"\A([A-Za-z_]\w*)\s*;?\s*\Z")
_CALL_RHS_RE = re.compile(r"\A\(?\s*(?:\([\w\s\*]+\)\s*)?([A-Za-z_]\w*)\s*\(")
_FIELD_RHS_RE = re.compile(
    r"\A\(?\s*(?:\([\w\s\*]+\)\s*)?&?\s*([A-Za-z_]\w*)\s*(?:->|\.)\s*"
    r"([A-Za-z_]\w*)\s*;?\s*\Z"
)


def _classify_rhs_text(rhs: str, params: Iterable[str]) -> str:
    """Regex-tier rhs provenance classification (best effort)."""
    text = rhs.strip().rstrip(";").strip()
    if text in _NULL_TOKENS or text == "0":
        return RHS_LITERAL_NULL
    if _CONST_RE.match(text):
        return RHS_LITERAL_CONST
    m = _FIELD_RHS_RE.match(text)
    if m:
        return f"{RHS_FROM_FIELD}:{m.group(1)}.{m.group(2)}"
    m = _CALL_RHS_RE.match(text)
    if m and m.group(1) not in _C_KEYWORDS:
        return f"{RHS_FROM_CALL}:{m.group(1)}"
    m = _IDENT_RE.match(text)
    if m:
        name = m.group(1)
        if name in set(params):
            return f"{RHS_FROM_PARAM}:{name}"
        return f"{RHS_FROM_VAR}:{name}"
    return RHS_UNKNOWN


def function_spans_regex(source: str) -> list[FunctionSpan]:
    """Regex-tier function span extraction (brace counting)."""
    spans: list[FunctionSpan] = []
    for m in _FUNC_DEF_RE.finditer(source):
        name = m.group("name")
        if name in _C_KEYWORDS:
            continue
        start_line = source.count("\n", 0, m.start()) + 1
        depth = 0
        end_line = start_line
        for idx in range(m.end() - 1, len(source)):
            ch = source[idx]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end_line = source.count("\n", 0, idx) + 1
                    break
        else:
            end_line = source.count("\n") + 1
        params = tuple(
            p.strip().rsplit(" ", 1)[-1].lstrip("*")
            for p in m.group("params").split(",")
            if p.strip() and p.strip() != "void"
        )
        spans.append(FunctionSpan(
            name=name,
            start=start_line,
            end=end_line,
            params=params,
            is_static="static" in m.group("head").split(),
        ))
    return spans


def function_spans(source: str, file_path: str = "") -> list[FunctionSpan]:
    """Function spans for one file: tree-sitter when available,
    regex fallback otherwise. Shared with the lock_region channel."""
    tree = None
    if file_path:
        try:
            from .callsite_consistency import parse_source_cached
            tree, lang = parse_source_cached(file_path, source)
            if lang not in _CENSUS_LANGUAGES:
                tree = None
        except Exception:
            tree = None
    if tree is None:
        return function_spans_regex(source)
    spans = _function_spans_ts(tree, source)
    return spans if spans else function_spans_regex(source)


# ── tree-sitter tier ────────────────────────────────────────────────


def _node_text(node: Any, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode(
        "utf-8", errors="replace",
    )


def _function_spans_ts(tree: Any, source: str) -> list[FunctionSpan]:
    src = source.encode("utf-8", errors="replace")
    spans: list[FunctionSpan] = []

    def _declarator_name(node: Any) -> str:
        cur = node
        while cur is not None:
            if cur.type == "function_declarator":
                inner = cur.child_by_field_name("declarator")
                if inner is not None and inner.type in (
                    "identifier", "field_identifier",
                ):
                    return _node_text(inner, src)
                cur = inner
                continue
            if cur.type in ("pointer_declarator", "parenthesized_declarator"):
                cur = cur.child_by_field_name("declarator") or (
                    cur.children[1] if len(cur.children) > 1 else None
                )
                continue
            if cur.type == "identifier":
                return _node_text(cur, src)
            return ""
        return ""

    def _params(node: Any) -> tuple[str, ...]:
        out: list[str] = []
        stack = [node]
        while stack:
            cur = stack.pop()
            if cur.type == "parameter_declaration":
                # The parameter name is the (sole) plain identifier in
                # the declarator subtree — type names are
                # type_identifier nodes. Handles function-pointer
                # params (``void (*cb)(int)``) whose declarator nests.
                sub = [cur]
                name = ""
                while sub:
                    n = sub.pop(0)
                    if n.type == "identifier":
                        name = _node_text(n, src)
                        break
                    sub.extend(n.children)
                if name:
                    out.append(name)
                continue
            stack.extend(cur.children)
        return tuple(out)

    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type == "function_definition":
            decl = node.child_by_field_name("declarator")
            name = _declarator_name(decl) if decl is not None else ""
            if name:
                fn_decl = decl
                while fn_decl is not None and \
                        fn_decl.type != "function_declarator":
                    fn_decl = fn_decl.child_by_field_name("declarator")
                params: tuple[str, ...] = ()
                if fn_decl is not None:
                    plist = fn_decl.child_by_field_name("parameters")
                    if plist is not None:
                        params = _params(plist)
                head = _node_text(node, src).split("(", 1)[0]
                spans.append(FunctionSpan(
                    name=name,
                    start=node.start_point[0] + 1,
                    end=node.end_point[0] + 1,
                    params=params,
                    is_static="static" in head.split(),
                ))
        stack.extend(node.children)
    spans.sort(key=lambda s: s.start)
    return spans


def _field_base_and_name(node: Any, src: bytes) -> tuple[str, str]:
    """(base identifier, field name) of a field_expression node."""
    fld = node.child_by_field_name("field")
    name = _node_text(fld, src) if fld is not None else ""
    base = node.child_by_field_name("argument")
    while base is not None and base.type in (
        "field_expression", "pointer_expression",
        "parenthesized_expression", "subscript_expression",
        "cast_expression",
    ):
        base = (
            base.child_by_field_name("argument")
            or base.child_by_field_name("value")
            or (base.children[-1] if base.children else None)
        )
    owner = _node_text(base, src) if base is not None and \
        base.type == "identifier" else ""
    return owner, name


def _unwrap_rhs(node: Any) -> Any:
    while node is not None and node.type in (
        "parenthesized_expression", "cast_expression",
        "pointer_expression",
    ):
        node = (
            node.child_by_field_name("value")
            or node.child_by_field_name("argument")
            or (node.children[-1] if node.children else None)
        )
    return node


def _classify_rhs_ts(node: Any, src: bytes,
                     params: Iterable[str]) -> str:
    node = _unwrap_rhs(node)
    if node is None:
        return RHS_UNKNOWN
    if node.type == "null" or (
        node.type == "identifier"
        and _node_text(node, src) in _NULL_TOKENS
    ):
        return RHS_LITERAL_NULL
    if node.type == "number_literal" and _node_text(node, src) == "0":
        return RHS_LITERAL_NULL
    if node.type in (
        "number_literal", "string_literal", "char_literal",
        "sizeof_expression", "true", "false", "concatenated_string",
    ):
        return RHS_LITERAL_CONST
    if node.type == "call_expression":
        fn = node.child_by_field_name("function")
        if fn is not None and fn.type == "identifier":
            return f"{RHS_FROM_CALL}:{_node_text(fn, src)}"
        return f"{RHS_FROM_CALL}:<indirect>"
    if node.type == "field_expression":
        owner, name = _field_base_and_name(node, src)
        return f"{RHS_FROM_FIELD}:{owner}.{name}"
    if node.type == "identifier":
        name = _node_text(node, src)
        if name in set(params):
            return f"{RHS_FROM_PARAM}:{name}"
        return f"{RHS_FROM_VAR}:{name}"
    return RHS_UNKNOWN


def _read_context(node: Any, src: bytes) -> str:
    """Use context of a field_expression that is not a write LHS."""
    parent = node.parent
    if parent is None:
        return "expr"
    fn = parent.child_by_field_name("function") \
        if parent.type == "call_expression" else None
    if fn is not None and (fn.start_byte, fn.end_byte) == \
            (node.start_byte, node.end_byte):
        return "invoke"
    cur = parent
    hops = 0
    provisional = ""
    while cur is not None and hops < 6:
        if cur.type == "argument_list":
            # Provisional: the value may still flow into an alias
            # through a passthrough call (p = rcu_dereference(o->f)),
            # so keep walking for an enclosing assignment.
            provisional = provisional or "call_arg"
        elif cur.type == "return_statement":
            return "return"
        elif cur.type in ("if_statement", "while_statement",
                          "condition_clause"):
            return "condition"
        elif cur.type == "init_declarator":
            decl = cur.child_by_field_name("declarator")
            while decl is not None and decl.type == \
                    "pointer_declarator":
                decl = decl.child_by_field_name("declarator")
            if decl is not None and decl.type == "identifier":
                return f"alias_assign:{_node_text(decl, src)}"
            return provisional or "expr"
        elif cur.type == "assignment_expression":
            left = cur.child_by_field_name("left")
            if left is not None and left.type == "identifier" and \
                    not _contains(left, node):
                return f"alias_assign:{_node_text(left, src)}"
            return provisional or "expr"
        cur = cur.parent
        hops += 1
    return provisional or "expr"


def _contains(ancestor: Any, node: Any) -> bool:
    return (
        ancestor.start_byte <= node.start_byte
        and node.end_byte <= ancestor.end_byte
    )


# ── census build ────────────────────────────────────────────────────


def priority_fields_from_study_list(
    study_list: Any,
) -> frozenset[str]:
    """Field names of study items whose lifecycle feature seeds
    (``resource_lifecycle`` / ``alloc_frees`` / ``state_transitions``)
    are non-empty — these fields walk first under the census caps.

    Accepts the ``study-list.json`` payload (dict with ``items`` or a
    bare list), a path to it, or ``None``.
    """
    items: list[Any] = []
    if study_list is None:
        return frozenset()
    if isinstance(study_list, (str, Path)):
        try:
            path = Path(study_list)
            if path.is_dir():
                path = path / "study-list.json"
            study_list = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return frozenset()
    if isinstance(study_list, dict):
        items = study_list.get("items") or []
    elif isinstance(study_list, list):
        items = study_list
    out: set[str] = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        if not (
            item.get("resource_lifecycle")
            or item.get("alloc_frees")
            or item.get("state_transitions")
        ):
            continue
        for f in item.get("fields") or []:
            if isinstance(f, str) and f:
                out.add(f.split(":", 1)[0].strip())
    return frozenset(n for n in out if n)


def build_field_census(
    source_texts: dict[str, str],
    *,
    priority_fields: frozenset[str] = frozenset(),
    budget_s: float = CENSUS_BUDGET_S,
    max_fields: int = MAX_CENSUS_FIELDS,
    max_sites_per_field: int = MAX_SITES_PER_FIELD,
) -> FieldCensus:
    """Build the whole-target field-access census.

    One parse per file on the shared cache; noise fields
    (``next``/``len``/… — the struct_accessor_index list) are dropped
    unless named in *priority_fields*.
    """
    t0 = time.monotonic()
    census = FieldCensus()
    telemetry: dict[str, Any] = {
        "files_scanned": 0,
        "files_skipped_language": 0,
        "fields_skipped": 0,
        "sites_capped_fields": 0,
        "budget_exceeded": False,
    }
    census.telemetry = telemetry

    raw: dict[str, FieldRecord] = {}
    tiers_seen: set[str] = set()

    def _keep_field(name: str) -> bool:
        if name in priority_fields:
            return True
        return len(name) >= _MIN_FIELD_LEN and name not in _NOISE_FIELDS

    for file_path in sorted(source_texts):
        if time.monotonic() - t0 > budget_s:
            telemetry["budget_exceeded"] = True
            break
        source = source_texts[file_path]
        try:
            from .callsite_consistency import parse_source_cached
            tree, lang = parse_source_cached(file_path, source)
        except Exception:
            tree, lang = None, None
        if lang is not None and lang not in _CENSUS_LANGUAGES:
            telemetry["files_skipped_language"] += 1
            continue
        if lang is None and not _looks_c_family(file_path):
            telemetry["files_skipped_language"] += 1
            continue
        telemetry["files_scanned"] += 1
        if tree is not None:
            tiers_seen.add(TIER_TREE_SITTER)
            census.functions[file_path] = _scan_file_ts(
                tree, source, file_path, raw, _keep_field,
            )
        else:
            tiers_seen.add(TIER_REGEX)
            census.functions[file_path] = _scan_file_regex(
                source, file_path, raw, _keep_field,
            )

    # Prioritised field cap: priority fields first, then site count.
    ordered = sorted(
        raw.items(),
        key=lambda kv: (
            kv[0] not in priority_fields,
            -(len(kv[1].writes) + len(kv[1].reads)),
            kv[0],
        ),
    )
    for name, rec in ordered[:max_fields]:
        if len(rec.writes) > max_sites_per_field:
            rec.writes = rec.writes[:max_sites_per_field]
            rec.sites_capped = True
        if len(rec.reads) > max_sites_per_field:
            rec.reads = rec.reads[:max_sites_per_field]
            rec.sites_capped = True
        if rec.sites_capped:
            telemetry["sites_capped_fields"] += 1
        census.fields[name] = rec
    telemetry["fields_skipped"] = max(0, len(raw) - max_fields)
    telemetry["fields_indexed"] = len(census.fields)

    if TIER_REGEX in tiers_seen:
        census.tier = TIER_REGEX if tiers_seen == {TIER_REGEX} else "mixed"
    telemetry["tier"] = census.tier
    telemetry["wall_time_s"] = round(time.monotonic() - t0, 3)
    return census


def _looks_c_family(file_path: str) -> bool:
    return Path(file_path).suffix in (
        ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp",
    )


def _span_for_line(spans: list[FunctionSpan],
                   line: int) -> FunctionSpan | None:
    for s in spans:
        if s.start <= line <= s.end:
            return s
    return None


def _scan_file_ts(
    tree: Any,
    source: str,
    file_path: str,
    raw: dict[str, FieldRecord],
    keep: Any,
) -> list[FunctionSpan]:
    src = source.encode("utf-8", errors="replace")
    spans = _function_spans_ts(tree, source)
    lines = source.splitlines()
    lock_cache: dict[str, str] = {}

    def _lock_for(span: FunctionSpan | None) -> str:
        if span is None:
            return ""
        if span.name not in lock_cache:
            segment = "\n".join(lines[span.start - 1:span.end])
            lock_cache[span.name] = _detect_lock(segment)
        return lock_cache[span.name]

    # Keyed by byte span: py-tree-sitter Node objects are not
    # identity-stable across child_by_field_name calls.
    write_lhs: set[tuple[int, int]] = set()
    stack = [tree.root_node]
    nodes: list[Any] = []
    while stack:
        node = stack.pop()
        nodes.append(node)
        stack.extend(node.children)

    for node in nodes:
        if node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            if left is not None and left.type == "field_expression":
                write_lhs.add((left.start_byte, left.end_byte))

    for node in nodes:
        if node.type != "field_expression":
            continue
        owner, name = _field_base_and_name(node, src)
        if not name or not keep(name):
            continue
        line = node.start_point[0] + 1
        span = _span_for_line(spans, line)
        function = span.name if span else ""
        params = span.params if span else ()
        code = lines[line - 1].strip() if 1 <= line <= len(lines) else ""
        rec = raw.setdefault(name, FieldRecord(field=name))
        if (node.start_byte, node.end_byte) in write_lhs:
            assign = node.parent
            rhs = assign.child_by_field_name("right") \
                if assign is not None else None
            op = assign.child_by_field_name("operator") \
                if assign is not None else None
            rhs_class = _classify_rhs_ts(rhs, src, params)
            if op is not None and _node_text(op, src) != "=":
                rhs_class = RHS_UNKNOWN  # compound assign: read+write
                rec.reads.append(FieldRead(
                    file=file_path, line=line, function=function,
                    owner=owner, context="expr", code=code,
                ))
            rec.writes.append(FieldWrite(
                file=file_path, line=line, function=function,
                owner=owner, rhs_class=rhs_class, code=code,
                lock_held=_lock_for(span),
            ))
        else:
            rec.reads.append(FieldRead(
                file=file_path, line=line, function=function,
                owner=owner, context=_read_context(node, src),
                code=code,
            ))
    return spans


def _scan_file_regex(
    source: str,
    file_path: str,
    raw: dict[str, FieldRecord],
    keep: Any,
) -> list[FunctionSpan]:
    spans = function_spans_regex(source)
    lines = source.splitlines()
    lock_cache: dict[str, str] = {}

    def _lock_for(span: FunctionSpan | None) -> str:
        if span is None:
            return ""
        if span.name not in lock_cache:
            segment = "\n".join(lines[span.start - 1:span.end])
            lock_cache[span.name] = _detect_lock(segment)
        return lock_cache[span.name]

    for lineno, text in enumerate(source.splitlines(), 1):
        span = _span_for_line(spans, lineno)
        function = span.name if span else ""
        params = span.params if span else ()
        code = text.strip()
        written: set[tuple[str, str]] = set()
        for m in _WRITE_RE.finditer(text):
            owner, name = m.group(1), m.group(2)
            if not keep(name):
                continue
            written.add((owner, name))
            rhs = text[m.end():].strip()
            rec = raw.setdefault(name, FieldRecord(
                field=name, tier=TIER_REGEX,
            ))
            rec.tier = TIER_REGEX
            rec.writes.append(FieldWrite(
                file=file_path, line=lineno, function=function,
                owner=owner,
                rhs_class=_classify_rhs_text(rhs, params),
                code=code, lock_held=_lock_for(span),
            ))
        alias = _LOCAL_ALIAS_RE.search(text)
        for m in _ACCESS_RE.finditer(text):
            owner, name = m.group(1), m.group(2)
            if not keep(name) or (owner, name) in written:
                continue
            if owner in _C_KEYWORDS:
                continue
            context = "expr"
            if _CALL_AFTER_RE.match(text[m.end():]):
                context = "invoke"
            elif alias and alias.group(2) == owner and \
                    alias.group(3) == name:
                context = f"alias_assign:{alias.group(1)}"
            elif "return" in text.split("->")[0]:
                context = "return"
            rec = raw.setdefault(name, FieldRecord(
                field=name, tier=TIER_REGEX,
            ))
            rec.tier = TIER_REGEX
            rec.reads.append(FieldRead(
                file=file_path, line=lineno, function=function,
                owner=owner, context=context, code=code,
            ))
    return spans


# ── by-products and helpers ─────────────────────────────────────────


def written_never_read(census: FieldCensus) -> list[FieldRecord]:
    """The free by-product: fields with writes > 0 and reads = 0
    target-wide — the cheap partial receipt for the protocol_state
    dead-state leg and a generic lead class."""
    return sorted(
        (
            rec for rec in census.fields.values()
            if rec.writes and not rec.reads
        ),
        key=lambda r: (-len(r.writes), r.field),
    )


def guards_for_site(
    target_path: Path,
    file_path: str,
    function_name: str,
    line: int,
    *,
    source: str = "",
) -> frozenset:
    """Dominating-guard conjunction for one site, on demand (CFG +
    dominators via :mod:`core.analysis.lifecycle_collector`). Returns
    an empty frozenset when the CFG cannot be built — callers treat
    absence as \"guards unknown\", never as \"unguarded\"."""
    try:
        from core.analysis.dominators import build_dom_tree
        from core.analysis.lifecycle_collector import collect_guards_at_site

        from .block_review import try_build_cfg
    except ImportError:
        return frozenset()
    try:
        cfg = try_build_cfg(
            file_path, function_name, Path(target_path), source=source,
        )
        if cfg is None:
            return frozenset()
        dom = build_dom_tree(cfg)
        return collect_guards_at_site(cfg, dom, line, file_path)
    except Exception:
        logger.debug("field census: guard collection failed",
                     exc_info=True)
        return frozenset()


def write_census_artifact(census: FieldCensus,
                          out_dir: Path) -> Path | None:
    """Persist ``field-census.json`` (mirrors ``return-census.json``)."""
    try:
        path = Path(out_dir) / ARTIFACT_NAME
        path.write_text(json.dumps(census.to_dict(), indent=1))
        return path
    except OSError:
        logger.debug("field-census.json write failed", exc_info=True)
        return None


def seed_injected_hypotheses(
    gaps: list[dict[str, Any]],
    handoffs: list[dict[str, Any]],
    *,
    source: str,
) -> int:
    """Seed channel handoff hypotheses onto their gaps (the
    ``fix_history`` / consistency-prepass injected-hypothesis
    precedent — G1 holds because the hypothesis exists before any
    finding)."""
    by_key: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for h in handoffs:
        by_key.setdefault(
            (h.get("file", ""), h.get("function", "")), [],
        ).append(h)
    seeded = 0
    for gap in gaps:
        key = (gap.get("file", ""), gap.get("name", ""))
        for h in by_key.get(key, []):
            gap.setdefault("injected_hypotheses", []).append({
                "mechanism": h["mechanism"],
                "confidence": "medium",
                "source": source,
            })
            seeded += 1
    return seeded
