"""Layered peer group resolver for /audit sibling analysis.

Replaces the global verb-prefix grouping in ``sibling_analysis.py`` with
a seven-layer resolver that uses progressively weaker signals.  Higher-
confidence layers (Joern call graph, binary edges, dispatch tables) claim
functions first; lower layers only group what remains unclaimed.

Layer hierarchy:

  L0  Joern co-callee groups     — CPG call graph (definitive)
  L1  r2 binary co-callee groups — binary call edges (definitive)
  L2  Dispatch-site groups       — tree-sitter extraction (definitive)
  L3  Domain model groups        — study-run concepts (high)

  L4  Type cohort groups         — shared type parameter (medium-high)
  L5  Verb-prefix + sig shape    — naming heuristic per-directory (medium)
  L6  Paired operations          — stem + verb match, global (medium)

L0–L3 claim exclusively (a function in a higher layer is removed from
lower layers' input).  L4–L6 run independently.
"""

from __future__ import annotations

import logging
import re
from collections import defaultdict
from pathlib import PurePosixPath
from typing import Any

from core.audit.sibling_analysis import (
    SiblingGroup,
    SiblingPath,
    SiblingType,
)

logger = logging.getLogger(__name__)

# Extended sibling types for new layers.  We use plain strings because
# SiblingType is a str enum — downstream consumers compare by value, so
# adding new values here is backwards-compatible.
_CO_CALLEE = "co_callee"
_DISPATCH_SITE = "dispatch_site"
_TYPE_COHORT = "type_cohort"


# ── Top-level resolver ────────────────────────────────────────────────


def resolve_peer_groups(
    functions: list[dict[str, Any]],
    *,
    joern_server: Any | None = None,
    binary_edge_index: Any | None = None,
    dispatch_tables: list | None = None,
    domain_model: dict[str, Any] | None = None,
    type_ref_index: dict[str, list[tuple[str, str]]] | None = None,
    checklist: dict[str, Any] | None = None,
) -> list[SiblingGroup]:
    """Build peer groups from all available signals.

    Parameters mirror the data available in the orchestrator prep phase.
    Everything is optional — missing inputs simply skip that layer.
    """
    groups: list[SiblingGroup] = []
    claimed: set[tuple[str, str]] = set()  # (file, function) pairs

    def _remaining():
        return [
            f for f in functions
            if (f.get("file", ""), f.get("name", "")) not in claimed
        ]

    def _claim(new_groups: list[SiblingGroup]) -> None:
        for g in new_groups:
            for s in g.siblings:
                claimed.add((s.file, s.function))

    # L0: Joern co-callee (exclusive)
    if joern_server is not None:
        l0 = _joern_co_callee_groups(joern_server, _remaining())
        _claim(l0)
        groups.extend(l0)

    # L1: r2 binary co-callee (exclusive)
    if binary_edge_index is not None:
        l1 = _binary_co_callee_groups(binary_edge_index, _remaining())
        _claim(l1)
        groups.extend(l1)

    # L2: Dispatch-site (exclusive)
    if dispatch_tables:
        l2 = _dispatch_site_groups(dispatch_tables, _remaining())
        _claim(l2)
        groups.extend(l2)

    # L3: Domain model (exclusive)
    if domain_model:
        l3 = _domain_model_groups(domain_model, _remaining())
        _claim(l3)
        groups.extend(l3)

    # L4–L6: independent (no claim removal between them)
    groups.extend(_type_cohort_groups(type_ref_index, functions))
    groups.extend(_verb_prefix_groups(functions, checklist=checklist))
    groups.extend(_paired_operation_groups(functions))

    logger.info(
        "peer group resolver: %d groups (%d functions claimed by L0-L3, "
        "%d total functions)",
        len(groups), len(claimed), len(functions),
    )
    return groups


# ── L0: Joern co-callee groups ────────────────────────────────────────


_JOERN_PEERS_RE = re.compile(r"^JOERN_PEERS:([^|]+)\|([^|]*)\|(.+)$")


def _parse_joern_peers(raw_output: str) -> list[tuple[str, str, list[str]]]:
    """Parse JOERN_PEERS: lines into (caller, file, [callees])."""
    results: list[tuple[str, str, list[str]]] = []
    for line in raw_output.splitlines():
        m = _JOERN_PEERS_RE.match(line.strip())
        if m:
            caller = m.group(1)
            caller_file = m.group(2)
            callees = [c for c in m.group(3).split(",") if c]
            if len(callees) >= 2:
                results.append((caller, caller_file, callees))
    return results


_CO_CALLEE_QUERY = """\
import io.shiftleft.semanticcpg.language._
import scala.util.Try

cpg.method.internal
  .filter(_.call.size > 1)
  .map { caller =>
    val callees = Try(
      caller.call
        .filterNot(c => c.name.startsWith("<") || c.name == caller.name)
        .filter(c => cpg.method.nameExact(c.name).nonEmpty)
        .name.dedup.l
    ).getOrElse(List.empty[String])
    if (callees.size >= 2) {
      val f = caller.filename.replace("\\\\", "\\\\\\\\").replace("\\"", "\\\\\\"")
      s"JOERN_PEERS:${caller.name}|${f}|${callees.mkString(",")}"
    } else ""
  }
  .filter(_.nonEmpty).l.foreach(println)
"""


def _joern_co_callee_groups(
    joern_server: Any,
    functions: list[dict[str, Any]],
) -> list[SiblingGroup]:
    """L0: functions called from the same method body (CPG call graph)."""
    if not functions:
        return []

    try:
        result = joern_server.query(
            _CO_CALLEE_QUERY, timeout=60, validate=True,
        )
    except Exception:
        logger.debug("joern co-callee query failed", exc_info=True)
        return []

    if not result or result.errors:
        if result and result.errors:
            logger.debug("joern co-callee query errors: %s", result.errors)
        return []

    raw_groups = _parse_joern_peers(result.raw_output or "")
    func_names = {f.get("name", "") for f in functions}
    func_by_name = {f.get("name", ""): f for f in functions if f.get("name")}

    groups: list[SiblingGroup] = []
    for caller, caller_file, callees in raw_groups:
        relevant = [c for c in callees if c in func_names]
        filtered = _filter_co_callees(relevant, func_by_name)
        if len(filtered) < 2:
            continue

        siblings = [
            SiblingPath(
                label=name,
                file=func_by_name[name].get("file", ""),
                function=name,
                line=func_by_name[name].get("line", 0),
            )
            for name in filtered
        ]
        groups.append(SiblingGroup(
            group_id=f"joern_co_callee:{caller}",
            sibling_type=_CO_CALLEE,
            description=f"Co-callees of {caller} (Joern CPG)",
            siblings=siblings,
            shared_context=f"Called from {caller} ({caller_file})",
        ))

    logger.debug("L0 joern co-callee: %d groups from %d raw caller sets",
                 len(groups), len(raw_groups))
    return groups


# ── L1: r2 binary co-callee groups ───────────────────────────────────


def _binary_co_callee_groups(
    edge_index: Any,
    functions: list[dict[str, Any]],
) -> list[SiblingGroup]:
    """L1: functions called from the same binary function (r2 edges)."""
    if not functions:
        return []

    edges = getattr(edge_index, "edges", [])
    if not edges:
        return []

    func_names = {f.get("name", "") for f in functions}
    func_by_name = {f.get("name", ""): f for f in functions if f.get("name")}

    caller_to_callees: dict[str, list[str]] = defaultdict(list)
    for edge in edges:
        callee = getattr(edge, "callee", "")
        caller = getattr(edge, "caller", "")
        if callee in func_names and caller:
            caller_to_callees[caller].append(callee)

    groups: list[SiblingGroup] = []
    for caller, callees in caller_to_callees.items():
        unique = sorted(set(callees))
        filtered = _filter_co_callees(unique, func_by_name)
        if len(filtered) < 2:
            continue

        siblings = [
            SiblingPath(
                label=name,
                file=func_by_name[name].get("file", ""),
                function=name,
                line=func_by_name[name].get("line", 0),
            )
            for name in filtered
        ]
        groups.append(SiblingGroup(
            group_id=f"binary_co_callee:{caller}",
            sibling_type=_CO_CALLEE,
            description=f"Co-callees of {caller} (binary edges)",
            siblings=siblings,
            shared_context=f"Called from {caller} (binary)",
        ))

    logger.info("L1 binary co-callee: %d groups", len(groups))
    return groups


# ── L2: Dispatch-site groups ─────────────────────────────────────────


def _dispatch_site_groups(
    tables: list,
    functions: list[dict[str, Any]],
) -> list[SiblingGroup]:
    """L2: functions serving as handlers in the same dispatch table."""
    if not tables or not functions:
        return []

    func_names = {f.get("name", "") for f in functions}
    func_by_name = {f.get("name", ""): f for f in functions if f.get("name")}

    groups: list[SiblingGroup] = []
    for table in tables:
        handlers = getattr(table, "handlers", None) or {}
        handler_names = [
            h for h in handlers.values()
            if h in func_names
        ]
        if len(handler_names) < 2:
            continue

        table_fn = getattr(table, "function", "")
        table_file = getattr(table, "file", "")
        siblings = [
            SiblingPath(
                label=name,
                file=func_by_name[name].get("file", ""),
                function=name,
                line=func_by_name[name].get("line", 0),
            )
            for name in handler_names
        ]
        groups.append(SiblingGroup(
            group_id=f"dispatch:{table_file}:{table_fn}",
            sibling_type=_DISPATCH_SITE,
            description=f"Dispatch handlers in {table_fn}",
            siblings=siblings,
            shared_context=f"Dispatch table in {table_fn} ({table_file})",
        ))

    logger.info("L2 dispatch-site: %d groups", len(groups))
    return groups


# ── L3: Domain model groups ──────────────────────────────────────────


def _domain_model_groups(
    model: dict[str, Any],
    functions: list[dict[str, Any]],
) -> list[SiblingGroup]:
    """L3: groups from study-run domain model concepts."""
    if not model or not functions:
        return []

    func_names = {f.get("name", "") for f in functions}
    func_by_name = {f.get("name", ""): f for f in functions if f.get("name")}

    concepts = model.get("concepts", [])
    if not concepts:
        return []

    groups: list[SiblingGroup] = []
    for concept in concepts:
        members = concept.get("functions", concept.get("members", []))
        if not isinstance(members, list) or len(members) < 2:
            continue

        matched = []
        for m in members:
            name = m if isinstance(m, str) else m.get("name", "")
            if name in func_names:
                matched.append(name)

        if len(matched) < 2:
            continue

        concept_name = concept.get("name", concept.get("id", "unknown"))
        siblings = [
            SiblingPath(
                label=name,
                file=func_by_name[name].get("file", ""),
                function=name,
                line=func_by_name[name].get("line", 0),
            )
            for name in matched
        ]
        groups.append(SiblingGroup(
            group_id=f"domain:{concept_name}",
            sibling_type=SiblingType.PEER_FUNCTIONS,
            description=f"Domain concept: {concept_name}",
            siblings=siblings,
            shared_context=concept.get("description", ""),
        ))

    logger.info("L3 domain model: %d groups", len(groups))
    return groups


# ── L4: Type cohort groups ───────────────────────────────────────────


def _type_cohort_groups(
    type_ref_index: dict[str, list[tuple[str, str]]] | None,
    functions: list[dict[str, Any]],
) -> list[SiblingGroup]:
    """L4: functions operating on the same struct/type."""
    if not type_ref_index or not functions:
        return []

    func_by_name = {f.get("name", ""): f for f in functions if f.get("name")}
    func_names = set(func_by_name)

    groups: list[SiblingGroup] = []
    for type_name, entries in type_ref_index.items():
        members = list(dict.fromkeys(fn for fn, _cls in entries if fn in func_names))
        if len(members) < 2:
            continue

        siblings = [
            SiblingPath(
                label=name,
                file=func_by_name[name].get("file", ""),
                function=name,
                line=func_by_name[name].get("line", 0),
            )
            for name in members
        ]
        groups.append(SiblingGroup(
            group_id=f"type_cohort:{type_name}",
            sibling_type=_TYPE_COHORT,
            description=f"Functions operating on {type_name}",
            siblings=siblings,
            shared_context=f"Shared type: {type_name}",
        ))

    logger.info("L4 type cohort: %d groups", len(groups))
    return groups


# ── L5: Verb-prefix per-directory + signature shape ──────────────────

_VERB_PREFIX_RE = re.compile(
    r"^(handle|process|parse|render|validate|check|verify|do|on|emit|send|recv|"
    r"read|write|get|set|create|delete|update|insert|remove|add|"
    r"init|setup|teardown|cleanup|reset|start|stop|open|close|"
    r"encode|decode|encrypt|decrypt|compress|decompress|"
    r"serialize|deserialize|marshal|unmarshal|pack|unpack|"
    r"load|save|store|fetch|put|push|pull|pop|"
    r"register|unregister|subscribe|unsubscribe|"
    r"connect|disconnect|bind|unbind|attach|detach|"
    r"enable|disable|show|hide|lock|unlock|alloc|free|"
    r"enter|exit|begin|end|run|exec|dispatch|route)_",
    re.IGNORECASE,
)


def _func_directory(func: dict[str, Any]) -> str:
    """Extract parent directory from a function's file path."""
    f = func.get("file", "")
    if not f:
        return ""
    return str(PurePosixPath(f).parent)


def _signatures_compatible(
    a: dict[str, Any],
    b: dict[str, Any],
    *,
    max_arity_diff: int = 1,
) -> bool:
    """Check whether two functions have compatible signatures."""
    meta_a = a.get("metadata", {}) or {}
    meta_b = b.get("metadata", {}) or {}

    params_a = meta_a.get("parameters", [])
    params_b = meta_b.get("parameters", [])

    if params_a and params_b:
        if abs(len(params_a) - len(params_b)) > max_arity_diff:
            return False

        if params_a and params_b:
            p0a, p0b = params_a[0], params_b[0]
            type_a = (p0a.get("type") if isinstance(p0a, dict)
                      else p0a[1] if isinstance(p0a, (list, tuple)) and len(p0a) > 1
                      else None)
            type_b = (p0b.get("type") if isinstance(p0b, dict)
                      else p0b[1] if isinstance(p0b, (list, tuple)) and len(p0b) > 1
                      else None)
            if type_a and type_b and type_a != type_b:
                return False

    ret_a = meta_a.get("return_type")
    ret_b = meta_b.get("return_type")
    if ret_a and ret_b and ret_a != ret_b:
        return False

    return True


def _shared_decorator(a: dict[str, Any], b: dict[str, Any]) -> str | None:
    """Return a shared decorator name if both functions have one."""
    meta_a = a.get("metadata", {}) or {}
    meta_b = b.get("metadata", {}) or {}
    attrs_a = set(meta_a.get("attributes", []))
    attrs_b = set(meta_b.get("attributes", []))
    shared = attrs_a & attrs_b
    if shared:
        return sorted(shared)[0]
    return None


def _verb_prefix_groups(
    functions: list[dict[str, Any]],
    checklist: dict[str, Any] | None = None,
) -> list[SiblingGroup]:
    """L5: verb-prefix groups scoped per-directory with signature filtering."""
    if not functions:
        return []

    cl_entries = checklist.get("functions", checklist) if checklist else {}
    if isinstance(cl_entries, list):
        cl_entries = {}

    def _enrich(func: dict[str, Any]) -> dict[str, Any]:
        """Attach metadata from checklist if available."""
        if func.get("metadata"):
            return func
        key = f"{func.get('file', '')}:{func.get('name', '')}"
        entry = cl_entries.get(key, {})
        if isinstance(entry, dict) and entry.get("metadata"):
            return {**func, "metadata": entry["metadata"]}
        return func

    # First pass: decorator-based groups per directory
    decorator_groups: list[SiblingGroup] = []
    decorator_claimed: set[tuple[str, str]] = set()  # (file, name)

    dir_funcs: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for f in functions:
        enriched = _enrich(f)
        d = _func_directory(enriched)
        dir_funcs[d].append(enriched)

    for directory, dir_members in dir_funcs.items():
        deco_to_funcs: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for f in dir_members:
            meta = f.get("metadata", {}) or {}
            for attr in meta.get("attributes", []):
                deco_to_funcs[attr].append(f)

        for deco, members in deco_to_funcs.items():
            if len(members) < 2:
                continue
            siblings = [
                SiblingPath(
                    label=m.get("name", ""),
                    file=m.get("file", ""),
                    function=m.get("name", ""),
                    line=m.get("line", 0),
                )
                for m in members
            ]
            decorator_groups.append(SiblingGroup(
                group_id=f"decorator:{directory}:{deco}",
                sibling_type=SiblingType.PEER_FUNCTIONS,
                description=f"@{deco} functions in {directory or '.'}",
                siblings=siblings,
                shared_context=f"Shared decorator: @{deco}",
            ))
            for m in members:
                decorator_claimed.add((m.get("file", ""), m.get("name", "")))

    # Second pass: verb-prefix groups per directory (excluding decorator-claimed)
    verb_groups: list[SiblingGroup] = []

    for directory, dir_members in dir_funcs.items():
        prefix_buckets: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for f in dir_members:
            name = f.get("name", "")
            if (f.get("file", ""), name) in decorator_claimed:
                continue
            m = _VERB_PREFIX_RE.match(name)
            if m:
                prefix_buckets[m.group(1).lower()].append(f)

        for verb, candidates in prefix_buckets.items():
            if len(candidates) < 2:
                continue

            # Signature-shape filtering: keep largest compatible subset
            compatible = _largest_compatible_subset(candidates)
            if len(compatible) < 2:
                continue

            siblings = [
                SiblingPath(
                    label=c.get("name", ""),
                    file=c.get("file", ""),
                    function=c.get("name", ""),
                    line=c.get("line", 0),
                )
                for c in compatible
            ]
            verb_groups.append(SiblingGroup(
                group_id=f"verb:{directory}:{verb}",
                sibling_type=SiblingType.PEER_FUNCTIONS,
                description=f"{verb}_* functions in {directory or '.'}",
                siblings=siblings,
            ))

    all_groups = decorator_groups + verb_groups
    logger.debug("L5 verb-prefix: %d groups (%d decorator, %d verb-prefix)",
                 len(all_groups), len(decorator_groups), len(verb_groups))
    return all_groups


def _largest_compatible_subset(
    candidates: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Find the largest subset of candidates with compatible signatures.

    Greedy: start with the first candidate, add each subsequent one if
    it is compatible with the first.  Simple and sufficient — the common
    case is a homogeneous set where everything matches.
    """
    if len(candidates) <= 1:
        return candidates

    anchor = candidates[0]
    result = [anchor]
    for c in candidates[1:]:
        if _shared_decorator(anchor, c) or _signatures_compatible(anchor, c):
            result.append(c)

    return result


# ── L6: Paired operations ────────────────────────────────────────────

_PAIR_PATTERNS: list[tuple[re.Pattern, re.Pattern]] = [
    (re.compile(r"^(encode)_(.+)", re.I), re.compile(r"^(decode)_(.+)", re.I)),
    (re.compile(r"^(encrypt)_(.+)", re.I), re.compile(r"^(decrypt)_(.+)", re.I)),
    (re.compile(r"^(serialize)_(.+)", re.I), re.compile(r"^(deserialize)_(.+)", re.I)),
    (re.compile(r"^(marshal)_(.+)", re.I), re.compile(r"^(unmarshal)_(.+)", re.I)),
    (re.compile(r"^(pack)_(.+)", re.I), re.compile(r"^(unpack)_(.+)", re.I)),
    (re.compile(r"^(compress)_(.+)", re.I), re.compile(r"^(decompress)_(.+)", re.I)),
    (re.compile(r"^(sanitize_input)_?(.+)?", re.I), re.compile(r"^(sanitize_output)_?(.+)?", re.I)),
    (re.compile(r"^(lock)_(.+)", re.I), re.compile(r"^(unlock)_(.+)", re.I)),
    (re.compile(r"^(alloc)_(.+)", re.I), re.compile(r"^(free)_(.+)", re.I)),
    (re.compile(r"^(get)_(.+)", re.I), re.compile(r"^(put)_(.+)", re.I)),
    (re.compile(r"^(get)_(.+)", re.I), re.compile(r"^(set)_(.+)", re.I)),
    (re.compile(r"^(acquire)_(.+)", re.I), re.compile(r"^(release)_(.+)", re.I)),
    (re.compile(r"^(ref)_(.+)", re.I), re.compile(r"^(unref)_(.+)", re.I)),
    (re.compile(r"^(inc)_(.+)", re.I), re.compile(r"^(dec)_(.+)", re.I)),
    (re.compile(r"^(register)_(.+)", re.I), re.compile(r"^(unregister)_(.+)", re.I)),
    (re.compile(r"^(subscribe)_(.+)", re.I), re.compile(r"^(unsubscribe)_(.+)", re.I)),
    (re.compile(r"^(connect)_(.+)", re.I), re.compile(r"^(disconnect)_(.+)", re.I)),
    (re.compile(r"^(attach)_(.+)", re.I), re.compile(r"^(detach)_(.+)", re.I)),
    (re.compile(r"^(enable)_(.+)", re.I), re.compile(r"^(disable)_(.+)", re.I)),
    (re.compile(r"^(bind)_(.+)", re.I), re.compile(r"^(unbind)_(.+)", re.I)),
    (re.compile(r"^(open)_(.+)", re.I), re.compile(r"^(close)_(.+)", re.I)),
    (re.compile(r"^(start)_(.+)", re.I), re.compile(r"^(stop)_(.+)", re.I)),
    (re.compile(r"^(init)_(.+)", re.I), re.compile(r"^(cleanup)_(.+)", re.I)),
    (re.compile(r"^(setup)_(.+)", re.I), re.compile(r"^(teardown)_(.+)", re.I)),
]

# Suffix-swap pairs (same stem, different suffix)
_SUFFIX_PAIRS = [
    ("hold", "free"),
    ("hold", "rele"),
    ("ref", "unref"),
    ("acquire", "release"),
    ("lock", "unlock"),
    ("get", "put"),
    ("inc", "dec"),
    ("get", "set"),
]


def _paired_operation_groups(
    functions: list[dict[str, Any]],
) -> list[SiblingGroup]:
    """L6: paired operations — global, stem-specific matching."""
    if not functions:
        return []

    func_by_name = {f.get("name", ""): f for f in functions if f.get("name")}
    names = set(func_by_name)
    groups: list[SiblingGroup] = []
    paired: set[str] = set()

    def _add_pair(a: str, b: str) -> None:
        if a in paired or b in paired:
            return
        paired.add(a)
        paired.add(b)
        fa, fb = func_by_name[a], func_by_name[b]
        groups.append(SiblingGroup(
            group_id=f"pair:{a}:{b}",
            sibling_type=SiblingType.PAIRED_OPERATIONS,
            description=f"Paired operations: {a} ↔ {b}",
            siblings=[
                SiblingPath(
                    label=a, file=fa.get("file", ""),
                    function=a, line=fa.get("line", 0),
                ),
                SiblingPath(
                    label=b, file=fb.get("file", ""),
                    function=b, line=fb.get("line", 0),
                ),
            ],
        ))

    # Prefix-swap pairs
    for fwd_pat, rev_pat in _PAIR_PATTERNS:
        forward: dict[str, str] = {}
        reverse: dict[str, str] = {}
        for name in names:
            m = fwd_pat.match(name)
            if m:
                stem = m.group(2) or ""
                forward[stem.lower()] = name
            m = rev_pat.match(name)
            if m:
                stem = m.group(2) or ""
                reverse[stem.lower()] = name
        for stem in forward:
            if stem in reverse:
                _add_pair(forward[stem], reverse[stem])

    # Suffix-swap pairs
    for acq_sfx, rel_sfx in _SUFFIX_PAIRS:
        for name in sorted(names):
            if name.endswith(acq_sfx):
                stem = name[: -len(acq_sfx)]
                partner = stem + rel_sfx
                if partner in names and partner != name:
                    _add_pair(name, partner)

    logger.debug("L6 paired operations: %d pairs", len(groups))
    return groups


# ── Shared helpers ────────────────────────────────────────────────────


def _filter_co_callees(
    callees: list[str],
    func_by_name: dict[str, dict[str, Any]],
    *,
    max_arity_diff: int = 1,
) -> list[str]:
    """Filter a raw co-callee set by signature compatibility.

    Removes utility calls (logging, validation, cleanup) that share a
    caller with the real dispatch targets but have incompatible signatures.
    """
    if len(callees) < 2:
        return callees

    resolved = [(c, func_by_name.get(c)) for c in callees]
    resolved = [(c, f) for c, f in resolved if f is not None]

    if len(resolved) < 2:
        return [c for c, _ in resolved]

    # Use first function as anchor; keep those compatible with it
    anchor_name, anchor = resolved[0]
    result = [anchor_name]
    for name, func in resolved[1:]:
        if _signatures_compatible(anchor, func, max_arity_diff=max_arity_diff):
            result.append(name)

    if len(result) < 2:
        return [c for c, _ in resolved]

    return result
