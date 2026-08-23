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
  L5  Decorator / verb-prefix    — shared-decorator groups first, then
                                    verb-prefix + sig shape on what
                                    remains, per-directory (medium)
  L6  Paired operations          — stem + verb match, global (medium)

L0–L3 claim exclusively (a function in a higher layer is removed from
lower layers' input).  L4–L6 run independently.
"""

from __future__ import annotations

import logging
import re
from collections import defaultdict
from pathlib import Path, PurePosixPath
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
    # Per-layer summary: "ran → N groups" vs "skipped (no input)". The
    # previous single "claimed by L0-L3" counter couldn't distinguish
    # the two, and its "L0" vocabulary collided with the unrelated
    # mechanical "Layer 0" pattern sweep — a run whose exclusive
    # layers all lacked inputs printed "0 functions claimed by L0-L3"
    # next to "Layer 0: N findings", reading as a contradiction.
    layer_report: list[str] = []

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
        layer_report.append(f"joern co-callee {len(l0)}")
    else:
        layer_report.append("joern co-callee skipped (no server)")

    # L1: r2 binary co-callee (exclusive)
    if binary_edge_index is not None:
        l1 = _binary_co_callee_groups(binary_edge_index, _remaining())
        _claim(l1)
        groups.extend(l1)
        layer_report.append(f"binary co-callee {len(l1)}")
    else:
        layer_report.append("binary co-callee skipped (no edge index)")

    # L2: Dispatch-site (exclusive)
    if dispatch_tables:
        l2 = _dispatch_site_groups(dispatch_tables, _remaining())
        _claim(l2)
        groups.extend(l2)
        layer_report.append(f"dispatch-site {len(l2)}")
    else:
        layer_report.append("dispatch-site skipped (no tables)")

    # L3: Domain model (exclusive)
    if domain_model:
        l3 = _domain_model_groups(domain_model, _remaining())
        _claim(l3)
        groups.extend(l3)
        layer_report.append(f"domain-model {len(l3)}")
    else:
        layer_report.append("domain-model skipped (no model)")

    # L4–L6: independent (no claim removal between them)
    if type_ref_index:
        l4 = _type_cohort_groups(type_ref_index, functions)
        groups.extend(l4)
        layer_report.append(f"type-cohort {len(l4)}")
    else:
        layer_report.append("type-cohort skipped (no index)")
    l5 = _verb_prefix_groups(functions, checklist=checklist)
    groups.extend(l5)
    layer_report.append(f"verb-prefix {len(l5)}")
    l6 = _paired_operation_groups(functions)
    groups.extend(l6)
    layer_report.append(f"paired-op {len(l6)}")

    logger.info(
        "peer group resolver: %d groups from %d functions, %d claimed "
        "by exclusive layers — %s",
        len(groups), len(functions), len(claimed),
        "; ".join(layer_report),
    )
    return groups


# ── Input producers (orchestrator prep phase) ────────────────────────
#
# The resolver takes its optional layer inputs pre-built.  The
# producers below build them from the data the audit prep phase
# already has — the enriched inventory.  Each returns ``None`` when
# its input is absent, and the resolver then behaves exactly as if
# the layer did not exist (equivalence pin).


def binary_edge_index_from_inventory(
    inventory: dict[str, Any] | None,
    *,
    no_binary_oracle: bool = False,
) -> Any | None:
    """L1 producer: cached r2 call edges for the run's declared binaries.

    Cache-only — never invokes r2 (audit prep must stay fast).  Consumes
    the per-build-id edge cache persisted by ``/agentic`` / ``/codeql``
    ``--binary-edges`` runs (Inc 2b) or a binary graph store left by
    ``/understand --map``.

    Chokepoint safeguards (all inherited or enforced here):

    * **Provenance** — only binaries recorded in
      ``inventory['binary_oracle']['binaries']`` are considered.  That
      list is produced upstream by ``resolve_binary_paths`` (git-
      untracked filter, operator-explicit ``--binary`` bypass) plus the
      source-coverage floor, so a planted or repo-committed binary
      never reaches this producer.
    * **Tier gating** — binaries that fell back to symbol-only or
      unknown tier are skipped: name-keyed joins from a stripped
      binary are not trustworthy enough for a layer that claims
      functions exclusively.
    * **Operator opt-out** — ``no_binary_oracle=True`` returns ``None``
      (mirrors ``--no-binary-oracle``).

    Returns a merged ``BinaryEdgeIndex`` across all eligible binaries,
    or ``None`` when nothing is available — the L1 layer then stays
    empty and resolver behaviour is unchanged.
    """
    if no_binary_oracle or not isinstance(inventory, dict):
        return None
    bo = inventory.get("binary_oracle")
    if not isinstance(bo, dict):
        return None
    binaries = bo.get("binaries")
    if not isinstance(binaries, list) or not binaries:
        return None

    try:
        from core.analysis.binary_oracle_edges import (
            BinaryEdgeIndex,
            load_cached_edge_index,
        )
    except ImportError:
        return None

    merged: Any = None
    n_loaded = 0
    for entry in binaries:
        if not isinstance(entry, dict):
            continue
        tier = entry.get("tier")
        path = entry.get("path")
        if not isinstance(path, str) or not path:
            continue
        if tier != "full":
            logger.debug(
                "peer groups L1: skipping %s (tier=%s, need full-DWARF)",
                path, tier,
            )
            continue
        idx = load_cached_edge_index(Path(path))
        if idx is None or not idx.edges:
            continue
        if merged is None:
            merged = BinaryEdgeIndex(binary_path=path)
        merged.edges.extend(idx.edges)
        merged.callees.update(idx.callees)
        n_loaded += 1

    if merged is None:
        return None
    logger.info(
        "peer groups L1: %d cached binary edges from %d binar%s",
        len(merged.edges), n_loaded, "y" if n_loaded == 1 else "ies",
    )
    return merged


# Types too ubiquitous to define a peer cohort.  Merged across
# languages — a lowercase match in ANY language's primitive set
# disqualifies the token (cross-language collisions like ``string``
# are never distinctive anyway).
_NON_DISTINCTIVE_TYPES = frozenset({
    # C / C++
    "void", "int", "char", "long", "short", "float", "double", "bool",
    "unsigned", "signed", "const", "volatile", "struct", "enum",
    "union", "auto", "register", "static", "extern", "inline",
    "size_t", "ssize_t", "wchar_t", "ptrdiff_t", "intptr_t",
    "uintptr_t", "int8_t", "int16_t", "int32_t", "int64_t", "uint8_t",
    "uint16_t", "uint32_t", "uint64_t", "uint", "uchar", "ulong",
    "ushort", "byte", "off_t", "time_t", "pid_t", "uid_t", "gid_t",
    "mode_t", "dev_t", "ino_t", "socklen_t", "va_list", "file",
    "std", "string", "vector", "map", "set", "pair", "shared_ptr",
    "unique_ptr", "weak_ptr", "optional", "variant", "function",
    "string_view", "array", "deque", "list", "tuple", "nullptr_t",
    # Python
    "str", "bytes", "bytearray", "dict", "frozenset", "none",
    "nonetype", "any", "object", "callable", "iterable", "iterator",
    "sequence", "mapping", "generator", "coroutine", "awaitable",
    "union", "type", "self", "cls", "path", "pathlike",
    # Java / C#
    "integer", "boolean", "character", "number", "arraylist",
    "hashmap", "hashset", "linkedlist", "exception",
    "runnable", "thread", "task", "action", "func", "ienumerable",
    "ilist", "idictionary", "stringbuilder", "charsequence",
    # JS / TS
    "promise", "record", "partial", "readonly", "undefined", "null",
    "symbol", "bigint", "date", "regexp", "error",
    # Go
    "rune", "uintptr", "interface", "chan", "context", "error",
    # Rust
    "i8", "i16", "i32", "i64", "i128", "isize", "u8", "u16", "u32",
    "u64", "u128", "usize", "f32", "f64", "vec", "box", "rc", "arc",
    "option", "result", "cow", "cell", "refcell", "mutex", "rwlock",
    "btreemap", "btreeset", "osstring", "pathbuf",
})

_TYPE_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

# C signature fallback: languages whose extractor records no parameter
# metadata but does record the raw signature — mine ``foo_t`` /
# ``struct foo`` tokens out of it (same trick the study-prep type
# index uses).
_SIG_FALLBACK_LANGUAGES = frozenset({"c", "cpp"})
_SIG_TYPE_RE = re.compile(r"\b(?:struct\s+(\w+)|(\w+_t))\b")


def _distinctive_type_tokens(type_str: str) -> set[str]:
    """Extract distinctive type-name tokens from one type annotation.

    Tokenises so decorated forms (``const request_ctx_t *``,
    ``Optional[AuthContext]``, ``std::vector<Packet>``) all yield their
    distinctive core; primitives / ubiquitous stdlib names are dropped.
    """
    tokens: set[str] = set()
    for tok in _TYPE_TOKEN_RE.findall(type_str):
        if len(tok) < 3:
            continue
        if tok.lower() in _NON_DISTINCTIVE_TYPES:
            continue
        tokens.add(tok)
    return tokens


def _param_type_strs(meta: dict[str, Any]) -> list[str]:
    """Parameter type annotations from inventory metadata.

    Handles both serialised shapes: ``[[name, type], ...]`` (checklist
    JSON round-trip) and ``[{"name": ..., "type": ...}, ...]``.
    """
    out: list[str] = []
    for p in meta.get("parameters") or []:
        t = None
        if isinstance(p, dict):
            t = p.get("type")
        elif isinstance(p, (list, tuple)) and len(p) > 1:
            t = p[1]
        if isinstance(t, str) and t:
            out.append(t)
    return out


def type_ref_index_from_inventory(
    inventory: dict[str, Any] | None,
    *,
    max_cohort_size: int = 24,
    max_types: int = 200,
) -> dict[str, list[tuple[str, str]]] | None:
    """L4 producer: type-cohort index from inventory type metadata.

    Walks the checklist inventory and maps each distinctive type name
    to the functions whose parameters or return type mention it — the
    ``type_ref_index`` shape ``_type_cohort_groups`` consumes
    (``{type_name: [(function, usage_class), ...]}``, usage class is
    ``"param"`` / ``"return"`` / ``"signature"``).

    Language-aware where the inventory supports it: typed extractors
    (Python AST, Java, tree-sitter C/C++) feed ``metadata.parameters``
    / ``metadata.return_type``; for C/C++ items without parameter
    metadata the raw signature is mined for ``foo_t`` / ``struct foo``
    tokens.  Bounded: cohorts larger than *max_cohort_size* are
    dropped (a type half the codebase touches is not distinctive), and
    at most *max_types* cohorts are returned (smallest — most
    distinctive — first).

    Returns ``None`` when the inventory records no usable type
    information, so the L4 layer stays empty and resolver behaviour is
    unchanged.
    """
    if not isinstance(inventory, dict):
        return None

    index: dict[str, dict[str, str]] = {}

    def _record(type_str: str, fn_name: str, usage: str) -> None:
        for tok in _distinctive_type_tokens(type_str):
            index.setdefault(tok, {}).setdefault(fn_name, usage)

    for f in inventory.get("files") or []:
        if not isinstance(f, dict):
            continue
        lang = (f.get("language") or "").lower()
        for item in f.get("items") or []:
            if not isinstance(item, dict):
                continue
            if item.get("kind", "function") != "function":
                continue
            name = item.get("name")
            if not isinstance(name, str) or not name:
                continue
            meta = item.get("metadata")
            meta = meta if isinstance(meta, dict) else {}
            param_types = _param_type_strs(meta)
            for t in param_types:
                _record(t, name, "param")
            ret = meta.get("return_type")
            if isinstance(ret, str) and ret:
                _record(ret, name, "return")
            if not param_types and lang in _SIG_FALLBACK_LANGUAGES:
                sig = item.get("signature")
                if isinstance(sig, str) and sig:
                    for m in _SIG_TYPE_RE.finditer(sig):
                        _record(m.group(1) or m.group(2), name,
                                "signature")

    cohorts = {
        t: members for t, members in index.items()
        if 2 <= len(members) <= max_cohort_size
    }
    if not cohorts:
        return None

    result: dict[str, list[tuple[str, str]]] = {}
    for t in sorted(cohorts, key=lambda k: (len(cohorts[k]), k))[:max_types]:
        result[t] = sorted(cohorts[t].items())
    logger.info(
        "peer groups L4: type-cohort index with %d distinctive types",
        len(result),
    )
    return result


# ── L0: Joern co-callee groups ────────────────────────────────────────


_JOERN_PEERS_RE = re.compile(r"^JOERN_PEERS:([^|]+)\|([^|]*)\|(.+)$")


def _name_index(functions: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Bare-name → record index for the grouping layers.

    Function identity in the resolver is the (file, name) pair — that
    is what the claim set tracks — but group membership arrives as
    bare names (Joern callees, binary edges, dispatch handler values,
    domain-model members, type refs, operation stems). When several
    still-unclaimed records share a name, the bare name is ambiguous:
    a last-wins dict would bind the sibling (and the subsequent
    claim) to an arbitrary record and permanently shadow the others.
    Ambiguous names are excluded from grouping instead.
    """
    by_name: dict[str, dict[str, Any]] = {}
    ambiguous: set[str] = set()
    for f in functions:
        name = f.get("name", "")
        if not name:
            continue
        if name in by_name:
            ambiguous.add(name)
        else:
            by_name[name] = f
    for name in ambiguous:
        del by_name[name]
    if ambiguous:
        logger.debug(
            "peer groups: %d name(s) ambiguous across files, excluded "
            "from name-keyed grouping: %s",
            len(ambiguous), sorted(ambiguous)[:8],
        )
    return by_name


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
    func_by_name = _name_index(functions)
    func_names = set(func_by_name)

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

    func_by_name = _name_index(functions)
    func_names = set(func_by_name)

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

    func_by_name = _name_index(functions)
    func_names = set(func_by_name)

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

    func_by_name = _name_index(functions)
    func_names = set(func_by_name)

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

    func_by_name = _name_index(functions)
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
    return not (ret_a and ret_b and ret_a != ret_b)


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
    """L5: two per-directory passes folded into one result list.

    First a decorator pass: functions sharing a decorator (checklist
    ``metadata.attributes``) form a group per (directory, decorator),
    with no verb match or signature filtering. Then a verb-prefix
    pass with signature-shape filtering over the functions the
    decorator pass did not claim.
    """
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
                shared_context=f"Shared verb prefix: {verb}_*",
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
    result.extend(c for c in candidates[1:] if _shared_decorator(anchor, c) or _signatures_compatible(anchor, c))

    return result


# ── L6: Paired operations ────────────────────────────────────────────

_PAIR_PATTERNS: list[tuple[re.Pattern, re.Pattern]] = [
    (re.compile(r"^(encode)_(.+)", re.IGNORECASE), re.compile(r"^(decode)_(.+)", re.IGNORECASE)),
    (re.compile(r"^(encrypt)_(.+)", re.IGNORECASE), re.compile(r"^(decrypt)_(.+)", re.IGNORECASE)),
    (re.compile(r"^(serialize)_(.+)", re.IGNORECASE), re.compile(r"^(deserialize)_(.+)", re.IGNORECASE)),
    (re.compile(r"^(marshal)_(.+)", re.IGNORECASE), re.compile(r"^(unmarshal)_(.+)", re.IGNORECASE)),
    (re.compile(r"^(pack)_(.+)", re.IGNORECASE), re.compile(r"^(unpack)_(.+)", re.IGNORECASE)),
    (re.compile(r"^(compress)_(.+)", re.IGNORECASE), re.compile(r"^(decompress)_(.+)", re.IGNORECASE)),
    (re.compile(r"^(sanitize_input)_?(.+)?", re.IGNORECASE), re.compile(r"^(sanitize_output)_?(.+)?", re.IGNORECASE)),
    (re.compile(r"^(lock)_(.+)", re.IGNORECASE), re.compile(r"^(unlock)_(.+)", re.IGNORECASE)),
    (re.compile(r"^(alloc)_(.+)", re.IGNORECASE), re.compile(r"^(free)_(.+)", re.IGNORECASE)),
    (re.compile(r"^(get)_(.+)", re.IGNORECASE), re.compile(r"^(put)_(.+)", re.IGNORECASE)),
    (re.compile(r"^(get)_(.+)", re.IGNORECASE), re.compile(r"^(set)_(.+)", re.IGNORECASE)),
    (re.compile(r"^(acquire)_(.+)", re.IGNORECASE), re.compile(r"^(release)_(.+)", re.IGNORECASE)),
    (re.compile(r"^(ref)_(.+)", re.IGNORECASE), re.compile(r"^(unref)_(.+)", re.IGNORECASE)),
    (re.compile(r"^(inc)_(.+)", re.IGNORECASE), re.compile(r"^(dec)_(.+)", re.IGNORECASE)),
    (re.compile(r"^(register)_(.+)", re.IGNORECASE), re.compile(r"^(unregister)_(.+)", re.IGNORECASE)),
    (re.compile(r"^(subscribe)_(.+)", re.IGNORECASE), re.compile(r"^(unsubscribe)_(.+)", re.IGNORECASE)),
    (re.compile(r"^(connect)_(.+)", re.IGNORECASE), re.compile(r"^(disconnect)_(.+)", re.IGNORECASE)),
    (re.compile(r"^(attach)_(.+)", re.IGNORECASE), re.compile(r"^(detach)_(.+)", re.IGNORECASE)),
    (re.compile(r"^(enable)_(.+)", re.IGNORECASE), re.compile(r"^(disable)_(.+)", re.IGNORECASE)),
    (re.compile(r"^(bind)_(.+)", re.IGNORECASE), re.compile(r"^(unbind)_(.+)", re.IGNORECASE)),
    (re.compile(r"^(open)_(.+)", re.IGNORECASE), re.compile(r"^(close)_(.+)", re.IGNORECASE)),
    (re.compile(r"^(start)_(.+)", re.IGNORECASE), re.compile(r"^(stop)_(.+)", re.IGNORECASE)),
    (re.compile(r"^(init)_(.+)", re.IGNORECASE), re.compile(r"^(cleanup)_(.+)", re.IGNORECASE)),
    (re.compile(r"^(setup)_(.+)", re.IGNORECASE), re.compile(r"^(teardown)_(.+)", re.IGNORECASE)),
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

    func_by_name = _name_index(functions)
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

    # Prefix-swap pairs. Iterate sorted so stem-collision winners and
    # first-claimed pairs are deterministic across runs (set iteration
    # order varies with hash randomization); mirrors the suffix loop.
    for fwd_pat, rev_pat in _PAIR_PATTERNS:
        forward: dict[str, str] = {}
        reverse: dict[str, str] = {}
        for name in sorted(names):
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
