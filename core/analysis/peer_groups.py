"""Layered peer group resolver for /audit sibling analysis.

Replaces the global verb-prefix grouping in ``sibling_analysis.py``
with a layered resolver that uses progressively weaker signals.
Higher-confidence layers (Joern call graph, binary edges, anchor
families, dispatch tables) claim functions first; the exclusive
layers group only what remains unclaimed, while the independent
layers run over the full input (see the hierarchy below).

Layer hierarchy:

  L10 Route family groups        — framework route registrations from
                                    the route-models artifact
                                    (mechanical, definitive)
  L7  Interface-slot groups      — ops-struct slot / subclass-override
                                    census (mechanical, definitive)
  L0  Joern co-callee groups     — CPG call graph (definitive)
  L1  r2 binary co-callee groups — binary call edges (definitive)
      Binary anchor families     — hunt string-xref co-occurrence
                                    (definitive, join-only)
      Binary shared-callee sigs  — >=K distinctive callees shared
                                    (definitive)
  L2  Dispatch-site groups       — tree-sitter extraction (definitive)
  L3  Domain model groups        — study-run concepts (high)

  L4  Type cohort groups         — shared type parameter (medium-high)
  L5  Decorator / verb-prefix    — shared-decorator groups first, then
                                    verb-prefix + sig shape on what
                                    remains, per-directory (medium)
  L6  Paired operations          — stem + verb match, global (medium)
      Binary decomp similarity   — normalized-hash / shingle-Jaccard
                                    via the ghidra similarity seam
                                    (decompiler-inferred, lower
                                    confidence, tier-labelled)

Exclusive layers claim (a function in a higher layer is removed from
lower exclusive layers' input); the independent layers never claim.

L10 placement: route families join the exclusive chain FIRST. Their
membership is mechanically certain — the route-models extractor
recognises registrations by import-joined framework structure, the
same grade as dispatch-table extraction — and handlers of the same
HTTP surface are the strongest peer notion available for them: a
mechanically-certain interface-shaped family must not lose members
to a weaker co-callee grouping (functions that merely share a
caller), so it claims before L0/L1.
"""

from __future__ import annotations

import logging
import os
import random
import re
from collections import defaultdict
from pathlib import Path, PurePosixPath
from typing import Any

from core.analysis.interface_slots import (
    # L7 group-type string is owned by the census module (the
    # producer and the layer must agree by construction); imported
    # here so consumers keep one surface for group-type names.
    GROUP_TYPE_INTERFACE_SLOT,
)
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
_ANCHOR_FAMILY = "binary_anchor_family"
_CALLEE_SIGNATURE = "shared_callee_signature"
_DECOMP_SIMILARITY = "decomp_similarity"

# Layer / group-type RESERVATION: claimed ids are L10 ("route_family"),
# L7 ("interface_slot"), L8 ("enum_switch"), L9 ("clone_family");
# binary-substrate layers are added independently — a new layer must
# pick an unclaimed number and group-type string and note it here.
# Public: the interface dimension admits "route_family" and
# "interface_slot" by string
# (consistency_dimensions._INTERFACE_GROUP_TYPES) and tests pin the
# strings against each other.
GROUP_TYPE_ROUTE_FAMILY = "route_family"

# Property key the route layer attaches to every family member:
# True when the member's recorded middleware chain carries an
# auth-matching decorator, explicit False when it does not (members
# whose chains were truncated never reach a family — see the layer's
# join contract). Two-valued and voted as its OWN property by the
# interface comparator on route-family groups: a DECORATION fact,
# never folded into ``auth_check`` (body evidence keeps that vote to
# itself — decorator presence must never be able to mask a
# body-evidence lead) and never a protection claim (chain entries do
# not prove wrapping — the route-models position caveat; an entry
# above the registration decorator may not wrap the registered
# callable. Position recording is a route-models follow-up that will
# tighten this fact). The peer-census consumer that votes raw group
# properties (``negative_space``) reads ``convention_*`` keys only,
# so the property is inert outside the interface dimension.
ROUTE_AUTH_PROPERTY = "route_auth_decorator_present"

# ── Binary-layer bounds ───────────────────────────────────────────────
#
# Every binary layer is fed attacker-shaped data (names, call edges,
# decompilation recovered from a hostile binary), so each is bounded
# in group count and group size, deterministic under shuffled input,
# and surfaces nothing as a verdict — groups are review structure.

#: Groups emitted per binary layer. Both directions: more groups let a
#: decoy-flooded binary (thousands of planted look-alike clusters)
#: drown the reviewer and multiply the downstream vector-extraction
#: work; fewer hides real structure in large dispatch-heavy targets.
#: 32 mirrors the hunt's family cap ceiling class.
MAX_BINARY_PEER_GROUPS = 32

#: Members per binary-layer group. Both directions: larger groups turn
#: one hub into a whole-binary blob (and the N-vs-K comparison
#: downstream degrades — one outlier in 200 members is noise);
#: smaller splits real wide handler families. 24 mirrors the L4
#: type-cohort ceiling (a cohort half the binary touches is not
#: distinctive).
MAX_BINARY_PEER_GROUP_SIZE = 24

#: K — distinct DISTINCTIVE callees two functions must share to join
#: one shared-callee-signature group. Both directions: K=1 merges
#: everything touching one common helper (the same one-string glue
#: failure the hunt's co-occurrence threshold refuses); K=3+ splits
#: real sibling handlers that share only a validator and an emitter.
#: K=2 is the smallest value that requires corroboration — the same
#: rationale as the hunt's MIN_SHARED_ANCHOR_STRINGS.
MIN_SHARED_DISTINCTIVE_CALLEES = 2

#: Distinctiveness ceiling: a callee with more callers than this is a
#: hub (libc wrapper, logging shim, allocator) and joins nothing —
#: shared vocabulary, not family evidence. Both directions: higher
#: lets memcpy-class hubs glue the whole binary into one group; lower
#: refuses genuinely shared family helpers in wide dispatch families.
#: 16 keeps signatures to helpers a bounded slice of the binary uses.
CALLEE_HUB_MAX_CALLERS = 16

#: Shingle-Jaccard threshold for the decomp-similarity join — the
#: matcher's tier-5 absolute floor (packages.ghidra.match._SIM_ABS),
#: kept equal so "similar" means the same thing in both consumers.
DECOMP_SIMILARITY_THRESHOLD = 0.7

#: Pairwise-comparison budget for the decomp-similarity join. Both
#: directions: a larger budget lets a decompilation-rich hostile
#: binary turn peer formation into a CPU sink (the work is quadratic
#: in candidates); smaller degrades the layer to exact-hash groups on
#: large targets — which is the documented degradation, surfaced in
#: the layer report, never silent.
MAX_DECOMP_PAIRWISE = 10_000

# ── Route-family bounds ───────────────────────────────────────────────

#: Route families emitted per run. Both directions: route patterns
#: are attacker-authored text, so a generated mega-API can mint one
#: path prefix per route and flood the exclusive chain (and the
#: downstream interface comparator) with single-purpose families;
#: fewer hides real surface breadth on large services. 64 — twice
#: the binary layer cap — because source route surfaces are
#: legitimately wider than binary review clusters.
MAX_ROUTE_FAMILIES = 64

#: Members per route family. Both directions: larger turns one
#: prefix into a whole-app blob where a single deviant among
#: hundreds of members is noise for the N-vs-K comparison; smaller
#: splits genuinely wide handler groups. 32 mirrors the binary
#: layers' group-size ceiling class.
MAX_ROUTE_FAMILY_MEMBERS = 32

#: Comparator-capability floor: a family CLAIMS (and emits) only
#: with at least this many joined members. The layer is exclusive,
#: so a family too small for the interface comparator to vote on
#: (its ≥3-member floor) would remove its handlers from the later
#: exclusive layers while producing nothing itself — pure lead
#: suppression, and a hostile artifact could mint 2-member families
#: on purpose to strip handlers out of dispatch/type groups. Literal
#: by this module's convention; pinned against
#: ``consistency_dimensions.INTERFACE_MIN_GROUP`` by test.
MIN_ROUTE_FAMILY_MEMBERS = 3

# ── Interface-slot bounds (L7) ────────────────────────────────────────

#: Same claim floor, same argument, for the L7 exclusive layer: an
#: interface-slot family the parity comparator cannot vote on must
#: not strip its implementations out of the later exclusive layers.
#: Pinned against ``consistency_dimensions.INTERFACE_MIN_GROUP`` by
#: test, like the route floor above.
MIN_INTERFACE_SLOT_MEMBERS = 3

#: Members per L7 group. Both directions: larger turns one hot slot
#: (a kernel-wide ops field) into a whole-tree blob where one deviant
#: among hundreds is noise for the majority vote; smaller splits
#: genuinely wide slot families. 32 — the family-size ceiling class
#: shared with the route layer.
MAX_INTERFACE_SLOT_MEMBERS = 32


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
    anchor_families: list[dict[str, Any]] | None = None,
    binary_callees: dict[str, set[str]] | None = None,
    decomp_texts: dict[str, str] | None = None,
    route_models: Any | None = None,
    interface_slots: list[Any] | None = None,
    notes: list[str] | None = None,
) -> list[SiblingGroup]:
    """Build peer groups from all available signals.

    ``notes`` is a caller-owned collector (the hunt's rejection-notes
    pattern): operator-facing degradation facts — a layer silently
    doing LESS than asked, like the decomp-similarity pairwise budget
    reducing to hash-only groups — are appended so interactive
    consumers can surface them in-band, not just in debug logs.

    Parameters mirror the data available in the orchestrator prep phase.
    Everything is optional — missing inputs simply skip that layer.

    The binary-native inputs follow the same contract:

    * ``anchor_families`` — hunt anchor-family payload dicts
      (``binary-hunt-*.json`` ``families`` entries: members with
      escaped names and optional fids). Exclusive layer — string
      co-occurrence backed by xrefs is family evidence of the same
      grade as call-graph position.
    * ``binary_callees`` — caller name → callee-name set from a
      persisted call substrate (re-database xrefs, map call subgraph,
      or the binary-oracle edge cache — the caller picks; this
      resolver never touches r2). Exclusive layer: functions sharing
      ≥ :data:`MIN_SHARED_DISTINCTIVE_CALLEES` distinctive callees.
    * ``decomp_texts`` — function name → raw decompiled text from a
      re-database that carries decompilation. Independent layer,
      tier-labelled decompiler-inferred (pseudo-code is approximate
      — lower confidence than the xref-backed layers above), via the
      similarity seam (``packages.ghidra.similarity``).
    * ``route_models`` — a ``core.analysis.route_models.RouteModels``
      (the :func:`route_models_for_prep` producer builds/loads one).
      Exclusive L10 layer, claiming first — see the module docstring
      for the placement argument and :func:`_route_family_groups`
      for the join contract (CBV exclusion, truncated-chain
      exclusion, claim floor, two-valued auth-decoration property).
    * ``interface_slots`` — ``core.analysis.interface_slots.
      SlotFamily`` records (the :func:`core.analysis.interface_slots.
      interface_slot_families` producer builds them). Exclusive L7
      layer, mechanically-certain membership, placed with the
      claim-first layers ahead of the co-callee groupings — see
      :func:`_interface_slot_groups` for the join contract (name
      resolution through the ambiguity-excluding index, claim floor,
      minority-unchoosable member cap).

    When ``checklist`` is supplied, every layer sees the functions
    enriched with the checklist items' ``metadata`` (parameters,
    return_type, attributes) — the orchestrator's gap dicts carry only
    name/file/line, so without this join the signature-shape filtering
    in L0/L1/L5 compares empty parameter lists (always compatible) and
    the L5 decorator pass can never form a group.
    """
    if checklist:
        meta_index = _checklist_metadata_index(checklist)
        if meta_index:
            functions = [_enrich_from_index(f, meta_index)
                         for f in functions]
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

    # L10: route families (exclusive, first — mechanically-certain
    # interface-shaped families must not lose members to the weaker
    # co-callee groupings below; see the module docstring).
    if route_models is not None:
        lr, lr_note = _route_family_groups(route_models, _remaining())
        _claim(lr)
        groups.extend(lr)
        layer_report.append(
            f"route-family {len(lr)}"
            + (f" ({lr_note})" if lr_note else ""))
        if lr_note and notes is not None:
            notes.append(f"route-family: {lr_note}")
    else:
        layer_report.append("route-family skipped (no route models)")

    # L7: interface slots (exclusive, with the claim-first layers —
    # mechanically-certain interface families must not lose members
    # to the weaker co-callee groupings below).
    if interface_slots:
        l7 = _interface_slot_groups(interface_slots, _remaining())
        _claim(l7)
        groups.extend(l7)
        caps_note = any(
            getattr(f, "caps_hit", False) for f in interface_slots
        )
        layer_report.append(
            f"interface-slot {len(l7)}"
            + (" (census capped)" if caps_note else ""))
        if caps_note and notes is not None:
            notes.append(
                "interface-slot: census family cap hit — families "
                "beyond the cap were dropped")
    else:
        layer_report.append("interface-slot skipped (no census)")

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

    # Binary anchor families (exclusive): xref-backed string
    # co-occurrence structure from /binary hunt artifacts.
    if anchor_families:
        la = _anchor_family_groups(anchor_families, _remaining())
        _claim(la)
        groups.extend(la)
        layer_report.append(f"binary anchor-family {len(la)}")
    else:
        layer_report.append("binary anchor-family skipped (no families)")

    # Binary shared-callee signatures (exclusive): functions calling
    # the same distinctive helpers.
    if binary_callees:
        lc = _shared_callee_signature_groups(binary_callees, _remaining())
        _claim(lc)
        groups.extend(lc)
        layer_report.append(f"binary shared-callee {len(lc)}")
    else:
        layer_report.append("binary shared-callee skipped (no callees)")

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
    # Binary decomp-similarity (independent): decompiler-inferred —
    # pseudo-code is approximate, so this layer never claims
    # exclusively and its groups carry the lower-confidence label.
    if decomp_texts:
        ld, ld_note = _decomp_similarity_groups(decomp_texts, functions)
        groups.extend(ld)
        layer_report.append(
            f"binary decomp-similarity {len(ld)}"
            + (f" ({ld_note})" if ld_note else ""))
        if ld_note and notes is not None:
            notes.append(f"binary decomp-similarity: {ld_note}")
    else:
        layer_report.append(
            "binary decomp-similarity skipped (no decompilation)")

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


def route_models_for_prep(
    *inventories: Any,
    out_dir: Path | None = None,
) -> Any | None:
    """L10 producer: route models for the run's target.

    A co-located ``route-models.json`` in *out_dir* wins (a prior
    run on the same output directory already extracted); otherwise
    the models are built from the first inventory-shaped dict whose
    file records carry ``call_graph`` registration facts (the
    checklist/inventory the audit prep already holds — building is a
    linear pass, no parsing). Returns ``None`` when neither source
    yields any route, so the L10 layer stays empty and resolver
    behaviour is unchanged (equivalence pin).
    """
    try:
        from core.analysis.route_models import (
            ROUTE_MODELS_FILENAME,
            build_route_models,
            load_route_models,
        )
    except ImportError:  # pragma: no cover - trimmed deployment
        return None

    if out_dir is not None:
        artifact = Path(out_dir) / ROUTE_MODELS_FILENAME
        if artifact.is_file():
            try:
                models = load_route_models(artifact)
                if models.routes:
                    logger.info(
                        "peer groups L10: %d routes from %s",
                        len(models.routes), ROUTE_MODELS_FILENAME,
                    )
                    return models
            except Exception:
                logger.debug(
                    "peer groups L10: route-models artifact load "
                    "failed, falling back to inventory build",
                    exc_info=True,
                )

    def _python_facts(f: Any) -> bool:
        # Only Python records populate the registration facts the
        # route builder reads; other languages carry call_graph
        # blocks too, and gating on the pair avoids building a
        # package callgraph per prep on targets that can never
        # yield a route.
        return (
            isinstance(f, dict)
            and isinstance(f.get("call_graph"), dict)
            and (f.get("language") == "python"
                 or str(f.get("path") or "").endswith((".py", ".pyi")))
        )

    for inv in inventories:
        if not isinstance(inv, dict):
            continue
        files = inv.get("files")
        if not isinstance(files, list):
            continue
        if not any(_python_facts(f) for f in files):
            continue
        try:
            models = build_route_models(inv)
        except Exception:
            logger.debug(
                "peer groups L10: route-model build failed",
                exc_info=True,
            )
            continue
        if models.routes:
            logger.info(
                "peer groups L10: %d routes built from inventory "
                "registration facts", len(models.routes),
            )
            return models
    return None


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


# ── L10: Route family groups ─────────────────────────────────────────


# Group-key segment for patterns whose first path segment is itself a
# parameter (``/<int:id>/...`` / ``/{item}/...`` / a regex group) —
# they share no literal prefix, so they family together explicitly.
_ROUTE_DYNAMIC_SEGMENT = "<dynamic>"

# Display bound for one escaped route pattern quoted in a group's
# shared context (patterns are attacker-authored text; the record
# needs recognisability, not the full 1024-char cap).
_MAX_ROUTE_PATTERN_DISPLAY = 128


def _parse_handler_id(handler: str) -> tuple[str, str, int] | None:
    """Split a ``<file>::<name>@<line>`` handler id (both the
    package-callgraph node-id form and the fallback form use it).
    None for anything else — an unparsable id contributes no member,
    never a guess."""
    head, sep, tail = handler.rpartition("@")
    if not sep or not tail.isdigit():
        return None
    file_part, sep2, name = head.rpartition("::")
    if not sep2 or not name:
        return None
    return file_part, name, int(tail)


def _route_prefix(pattern: str) -> str:
    """First path segment of a route pattern — the family key.
    Regex anchors and leading slashes are stripped; a parameterised
    first segment maps to :data:`_ROUTE_DYNAMIC_SEGMENT`."""
    seg = pattern.lstrip("^/").split("/", 1)[0]
    if any(c in seg for c in "<{("):
        return _ROUTE_DYNAMIC_SEGMENT
    return seg


def _elide(s: str, limit: int) -> str:
    """Display-bound with an explicit elision marker — a silently
    cut excerpt misreads as the whole value."""
    return s if len(s) <= limit else s[:limit] + "…[truncated]"


def _capped_route_members(
    member_keys: list[tuple[str, str]],
    members: dict[tuple[str, str], dict[str, Any]],
    cap: int,
) -> tuple[list[tuple[str, str]], bool]:
    """Survivor selection under the member cap.

    Property-MINORITY members are retained first (their votes are
    the ones a truncation could erase — member names are
    attacker-chosen text, so deterministic first-N would let a
    hostile repo name the deviant to sort past the cut), then the
    remaining slots fill from the majority by seeded-random sample
    (majority members are interchangeable for the vote; random fill
    keeps the surviving exhibit set unchoosable too). An exact tie
    has no majority — nothing can vote — so the whole pool samples
    randomly. Returns ``(kept_name_sorted, truncated)``.
    """
    if len(member_keys) <= cap:
        return member_keys, False
    true_keys = [k for k in member_keys if members[k]["auth"]]
    false_keys = [k for k in member_keys if not members[k]["auth"]]
    if len(true_keys) == len(false_keys):
        first: list[tuple[str, str]] = []
        rest = member_keys
    elif len(true_keys) < len(false_keys):
        first, rest = true_keys, false_keys
    else:
        first, rest = false_keys, true_keys
    kept = first[:cap]
    remaining = cap - len(kept)
    if remaining > 0:
        rnd = random.Random(os.urandom(16))
        kept.extend(rnd.sample(rest, remaining))
    return sorted(kept), True


def _route_family_groups(
    route_models: Any,
    functions: list[dict[str, Any]],
) -> tuple[list[SiblingGroup], str]:
    """L10: handlers of the same route surface, from the route-models
    artifact.

    Families group by (framework, registration style, first path
    segment) — mechanical facts of the registration, no naming
    heuristics. Returns ``(groups, note)``; the note reports the
    family cap evicting candidate families (degradation is said,
    never silent — the decomp layer's pattern).

    Join contract (the route-models consumer caveats, enforced here
    so no downstream consumer has to re-learn them):

    * **CBV exclusion** — ``handler_kind == "class"`` records are
      skipped: their middleware chains are unwalked method-decorator
      stacks, so an empty chain is not an unprotected peer. Defense
      in depth: a class name also never joins a function record.
    * **Truncated chains poison the member** — a route with
      ``middleware_truncated`` removes its handler from the family
      (noted in the group context): a cut chain must never be read
      as "no auth decorator", so the member cannot vote either way.
    * **Auth decoration is a two-valued fact** — every member gets
      :data:`ROUTE_AUTH_PROPERTY` (True when an auth-matching
      decorator is recorded, explicit False when not), voted as its
      own property by the interface comparator. It is a DECORATION
      fact, never a protection claim: chain entries do not prove
      wrapping (an entry above the registration decorator may not
      protect the registered callable), so identical chains are
      treated identically regardless of source position, and the
      fact is never folded into the body-evidence ``auth_check``
      vote.
    * **Claim floor** — families below
      :data:`MIN_ROUTE_FAMILY_MEMBERS` joined members neither claim
      nor emit: an exclusive claim by a family the comparator
      cannot vote on would only strip its handlers out of the later
      exclusive layers (see the constant's comment).
    * ``http_methods`` is never consulted: empty means "not
      constrained at registration" (Django function views), and
      methods are prioritization hints, not grouping facts.

    Handler-id joins are (file, name) exact first; the bare-name
    rescue (path-root normalization differences) additionally
    requires the candidate's file BASENAME to match the handler
    id's — a same-named function in an unrelated file must not be
    pulled into (and claimed out of) its real groups.

    Pattern text, framework and style strings ride in from the
    artifact (target-derived) — everything quoted in ids,
    descriptions or contexts is escaped first, with an explicit
    elision marker when display-truncated.
    """
    if not functions:
        return [], ""
    try:
        routes = route_models.all_routes()
    except AttributeError:
        routes = getattr(route_models, "routes", ()) or ()
    if not routes:
        return [], ""
    from core.security.log_sanitisation import escape_nonprintable

    # The auth matcher for decorator names — the same in-tree
    # property regex the interface dimension applies to bodies
    # (imported, not twinned: "auth-shaped" must mean one thing in
    # both voters). No project vocabulary.
    from core.audit.sibling_analysis import _AUTH_CHECK_RE

    func_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for f in functions:
        key = (f.get("file", ""), f.get("name", ""))
        if key[1]:
            func_by_key.setdefault(key, f)
    func_by_name = _name_index(functions)

    families: dict[tuple[str, str, str], dict[str, Any]] = {}
    for r in routes:
        if getattr(r, "handler_kind", "") == "class":
            continue
        parsed = _parse_handler_id(str(getattr(r, "handler", "") or ""))
        if parsed is None:
            continue
        hfile, hname, _hline = parsed
        bare = hname.rsplit(".", 1)[-1]
        record = (
            func_by_key.get((hfile, hname))
            or func_by_key.get((hfile, bare))
        )
        if record is None:
            candidate = func_by_name.get(bare)
            # Bare-name rescue is for path-ROOT normalization
            # differences only, so the file basename must agree — a
            # same-named function in an unrelated file must not be
            # pulled into (and exclusively claimed out of) its real
            # groups.
            if candidate is not None and PurePosixPath(
                    str(candidate.get("file", ""))).name \
                    == PurePosixPath(hfile).name:
                record = candidate
        if record is None:
            continue
        member_key = (record.get("file", ""), record.get("name", ""))
        fam_key = (
            str(getattr(r, "framework", "") or ""),
            str(getattr(r, "style", "") or ""),
            _route_prefix(str(getattr(r, "route_pattern", "") or "")),
        )
        fam = families.setdefault(fam_key, {
            "members": {}, "excluded": set(), "patterns": [],
        })
        if len(fam["patterns"]) < 3:
            fam["patterns"].append(
                str(getattr(r, "route_pattern", "") or ""))
        if getattr(r, "middleware_truncated", False):
            fam["excluded"].add(member_key)
            continue
        entry = fam["members"].setdefault(
            member_key, {"record": record, "auth": False})
        if any(
            _AUTH_CHECK_RE.search(str(getattr(m, "name", "") or ""))
            for m in getattr(r, "middleware_chain", ()) or ()
        ):
            entry["auth"] = True

    groups: list[SiblingGroup] = []
    eligible = 0
    for fam_key in sorted(families):
        fam = families[fam_key]
        member_keys = sorted(
            k for k in fam["members"] if k not in fam["excluded"]
        )
        # Claim floor: below the comparator's group floor the family
        # can produce no vote, so an exclusive claim would only strip
        # its handlers out of the later layers (see the constant).
        if len(member_keys) < MIN_ROUTE_FAMILY_MEMBERS:
            continue
        eligible += 1
        if len(groups) >= MAX_ROUTE_FAMILIES:
            # Keep counting eligible families so the eviction is
            # reported in-band (caps never degrade partial-silent).
            continue
        kept, truncated = _capped_route_members(
            member_keys, fam["members"], MAX_ROUTE_FAMILY_MEMBERS,
        )
        framework, style, prefix = (
            escape_nonprintable(part) for part in fam_key
        )
        siblings: list[SiblingPath] = []
        for key in kept:
            entry = fam["members"][key]
            rec = entry["record"]
            siblings.append(SiblingPath(
                label=rec.get("name", ""),
                file=rec.get("file", ""),
                function=rec.get("name", ""),
                line=rec.get("line", 0),
                # Two-valued decoration fact — see ROUTE_AUTH_PROPERTY.
                properties={ROUTE_AUTH_PROPERTY: bool(entry["auth"])},
            ))
        context = "Registered routes: " + "; ".join(
            _elide(escape_nonprintable(p), _MAX_ROUTE_PATTERN_DISPLAY)
            for p in fam["patterns"]
        )
        n_excluded = len(fam["excluded"])
        if n_excluded:
            # In-band, like the binary layers' cap labels — a
            # silently shrunk family misreads as the whole family.
            context += (
                f" [{n_excluded} member(s) excluded: middleware "
                f"chain truncated, presence facts unknown]"
            )
        if truncated:
            context += (
                f" [group capped at {MAX_ROUTE_FAMILY_MEMBERS} of "
                f"{len(member_keys)} members, minority-preserving "
                f"selection]"
            )
        groups.append(SiblingGroup(
            group_id=f"route_family:{framework}:{style}:{prefix}",
            # Plain string by the module-header convention (SiblingType
            # is a str enum; consumers compare by value).
            sibling_type=GROUP_TYPE_ROUTE_FAMILY,  # type: ignore[arg-type]
            description=(
                f"{framework} {style} route handlers under "
                f"/{_elide(prefix, 64)}"
            ),
            siblings=siblings,
            shared_context=context,
        ))

    note = ""
    if eligible > len(groups):
        note = (
            f"family cap: {eligible} comparator-capable families, "
            f"kept {len(groups)} (first {MAX_ROUTE_FAMILIES} in "
            f"key order)"
        )
        logger.info("route-family layer: %s", note)
    logger.info("L10 route-family: %d groups", len(groups))
    return groups, note


# ── L7: Interface-slot groups ────────────────────────────────────────


def _interface_slot_groups(
    slot_families: list[Any],
    functions: list[dict[str, Any]],
) -> list[SiblingGroup]:
    """L7: implementations of one interface slot, from the census.

    Families arrive pre-built (``core.analysis.interface_slots``); this
    layer only JOINS them to the resolver's function records — it never
    re-censuses, so the producer's caps and determinism carry through.

    Join contract:

    * Members carrying (file, function) join by exact key first
      (override sets record their definition site); name-only members
      (ops-slot registrations name the function, not its definition)
      resolve through the ambiguity-excluding name index — a bare name
      shared by several records joins nothing rather than mis-binding.
    * **Claim floor** — families below
      :data:`MIN_INTERFACE_SLOT_MEMBERS` joined members neither claim
      nor emit (the route layer's argument: an exclusive claim by a
      family the parity comparator cannot vote on only strips its
      implementations out of the later layers).
    * **Member cap** — groups over :data:`MAX_INTERFACE_SLOT_MEMBERS`
      keep a seeded-random survivor sample, never deterministic
      first-N: member names are attacker-chosen text, and a sortable
      truncation would let a hostile repo name the deviant past the
      cut. In-band cap label on the group context.

    Slot keys and function names are target-derived — escaped before
    entering ids, descriptions, or contexts.
    """
    if not slot_families or not functions:
        return []
    from core.security.log_sanitisation import escape_nonprintable

    func_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for f in functions:
        key = (f.get("file", ""), f.get("name", ""))
        if key[1]:
            func_by_key.setdefault(key, f)
    func_by_name = _name_index(functions)

    groups: list[SiblingGroup] = []
    for fam in slot_families:
        kind = str(getattr(fam, "kind", "") or "")
        fam_key = str(getattr(fam, "key", "") or "")
        matched: dict[tuple[str, str], dict[str, Any]] = {}
        for member in getattr(fam, "members", ()) or ():
            fn = str(getattr(member, "function", "") or "")
            mfile = str(getattr(member, "file", "") or "")
            if not fn:
                continue
            record = None
            if mfile:
                record = func_by_key.get((mfile, fn))
            if record is None:
                record = func_by_name.get(fn)
            if record is None:
                continue
            rkey = (record.get("file", ""), record.get("name", ""))
            matched.setdefault(rkey, record)
        if len(matched) < MIN_INTERFACE_SLOT_MEMBERS:
            continue
        member_keys = sorted(matched)
        truncated = len(member_keys) > MAX_INTERFACE_SLOT_MEMBERS
        if truncated:
            # Seeded-random survivors (unchoosable), never a sorted
            # prefix — see the docstring's member-cap note.
            rnd = random.Random(os.urandom(16))
            member_keys = sorted(rnd.sample(
                member_keys, MAX_INTERFACE_SLOT_MEMBERS,
            ))
        key_esc = escape_nonprintable(fam_key)
        siblings = [
            SiblingPath(
                label=matched[k].get("name", ""),
                file=matched[k].get("file", ""),
                function=matched[k].get("name", ""),
                line=matched[k].get("line", 0),
            )
            for k in member_keys
        ]
        kind_label = (
            "ops-struct slot" if kind == "ops_slot"
            else "subclass override set"
        )
        context = f"Interface slot: {key_esc} ({kind_label})"
        if truncated:
            context += (
                f" [group capped at {MAX_INTERFACE_SLOT_MEMBERS} of "
                f"{len(matched)} members, seeded-random selection]"
            )
        groups.append(SiblingGroup(
            group_id=f"interface_slot:{kind}:{key_esc}",
            # Plain string by the module-header convention (SiblingType
            # is a str enum; consumers compare by value).
            sibling_type=GROUP_TYPE_INTERFACE_SLOT,  # type: ignore[arg-type]
            description=f"Implementations of {key_esc} ({kind_label})",
            siblings=siblings,
            shared_context=context,
        ))

    logger.info("L7 interface-slot: %d groups", len(groups))
    return groups


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
    """Parse JOERN_PEERS: records into (caller, file, [callees]).

    Primary format: one ``JOERN_PEERS:{json}`` record per line
    (``{"caller": ..., "file": ..., "callees": [...]}``), parsed
    transport-tolerantly via :func:`parse_marker_records` so records
    carried only in the server transport's value echo still decode.
    The legacy pipe-delimited ``JOERN_PEERS:caller|file|c1,c2`` shape
    is kept as a fallback for old transcripts; its unescaped
    delimiters make it a lossy carrier, so JSON records win when any
    are present.
    """
    from core.analysis._joern_lines import parse_marker_records

    records, _decode_errors = parse_marker_records(
        raw_output or "", "JOERN_PEERS:",
    )
    results: list[tuple[str, str, list[str]]] = []
    for rec in records:
        if not isinstance(rec, dict):
            continue
        caller = rec.get("caller")
        caller_file = rec.get("file")
        raw_callees = rec.get("callees")
        if not isinstance(caller, str) or not isinstance(raw_callees, list):
            continue
        callees = [c for c in raw_callees if isinstance(c, str) and c]
        if len(callees) >= 2:
            results.append((
                caller,
                caller_file if isinstance(caller_file, str) else "",
                callees,
            ))
    if results:
        return results
    for line in (raw_output or "").splitlines():
        m = _JOERN_PEERS_RE.match(line.strip())
        if m:
            caller = m.group(1)
            caller_file = m.group(2)
            callees = [c for c in m.group(3).split(",") if c]
            if len(callees) >= 2:
                results.append((caller, caller_file, callees))
    return results


# Dual-emit doctrine (same as the reachability-gates queries): records
# are println'd for the subprocess transport AND returned as the final
# expression so the server transport (/query-sync drops println,
# echo-frames the final expression) still carries them. The previous
# println-only form was dead on the server transport. jsonEsc guards
# every interpolated value — caller/file/callee names come from the
# SCANNED repo, and the old raw pipe/comma delimiters let a hostile
# name forge or destroy records. The embedded jsonEsc line is byte-
# identical to ``packages.joern.runner.SCALA_JSON_ESC_DEF`` (drift-
# guarded by a test; not imported here to keep this module free of
# the joern package at import time).
_CO_CALLEE_QUERY = """\
import io.shiftleft.semanticcpg.language._
import scala.util.Try

def jsonEsc(v: String): String = v.replace("\\\\", "\\\\\\\\").replace("\\"", "\\\\\\"").replace("\\r", "").replace("\\n", " ").flatMap(c => if (c.toInt < 0x20 || c.toInt == 0x85 || c.toInt == 0x2028 || c.toInt == 0x2029) " " else c.toString)

val peerLines = cpg.method.internal
  .filter(_.call.size > 1)
  .map { caller =>
    val callees = Try(
      caller.call
        .filterNot(c => c.name.startsWith("<") || c.name == caller.name)
        .filter(c => cpg.method.nameExact(c.name).nonEmpty)
        .name.dedup.l
    ).getOrElse(List.empty[String])
    if (callees.size >= 2) {
      val f = jsonEsc(caller.filename)
      val n = jsonEsc(caller.name)
      val cs = callees.map(c => "\\"" + jsonEsc(c) + "\\"").mkString(",")
      s"JOERN_PEERS:{\\"caller\\":\\"$n\\",\\"file\\":\\"$f\\",\\"callees\\":[$cs]}"
    } else ""
  }
  .filter(_.nonEmpty).l

peerLines.foreach(println)
peerLines.mkString("\\n")
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


# ── Binary anchor-family groups ──────────────────────────────────────


def _member_record(
    member: Any,
    func_by_name: dict[str, dict[str, Any]],
    func_by_fid: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    """Resolve one anchor-family member to a function record.

    fid first (exact identity across producers), bare name second —
    the same precedence FidIndex documents; ambiguous names were
    already excluded by :func:`_name_index`.
    """
    if not isinstance(member, dict):
        return None
    fid = member.get("fid")
    if isinstance(fid, str) and fid in func_by_fid:
        return func_by_fid[fid]
    name = member.get("name")
    if isinstance(name, str) and name:
        return func_by_name.get(name)
    return None


def _fid_index(
    functions: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Strict-parsed fid → record. Junk fids collapse to absent and
    duplicate fids (two records claiming one identity — corrupt or
    hostile input) are excluded like ambiguous names."""
    from core.binary.addrmap import normalise_fid

    by_fid: dict[str, dict[str, Any]] = {}
    ambiguous: set[str] = set()
    for f in functions:
        fid = normalise_fid(f.get("fid"))
        if fid is None:
            continue
        if fid in by_fid:
            ambiguous.add(fid)
        else:
            by_fid[fid] = f
    for fid in ambiguous:
        del by_fid[fid]
    return by_fid


def _anchor_family_groups(
    anchor_families: list[dict[str, Any]],
    functions: list[dict[str, Any]],
) -> list[SiblingGroup]:
    """Anchor-family layer: hunt families joined to the gap queue.

    Families arrive pre-clustered (and pre-escaped) from the hunt's
    bounded string-xref pass; this layer only JOINS them to the
    resolver's function records — it never re-clusters, so the hunt's
    caps and determinism carry through.
    """
    if not anchor_families or not functions:
        return []

    func_by_name = _name_index(functions)
    func_by_fid = _fid_index(functions)

    groups: list[SiblingGroup] = []
    for family in anchor_families:
        if len(groups) >= MAX_BINARY_PEER_GROUPS:
            logger.info(
                "binary anchor-family layer capped at %d groups",
                MAX_BINARY_PEER_GROUPS,
            )
            break
        if not isinstance(family, dict):
            continue
        matched: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        truncated = False
        for member in family.get("members") or []:
            record = _member_record(member, func_by_name, func_by_fid)
            if record is None:
                continue
            key = (record.get("file", ""), record.get("name", ""))
            if key in seen:
                continue
            seen.add(key)
            if len(matched) >= MAX_BINARY_PEER_GROUP_SIZE:
                truncated = True
                break
            matched.append(record)
        if len(matched) < 2:
            continue
        family_id = str(family.get("id") or "")
        samples = [
            str(s) for s in (family.get("sample_strings") or [])[:3]
        ]
        siblings = [
            SiblingPath(
                label=r.get("name", ""),
                file=r.get("file", ""),
                function=r.get("name", ""),
                line=r.get("line", 0),
            )
            for r in matched
        ]
        context = (
            "Shared anchor strings: " + "; ".join(samples)
            if samples else "Shared anchor strings"
        )
        if truncated:
            # In-band, like the callee layer's cap label — a silently
            # shrunk family misreads as the whole family.
            context += (
                f" [group capped at {MAX_BINARY_PEER_GROUP_SIZE} "
                f"members, kept family order]"
            )
        groups.append(SiblingGroup(
            group_id=f"binary_anchor:{family_id or siblings[0].function}",
            sibling_type=_ANCHOR_FAMILY,
            description=(
                f"Anchor family {family_id or '(unnamed)'} "
                f"(string-xref co-occurrence)"
            ),
            siblings=siblings,
            shared_context=context,
        ))

    logger.info("binary anchor-family: %d groups", len(groups))
    return groups


# ── Binary shared-callee-signature groups ────────────────────────────


def distinctive_callee_set(
    binary_callees: dict[str, set[str]],
) -> set[str]:
    """Callees distinctive enough to be family evidence.

    Caller counts run over the WHOLE substrate (not just the
    resolver's input) — distinctiveness is a property of the binary.
    A callee needs 2..:data:`CALLEE_HUB_MAX_CALLERS` callers: below,
    it corroborates nothing; above, it is a hub (allocator, logging
    shim, libc wrapper) — shared vocabulary, not family evidence.
    Shared with the check-vector consumers so "distinctive" means one
    thing everywhere.
    """
    caller_count: dict[str, int] = defaultdict(int)
    for caller in sorted(binary_callees):
        for callee in binary_callees[caller]:
            caller_count[callee] += 1
    return {
        callee for callee, count in caller_count.items()
        if 2 <= count <= CALLEE_HUB_MAX_CALLERS
    }


def _shared_callee_signature_groups(
    binary_callees: dict[str, set[str]],
    functions: list[dict[str, Any]],
) -> list[SiblingGroup]:
    """Functions calling the same distinctive helpers.

    ``binary_callees`` is caller name → callee-name set from a
    persisted substrate. Distinctive callee = called by 2..
    :data:`CALLEE_HUB_MAX_CALLERS` of the map's functions — hubs
    (allocators, logging shims, libc wrappers) join nothing. Two
    functions sharing ≥ :data:`MIN_SHARED_DISTINCTIVE_CALLEES`
    distinctive callees union into one group. Deterministic under
    shuffled input: callers, callees, and union roots iterate sorted.
    """
    if not binary_callees or not functions:
        return []

    func_by_name = _name_index(functions)

    distinctive = distinctive_callee_set(binary_callees)
    if not distinctive:
        return []

    signatures: dict[str, frozenset[str]] = {}
    for name in sorted(func_by_name):
        callees = binary_callees.get(name)
        if not callees:
            continue
        sig = frozenset(callees & distinctive)
        if sig:
            signatures[name] = sig

    names = sorted(signatures)
    # Pairwise join via the shared-callee inverted index — pair work
    # is bounded by the hub ceiling (each distinctive callee has at
    # most CALLEE_HUB_MAX_CALLERS callers).
    by_callee: dict[str, list[str]] = defaultdict(list)
    for name in names:
        for callee in sorted(signatures[name]):
            by_callee[callee].append(name)

    parent: dict[str, str] = {name: name for name in names}

    def _find(name: str) -> str:
        while parent[name] != name:
            parent[name] = parent[parent[name]]
            name = parent[name]
        return name

    pair_shared: dict[tuple[str, str], int] = {}
    for callee in sorted(by_callee):
        members = by_callee[callee]
        for i, a in enumerate(members):
            for b in members[i + 1:]:
                pair_shared[(a, b)] = pair_shared.get((a, b), 0) + 1
    for (a, b), shared in sorted(pair_shared.items()):
        if shared >= MIN_SHARED_DISTINCTIVE_CALLEES:
            ra, rb = _find(a), _find(b)
            if ra != rb:
                # Deterministic root: lexicographic min wins.
                lo, hi = sorted((ra, rb))
                parent[hi] = lo

    components: dict[str, list[str]] = defaultdict(list)
    for name in names:
        components[_find(name)].append(name)

    groups: list[SiblingGroup] = []
    for root in sorted(components):
        members = sorted(components[root])
        if len(members) < 2:
            continue
        if len(groups) >= MAX_BINARY_PEER_GROUPS:
            logger.info(
                "binary shared-callee layer capped at %d groups",
                MAX_BINARY_PEER_GROUPS,
            )
            break
        truncated = len(members) > MAX_BINARY_PEER_GROUP_SIZE
        kept = members[:MAX_BINARY_PEER_GROUP_SIZE]
        shared_all = sorted(
            frozenset.intersection(*(signatures[m] for m in kept)),
        )
        siblings = [
            SiblingPath(
                label=name,
                file=func_by_name[name].get("file", ""),
                function=name,
                line=func_by_name[name].get("line", 0),
            )
            for name in kept
        ]
        context = (
            "Shared distinctive callees: " + ", ".join(shared_all[:6])
            if shared_all else
            "Chained shared-callee overlaps (no single callee spans "
            "the whole group)"
        )
        if truncated:
            context += (
                f" [group capped at {MAX_BINARY_PEER_GROUP_SIZE} of "
                f"{len(members)} members, kept name-ordered]"
            )
        groups.append(SiblingGroup(
            group_id=f"binary_callee_sig:{kept[0]}",
            sibling_type=_CALLEE_SIGNATURE,
            description=(
                f"Functions sharing ≥{MIN_SHARED_DISTINCTIVE_CALLEES} "
                f"distinctive callees"
            ),
            siblings=siblings,
            shared_context=context,
        ))

    logger.info("binary shared-callee: %d groups", len(groups))
    return groups


# ── Binary decomp-similarity groups (independent, lower confidence) ──


_DECOMP_TIER_NOTE = (
    "decompiler-inferred similarity (approximate pseudo-code — lower "
    "confidence than xref-backed layers)"
)


def _decomp_similarity_groups(
    decomp_texts: dict[str, str],
    functions: list[dict[str, Any]],
) -> tuple[list[SiblingGroup], str]:
    """Decompilation-hash/shingle similarity via the similarity seam.

    Two stages, both deterministic: exact normalized-hash equality
    (clones), then bounded pairwise shingle-Jaccard at the matcher's
    absolute floor. Returns ``(groups, note)`` — the note reports the
    pairwise stage being skipped over budget (degradation is said,
    never silent). Requires ``packages.ghidra.similarity``; when the
    packages tree is absent the layer stays empty.
    """
    if not decomp_texts or not functions:
        return [], ""
    try:
        from packages.ghidra.similarity import (
            decomp_hash_text,
            jaccard,
            shingles_text,
        )
    except ImportError:  # pragma: no cover - packages tree absent
        return [], "similarity seam unavailable"

    func_by_name = _name_index(functions)

    # Own-name masking rides INSIDE the seam's single
    # strip→mask→normalize pipeline (own=): two clones of one body
    # differ only in their own identifier — the matcher's
    # rename-aware diff normalization, applied per member. Masking
    # outside the seam and re-stripping inside would dissolve the
    # NUL-delimited sentinel (forgeable by a literal identifier).
    hashed: dict[str, str] = {}
    for name in sorted(func_by_name):
        text = decomp_texts.get(name)
        if not text:
            continue
        digest = decomp_hash_text(text, own=name)
        if digest:
            hashed[name] = digest

    names = sorted(hashed)
    parent: dict[str, str] = {name: name for name in names}

    def _find(name: str) -> str:
        while parent[name] != name:
            parent[name] = parent[parent[name]]
            name = parent[name]
        return name

    def _union(a: str, b: str) -> None:
        ra, rb = _find(a), _find(b)
        if ra != rb:
            lo, hi = sorted((ra, rb))
            parent[hi] = lo

    # Stage 1: exact normalized-hash equality.
    by_hash: dict[str, list[str]] = defaultdict(list)
    for name in names:
        by_hash[hashed[name]].append(name)
    for members in by_hash.values():
        for other in members[1:]:
            _union(members[0], other)

    # Stage 2: bounded pairwise shingle similarity.
    note = ""
    pair_budget = len(names) * (len(names) - 1) // 2
    if pair_budget > MAX_DECOMP_PAIRWISE:
        note = (
            f"pairwise similarity skipped: {pair_budget} pairs exceed "
            f"the {MAX_DECOMP_PAIRWISE} budget; exact-hash groups only"
        )
    else:
        shingle_sets = {
            name: shingles_text(decomp_texts[name], own=name)
            for name in names
        }
        for i, a in enumerate(names):
            sa = shingle_sets[a]
            if not sa:
                continue
            for b in names[i + 1:]:
                sb = shingle_sets[b]
                if not sb:
                    continue
                sim = jaccard(sa, sb)
                if sim is not None and sim >= DECOMP_SIMILARITY_THRESHOLD:
                    _union(a, b)

    components: dict[str, list[str]] = defaultdict(list)
    for name in names:
        components[_find(name)].append(name)

    groups: list[SiblingGroup] = []
    for root in sorted(components):
        members = sorted(components[root])
        if len(members) < 2:
            continue
        if len(groups) >= MAX_BINARY_PEER_GROUPS:
            logger.info(
                "binary decomp-similarity layer capped at %d groups",
                MAX_BINARY_PEER_GROUPS,
            )
            break
        kept = members[:MAX_BINARY_PEER_GROUP_SIZE]
        siblings = [
            SiblingPath(
                label=name,
                file=func_by_name[name].get("file", ""),
                function=name,
                line=func_by_name[name].get("line", 0),
            )
            for name in kept
        ]
        groups.append(SiblingGroup(
            group_id=f"binary_decomp:{kept[0]}",
            sibling_type=_DECOMP_SIMILARITY,
            description=f"Similar decompilations ({_DECOMP_TIER_NOTE})",
            siblings=siblings,
            shared_context=_DECOMP_TIER_NOTE,
        ))

    logger.info("binary decomp-similarity: %d groups", len(groups))
    return groups, note


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

    # Metadata values are producer-controlled (checklist items are
    # LLM-enrichable); a scalar where the parameter list belongs must
    # read as "no signature info", not TypeError the len() below —
    # the orchestrator prep call has no per-function containment.
    params_a = meta_a.get("parameters", [])
    params_b = meta_b.get("parameters", [])
    if not isinstance(params_a, (list, tuple)):
        params_a = []
    if not isinstance(params_b, (list, tuple)):
        params_b = []

    if params_a and params_b:
        if abs(len(params_a) - len(params_b)) > max_arity_diff:
            return False

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


def _decorator_base(attr: str) -> str:
    """Base callable name of a decorator/annotation string.

    Extractors record decorators verbatim (``ast.unparse`` /
    tree-sitter text), so the common web-route shape carries
    arguments: ``app.route('/login', methods=['POST'])``. Comparing
    full strings means two routes NEVER share a decorator; the base
    callable — the text before the argument list — is the identity
    siblings actually share. Argument-less decorators pass through
    unchanged.
    """
    return attr.split("(", 1)[0].strip()


def _decorator_bases(meta: dict[str, Any]) -> list[str]:
    """Deduped, order-preserving decorator base names from metadata.

    Type-validates as it reads: ``attributes`` is producer-controlled
    (checklist items are LLM-enrichable), so a scalar where the list
    belongs, or a non-str member, must contribute nothing rather than
    TypeError the grouping pass. Order is preserved so group emission
    stays deterministic.
    """
    attrs = meta.get("attributes")
    if not isinstance(attrs, list):
        return []
    bases: list[str] = []
    for attr in attrs:
        if not isinstance(attr, str):
            continue
        base = _decorator_base(attr)
        if base and base not in bases:
            bases.append(base)
    return bases


def _shared_decorator(a: dict[str, Any], b: dict[str, Any]) -> str | None:
    """Return a shared decorator base name if both functions have one."""
    meta_a = a.get("metadata", {}) or {}
    meta_b = b.get("metadata", {}) or {}
    shared = set(_decorator_bases(meta_a)) & set(_decorator_bases(meta_b))
    if shared:
        return sorted(shared)[0]
    return None


def _checklist_metadata_index(
    checklist: dict[str, Any],
) -> dict[tuple[str, str], dict[str, Any]]:
    """``(path, name) → metadata`` over the REAL checklist shape.

    ``read_checklist`` produces ``{"files": [{"path": …, "items":
    […]}]}`` (legacy: per-file ``functions`` list) — the same walk
    :func:`type_ref_index_from_inventory` and ``find_checklist_item``
    (core/audit/gaps.py) use. An earlier join here expected a
    top-level ``{"<file>:<name>": entry}`` dict that no producer
    emits, so the enrichment never matched anything.

    Checklist content is producer-controlled (understand-bridge
    imports are LLM-written), so every level is type-validated as it
    is read — wrong shapes contribute nothing rather than TypeError
    the orchestrator prep that consumes the enriched functions.
    """
    index: dict[tuple[str, str], dict[str, Any]] = {}
    if not isinstance(checklist, dict):
        return index
    files = checklist.get("files")
    if not isinstance(files, list):
        return index
    for file_entry in files:
        if not isinstance(file_entry, dict):
            continue
        path = file_entry.get("path")
        if not isinstance(path, str):
            path = ""
        items = file_entry.get("items", file_entry.get("functions"))
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            meta = item.get("metadata")
            if (isinstance(name, str) and name
                    and isinstance(meta, dict) and meta):
                meta = _validated_metadata(meta)
                if meta:
                    # First-wins on a duplicate (path, name) — e.g.
                    # same-named methods of two classes in one file.
                    # The join carries no line info to disambiguate;
                    # a wrong ride-along only loosens filtering (the
                    # harmless direction), never drops a function.
                    index.setdefault((path, name), meta)
    return index


def _validated_metadata(meta: dict[str, Any]) -> dict[str, Any]:
    """Shape-validate checklist metadata before it feeds the filters.

    The consumers this index feeds (:func:`_signatures_compatible`,
    :func:`_shared_decorator`, the L5 decorator pass) do len()/set()
    work on these values with no per-function containment at the
    orchestrator prep call, so a wrong-typed value is dropped here:
    ``parameters`` must be a list, ``return_type`` a str,
    ``attributes`` a list (non-str members dropped). Unrecognized
    keys pass through untouched.
    """
    cleaned = dict(meta)
    params = cleaned.get("parameters")
    if params is not None and not isinstance(params, list):
        del cleaned["parameters"]
    return_type = cleaned.get("return_type")
    if return_type is not None and not isinstance(return_type, str):
        del cleaned["return_type"]
    attrs = cleaned.get("attributes")
    if attrs is not None:
        if isinstance(attrs, list):
            cleaned["attributes"] = [
                a for a in attrs if isinstance(a, str)
            ]
        else:
            del cleaned["attributes"]
    return cleaned


def _enrich_from_index(
    func: dict[str, Any],
    meta_index: dict[tuple[str, str], dict[str, Any]],
) -> dict[str, Any]:
    """Attach checklist metadata to *func* (copy) when it has none."""
    if func.get("metadata"):
        return func
    meta = meta_index.get((func.get("file", ""), func.get("name", "")))
    if meta:
        return {**func, "metadata": meta}
    return func


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

    meta_index = (_checklist_metadata_index(checklist)
                  if checklist else {})

    # First pass: decorator-based groups per directory
    decorator_groups: list[SiblingGroup] = []
    decorator_claimed: set[tuple[str, str]] = set()  # (file, name)

    dir_funcs: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for f in functions:
        enriched = _enrich_from_index(f, meta_index)
        d = _func_directory(enriched)
        dir_funcs[d].append(enriched)

    for directory, dir_members in dir_funcs.items():
        deco_to_funcs: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for f in dir_members:
            meta = f.get("metadata", {}) or {}
            # Base names (see _decorator_base): arg-carrying route
            # decorators must land in ONE bucket per callable, and
            # _decorator_bases type-validates as it reads.
            for attr in _decorator_bases(meta):
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
