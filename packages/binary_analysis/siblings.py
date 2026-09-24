"""Sibling-consistency pass over a mapped binary run directory.

Formation and comparison both REUSE the audit lane's engines — this
module is adapters and plumbing, never a second implementation:

* peer groups come from ``core.analysis.peer_groups`` (the binary
  layers: hunt anchor families, shared-callee signatures, decomp
  similarity via the ghidra similarity seam);
* per-member check vectors come from
  ``core.audit.binary_check_vectors`` (called-helper presence +
  compare-operand constants, persisted artifacts only);
* the outlier verdictless flagging is
  ``core.audit.sibling_analysis.find_asymmetries`` — the exact
  N-vs-K pass the source lane runs.

Outputs: ``sibling-clusters.json`` (member×check matrix + asymmetry
rows), ``sibling-hypotheses.json`` (audit hypothesis-seed intake
schema — claims with evidence refs, tier, and a disproof recipe;
seeds never mint findings), and a markdown report.

Claims discipline (each line also rides in the artifacts):

* This pass finds only ASYMMETRIC weaknesses. A fully-consistent
  cluster is UNEXAMINED, not safe — a uniformly-missing check
  reports nothing here.
* Check presence is SYNTACTIC — a dead or dominated call satisfies
  every column. Outlier rows are review leads with disproof
  recipes, never findings.
* Clustering recall is attacker-influenced: a backdoor shaped to
  not cluster with its siblings is out of scope for this pass.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

from core.analysis.peer_groups import (
    distinctive_callee_set,
    resolve_peer_groups,
)
from core.artifacts.provenance import stamp_provenance
from core.audit.binary_check_vectors import (
    GroupCheckVectors,
    extract_group_check_vectors,
)
from core.audit.sibling_analysis import find_asymmetries
from core.binary.addrmap import (
    FidIndex,
    normalise_fid,
    record_fid_misses,
)
from core.evidence import EvidenceTier, TIER_RANK
from core.inventory.binary_builder import binary_path_key
from core.json import load_json, save_json
from core.security.log_sanitisation import escape_nonprintable
from core.security.markdown_render import md_inline

from ._artifact_lock import run_artifacts_lock
from .graph_store import graph_path_for_run, query_evidence
from .hunt import (
    HuntError,
    _load_context_map,
    _load_manifest,
    _parse_addr,
    load_call_graph,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from .manifest import BinaryManifest

logger = logging.getLogger(__name__)

CLUSTERS_FILENAME = "sibling-clusters.json"
#: Fixed name — the audit hypothesis-seed intake discovers exactly
#: this co-located spelling; a slugged/suffixed variant would be
#: invisible to it.
HYPOTHESES_FILENAME = "sibling-hypotheses.json"
REPORT_FILENAME = "sibling-clusters.md"

#: Hunt artifacts scanned for anchor families. Both directions: more
#: files admit long hunt sessions but hand a run dir full of planted
#: artifacts a per-run parse budget; fewer drops older hunts first.
#: 16 matches the hunt's own per-invocation family cap class.
MAX_HUNT_ARTIFACTS = 16

#: Per-artifact read bound (hunt artifacts are family-capped, so real
#: files are far smaller; a planted multi-GB file must not stall the
#: pass).
MAX_HUNT_ARTIFACT_BYTES = 8 * 1024 * 1024

#: Clusters analysed per run. Both directions: more clusters mean
#: more matrix work and a longer report on decoy-flooded binaries;
#: fewer can drop real families on very wide targets. Matches the
#: peer-group layer cap so formation and analysis agree.
MAX_CLUSTERS_ANALYSED = 32

#: Hypothesis seeds emitted. The audit intake accepts 200 records
#: across ALL sources — emitting more than it can load would silently
#: truncate at the consumer; emitting fewer starves nothing (real
#: outlier sets are tens of rows).
MAX_HYPOTHESES = 200

#: Default minimum cluster size. The engine's outlier checks need a
#: clear majority (N-1 vs 1 at N=3 is the smallest informative
#: split); 2-member groups can never flag a minority.
MIN_CLUSTER_DEFAULT = 3

ASYMMETRY_ONLY_NOTE = (
    "This pass finds only asymmetric weaknesses: a fully-consistent "
    "cluster is unexamined, not safe. A check every member skips "
    "reports nothing here."
)
CLUSTERING_RECALL_NOTE = (
    "Clustering recall is attacker-influenced: a function shaped to "
    "not cluster with its siblings is out of scope for this pass."
)
ALTERNATIVE_EXPLANATIONS = (
    "Alternative explanations before treating this as a bug: the "
    "outlier plays a different role in the family; the check happens "
    "in a wrapper or caller this substrate does not see; the code is "
    "dead; the decompiler failed on this member; the cluster "
    "over-merged unrelated functions."
)

_DISPROOF_CALLS = (
    "Disproof: show the outlier reaches {callee} through a wrapper, "
    "tail call, or function pointer this substrate missed — or that "
    "the majority's call sites are dead or do not dominate the "
    "dangerous operation."
)
_DISPROOF_COMPARE = (
    "Disproof: decompile or decode the outlier and show an "
    "equivalent guard with different structure or constant — or "
    "that the majority's checks do not dominate the dangerous "
    "operation (syntactic presence proves neither reachability nor "
    "effect)."
)


def _esc(value: Any) -> str:
    return escape_nonprintable(str(value))


# ── Input loading ─────────────────────────────────────────────────────


def _load_hunt_families(
    run_dir: Path,
    family_id: str | None,
) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    """Anchor families from persisted ``binary-hunt-*.json`` artifacts.

    Returns ``(families, sources, notes)``. Newest artifacts win the
    file cap (a long session's latest hunts are the operator's
    current focus); unreadable files are counted in notes, never
    fatal.
    """
    paths = sorted(
        Path(run_dir).glob("binary-hunt-*.json"),
        key=lambda p: p.stat().st_mtime if p.exists() else 0,
        reverse=True,
    )
    notes: list[str] = []
    if len(paths) > MAX_HUNT_ARTIFACTS:
        notes.append(
            f"hunt artifacts capped at {MAX_HUNT_ARTIFACTS} of "
            f"{len(paths)} (newest kept)"
        )
        paths = paths[:MAX_HUNT_ARTIFACTS]
    families: list[dict[str, Any]] = []
    sources: list[str] = []
    for path in paths:
        payload = load_json(path, max_bytes=MAX_HUNT_ARTIFACT_BYTES)
        if not isinstance(payload, dict) or payload.get("mode") != "anchor":
            continue
        entries = payload.get("families")
        if not isinstance(entries, list):
            continue
        used = False
        for fam in entries:
            if not isinstance(fam, dict):
                continue
            if family_id is not None and fam.get("id") != family_id:
                continue
            families.append(fam)
            used = True
        if used:
            sources.append(path.name)
    return families, sources, notes


def _function_records(
    context_map: dict[str, Any],
    manifest: "BinaryManifest",
) -> list[dict[str, Any]]:
    """Resolver-shaped function dicts from the map inventory."""
    file_key = binary_path_key(manifest.binary_path)
    records: list[dict[str, Any]] = []
    for item in context_map.get("interesting_functions") or []:
        if not isinstance(item, dict) or not item.get("name"):
            continue
        record: dict[str, Any] = {
            "name": str(item["name"]),
            "file": file_key,
            "line": 0,
            "address": _parse_addr(item.get("address")),
            "is_exported": bool(item.get("is_exported")),
        }
        fid = normalise_fid(item.get("fid"))
        if fid:
            record["fid"] = fid
        records.append(record)
    return records


def _load_decomp_texts(run_dir: Path) -> dict[str, str]:
    """Persisted decompilations, keyed by function name.

    Two persisted sources, re-database (Ghidra-grade) preferred per
    name: ``re-database.json`` function decompilation, then the map's
    ``binary-decompilations.json`` bodies. No decompiler runs here.
    """
    texts: dict[str, str] = {}
    decomp = load_json(
        Path(run_dir) / "binary-decompilations.json",
        max_bytes=64 * 1024 * 1024,
    )
    if isinstance(decomp, dict):
        for fn in decomp.get("functions") or []:
            if isinstance(fn, dict) and fn.get("name") and fn.get("body"):
                texts.setdefault(str(fn["name"]), str(fn["body"]))
    redb = _load_redb(run_dir)
    if redb is not None:
        for fn in redb.functions:
            if fn.name and fn.decompilation:
                texts[fn.name] = str(fn.decompilation)
    return texts


def _load_redb(run_dir: Path) -> Any | None:
    """Co-located re-database, when present and readable."""
    path = Path(run_dir) / "re-database.json"
    if not path.is_file():
        return None
    try:
        from core.json.utils import RE_DATABASE_MAX_BYTES
        from packages.ghidra.model import REDatabase
    except ImportError:  # pragma: no cover - ghidra package absent
        return None
    payload = load_json(path, max_bytes=RE_DATABASE_MAX_BYTES)
    if not isinstance(payload, dict):
        return None
    return REDatabase.from_dict(payload)


def _decoded_compare_index(run_dir: Path) -> dict[str, list[Any]]:
    """Decoded compare evidence from the run's graph store.

    Consume-if-present: records with the ``decoded_instruction`` tier
    whose props carry a function name and a ``compares`` list. No
    producer requirement — absence simply leaves the decompilation
    fallback in charge.
    """
    index: dict[str, list[Any]] = {}
    try:
        records = query_evidence(
            graph_path_for_run(Path(run_dir)),
            tier=EvidenceTier.DECODED_INSTRUCTION.value,
        )
    except Exception:  # noqa: BLE001 - enrichment only; a corrupt store must not kill the pass
        logger.debug("siblings: decoded-evidence query failed",
                     exc_info=True)
        return index
    for record in records:
        props = record.get("props")
        if not isinstance(props, dict):
            continue
        name = props.get("function", props.get("name"))
        compares = props.get("compares")
        if isinstance(name, str) and name and isinstance(compares, list):
            index.setdefault(name, []).extend(compares)
    return index


# ── Analysis ──────────────────────────────────────────────────────────


def _disproof_for(property_name: str) -> str:
    if property_name.startswith("calls:"):
        return _DISPROOF_CALLS.format(
            callee=property_name.split(":", 1)[1])
    return _DISPROOF_COMPARE


def _asymmetry_rows(
    group: Any,
    vectors: GroupCheckVectors,
    kind: str,
) -> list[dict[str, Any]]:
    """Engine output → escaped review-lead rows with disproof and
    alternative-explanation lines. The engine's confidence is kept
    verbatim — never re-graded here."""
    tier_by_member = {m.function: m for m in vectors.members}
    rows: list[dict[str, Any]] = []
    for asym in find_asymmetries(group):
        # Weakest evidence tier among members carrying this check —
        # the honest grade for a cross-member comparison.
        tiers = [
            member.tiers[asym.property_name]
            for member in vectors.members
            if asym.property_name in member.tiers
        ]
        tier = min(
            tiers,
            key=lambda t: TIER_RANK.get(EvidenceTier(t), 0),
            default=EvidenceTier.HEURISTIC.value,
        )
        rows.append({
            "kind": kind,
            "group_id": _esc(asym.group_id),
            "property": _esc(asym.property_name),
            "majority_value": _esc(asym.majority_value),
            "minority_value": _esc(asym.minority_value),
            "majority_count": asym.majority_count,
            "minority_count": asym.minority_count,
            "outliers": [_esc(name) for name in asym.minority_siblings],
            # None placeholders on misses keep the list INDEX-ALIGNED
            # with outliers — the seed emitter pairs them by position.
            "outlier_fids": [
                tier_by_member[name].fid
                if name in tier_by_member else None
                for name in asym.minority_siblings
            ],
            "confidence": asym.confidence,
            "severity": asym.severity,
            "explanation": _esc(asym.explanation),
            "evidence_tier": tier,
            "disproof": _disproof_for(asym.property_name),
            "alternative_explanations": ALTERNATIVE_EXPLANATIONS,
        })
    return rows


def _checklist_join(redb: Any) -> FidIndex | None:
    """FidIndex over the re-database — the space the audit checklist
    for this binary is built from. Seeds joined through it carry
    checklist-space addresses and names; without a re-database the
    map's own space is the best (and only) space available."""
    if redb is None:
        return None
    index = FidIndex()
    for fn in redb.functions:
        index.add(fn, fid=fn.fid, name=fn.name)
    return index


def _seed_identity(
    function: str,
    fid: str | None,
    address: int | None,
    join: FidIndex | None,
    misses: list[dict[str, Any]],
) -> tuple[str, int | None]:
    """(checklist-space function name, checklist-space address).

    With a re-database join, resolve through the fid policy (exact →
    bounded fuzzy → unique non-placeholder name) so the emitted seed
    addresses live in the space the audit checklist was built from —
    the intake's join is address+name, and a map-space address
    against a Ghidra-base checklist would be a recorded miss on
    every seed. Unresolved members keep the map identity and are
    RECORDED misses (visible, never silently wrong).
    """
    if join is None:
        return function, address
    match = join.resolve(fid=fid, name=function)
    if match is not None:
        fn = match.payload
        name = getattr(fn, "name", "") or function
        redb_addr = getattr(fn, "address", None)
        if isinstance(redb_addr, int) and not isinstance(redb_addr, bool):
            return name, redb_addr
        return name, address
    misses.append({
        "operation_detail": "sibling_seed",
        "name": function,
        "fid": fid or "",
        "reason": "not_in_re_database",
    })
    return function, address


def _hypothesis_seeds(
    rows: list[dict[str, Any]],
    file_key: str,
    join: FidIndex | None,
    misses: list[dict[str, Any]],
    addr_by_function: dict[str, int | None] | None = None,
) -> tuple[list[dict[str, Any]], int]:
    """Outlier rows → (audit hypothesis-seed records, overflow count).

    Schema is the audit intake's (``core.audit.hypothesis_intake``):
    fid, file (the ``binary:<stem>`` sentinel), function, address
    (checklist-space), claim, evidence refs, evidence_tier
    (core.evidence value spelling), disproof, derived_from_target.
    Seeds are hints — they boost gap priority and ride into review
    context enveloped; they never mint findings.
    """
    seeds: list[dict[str, Any]] = []
    overflow = 0
    seen: set[tuple[str, str]] = set()
    for row_index, row in enumerate(rows):
        for outlier_index, outlier in enumerate(row["outliers"]):
            key = (outlier, row["property"])
            if key in seen:
                continue
            seen.add(key)
            if len(seeds) >= MAX_HYPOTHESES:
                # Counted, not silent — the intake counts ITS overflow
                # loudly; the emitter must too (see run_siblings note).
                overflow += 1
                continue
            fids = row.get("outlier_fids") or []
            fid = fids[outlier_index] if outlier_index < len(fids) else None
            map_addr = (addr_by_function or {}).get(outlier)
            name, address = _seed_identity(
                outlier, fid, map_addr, join, misses,
            )
            claim = (
                f"Sibling asymmetry ({row['kind']}): {row['explanation']}"
            )
            seed: dict[str, Any] = {
                "file": file_key,
                "function": _esc(name),
                "claim": claim,
                "evidence_tier": row["evidence_tier"],
                "evidence": [{
                    "artifact": CLUSTERS_FILENAME,
                    "pointer": (
                        f"asymmetries[{row_index}]"
                    ),
                }],
                "disproof": row["disproof"],
                # Claim/disproof embed names and counts recovered
                # from the analysed binary — enveloped downstream
                # regardless, but the flag must tell the truth.
                "derived_from_target": {"claim": True, "disproof": True},
            }
            if fid:
                seed["fid"] = fid
            if address is not None:
                seed["address"] = address
            seeds.append(seed)
    return seeds, overflow


# ── Orchestration ─────────────────────────────────────────────────────


def run_siblings(
    run_dir: Path,
    *,
    family: str | None = None,
    auto: bool = False,
    min_cluster: int = MIN_CLUSTER_DEFAULT,
    graph_loader: "Callable[[Path, Any], Any] | None" = None,
) -> dict[str, Any]:
    """Sibling-consistency pass over an existing binary run dir.

    Default mode consumes families from persisted hunt artifacts
    (``--family <id>`` narrows to one); ``--auto`` runs the full
    peer-group formation (all layers) instead. Returns the artifact
    payload (already written).
    """
    run_dir = Path(run_dir)
    manifest = _load_manifest(run_dir)
    context_map = _load_context_map(run_dir)
    loader = graph_loader or load_call_graph
    graph = loader(run_dir, manifest)

    functions = _function_records(context_map, manifest)
    if not functions:
        msg = "binary-context-map.json carries no recovered functions"
        raise HuntError(msg)

    families, family_sources, notes = _load_hunt_families(run_dir, family)
    if family is not None and not families:
        msg = (
            f"anchor family not found in this run's hunt artifacts: "
            f"{escape_nonprintable(family)}"
        )
        raise HuntError(msg)
    if not auto and not families:
        msg = (
            "no anchor families in this run dir — run `/binary hunt "
            "<run-dir> --anchor <text>` first, or pass --auto for "
            "full peer-group formation"
        )
        raise HuntError(msg)

    decomp_texts = _load_decomp_texts(run_dir)
    decoded_compares = _decoded_compare_index(run_dir)
    redb = _load_redb(run_dir)

    # Formation degradation facts (e.g. the decomp-similarity
    # pairwise budget reducing to hash-only groups) ride the payload
    # notes and the report — a layer quietly doing less than asked
    # must be visible where the operator is looking.
    groups = resolve_peer_groups(
        functions,
        anchor_families=families or None,
        binary_callees=graph.callees or None,
        decomp_texts=decomp_texts or None,
        notes=notes,
    )
    if not auto:
        groups = [
            g for g in groups
            if str(g.sibling_type) == "binary_anchor_family"
        ]
    small = sum(1 for g in groups if len(g.siblings) < min_cluster)
    groups = [g for g in groups if len(g.siblings) >= min_cluster]
    if small:
        notes.append(
            f"{small} cluster(s) below --min-cluster {min_cluster} "
            f"skipped (the engine needs a clear majority; N=3 is the "
            f"smallest informative split)"
        )
    if len(groups) > MAX_CLUSTERS_ANALYSED:
        notes.append(
            f"clusters capped at {MAX_CLUSTERS_ANALYSED} of "
            f"{len(groups)}"
        )
        groups = groups[:MAX_CLUSTERS_ANALYSED]

    distinctive = distinctive_callee_set(graph.callees or {})
    callee_fids = {
        name: info["fid"]
        for name, info in (graph.meta or {}).items()
        if isinstance(info, dict) and info.get("fid")
    }
    fid_by_function = {
        f["name"]: f.get("fid") for f in functions if f.get("name")
    }

    # Export-contract rows are computed FIRST and lead the emission
    # order: they are the scarcer signal (bounded by the export
    # surface) and the less attacker-shapeable one (export names are
    # the library's public contract, not free-form internal naming),
    # so when the seed cap bites they must survive ahead of the
    # cluster rows a decoy-flooded binary can multiply.
    contract_rows = _export_contract_rows(
        functions, graph, distinctive, callee_fids, fid_by_function,
        decomp_texts, decoded_compares, min_cluster,
    )

    clusters: list[dict[str, Any]] = []
    cluster_rows: list[dict[str, Any]] = []
    for group in groups:
        vectors = extract_group_check_vectors(
            group,
            callees_by_function=graph.callees,
            distinctive_callees=distinctive or None,
            fid_by_function=fid_by_function,
            callee_fids=callee_fids,
            decomp_texts=decomp_texts,
            decoded_compares=decoded_compares,
        )
        rows = _asymmetry_rows(group, vectors, _kind_of(group))
        cluster_rows.extend(rows)
        clusters.append({
            "group_id": _esc(group.group_id),
            "kind": _kind_of(group),
            "description": _esc(group.description),
            "shared_context": _esc(group.shared_context),
            "member_count": len(group.siblings),
            "matrix": _escaped_matrix(vectors),
            "asymmetries": rows,
            "consistent_note": (
                None if rows else ASYMMETRY_ONLY_NOTE
            ),
        })

    # One row list, contract rows first (rationale above); the seed
    # emitter and the payload's asymmetries share it so the seeds'
    # `asymmetries[i]` evidence pointers stay index-accurate.
    all_rows = [*contract_rows, *cluster_rows]

    misses: list[dict[str, Any]] = []
    join = _checklist_join(redb)
    file_key = binary_path_key(manifest.binary_path)
    addr_by_function = {
        f["name"]: f.get("address") for f in functions if f.get("name")
    }
    seeds, seed_overflow = _hypothesis_seeds(
        all_rows, file_key, join, misses, addr_by_function,
    )
    if seed_overflow:
        notes.append(
            f"hypothesis seeds capped at {MAX_HYPOTHESES}; "
            f"{seed_overflow} further outlier row(s) not emitted "
            f"(export-contract rows were emitted first)"
        )
    if misses:
        record_fid_misses(run_dir, "binary-siblings", misses)

    honesty = [
        ASYMMETRY_ONLY_NOTE,
        # The extractor's own note (single home) rides through the
        # matrix notes as well; repeated at top level for the report.
        _syntactic_note(),
        CLUSTERING_RECALL_NOTE,
    ]
    payload: dict[str, Any] = {
        "schema_version": 1,
        "mode": "siblings",
        "binary": manifest.binary_path,
        "binary_sha256": manifest.binary_sha256,
        "query": {
            "family": _esc(family) if family is not None else None,
            "auto": bool(auto),
            "min_cluster": int(min_cluster),
        },
        "substrate": graph.substrate,
        "substrate_notes": [_esc(n) for n in graph.notes],
        "family_sources": [_esc(s) for s in family_sources],
        "clusters": clusters,
        "asymmetries": all_rows,
        "export_contract_asymmetries": len(contract_rows),
        "hypothesis_seeds_emitted": len(seeds),
        "claim": "structural_lead_only",
        "honesty": honesty,
        "notes": [_esc(n) for n in notes],
    }

    hypotheses_payload: dict[str, Any] = {
        "schema_version": 1,
        "producer": "binary-siblings",
        "seeds": seeds,
    }
    stamp_provenance(payload, "binary-siblings", untrusted=True)
    stamp_provenance(
        hypotheses_payload, "binary-siblings", untrusted=True,
    )
    with run_artifacts_lock(run_dir):
        save_json(run_dir / CLUSTERS_FILENAME, payload)
        save_json(run_dir / HYPOTHESES_FILENAME, hypotheses_payload)
        (run_dir / REPORT_FILENAME).write_text(
            _render_report(payload), encoding="utf-8",
        )
    payload["artifacts"] = {
        "json": str(run_dir / CLUSTERS_FILENAME),
        "hypotheses": str(run_dir / HYPOTHESES_FILENAME),
        "report": str(run_dir / REPORT_FILENAME),
    }
    return payload


def _syntactic_note() -> str:
    from core.audit.binary_check_vectors import CHECKS_ARE_SYNTACTIC_NOTE
    return CHECKS_ARE_SYNTACTIC_NOTE


def _kind_of(group: Any) -> str:
    return str(getattr(group.sibling_type, "value", group.sibling_type))


def _escaped_matrix(vectors: GroupCheckVectors) -> dict[str, Any]:
    matrix = vectors.to_dict()
    matrix["check_keys"] = [_esc(k) for k in matrix["check_keys"]]
    for member in matrix["members"]:
        member["function"] = _esc(member["function"])
        member["checks"] = {
            _esc(k): v for k, v in member["checks"].items()
        }
        member["tiers"] = {
            _esc(k): v for k, v in member["tiers"].items()
        }
    matrix["notes"] = [_esc(n) for n in matrix["notes"]]
    return matrix


def _export_contract_rows(
    functions: list[dict[str, Any]],
    graph: Any,
    distinctive: set[str],
    callee_fids: dict[str, str],
    fid_by_function: dict[str, Any],
    decomp_texts: dict[str, str],
    decoded_compares: dict[str, list[Any]],
    min_cluster: int,
) -> list[dict[str, Any]]:
    """Export-contract consistency: length-cap / null-check presence
    compared across named export families (verb-prefix / paired-op
    formation over the exported functions only, via the same
    resolver). Same extraction layer, one implementation."""
    exported = [f for f in functions if f.get("is_exported")]
    if len(exported) < min_cluster:
        return []
    groups = [
        g for g in resolve_peer_groups(exported)
        if len(g.siblings) >= min_cluster
    ][:MAX_CLUSTERS_ANALYSED]
    rows: list[dict[str, Any]] = []
    for group in groups:
        vectors = extract_group_check_vectors(
            group,
            callees_by_function=graph.callees,
            distinctive_callees=distinctive or None,
            fid_by_function=fid_by_function,
            callee_fids=callee_fids,
            decomp_texts=decomp_texts,
            decoded_compares=decoded_compares,
        )
        rows.extend(
            row for row in _asymmetry_rows(
                group, vectors, "export_contract",
            )
            if row["property"] in (
                "length_cap_present", "null_check_present",
            )
        )
    return rows


# ── Report ────────────────────────────────────────────────────────────


def _mark(value: Any) -> str:
    if value is True:
        return "present"
    if value is False:
        return "absent"
    return "no evidence"


def _render_report(payload: dict[str, Any]) -> str:
    lines: list[str] = [
        f"# Sibling consistency — {md_inline(payload.get('binary'))}",
        "",
        f"Substrate: {md_inline(payload.get('substrate'))}",
        "",
        "## Claims and non-claims",
        "",
    ]
    lines.extend(f"- {md_inline(note)}" for note in payload["honesty"])
    for note in payload.get("substrate_notes") or []:
        lines.append(f"- ⚠️ {md_inline(note)}")
    for note in payload.get("notes") or []:
        lines.append(f"- ⚠️ {md_inline(note)}")
    lines.append("")

    for cluster in payload.get("clusters") or []:
        lines.append(f"## {md_inline(cluster['group_id'])}")
        lines.append("")
        lines.append(md_inline(cluster["description"]))
        lines.append("")
        matrix = cluster.get("matrix") or {}
        keys = matrix.get("check_keys") or []
        if keys:
            header = "| member | " + " | ".join(
                md_inline(k) for k in keys) + " |"
            lines.append(header)
            lines.append("|" + "---|" * (len(keys) + 1))
            for member in matrix.get("members") or []:
                cells = [
                    _mark(member.get("checks", {}).get(k))
                    for k in keys
                ]
                lines.append(
                    "| " + md_inline(member["function"]) + " | "
                    + " | ".join(cells) + " |"
                )
            lines.append("")
        if cluster.get("asymmetries"):
            for row in cluster["asymmetries"]:
                lines.append(
                    f"- **Outlier** [{md_inline(row['severity'])}] "
                    f"{md_inline(row['explanation'])}"
                )
                lines.append(f"  - Tier: {md_inline(row['evidence_tier'])}")
                lines.append(f"  - {md_inline(row['disproof'])}")
                lines.append(
                    f"  - {md_inline(row['alternative_explanations'])}"
                )
        else:
            lines.append(
                f"No asymmetry. {md_inline(cluster['consistent_note'])}"
            )
        lines.append("")

    contract = [
        row for row in payload.get("asymmetries") or []
        if row.get("kind") == "export_contract"
    ]
    if contract:
        lines.append("## Export-contract asymmetries")
        lines.append("")
        for row in contract:
            lines.append(
                f"- **{md_inline(row['property'])}** "
                f"{md_inline(row['explanation'])}"
            )
            lines.append(f"  - {md_inline(row['disproof'])}")
            lines.append(
                f"  - {md_inline(row['alternative_explanations'])}"
            )
        lines.append("")

    lines.append(
        f"Hypothesis seeds emitted: "
        f"{int(payload.get('hypothesis_seeds_emitted') or 0)} "
        f"({HYPOTHESES_FILENAME} — audit-intake hints; seeds never "
        f"mint findings)"
    )
    lines.append("")
    return "\n".join(lines)
