"""Cross-artifact hypothesis routing over the engagement ledger.

The ledger (:mod:`core.engagement.ledger`) knows every artifact in an
install-directory target, its content identity, its DT_NEEDED link
graph, and its corpus families. Sibling runs know things ABOUT those
artifacts — externally-produced hypothesis seeds, binary sink edges,
parser boundaries. This module joins the two: it collects candidate
hypotheses from four producer classes, resolves each candidate to the
ledger artifact it is ABOUT (content identity first, recorded name
fallback second), ranks and quota-allocates per artifact BEFORE any
file is written, and emits one intake-schema seed file per artifact::

    <output_dir>/routing/<artifact_id>.hypotheses.json

Each file is a ``{"seeds": [...]}`` document the audit's hypothesis
intake (:mod:`core.audit.hypothesis_intake`) loads verbatim via
``--hypothesis-seeds`` — the router mints NO new consumer seam.

Producer classes, strongest first (the quota rank order):

* ``sibling_hypotheses`` — ``sibling-hypotheses.json`` files from
  same-target sibling runs (discovered through
  :func:`core.orchestration.run_discovery.collect_sibling_runs`,
  validated by the intake's own loader).
* ``context_map_sinks`` — binary sink edges from sibling binary
  analysis (:func:`core.audit.binary_bridge.load_binary_bridge`).
* ``abi_facts`` — provider/consumer symbol overlap along the
  ledger's ``reverse_needed`` DT_NEEDED graph (a provider's exported
  symbol that an in-target consumer imports is a cross-module input
  boundary).
* ``corpus_facts`` — corpus-family rows crossed with parser
  boundaries, attributed only when exactly ONE artifact carries a
  file input channel (ambiguity refuses, recorded).

Why rank-then-quota (and never first-come): the intake accepts at
most :data:`core.audit.hypothesis_intake.MAX_SEED_RECORDS` records
per run, first-come. Writing candidates unranked would let a flood of
weak corpus templates push a strong sibling lead past the cap — so
the cap is enforced HERE, per artifact, with per-class floors and
rank-ordered redistribution. That only holds if ranking sees the
whole pool: sibling files are therefore validated at a raised
per-file loader bound (:data:`_LOADER_RECORDS_PER_FILE`, 5× the
intake cap) instead of the loader's own first-come acceptance cap,
and every loader skip is surfaced as a ``loader_*`` miss. A non-zero
overflow — beyond an artifact's quota or beyond the loader ceiling —
escalates to the engagement governor (``routing_saturated``) instead
of dropping silently.

Identity discipline: every routed seed carries the owner row's
``module_sha256`` (content hash alongside any build-id-derived fid —
a forged/copied identity value cannot survive the intake's
content-hash check), joins resolve by identity anchor first, and
name-fallback joins are counted per route in the routing report plus
the addrmap miss ledger.

Trust: candidate text originates in hostile artifacts and sibling
JSON. Everything embedded in claims is escaped and capped at mint;
report/terminal rendering carries only counts, minted ids, and
pre-escaped notes. The router is mechanical — no LLM, no dispatch, no
network, no subprocess of its own (the ELF fact extractors it calls
carry their own sandbox gates).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.audit.hypothesis_intake import (
    MAX_SEED_RECORDS,
    MAX_SEEDS_PER_FUNCTION,
    SEEDS_FILENAME,
    load_seed_files,
)
from core.engagement.ledger import (
    CLASS_CORPUS_FAMILY,
    is_artifact_id,
    load_ledger,
)
from core.json import save_json
from core.security.log_sanitisation import escape_nonprintable

logger = logging.getLogger(__name__)

#: Everything the router writes lives under this run-dir subdirectory.
ROUTING_DIR_NAME = "routing"
#: Per-run routing accounting (allocation, joins, misses, notes).
ROUTING_REPORT_FILENAME = "routing-report.json"
#: Per-artifact seed file suffix (prefix = the minted artifact id).
SEED_FILE_SUFFIX = ".hypotheses.json"

#: Producer classes in quota rank order (strongest evidence first —
#: redistribution of unused floor budget follows this order).
PRODUCER_CLASSES = (
    "sibling_hypotheses",
    "context_map_sinks",
    "abi_facts",
    "corpus_facts",
)

#: Per-class floor shares of the intake cap. Both directions: a
#: larger sibling share protects externally-validated leads but can
#: starve the mechanical producers on artifact-dense targets; smaller
#: lets template floods crowd out the strongest class. Floors only
#: bind under contention — an underfull class donates its slack in
#: rank order.
QUOTA_SHARES: dict[str, float] = {
    "sibling_hypotheses": 0.50,
    "context_map_sinks": 0.25,
    "abi_facts": 0.15,
    "corpus_facts": 0.10,
}

# Collection bounds. Each is a scan/flood guard, not a quality claim:
# the quota allocator (rank-ordered) decides what is WRITTEN.
_MAX_SIBLING_DIRS = 8
_MAX_SINK_EDGES_SCANNED = 400
_MAX_ABI_PROVIDERS = 8
_MAX_ABI_CONSUMERS_SAMPLED = 4
_MAX_ABI_SYMBOLS_PER_PROVIDER = 16
_MAX_CORPUS_FAMILIES = 4
_MAX_CORPUS_BOUNDARIES = 4
_MAX_CANDIDATES_PER_CLASS = 1000

#: Per-sibling-file loader bound for the router path. The intake's
#: loader truncates first-come at its acceptance cap — ranking AFTER
#: that truncation would let a file-initial run of junk records evict
#: every ranked signal seed below them before the allocator ever
#: runs. The router validates up to 5× the intake cap per file
#: (matching the per-class scan cap) and ranks over the full
#: validated pool; a file saturating THIS ceiling is counted
#: (``loader_over_cap``), reported per producer, and escalated as
#: ``routing_saturated`` — never a silent drop. Both directions:
#: raising it costs memory on hostile floods (records are
#: escape-capped, ~kB each); lowering it back toward the intake cap
#: reintroduces the intra-file eviction it exists to prevent.
_LOADER_RECORDS_PER_FILE = 5 * MAX_SEED_RECORDS

# Text caps mirror the intake's own load caps — the router writes
# what the intake will accept, so nothing is silently re-clipped.
_MAX_CLAIM_CHARS = 300
_MAX_TEXT_CHARS = 200


@dataclass
class _Candidate:
    """One routed hypothesis before allocation."""

    artifact_id: str
    producer: str
    rank: float
    seed: dict[str, Any]
    join: str  # "identity" | "name_fallback"


@dataclass
class _Collection:
    """Producer output: candidates plus join/miss accounting."""

    candidates: list[_Candidate] = field(default_factory=list)
    misses: dict[str, int] = field(default_factory=dict)
    miss_rows: list[dict[str, Any]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def miss(self, reason: str, row: dict[str, Any] | None = None) -> None:
        self.misses[reason] = self.misses.get(reason, 0) + 1
        if row is not None:
            row = dict(row)
            row["reason"] = reason
            self.miss_rows.append(row)


def _esc(value: Any, cap: int = _MAX_TEXT_CHARS) -> str:
    """Escape-and-cap for target/sibling-derived text at mint."""
    return escape_nonprintable(str(value))[:cap]


def _tier_rank(tier: str) -> int:
    """Relative strength of an evidence-tier string; 0 for unknown."""
    from core.evidence import TIER_RANK, EvidenceTier
    try:
        return TIER_RANK.get(EvidenceTier(tier), 0)
    except ValueError:
        return 0


def _valid_tier(tier: Any) -> str:
    from core.evidence import EvidenceTier
    if isinstance(tier, str):
        try:
            return EvidenceTier(tier).value
        except ValueError:
            return ""
    return ""


# ── Ledger resolution tables ─────────────────────────────────────────

@dataclass
class _ArtifactTables:
    """Owner-resolution tables over the ledger rows."""

    by_anchor: dict[str, dict[str, Any]]
    by_stem: dict[str, list[dict[str, Any]]]
    by_id: dict[str, dict[str, Any]]
    target_root: Path


def _artifact_tables(ledger: dict[str, Any]) -> _ArtifactTables:
    by_anchor: dict[str, dict[str, Any]] = {}
    anchor_dropped: set[str] = set()
    by_stem: dict[str, list[dict[str, Any]]] = {}
    by_id: dict[str, dict[str, Any]] = {}
    for row in ledger.get("rows") or []:
        if not isinstance(row, dict):
            continue
        artifact_id = row.get("artifact_id")
        if not isinstance(artifact_id, str) or not is_artifact_id(
            artifact_id,
        ):
            continue
        by_id.setdefault(artifact_id, row)
        ident = row.get("identity") or {}
        anchor = ident.get("anchor")
        if isinstance(anchor, str) and anchor:
            # Ambiguous anchors refuse identity joins entirely (the
            # ledger already demotes/flags collisions; the router
            # must not pick a side).
            if anchor in anchor_dropped:
                pass
            elif anchor in by_anchor and by_anchor[anchor] is not row:
                del by_anchor[anchor]
                anchor_dropped.add(anchor)
            else:
                by_anchor.setdefault(anchor, row)
        path_val = row.get("path")
        if isinstance(path_val, str) and path_val:
            stem = Path(path_val).stem
            if stem:
                by_stem.setdefault(stem, []).append(row)
    return _ArtifactTables(
        by_anchor=by_anchor,
        by_stem=by_stem,
        by_id=by_id,
        target_root=Path(str(ledger.get("target_root") or "")),
    )


def _row_sha(row: dict[str, Any]) -> str:
    sha = (row.get("identity") or {}).get("sha256")
    return sha if isinstance(sha, str) else ""


def _artifact_disk_path(
    row: dict[str, Any], target_root: Path,
) -> Path | None:
    """On-disk path for a target-walk row, containment-checked.

    The ledger's ``path`` values are self-produced relative paths,
    but the on-disk document is same-trust-domain-as-run-dir JSON —
    a tampered path must not read outside the target root.
    """
    if (row.get("provenance") or {}).get("origin") != "target_walk":
        return None
    rel = row.get("path")
    if not isinstance(rel, str) or not rel:
        return None
    try:
        candidate = (target_root / rel).resolve()
        candidate.relative_to(target_root.resolve())
    except (OSError, ValueError):
        return None
    return candidate if candidate.is_file() else None


# ── Producers ────────────────────────────────────────────────────────

def _resolve_owner(
    tables: _ArtifactTables,
    *,
    fid: str | None,
    module_sha256: str,
    file_key: str,
) -> tuple[dict[str, Any] | None, str, str]:
    """``(row, join_method, miss_reason)`` for one candidate.

    Identity first: a fid's anchor joins the ledger's identity
    anchors; a producer-asserted content hash that contradicts the
    resolved row's recorded hash refuses (``module_content_mismatch``
    — never falls to the name leg). Name fallback: a ``binary:<stem>``
    file key joins a UNIQUE row stem; ambiguity refuses.
    """
    if fid:
        from core.binary.addrmap import from_fid, module_anchor
        parsed = from_fid(fid)
        anchor = module_anchor(build_id=parsed[0]) if parsed else None
        row = tables.by_anchor.get(anchor) if anchor else None
        if row is not None:
            row_sha = _row_sha(row)
            if module_sha256 and row_sha and module_sha256 != row_sha:
                return None, "", "module_content_mismatch"
            return row, "identity", ""
    stem = ""
    if file_key.startswith("binary:"):
        stem = file_key.split(":", 1)[1]
    elif file_key:
        stem = Path(file_key).stem
    rows = tables.by_stem.get(stem, []) if stem else []
    if len(rows) == 1:
        row_sha = _row_sha(rows[0])
        if module_sha256 and row_sha and module_sha256 != row_sha:
            return None, "", "module_content_mismatch"
        return rows[0], "name_fallback", ""
    if len(rows) > 1:
        return None, "", "owner_ambiguous"
    return None, "", "owner_unknown"


def _sibling_candidates(
    output_dir: Path, tables: _ArtifactTables,
) -> _Collection:
    """Externally-produced hypothesis seeds from same-target siblings,
    re-validated through the intake's own loader (escape/caps/schema
    are the loader's, applied once here at collection)."""
    out = _Collection()
    try:
        from core.orchestration.run_discovery import collect_sibling_runs
        dirs = collect_sibling_runs(
            output_dir, SEEDS_FILENAME,
            exclude=output_dir,
            # An unset target_root must stay None — Path("") resolves
            # to the cwd and would gate siblings against the wrong
            # tree entirely.
            target_path=(
                tables.target_root
                if str(tables.target_root) not in ("", ".") else None
            ),
        )
    except Exception:  # noqa: BLE001 — discovery is an aid, never a gate
        logger.debug("routing: sibling discovery failed", exc_info=True)
        dirs = []
    if len(dirs) > _MAX_SIBLING_DIRS:
        out.notes.append(
            f"sibling scan capped at {_MAX_SIBLING_DIRS} of "
            f"{len(dirs)} candidate run dirs",
        )
        dirs = dirs[:_MAX_SIBLING_DIRS]
    for run_dir in dirs:
        # One loader call per sibling at the router's raised bound:
        # the loader's record cap is per-call, so a first sibling
        # flooding a shared cap — or a file-initial junk run eating
        # one file's cap — would starve ranked signal BEFORE the
        # allocator sees it. The loader's skip counters surface as
        # loader_* misses instead of being discarded.
        seeds, skips, _sources = load_seed_files(
            [Path(run_dir) / SEEDS_FILENAME],
            max_records=_LOADER_RECORDS_PER_FILE,
        )
        for reason, count in skips.items():
            if count:
                key = f"loader_{reason}"
                out.misses[key] = out.misses.get(key, 0) + count
        for seed in seeds:
            if len(out.candidates) >= _MAX_CANDIDATES_PER_CLASS:
                out.miss("class_scan_cap")
                break
            row, join, reason = _resolve_owner(
                tables,
                fid=seed.fid,
                module_sha256=seed.module_sha256,
                file_key=seed.file,
            )
            if row is None:
                out.miss(reason, {
                    "producer": "sibling_hypotheses",
                    "seed_id": seed.seed_id,
                    "file": seed.file,
                    **({"fid": seed.fid} if seed.fid else {}),
                })
                continue
            record: dict[str, Any] = {
                "file": seed.file,
                "claim": seed.claim,
            }
            if seed.function:
                record["function"] = seed.function
            if seed.address is not None:
                record["address"] = seed.address
            if seed.fid:
                record["fid"] = seed.fid
            record["module_sha256"] = seed.module_sha256 or _row_sha(row)
            if seed.disproof:
                record["disproof"] = seed.disproof
            if seed.evidence_tier:
                record["evidence_tier"] = seed.evidence_tier
            if seed.evidence:
                record["evidence"] = seed.evidence
            if seed.derived_from_target:
                record["derived_from_target"] = seed.derived_from_target
            out.candidates.append(_Candidate(
                artifact_id=row["artifact_id"],
                producer="sibling_hypotheses",
                rank=float(_tier_rank(seed.evidence_tier)),
                seed=record,
                join=join,
            ))
    return out


def _load_bridge(output_dir: Path, target_root: Path) -> Any:
    try:
        from core.audit.binary_bridge import load_binary_bridge
        return load_binary_bridge(
            output_dir,
            target_path=target_root if target_root.is_dir() else None,
        )
    except Exception:  # noqa: BLE001 — bridge is an aid, never a gate
        logger.debug("routing: binary bridge load failed", exc_info=True)
        return None


def _sink_candidates(bridge: Any, tables: _ArtifactTables) -> _Collection:
    """Binary sink edges from sibling analysis, one candidate per
    caller→sink edge at the artifact owning the analysed binary."""
    out = _Collection()
    edges = list(getattr(bridge, "sink_edges", None) or [])
    if len(edges) > _MAX_SINK_EDGES_SCANNED:
        out.notes.append(
            f"sink-edge scan capped at {_MAX_SINK_EDGES_SCANNED} of "
            f"{len(edges)} edges",
        )
        edges = edges[:_MAX_SINK_EDGES_SCANNED]
    anchor_cache: dict[str, str | None] = {}
    for edge in edges:
        if len(out.candidates) >= _MAX_CANDIDATES_PER_CLASS:
            out.miss("class_scan_cap")
            break
        caller = getattr(edge, "caller", "") or ""
        sink = getattr(edge, "sink", "") or ""
        binary_path = getattr(edge, "binary_path", "") or ""
        if not caller or not sink:
            out.miss("edge_incomplete")
            continue
        row = _owner_for_binary_path(binary_path, tables, anchor_cache)
        if row is None:
            out.miss("owner_unknown", {
                "producer": "context_map_sinks",
                "function": _esc(caller),
            })
            continue
        join = "identity" if anchor_cache.get(binary_path) else \
            "name_fallback"
        tier = _valid_tier(getattr(edge, "evidence_tier", ""))
        confidence = _esc(getattr(edge, "confidence", "") or "", 32)
        record: dict[str, Any] = {
            "file": f"binary:{Path(row.get('path') or '').stem}",
            "function": _esc(caller),
            "claim": _esc(
                f"binary analysis observed a call into sink "
                f"{_esc(sink, 80)}"
                + (f" (confidence {confidence})" if confidence else "")
                + " — verify the arguments reaching it are bounded "
                  "and attacker-independent",
                _MAX_CLAIM_CHARS,
            ),
            "disproof": (
                "show every argument to the sink call is derived from "
                "constants or validated lengths"
            ),
            "module_sha256": _row_sha(row),
            "derived_from_target": {"claim": True, "function": True},
        }
        if tier:
            record["evidence_tier"] = tier
        out.candidates.append(_Candidate(
            artifact_id=row["artifact_id"],
            producer="context_map_sinks",
            rank=float(_tier_rank(tier)),
            seed=record,
            join=join,
        ))
    return out


def _owner_for_binary_path(
    binary_path: str,
    tables: _ArtifactTables,
    anchor_cache: dict[str, str | None],
) -> dict[str, Any] | None:
    """Ledger row for a sibling artifact's recorded binary path —
    content identity when the file is still readable, stem fallback
    otherwise. The cache holds one identity probe per distinct path."""
    if binary_path not in anchor_cache:
        anchor: str | None = None
        try:
            from core.binary.addrmap import content_anchor
            anchor = content_anchor(binary_path)
        except Exception:  # noqa: BLE001 — hostile path costs one edge
            anchor = None
        anchor_cache[binary_path] = anchor
    anchor = anchor_cache[binary_path]
    if anchor:
        row = tables.by_anchor.get(anchor)
        if row is not None:
            return row
        # Identity probe succeeded but matches no ledger row: the
        # analysed binary is NOT one of this target's artifacts —
        # never fall through to a stem guess for it.
        return None
    stem = Path(binary_path).stem
    rows = tables.by_stem.get(stem, []) if stem else []
    return rows[0] if len(rows) == 1 else None


def _abi_candidates(
    ledger: dict[str, Any], tables: _ArtifactTables,
) -> _Collection:
    """Provider/consumer symbol overlap on the DT_NEEDED graph: a
    provider's exported symbol that an in-target consumer imports is
    a cross-module input boundary worth a hypothesis at the provider."""
    out = _Collection()
    from core.binary.elf import extract_elf_facts, parse_elf
    providers_seen: set[str] = set()
    provider_edges: dict[str, set[str]] = {}
    for entry in ledger.get("reverse_needed") or []:
        if not isinstance(entry, dict):
            continue
        provider_ids = entry.get("providers") or []
        consumer_ids = entry.get("consumers") or []
        if not provider_ids or not consumer_ids:
            continue
        for pid in provider_ids:
            if pid in tables.by_id:
                provider_edges.setdefault(pid, set()).update(
                    c for c in consumer_ids if c in tables.by_id
                )
    # Deterministic provider order: most in-target consumers first.
    ordered = sorted(
        provider_edges.items(), key=lambda kv: (-len(kv[1]), kv[0]),
    )
    for pid, consumer_ids in ordered:
        if len(providers_seen) >= _MAX_ABI_PROVIDERS:
            out.notes.append(
                f"abi scan capped at {_MAX_ABI_PROVIDERS} providers "
                f"of {len(ordered)}",
            )
            break
        providers_seen.add(pid)
        provider_row = tables.by_id[pid]
        provider_path = _artifact_disk_path(
            provider_row, tables.target_root,
        )
        if provider_path is None:
            out.miss("provider_unreadable")
            continue
        facts = extract_elf_facts(provider_path)
        exports = set(getattr(facts, "exports", None) or [])
        if not exports:
            out.miss("provider_no_exports")
            continue
        imported: set[str] = set()
        consumer_count = 0
        for cid in sorted(consumer_ids)[:_MAX_ABI_CONSUMERS_SAMPLED]:
            consumer_path = _artifact_disk_path(
                tables.by_id[cid], tables.target_root,
            )
            if consumer_path is None:
                continue
            meta = parse_elf(consumer_path)
            if meta is None:
                continue
            consumer_count += 1
            imported.update(getattr(meta, "imports", None) or set())
        shared = sorted(exports & imported)
        if not shared:
            out.miss("no_symbol_overlap")
            continue
        for symbol in shared[:_MAX_ABI_SYMBOLS_PER_PROVIDER]:
            if len(out.candidates) >= _MAX_CANDIDATES_PER_CLASS:
                out.miss("class_scan_cap")
                break
            sym = _esc(symbol)
            out.candidates.append(_Candidate(
                artifact_id=pid,
                producer="abi_facts",
                rank=float(len(consumer_ids)),
                seed={
                    "file": (
                        f"binary:"
                        f"{Path(provider_row.get('path') or '').stem}"
                    ),
                    "function": sym,
                    "claim": _esc(
                        f"exported symbol {sym} is imported by "
                        f"{consumer_count} in-target consumer(s) — "
                        "arguments cross a module boundary here; "
                        "verify the exported entry validates them",
                        _MAX_CLAIM_CHARS,
                    ),
                    "disproof": (
                        "show every in-target caller passes only "
                        "validated values, or the entry re-validates"
                    ),
                    "evidence_tier": "header_backed",
                    "module_sha256": _row_sha(provider_row),
                    "derived_from_target": {
                        "claim": True, "function": True,
                    },
                },
                join="identity",
            ))
    return out


def _corpus_candidates(
    ledger: dict[str, Any], bridge: Any, tables: _ArtifactTables,
) -> _Collection:
    """Corpus families × parser boundaries. Attribution is
    fail-closed: only when exactly ONE artifact carries a file input
    channel do family claims route to it — the bridge's boundary
    records carry no binary attribution of their own, and guessing
    between candidates would seed the wrong module."""
    out = _Collection()
    families = [
        row for row in ledger.get("rows") or []
        if isinstance(row, dict)
        and row.get("class") == CLASS_CORPUS_FAMILY
        and isinstance(row.get("family"), dict)
    ]
    boundaries = list(getattr(bridge, "parser_boundaries", None) or [])
    if not families or not boundaries:
        return out
    file_readers = [
        row for row in ledger.get("rows") or []
        if isinstance(row, dict) and any(
            f.get("feature") == "input_channels"
            and "file" in (f.get("value") or [])
            for f in row.get("exposure") or []
            if isinstance(f, dict)
        )
    ]
    if len(file_readers) != 1:
        out.notes.append(
            f"corpus attribution refused: {len(file_readers)} "
            "artifact(s) carry a file input channel (need exactly 1)",
        )
        out.miss("corpus_attribution_ambiguous")
        return out
    reader = file_readers[0]
    families.sort(
        key=lambda r: -(r["family"].get("member_count") or 0),
    )
    boundaries.sort(
        key=lambda b: -(getattr(b, "score", 0.0) or 0.0),
    )
    for fam_row in families[:_MAX_CORPUS_FAMILIES]:
        fam = fam_row["family"]
        key = _esc(fam.get("key") or "", 96)
        examples = fam.get("examples_escaped") or []
        example = _esc(examples[0], 80) if examples else ""
        count = fam.get("member_count") or 0
        for boundary in boundaries[:_MAX_CORPUS_BOUNDARIES]:
            if len(out.candidates) >= _MAX_CANDIDATES_PER_CLASS:
                out.miss("class_scan_cap")
                break
            function = _esc(getattr(boundary, "function", "") or "")
            if not function:
                continue
            ingress = _esc(
                getattr(boundary, "ingress_function", "") or "", 80,
            )
            out.candidates.append(_Candidate(
                artifact_id=reader["artifact_id"],
                producer="corpus_facts",
                rank=float(getattr(boundary, "score", 0.0) or 0.0),
                seed={
                    "file": (
                        f"binary:{Path(reader.get('path') or '').stem}"
                    ),
                    "function": function,
                    "claim": _esc(
                        f"target ships a corpus family {key} "
                        f"({count} member(s)"
                        + (f", e.g. {example}" if example else "")
                        + ") and this parser boundary"
                        + (f" (ingress {ingress})" if ingress else "")
                        + " is where such data plausibly enters — "
                          "verify malformed family members are "
                          "rejected before parsing",
                        _MAX_CLAIM_CHARS,
                    ),
                    "disproof": (
                        "show this boundary never consumes files of "
                        "this family's format"
                    ),
                    "evidence_tier": "heuristic",
                    "module_sha256": _row_sha(reader),
                    "derived_from_target": {
                        "claim": True, "function": True,
                    },
                },
                join="identity",
            ))
    return out


# ── Allocation (rank + quota BEFORE any write) ───────────────────────

def _allocate(
    candidates: list[_Candidate], cap: int,
) -> tuple[list[_Candidate], int, int, dict[str, int]]:
    """Rank + quota one artifact's candidates.

    Returns ``(written, over_cap, function_capped, by_class)``.
    Within each class, candidates order by rank (descending, stable).
    A per-function cap (the intake's own stamp discipline) applies
    first in class order; the class floors then bind only under
    contention, with slack redistributed in class rank order.

    Raises ``ValueError`` on a candidate whose producer class is not
    registered in :data:`PRODUCER_CLASSES` — an unregistered class
    has no floor share and would otherwise vanish from every counter
    (written / over_cap / by_class). A new producer (the q4
    carved-anomaly flip adds one) must register consciously.
    """
    by_class: dict[str, list[_Candidate]] = {
        cls: [] for cls in PRODUCER_CLASSES
    }
    for cand in candidates:
        pool = by_class.get(cand.producer)
        if pool is None:
            raise ValueError(
                f"unknown producer class {cand.producer!r} — "
                "register it in PRODUCER_CLASSES and QUOTA_SHARES "
                "before routing its candidates",
            )
        pool.append(cand)
    function_capped = 0
    per_function: dict[tuple[str, str], int] = {}
    for cls in PRODUCER_CLASSES:
        ranked = sorted(
            by_class.get(cls, []), key=lambda c: -c.rank,
        )
        kept: list[_Candidate] = []
        for cand in ranked:
            fn_key = (
                cand.seed.get("file") or "",
                cand.seed.get("function") or "",
            )
            seen = per_function.get(fn_key, 0)
            if cand.seed.get("function") and seen >= \
                    MAX_SEEDS_PER_FUNCTION:
                function_capped += 1
                continue
            per_function[fn_key] = seen + 1
            kept.append(cand)
        by_class[cls] = kept
    floors = {
        cls: int(cap * QUOTA_SHARES.get(cls, 0.0))
        for cls in PRODUCER_CLASSES
    }
    take: dict[str, int] = {}
    for cls in PRODUCER_CLASSES:
        take[cls] = min(len(by_class.get(cls, [])), floors[cls])
    remaining = cap - sum(take.values())
    for cls in PRODUCER_CLASSES:
        if remaining <= 0:
            break
        extra = min(len(by_class.get(cls, [])) - take[cls], remaining)
        if extra > 0:
            take[cls] += extra
            remaining -= extra
    written: list[_Candidate] = []
    over_cap = 0
    class_counts: dict[str, int] = {}
    for cls in PRODUCER_CLASSES:
        pool = by_class.get(cls, [])
        written.extend(pool[:take[cls]])
        over_cap += len(pool) - take[cls]
        if take[cls]:
            class_counts[cls] = take[cls]
    return written, over_cap, function_capped, class_counts


# ── Entry point ──────────────────────────────────────────────────────

def route_hypotheses(
    output_dir: Path | str,
    *,
    ledger: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Collect, resolve, rank, quota, and write routed seed files.

    Returns the routing report (also written to
    ``routing/routing-report.json``), or ``None`` when the output
    directory carries no engagement ledger — routing is an
    engagement-lane capability and refuses to guess artifacts
    without one.
    """
    out_dir = Path(output_dir)
    doc = ledger if ledger is not None else load_ledger(out_dir)
    if not isinstance(doc, dict) or not doc.get("rows"):
        logger.info(
            "routing: no engagement ledger under %s — nothing to "
            "route (run the ledger build first)", out_dir,
        )
        return None
    tables = _artifact_tables(doc)
    bridge = _load_bridge(out_dir, tables.target_root)
    collections: dict[str, _Collection] = {
        "sibling_hypotheses": _sibling_candidates(out_dir, tables),
        "context_map_sinks": _sink_candidates(bridge, tables),
        "abi_facts": _abi_candidates(doc, tables),
        "corpus_facts": _corpus_candidates(doc, bridge, tables),
    }

    per_artifact: dict[str, list[_Candidate]] = {}
    for coll in collections.values():
        for cand in coll.candidates:
            per_artifact.setdefault(cand.artifact_id, []).append(cand)

    routing_dir = out_dir / ROUTING_DIR_NAME
    artifacts_report: dict[str, dict[str, Any]] = {}
    written_by_class: dict[str, int] = {}
    over_cap_total = 0
    escalations = 0
    for artifact_id in sorted(per_artifact):
        if not is_artifact_id(artifact_id):  # pragma: no cover - producers resolve rows through the id-gated tables
            continue
        written, over_cap, function_capped, class_counts = _allocate(
            per_artifact[artifact_id], MAX_SEED_RECORDS,
        )
        seed_file = routing_dir / f"{artifact_id}{SEED_FILE_SUFFIX}"
        save_json(seed_file, {
            "generated_at": datetime.now(tz=timezone.utc).isoformat(),
            "producer": "core.engagement.router",
            "artifact_id": artifact_id,
            "seeds": [cand.seed for cand in written],
        })
        for cls, count in class_counts.items():
            written_by_class[cls] = written_by_class.get(cls, 0) + count
        artifacts_report[artifact_id] = {
            "written": len(written),
            "over_cap": over_cap,
            "function_capped": function_capped,
            "by_class": class_counts,
            "seed_file": str(
                seed_file.relative_to(out_dir),
            ),
        }
        over_cap_total += over_cap
        if over_cap > 0:
            # Saturation is a policy event, not a silent drop: the
            # governor's amendment trail records it durably (bounded
            # per kind by the governor itself).
            try:
                from core.engagement.governor import record_escalation
                if record_escalation(
                    out_dir,
                    kind="routing_saturated",
                    message=(
                        f"routing saturated on {artifact_id}: "
                        f"{over_cap} ranked candidate(s) beyond the "
                        f"{MAX_SEED_RECORDS}-seed intake cap dropped "
                        "after per-class quota"
                    ),
                ):
                    escalations += 1
            except Exception:  # noqa: BLE001 — escalation never fails routing
                logger.warning(
                    "routing: governor escalation failed",
                    exc_info=True,
                )

    producers_report: dict[str, dict[str, Any]] = {}
    notes: list[str] = []
    miss_rows: list[dict[str, Any]] = []
    for cls in PRODUCER_CLASSES:
        coll = collections[cls]
        joins = {"identity": 0, "name_fallback": 0}
        for cand in coll.candidates:
            joins[cand.join] = joins.get(cand.join, 0) + 1
        producers_report[cls] = {
            "candidates": len(coll.candidates),
            "written": written_by_class.get(cls, 0),
            "joins": joins,
            "misses": coll.misses,
        }
        notes.extend(coll.notes)
        miss_rows.extend(coll.miss_rows)
    loader_over_cap = sum(
        coll.misses.get("loader_over_cap", 0)
        for coll in collections.values()
    )
    if loader_over_cap > 0:
        # A seed file bigger than the per-file validation ceiling was
        # truncated BEFORE ranking — the residue was never allocated,
        # so it saturates routing the same way quota overflow does.
        notes.append(
            f"loader saturated: {loader_over_cap} record(s) beyond "
            f"the {_LOADER_RECORDS_PER_FILE}-record per-file "
            "validation ceiling were never ranked",
        )
        try:
            from core.engagement.governor import record_escalation
            if record_escalation(
                out_dir,
                kind="routing_saturated",
                message=(
                    f"routing loader saturated: {loader_over_cap} "
                    "seed record(s) beyond the "
                    f"{_LOADER_RECORDS_PER_FILE}-record per-file "
                    "validation ceiling were dropped before ranking"
                ),
            ):
                escalations += 1
        except Exception:  # noqa: BLE001 — escalation never fails routing
            logger.warning(
                "routing: governor escalation failed", exc_info=True,
            )
    if miss_rows:
        try:
            from core.binary.addrmap import record_fid_misses
            record_fid_misses(out_dir, "engagement-routing", miss_rows)
        except Exception:  # noqa: BLE001 — miss log never fails routing
            logger.warning("routing: miss recording failed",
                           exc_info=True)

    report: dict[str, Any] = {
        "schema_version": 1,
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        "producers": producers_report,
        "artifacts": artifacts_report,
        "over_cap_total": over_cap_total,
        "escalations": escalations,
        "notes": notes,
    }
    save_json(routing_dir / ROUTING_REPORT_FILENAME, report)
    logger.info(
        "routing: %d artifact(s) seeded, %d candidate(s) written, "
        "%d beyond quota%s — report at %s",
        len(artifacts_report),
        sum(a["written"] for a in artifacts_report.values()),
        over_cap_total,
        f" ({escalations} escalated)" if escalations else "",
        routing_dir / ROUTING_REPORT_FILENAME,
    )
    return report


__all__ = [
    "PRODUCER_CLASSES",
    "QUOTA_SHARES",
    "ROUTING_DIR_NAME",
    "ROUTING_REPORT_FILENAME",
    "SEED_FILE_SUFFIX",
    "route_hypotheses",
]
