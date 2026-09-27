"""File-based hypothesis-seed intake for the audit orchestrator.

``sibling-hypotheses.json`` carries externally-produced hypothesis
seeds — claims about specific functions with evidence references and
a disproof recipe — into the audit's two EXISTING attention seams:

1. the gap-queue priority boost (the same bounded bump the
   understand-graph ``hypothesis_seeds`` consumer applies), and
2. the hint-tier review-context prompt block (rendered enveloped by
   ``core.audit.context``, following the injector discipline of
   ``packages.ghidra.context_inject``: every target-derived text
   field escaped and length-capped).

Seeds are HINTS, never verdicts: the LLM still forms and validates
hypotheses, tools still render verdicts, and a seed can never mint a
finding, suppress one, or resolve a function without review. The
pre-identified-finding lane remains ``packages.ghidra``'s bookmarks
bridge (operator-curated Ghidra bookmarks that enter as findings) —
this intake is deliberately NOT that lane.

Seed text originates outside the run (typically derived from a
hostile binary), so the loader treats every field as untrusted:
bounded file read, schema validation, escape-at-load, length caps,
strict fid normalisation via ``core.binary.addrmap`` (junk collapses
to absent), and per-reason skip counting. A junk file degrades to
"no seeds" — it never crashes the audit. Seeds naming functions the
gap queue does not know are recorded misses (``fid-misses.json``,
the addrmap miss ledger), never errors.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, NamedTuple

logger = logging.getLogger(__name__)

#: Co-located discovery name in the run's output directory (probed on
#: every run alongside any explicit ``--hypothesis-seeds`` paths).
SEEDS_FILENAME = "sibling-hypotheses.json"

#: Intake receipt written next to the seeds: per-source counts,
#: per-reason skip tallies, match/miss totals. The audit trail for
#: "where did this prompt hint come from".
INTAKE_SUMMARY_FILENAME = "hypothesis-seed-intake.json"

#: Per-file read ceiling. Both directions: larger admits bigger
#: producer artifacts but hands a planted file a memory/parse budget
#: on every run start; smaller starves nothing real — the record cap
#: below bounds useful content to well under 1 MiB, so 2 MiB reads
#: every legitimate file with headroom while capping a hostile one.
MAX_SEED_FILE_BYTES = 2 * 1024 * 1024

#: Total records accepted across ALL sources. Both directions: a
#: higher cap admits broader producer sweeps but lets a decoy-flooded
#: artifact steer more of the gap queue's boost budget and inflate
#: every matched function's prompt; lower risks dropping real seeds
#: from a large sibling analysis. 200 covers every observed producer
#: (sibling outlier sets are tens of rows) with room, while bounding
#: the flood to a fraction of any realistic gap queue.
MAX_SEED_RECORDS = 200

#: Seeds stamped onto one gap (the rest are counted, not stamped).
#: Both directions: more seeds per function give the reviewer more
#: leads but inflate that function's prompt linearly with
#: attacker-influenceable text; fewer starves multi-claim functions.
#: 8 matches the sibling injectors' per-section item discipline.
MAX_SEEDS_PER_FUNCTION = 8

#: Priority bump for a gap matched by at least one seed, applied at
#: most once per gap however many seeds match it (a flood of seeds
#: for one function must not compound into an unbounded queue jump).
#: SHARED with the understand-graph hypothesis_seeds boost — both
#: orchestrator sites add exactly this constant, and a value-pin test
#: holds the two-site contract (revisit only at both sites together).
#: What the bump actually does: both boosts land AFTER the sort that
#: fixes the budget cut, so a boosted gap's membership in the cut is
#: unchanged — the score steers review ORDER (the workqueue
#: topological tiebreak, subsystem grouping, schedule=priority) and
#: crosses the folded spec-inference request gate
#: (priority_score >= 0.7 in review-context assembly). Both
#: directions on NOT re-sorting after the boost: a post-boost re-sort
#: would let seeds displace unboosted gaps out of the budget cut —
#: raising a hostile producer's steering ceiling from order-only to
#: actual review-slot displacement — while the status quo caps seed
#: influence at "same work, earlier"; if a future series decides
#: seeds should move the cut, it must change BOTH sites and this
#: rationale together. ONE consented exception exists and it is NOT
#: this boost: under ``--seed-rereview`` (opt-in, default off) the
#: scheduled RE-REVIEW lane rides the --pin hoist, so on a bounded
#: run seed-scheduled functions claim budget slots first and CAN
#: displace never-reviewed gaps (recorded in not-attempted.json).
#: That displacement is operator-consented spend, bounded by
#: MAX_SEED_RECORDS (200), and flag-gated — with the flag off, and
#: at BOTH boost sites always, the no-displacement contract above
#: stands unchanged.
SEED_PRIORITY_BOOST = 10

# Text caps mirror the sibling injectors (context_inject clips
# comments at 300 and names at 200; the injected-hypotheses renderer
# clips mechanisms at 300). Escape-at-load + cap here, and the
# renderer re-caps at render time (defence in depth — a stamped gap
# dict is still mutable in-process).
_MAX_CLAIM_CHARS = 300
_MAX_DISPROOF_CHARS = 300
_MAX_TEXT_CHARS = 200
_MAX_FILE_CHARS = 512
_MAX_FUNCTION_CHARS = 256
_MAX_REFS_PER_SEED = 4

# Producer-asserted content identity of the module a seed's fid
# addresses: a full lowercase SHA-256 hex, nothing else. The strict
# shape mirrors normalise_fid's discipline — junk collapses to absent
# (counted), never rides into the join.
_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")

# Identity-join outcomes that refuse the WHOLE join (no name/address
# fallback): a content-hash contradiction or an ambiguous resolution
# must stop the seed, not reroute it — fallback after a refused
# identity would hand a forged anchor exactly the steering the check
# denied.
_FID_HARD_REFUSALS = frozenset({
    "module_content_mismatch", "fid_ambiguous_window", "fid_conflict",
})


@dataclass
class SeedRecord:
    """One validated, escaped, capped hypothesis seed."""

    seed_id: str
    source: str
    file: str
    claim: str
    function: str = ""
    address: int | None = None
    fid: str | None = None
    # Full SHA-256 of the module the producer minted the fid against
    # ("" = not asserted). When BOTH sides know the content hash and
    # they disagree, the join refuses outright — a matching anchor
    # over mismatched bytes is exactly the forged/copied build-id
    # shape, and falling back to a name join would hand the forger
    # the steering the anchor check just denied.
    module_sha256: str = ""
    disproof: str = ""
    evidence_tier: str = ""
    evidence: list[dict[str, str]] = field(default_factory=list)
    # Producer-declared provenance flags per text field. Recorded for
    # the audit trail; the prompt renderer envelopes claim/disproof
    # UNCONDITIONALLY (they are target-derived by construction — a
    # producer forgetting the flag must not skip the envelope).
    derived_from_target: dict[str, bool] = field(default_factory=dict)

    def stamp(self) -> dict[str, Any]:
        """The compact dict stamped onto a matched gap (rides into
        review context and, id+source only, into the journal)."""
        out: dict[str, Any] = {
            "id": self.seed_id,
            "source": self.source,
            "claim": self.claim,
        }
        if self.disproof:
            out["disproof"] = self.disproof
        if self.evidence_tier:
            out["tier"] = self.evidence_tier
        if self.evidence:
            out["evidence"] = self.evidence
        if self.derived_from_target:
            # Producer-declared provenance rides the stamp into
            # review context and the run artifacts — downstream
            # consumers can see WHICH fields the producer marked
            # target-derived (the renderer envelopes claim/disproof
            # regardless; these flags add audit-trail precision, not
            # trust).
            out["derived_from_target"] = self.derived_from_target
        return out


def _escape(value: Any, cap: int) -> str:
    """Escape-at-load for seed text: hostile bytes in any field must
    not reach prompts, terminals, or JSON artifacts raw."""
    from core.security.log_sanitisation import escape_nonprintable
    return escape_nonprintable(str(value))[:cap]


def _parse_address(value: Any) -> int | None:
    """Non-negative int from an int or a hex/decimal string; junk
    collapses to None (the record keeps its other join keys)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, str):
        text = value.strip().lower()
        try:
            parsed = int(text, 16) if text.startswith("0x") else int(text)
        except ValueError:
            return None
        return parsed if parsed >= 0 else None
    return None


def _valid_tiers() -> set[str]:
    from core.evidence import EvidenceTier
    return {tier.value for tier in EvidenceTier}


def _load_one_record(
    raw: Any, index: int, source: str, skips: dict[str, int],
) -> SeedRecord | None:
    """Validate one raw record; count the skip reason on refusal."""

    def _skip(reason: str) -> None:
        skips[reason] = skips.get(reason, 0) + 1

    if not isinstance(raw, dict):
        _skip("not_a_dict")
        return None
    file_val = raw.get("file")
    if not isinstance(file_val, str) or not file_val.strip():
        _skip("missing_file")
        return None
    claim = raw.get("claim")
    if not isinstance(claim, str) or not claim.strip():
        _skip("missing_claim")
        return None
    tier = raw.get("evidence_tier")
    tier_text = ""
    if tier is not None:
        # Fail-closed on grading: an unknown tier spelling is refused
        # rather than silently rendered as if it graded something —
        # a misspelt tier must surface at the producer, not launder
        # into the prompt as apparent evidence.
        if not isinstance(tier, str) or tier not in _valid_tiers():
            _skip("bad_tier")
            return None
        tier_text = tier

    # Strict fid normalisation (core.binary.addrmap): junk shapes
    # collapse to absent — the record survives on its other join keys
    # but the collapse is counted so a producer minting garbage fids
    # is visible in the intake receipt.
    fid = None
    if raw.get("fid") is not None:
        from core.binary.addrmap import normalise_fid
        fid = normalise_fid(raw.get("fid"))
        if fid is None:
            skips["fid_collapsed"] = skips.get("fid_collapsed", 0) + 1

    # Same collapse discipline for the content-hash assertion: a
    # malformed value is counted and dropped, the record survives on
    # its other keys (an over-strict refusal here would let a typo'd
    # hash silently strip a real seed's join keys too).
    module_sha256 = ""
    if raw.get("module_sha256") is not None:
        candidate = raw.get("module_sha256")
        if isinstance(candidate, str) and _SHA256_HEX_RE.fullmatch(
            candidate.strip().lower(),
        ):
            module_sha256 = candidate.strip().lower()
        else:
            skips["module_sha256_collapsed"] = (
                skips.get("module_sha256_collapsed", 0) + 1
            )

    evidence: list[dict[str, str]] = []
    refs = raw.get("evidence")
    if isinstance(refs, list):
        for ref in refs[:_MAX_REFS_PER_SEED]:
            if not isinstance(ref, dict):
                continue
            row: dict[str, str] = {}
            if ref.get("artifact"):
                row["artifact"] = _escape(ref["artifact"], _MAX_TEXT_CHARS)
            if ref.get("pointer"):
                row["pointer"] = _escape(ref["pointer"], _MAX_TEXT_CHARS)
            if row:
                evidence.append(row)

    flags_raw = raw.get("derived_from_target")
    flags: dict[str, bool] = {}
    if isinstance(flags_raw, dict):
        flags = {
            _escape(k, 32): bool(v)
            for k, v in list(flags_raw.items())[:8]
            if isinstance(k, str)
        }

    function = raw.get("function")
    return SeedRecord(
        seed_id=f"{source}#{index}",
        source=source,
        file=_escape(file_val.strip(), _MAX_FILE_CHARS),
        function=(
            _escape(function.strip(), _MAX_FUNCTION_CHARS)
            if isinstance(function, str) else ""
        ),
        address=_parse_address(raw.get("address")),
        fid=fid,
        module_sha256=module_sha256,
        claim=_escape(claim.strip(), _MAX_CLAIM_CHARS),
        disproof=(
            _escape(raw["disproof"].strip(), _MAX_DISPROOF_CHARS)
            if isinstance(raw.get("disproof"), str) else ""
        ),
        evidence_tier=tier_text,
        evidence=evidence,
        derived_from_target=flags,
    )


def load_seed_files(
    paths: list[Path],
    *,
    max_records: int = MAX_SEED_RECORDS,
) -> tuple[list[SeedRecord], dict[str, int], list[dict[str, str]]]:
    """Load and validate seed files.

    Returns ``(seeds, skip_counts, sources)``. Every failure mode is
    a counted skip, never an exception: the intake is an enrichment
    and a hostile or truncated file must cost only its own records.

    ``max_records`` bounds the validated pool per CALL, first-come
    (the residue is the ``over_cap`` skip). The default is the
    intake's own acceptance cap; a caller that ranks BEFORE capping
    (the engagement router) raises it so first-come truncation cannot
    evict ranked signal records — it stays a flood guard, never a
    quality claim.

    Each ``sources`` entry content-binds the receipt to what was
    actually read: ``{"id", "path", "sha256"}``, where ``id`` is
    ``<basename>@<path-hash8>`` — the path-derived component keeps two
    same-named files (out-dir co-located + an explicit sibling both
    called sibling-hypotheses.json) from minting colliding seed ids,
    and the file sha256 lets a reviewer verify which BYTES a receipt's
    claims were made about.
    """
    import hashlib

    from core.json import load_json

    seeds: list[SeedRecord] = []
    skips: dict[str, int] = {}
    sources: list[dict[str, str]] = []
    seen: set[str] = set()
    for path in paths:
        try:
            resolved = str(Path(path).resolve())
        except (OSError, ValueError):
            skips["unreadable_file"] = skips.get("unreadable_file", 0) + 1
            continue
        if resolved in seen:
            continue
        seen.add(resolved)
        path_h8 = hashlib.sha256(resolved.encode("utf-8")).hexdigest()[:8]
        source = (
            _escape(Path(path).name, _MAX_TEXT_CHARS) + "@" + path_h8
        )
        try:
            data = load_json(Path(path), max_bytes=MAX_SEED_FILE_BYTES)
        except (OSError, ValueError):
            data = None
        if data is None:
            skips["unreadable_file"] = skips.get("unreadable_file", 0) + 1
            logger.warning(
                "hypothesis-seed intake: %s unreadable or over the "
                "%d-byte bound — skipped", path, MAX_SEED_FILE_BYTES,
            )
            continue
        records = data.get("seeds") if isinstance(data, dict) else None
        if not isinstance(records, list):
            skips["bad_shape"] = skips.get("bad_shape", 0) + 1
            logger.warning(
                "hypothesis-seed intake: %s has no top-level 'seeds' "
                "list — skipped", path,
            )
            continue
        # Content hash of the consumed file, through the safe-read
        # chokepoint (bounded, symlink-refusing, regular-file-only —
        # the seed path is operator/producer-influenced). Best-effort
        # degrades: a re-read that fails, or a file that grew past
        # the load bound between the parse above and this hash
        # (TOCTOU), records an EMPTY hash rather than a misleading
        # prefix hash or a dropped source row.
        from core.source import read_bytes_capped
        capped = read_bytes_capped(Path(path), MAX_SEED_FILE_BYTES)
        if capped is not None and not capped[1]:
            file_sha = hashlib.sha256(capped[0]).hexdigest()
        else:
            file_sha = ""
        sources.append({
            "id": source,
            "path": _escape(resolved, _MAX_FILE_CHARS),
            "sha256": file_sha,
        })
        for index, raw in enumerate(records):
            if len(seeds) >= max_records:
                skips["over_cap"] = (
                    skips.get("over_cap", 0) + len(records) - index
                )
                break
            record = _load_one_record(raw, index, source, skips)
            if record is not None:
                seeds.append(record)
    return seeds, skips, sources


def discover_seed_paths(
    out_dir: Path,
    extra_paths: list[Path] | None = None,
) -> list[Path]:
    """Seed sources for a run: the co-located file (when present)
    plus every explicit ``--hypothesis-seeds`` path. Explicit paths
    are returned even when missing — the loader counts the miss so a
    typo'd flag surfaces in the intake receipt instead of vanishing."""
    paths: list[Path] = []
    co_located = Path(out_dir) / SEEDS_FILENAME
    if co_located.is_file():
        paths.append(co_located)
    for extra in extra_paths or []:
        paths.append(Path(extra))
    return paths


def _looks_placeholder(name: str) -> bool:
    """Tool-synthetic placeholder check via the single existing
    definition; unavailable = refuse the name as a join key
    (fail-closed — ``FUN_00401000`` is base-dependent, and matching
    it by name joins the claim to whatever function happens to carry
    that rendering here)."""
    try:
        from packages.ghidra.model import looks_tool_synthetic
    except ImportError:  # pragma: no cover - packages tree absent
        return True
    return looks_tool_synthetic(name)


def _gap_indexes(
    gaps: list[dict[str, Any]],
) -> tuple[dict[tuple[str, str], dict], dict[tuple[str, int], dict]]:
    """(file, name) and binary (file, address) lookup over the queue."""
    from core.inventory.binary_builder import is_binary_item

    by_name: dict[tuple[str, str], dict] = {}
    by_addr: dict[tuple[str, int], dict] = {}
    for gap in gaps:
        file_val = gap.get("file") or ""
        name = gap.get("name") or ""
        if file_val and name:
            by_name.setdefault((file_val, name), gap)
        if is_binary_item(gap):
            metadata = gap.get("metadata") or {}
            addr = metadata.get("address")
            if isinstance(addr, int) and not isinstance(addr, bool):
                by_addr.setdefault((file_val, addr), gap)
    return by_name, by_addr


class _JoinOutcome(NamedTuple):
    """One seed's resolution: the gap (or None), the miss reason,
    the join method that won (``fid`` / ``fid_fuzzy`` / ``address``
    / ``name`` / ``""``), and the fid leg's soft-failure state when
    the identity join could not run to completion (``""`` when the
    leg won, hard-refused, or never had a fid to try)."""

    gap: dict | None
    miss_reason: str
    method: str
    fid_state: str


def checklist_module_spaces(
    checklist: dict[str, Any] | None,
) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    """Identity-join spaces over the checklist's ``module_identity``
    blocks (stamped by ``core.inventory.binary_builder``).

    Returns ``(modules, file_sha)``:

    * ``modules``: anchor → ``{"file", "base", "sha256"}`` — the
      resolution table a fid's ``<anchor>:0x<rel>`` joins through.
      Anchors are normalised via ``module_anchor`` (the one prefix
      rule) so a fid minted from a full-length identity value joins
      the checklist's ≤16-hex anchor. Two files claiming the SAME
      anchor is exactly the copied/forged-identity shape — the anchor
      is dropped from the table entirely (fail-closed: an ambiguous
      identity must not steer either way) and the collision logged.
    * ``file_sha``: file path key → recorded content hash, for the
      producer-asserted ``module_sha256`` check on name/address joins.

    Checklists without identity blocks (source trees, pre-block
    binary checklists) yield empty spaces — every fid leg goes inert
    and behaviour is byte-identical to the name/address-only join.
    """
    modules: dict[str, dict[str, Any]] = {}
    dropped: set[str] = set()
    file_sha: dict[str, str] = {}
    if not isinstance(checklist, dict):
        return modules, file_sha
    from core.binary.addrmap import image_base, module_anchor
    for file_info in checklist.get("files", []) or []:
        if not isinstance(file_info, dict):
            continue
        fp = file_info.get("path", "") or ""
        if not fp:
            continue
        sha = file_info.get("sha256")
        if isinstance(sha, str) and _SHA256_HEX_RE.fullmatch(sha):
            file_sha.setdefault(fp, sha)
        block = file_info.get("module_identity")
        if not isinstance(block, dict):
            continue
        anchor = module_anchor(
            build_id=block.get("anchor")
            if isinstance(block.get("anchor"), str) else None,
        )
        if anchor is None or anchor in dropped:
            continue
        existing = modules.get(anchor)
        if existing is not None and existing["file"] != fp:
            del modules[anchor]
            dropped.add(anchor)
            logger.warning(
                "hypothesis-seed intake: module anchor collision — "
                "two checklist files share identity anchor %s; "
                "fid joins for it refused (fail-closed)", anchor,
            )
            continue
        entry_sha = block.get("value") if block.get("kind") == "sha256" \
            else file_info.get("sha256")
        modules.setdefault(anchor, {
            "file": fp,
            "base": image_base(block),
            "sha256": entry_sha if isinstance(entry_sha, str)
            and _SHA256_HEX_RE.fullmatch(entry_sha) else "",
        })
    return modules, file_sha


def _fid_leg(
    seed: SeedRecord,
    by_addr: dict[tuple[str, int], dict],
    modules: dict[str, dict[str, Any]],
) -> tuple[dict | None, str, str, str]:
    """The identity join: ``(gap, hard_refusal, method, soft_state)``.

    Resolution order mirrors ``core.binary.addrmap.FidIndex``: exact
    address hit, then a unique candidate inside the exclusive
    ``FID_FUZZY_WINDOW_BYTES`` window; two in-window candidates are
    ambiguous and HARD-refuse (``fid_ambiguous_window``). A
    producer-asserted ``module_sha256`` that contradicts the
    checklist's recorded content hash for the anchor's file
    HARD-refuses the whole join (``module_content_mismatch``) —
    matching anchor over mismatched bytes is the forged-identity
    shape, and no name fallback may run for it. Soft states
    (anchor unknown / no recorded base / address unknown) return the
    leg to the caller for name/address fallback WITH the state
    recorded.
    """
    from core.binary.addrmap import (
        FID_FUZZY_WINDOW_BYTES,
        from_fid,
        module_anchor,
    )
    parsed = from_fid(seed.fid)
    if parsed is None:
        return None, "", "", ""
    anchor = module_anchor(build_id=parsed[0])
    mod = modules.get(anchor) if anchor else None
    if mod is None:
        return None, "", "", "fid_anchor_unknown"
    if (
        seed.module_sha256 and mod["sha256"]
        and seed.module_sha256 != mod["sha256"]
    ):
        return None, "module_content_mismatch", "", ""
    if mod["base"] is None:
        return None, "", "", "fid_no_recorded_base"
    addr = mod["base"] + parsed[1]
    exact = by_addr.get((mod["file"], addr))
    if exact is not None:
        return exact, "", "fid", ""
    hits: list[dict] = []
    hit_ids: set[int] = set()
    for delta in range(1, FID_FUZZY_WINDOW_BYTES):
        for cand_addr in (addr - delta, addr + delta):
            cand = by_addr.get((mod["file"], cand_addr))
            if cand is not None and id(cand) not in hit_ids:
                hit_ids.add(id(cand))
                hits.append(cand)
    if len(hits) == 1:
        return hits[0], "", "fid_fuzzy", ""
    if len(hits) > 1:
        return None, "fid_ambiguous_window", "", ""
    return None, "", "", "fid_address_unknown"


def _match_gap(
    seed: SeedRecord,
    by_name: dict[tuple[str, str], dict],
    by_addr: dict[tuple[str, int], dict],
    *,
    modules: dict[str, dict[str, Any]] | None = None,
    file_sha: dict[str, str] | None = None,
) -> _JoinOutcome:
    """Resolve one seed against the queue → :class:`_JoinOutcome`.

    The IDENTITY join runs first (``modules`` — the checklist's
    ``module_identity`` anchor space, see :func:`_fid_leg`): a fid
    that resolves wins outright, may cross the seed's declared
    ``file`` (the anchor is authoritative; a producer's stale module
    NAME must not veto a content-identity match), and refuses hard on
    content-hash mismatch or in-window ambiguity. Then the historical
    file-scoped keys: address wins, then a non-placeholder name.
    Name/address keys are FILE-scoped: the same address in a
    different binary, or the same function name in a different file,
    is a miss, never a cross-file join.

    Miss reasons are differentiated for the producer:
    ``module_content_mismatch`` — the producer's asserted content
    hash contradicts the checklist's (fid leg, or a name/address join
    into a file whose recorded hash disagrees; no fallback runs),
    ``fid_ambiguous_window`` — two candidates inside the fuzzy
    window, ``fid_conflict`` — the identity join and the name/address
    keys resolve to DIFFERENT gaps, ``address_name_conflict`` — the
    address key and the name key disagree (a cross-base address
    collision would otherwise silently misdirect the claim),
    ``placeholder_name_refused`` — the only name offered is a
    tool-synthetic placeholder, ``no_matching_gap`` — genuinely
    unknown to the queue.
    """
    fid_gap = None
    fid_method = ""
    fid_state = ""
    if seed.fid and modules:
        fid_gap, hard, fid_method, fid_state = _fid_leg(
            seed, by_addr, modules,
        )
        if hard:
            return _JoinOutcome(None, hard, "", "")
    addr_gap = None
    if seed.address is not None:
        addr_gap = by_addr.get((seed.file, seed.address))
    name_gap = None
    name_is_placeholder = bool(
        seed.function and _looks_placeholder(seed.function),
    )
    if seed.function and not name_is_placeholder:
        name_gap = by_name.get((seed.file, seed.function))
    if fid_gap is not None:
        for other in (addr_gap, name_gap):
            if other is not None and other is not fid_gap:
                return _JoinOutcome(None, "fid_conflict", "", "")
        return _JoinOutcome(fid_gap, "", fid_method, "")
    if (
        addr_gap is not None
        and name_gap is not None
        and addr_gap is not name_gap
    ):
        return _JoinOutcome(None, "address_name_conflict", "", fid_state)
    chosen, method = (
        (addr_gap, "address") if addr_gap is not None
        else (name_gap, "name")
    )
    if chosen is not None:
        if seed.module_sha256 and file_sha:
            have = file_sha.get(seed.file, "")
            if have and have != seed.module_sha256:
                return _JoinOutcome(
                    None, "module_content_mismatch", "", "",
                )
        return _JoinOutcome(chosen, "", method, fid_state)
    if name_is_placeholder:
        return _JoinOutcome(None, "placeholder_name_refused", "", fid_state)
    return _JoinOutcome(None, "no_matching_gap", "", fid_state)


def _checklist_indexes(
    checklist: dict[str, Any],
) -> tuple[dict[tuple[str, str], dict], dict[tuple[str, int], dict]]:
    """(file, name) and binary (file, address) lookup over the FULL
    checklist inventory (every item, covered or not) — the re-review
    resolution space. Same key scheme as :func:`_gap_indexes`; one
    entry object per item feeds both indexes so the address/name
    conflict refusal in :func:`_match_gap` keeps working on identity."""
    from core.inventory.binary_builder import is_binary_item

    by_name: dict[tuple[str, str], dict] = {}
    by_addr: dict[tuple[str, int], dict] = {}
    for file_info in checklist.get("files", []) or []:
        fp = file_info.get("path", "") or ""
        if not fp:
            continue
        for item in file_info.get("items", file_info.get("functions", [])):
            if not isinstance(item, dict):
                continue
            name = item.get("name", "") or ""
            if not name:
                continue
            metadata = item.get("metadata") or {}
            entry = {"file": fp, "name": name}
            by_name.setdefault((fp, name), entry)
            addr = metadata.get("address")
            if addr is None:
                addr = item.get("address")
            probe = {"file": fp, "address": item.get("address")}
            if is_binary_item(probe) and isinstance(
                addr, int,
            ) and not isinstance(addr, bool):
                by_addr.setdefault((fp, addr), entry)
    return by_name, by_addr


def _satisfied_rereview_keys(out_dir: Path) -> set[str]:
    """``file:function`` keys whose run journal already holds a
    COMPLETED seed-forced re-review row.

    The ``seed_rereview`` row marker exists precisely for this: once
    the seed-forced fresh review has produced a settled verdict, the
    key returns to normal covered/verdict-reuse semantics — without
    this, every resume segment re-scheduled every seed (N seeds × M
    segments of repeated full-price reviews under ONE consent, the
    schedule head occupied ahead of residual progress). Error and
    dark verdicts do NOT satisfy — same retry discipline as the
    coverage fold — and edge rows never carry the marker's meaning
    for the function itself. Same trust domain as the rest of the
    run dir (the journal this run wrote); best-effort — an unreadable
    journal degrades to "nothing satisfied", never an error.
    """
    try:
        from core.coverage.journal import load_entries
        return {
            entry.key for entry in load_entries(Path(out_dir))
            if getattr(entry, "seed_rereview", None)
            and entry.verdict not in ("error", "dark")
            and not entry.edge_callee
        }
    except Exception:  # noqa: BLE001 — enrichment, never a gate
        logger.debug("seed-rereview satisfaction scan failed",
                     exc_info=True)
        return set()


def _completed_review_keys(out_dir: Path) -> set[str]:
    """``file:function`` keys with ANY completed review row in THIS
    run's journal.

    The default-mode resume classifier: an audit resumed into a new
    segment re-runs the intake against that segment's RESIDUAL gap
    queue, in which every already-reviewed function no longer exists.
    Without this set, a seed whose join succeeded in segment 1 (its
    target reviewed at the head of the schedule, boosted by the seed
    itself) re-ledgers on every resume as a JOIN failure — with a
    reason computed from the seed's name shape
    (``placeholder_name_refused`` for tool-synthetic names,
    ``no_matching_gap`` for real ones), both of which misdescribe
    "already reviewed" as producer error. Error and dark verdicts do
    NOT count — same retry discipline as the coverage fold — and
    edge rows never speak for the function itself. Same trust domain
    as the rest of the run dir; best-effort — an unreadable journal
    degrades to "nothing covered", never an error.
    """
    try:
        from core.coverage.journal import load_entries
        return {
            entry.key for entry in load_entries(Path(out_dir))
            if entry.verdict not in ("error", "dark")
            and not entry.edge_callee
        }
    except Exception:  # noqa: BLE001 — enrichment, never a gate
        logger.debug("completed-review key scan failed", exc_info=True)
        return set()


def rereview_candidate_keys(
    checklist: dict[str, Any],
    out_dir: Path,
    extra_paths: list[Path] | None = None,
) -> set[str]:
    """Resolve this run's seeds against the FULL checklist inventory.

    The ``--seed-rereview`` resolution pass: every seed that joins a
    checklist item (address wins, then a non-placeholder name — the
    exact :func:`_match_gap` semantics, including the conflict and
    placeholder refusals) contributes that item's
    ``make_function_key``. ``compute_gaps`` consumes the set as its
    ``seed_rereview_keys`` — a key the coverage/journal/reuse folds
    would have suppressed is un-suppressed and marked for a fresh,
    seed-forced review. A seed naming a function absent from the
    checklist resolves to nothing here and stays a recorded miss in
    the intake proper. Pure resolution: no boost, no stamp, no
    artifact — accounting stays in :func:`apply_hypothesis_seeds`.

    ONE fresh review per consent: keys whose run journal already
    holds a completed ``seed_rereview`` row are excluded
    (:func:`_satisfied_rereview_keys`), so resume segments do not
    re-buy the review the seed already forced. A NEW run (fresh out
    dir) with the flag is a new consent and schedules again.
    """
    from core.coverage.journal import make_function_key

    paths = discover_seed_paths(Path(out_dir), extra_paths)
    if not paths:
        return set()
    seeds, _skips, _sources = load_seed_files(paths)
    if not seeds:
        return set()
    by_name, by_addr = _checklist_indexes(checklist)
    modules, file_sha = checklist_module_spaces(checklist)
    keys: set[str] = set()
    for seed in seeds:
        outcome = _match_gap(
            seed, by_name, by_addr, modules=modules, file_sha=file_sha,
        )
        if outcome.gap is not None:
            keys.add(
                make_function_key(outcome.gap["file"], outcome.gap["name"]),
            )
    if keys:
        keys -= _satisfied_rereview_keys(Path(out_dir))
    return keys


def apply_hypothesis_seeds(
    gaps: list[dict[str, Any]],
    out_dir: Path,
    extra_paths: list[Path] | None = None,
    *,
    rereview: bool = False,
    checklist: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Load seeds, boost matched gaps, stamp review-context hints.

    Sources: the co-located ``sibling-hypotheses.json`` in *out_dir*
    plus any explicit paths. Returns the intake summary (also written
    to ``hypothesis-seed-intake.json``) or ``None`` when there is
    nothing to ingest. Never raises past its own logging — the caller
    treats the whole intake as best-effort.

    ``rereview`` (the ``--seed-rereview`` consent flag): seeds whose
    matched gap carries the ``seed_rereview`` marker (stamped by
    ``compute_gaps`` when the seed resolution un-suppressed a covered
    checklist function) are accounted in a third bucket —
    ``rereview_scheduled`` in the receipt, reason
    ``rereview_scheduled`` in the fid-miss ledger (join succeeded;
    the row keeps the resolved address as its audit trail) — instead
    of ``matched``. Stamp + boost semantics are identical to matched
    gaps: the claim/evidence context injects at the same review seam.
    With the flag off this function is behaviourally identical to the
    two-bucket intake (no marker can exist, the receipt carries no
    ``rereview_scheduled`` key, the log line keeps its shape).

    ``checklist``: a seed that misses the gap queue is resolved
    against the FULL checklist inventory (address wins, then a
    non-placeholder name — a tool-synthetic name rides its address
    here exactly as it does on the queue join). Resolution refines
    the accounting in BOTH modes:

    * key already reviewed by THIS run's journal
      (:func:`_completed_review_keys`) → counted in the
      ``already_covered`` receipt bucket, NO ledger row. This is the
      resume-segment shape: segment 1 matched the seed and reviewed
      its target; the segment-2 intake re-runs against the residual
      queue where the target no longer exists. Re-ledgering it as a
      join failure (reason computed from the seed's NAME shape —
      ``placeholder_name_refused`` / ``no_matching_gap``) misread
      "already reviewed" as producer error, one fid-misses operation
      per resume.
    * under ``rereview``, key with a completed seed-forced row
      (:func:`_satisfied_rereview_keys`) → the more specific
      ``rereview_already_satisfied`` bucket, checked first; also no
      ledger row.
    * resolves but never reviewed this run → the miss is kept, with
      the precise reason ``not_in_gap_queue`` (recognised by the
      checklist, suppressed or cut from this segment's queue) rather
      than a name-shape guess.
    * does not resolve → the queue join's reason stands
      (``no_matching_gap`` / ``placeholder_name_refused``).

    Without ``checklist`` the intake keeps the plain two-bucket
    accounting and the receipt carries no ``already_covered`` key.

    Identity joins: when the checklist carries ``module_identity``
    blocks, a seed's fid resolves through them FIRST (see
    :func:`_match_gap`) — exact, then fuzzy-window, refusing on
    content-hash mismatch or ambiguity. Seeds whose fid could not
    resolve still join by name/address (fallback recorded per route:
    the receipt's ``fid`` block and ``fid_fallback`` ledger rows),
    so producers minting unknown anchors surface without starving
    the intake. Fid-less seeds keep the receipt byte-identical.
    """
    paths = discover_seed_paths(out_dir, extra_paths)
    if not paths:
        # A prior segment's receipt must not survive its sources: a
        # co-located file deleted between runs would otherwise leave a
        # stale "loaded N, matched N" claim standing in the run dir.
        try:
            (Path(out_dir) / INTAKE_SUMMARY_FILENAME).unlink(
                missing_ok=True,
            )
        except OSError:
            logger.debug("stale intake receipt removal failed",
                         exc_info=True)
        return None

    seeds, skips, sources = load_seed_files(paths)
    boosted: set[int] = set()
    matched = 0
    already_covered = 0
    rereview_scheduled = 0
    rereview_satisfied = 0
    conflicts = 0
    misses: list[dict[str, Any]] = []
    scheduled_rows: list[dict[str, Any]] = []
    # Resume classifier: a queue-missing seed is resolved against the
    # FULL checklist inventory; a key the run journal already reviewed
    # is "already covered" (or, under the rereview consent, "already
    # satisfied" when the completed row carries the seed_rereview
    # marker), not a join failure. Built once, only when the caller
    # passed the checklist.
    cl_by_name: dict = {}
    cl_by_addr: dict = {}
    modules: dict[str, dict[str, Any]] = {}
    file_sha: dict[str, str] = {}
    satisfied_keys: set[str] = set()
    completed_keys: set[str] = set()
    if checklist is not None and seeds:
        cl_by_name, cl_by_addr = _checklist_indexes(checklist)
        modules, file_sha = checklist_module_spaces(checklist)
        completed_keys = _completed_review_keys(Path(out_dir))
        if rereview:
            satisfied_keys = _satisfied_rereview_keys(Path(out_dir))
    # Per-route fid accounting: how many seeds carried an identity,
    # how many the identity join RESOLVED (exact / fuzzy), how many
    # fell back to the name/address keys (fallback state recorded —
    # a producer minting anchors the checklist never earns must be
    # visible), and the per-reason fid misses.
    fid_seeds = 0
    fid_exact = 0
    fid_fuzzy = 0
    fid_fallback = 0
    fid_miss_reasons: dict[str, int] = {}
    fallback_rows: list[dict[str, Any]] = []
    if seeds:
        by_name, by_addr = _gap_indexes(gaps)
        for seed in seeds:
            if seed.fid:
                fid_seeds += 1
            gap, miss_reason, method, fid_state = _match_gap(
                seed, by_name, by_addr,
                modules=modules, file_sha=file_sha,
            )
            if gap is None:
                if (
                    miss_reason in (
                        "no_matching_gap", "placeholder_name_refused",
                    )
                    and (cl_by_name or cl_by_addr)
                ):
                    entry, _cl_reason, _cl_method, _cl_state = _match_gap(
                        seed, cl_by_name, cl_by_addr,
                        modules=modules, file_sha=file_sha,
                    )
                    if entry is not None:
                        from core.coverage.journal import (
                            make_function_key,
                        )
                        key = make_function_key(
                            entry["file"], entry["name"],
                        )
                        if key in satisfied_keys:
                            rereview_satisfied += 1
                            continue
                        if key in completed_keys:
                            already_covered += 1
                            continue
                        # Recognised by the checklist, absent from
                        # this segment's queue, no completed review:
                        # coverage-suppressed or budget-cut. The
                        # precise signal (vs the name-shape guesses
                        # above) — --seed-rereview is the lever that
                        # forces these open.
                        miss_reason = "not_in_gap_queue"
                # A seed the queue cannot place is a recorded miss,
                # never an error: entry-detection disagreements and
                # out-of-scope functions are expected residue of any
                # cross-tool join. The reason differentiates producer
                # errors (placeholder names, address/name conflicts)
                # from genuinely-unknown functions.
                if miss_reason == "address_name_conflict":
                    conflicts += 1
                miss: dict[str, Any] = {
                    "seed_id": seed.seed_id,
                    "file": seed.file,
                    "reason": miss_reason,
                }
                if seed.function:
                    miss["function"] = seed.function
                if seed.address is not None:
                    miss["address"] = f"{seed.address:#x}"
                if seed.fid:
                    miss["fid"] = seed.fid
                    fid_key = (
                        miss_reason
                        if miss_reason in _FID_HARD_REFUSALS
                        else (fid_state or "no_module_identity")
                    )
                    fid_miss_reasons[fid_key] = (
                        fid_miss_reasons.get(fid_key, 0) + 1
                    )
                if fid_state:
                    miss["fid_state"] = fid_state
                misses.append(miss)
                continue
            scheduled = bool(rereview and gap.get("seed_rereview"))
            fallback_state = ""
            if seed.fid:
                if method == "fid":
                    fid_exact += 1
                elif method == "fid_fuzzy":
                    fid_fuzzy += 1
                else:
                    # The identity leg did not resolve; the historical
                    # name/address key carried the join. Recorded, not
                    # refused — until every producer mints checklist-
                    # known anchors, name fallback keeps seeds flowing
                    # while the receipt shows the identity gap.
                    fid_fallback += 1
                    fallback_state = fid_state or "no_module_identity"
                    fid_miss_reasons[fallback_state] = (
                        fid_miss_reasons.get(fallback_state, 0) + 1
                    )
                    # Ledger rows only when an identity space EXISTED
                    # and this fid still failed it — a checklist with
                    # no module_identity blocks (source trees, legacy
                    # binary checklists) or a checklist-less intake
                    # must not flood fid-misses.json for every seed.
                    # ONE row per seed: a rereview-scheduled seed's
                    # row (below) carries the state instead.
                    if modules and not scheduled:
                        fallback_rows.append({
                            "seed_id": seed.seed_id,
                            "file": seed.file,
                            "reason": "fid_fallback",
                            "fid_state": fallback_state,
                            "fid": seed.fid,
                            "joined_via": method,
                        })
            if scheduled:
                # Seed-forced re-review (--seed-rereview): the gap
                # exists only because the resolution pass
                # un-suppressed a covered checklist function. The
                # join SUCCEEDED — record it in the ledger with the
                # resolved address, reason ``rereview_scheduled``,
                # never as a miss count.
                rereview_scheduled += 1
                row: dict[str, Any] = {
                    "seed_id": seed.seed_id,
                    "file": seed.file,
                    "reason": "rereview_scheduled",
                }
                if seed.function:
                    row["function"] = seed.function
                resolved_addr = seed.address
                if resolved_addr is None:
                    meta_addr = (gap.get("metadata") or {}).get("address")
                    if isinstance(meta_addr, int) and not isinstance(
                        meta_addr, bool,
                    ):
                        resolved_addr = meta_addr
                if resolved_addr is not None:
                    row["address"] = f"{resolved_addr:#x}"
                if seed.fid:
                    row["fid"] = seed.fid
                if fallback_state and modules:
                    row["fid_state"] = fallback_state
                scheduled_rows.append(row)
            else:
                matched += 1
            stamped = gap.setdefault("seed_hypotheses", [])
            if len(stamped) < MAX_SEEDS_PER_FUNCTION:
                stamped.append(seed.stamp())
            else:
                skips["stamp_cap"] = skips.get("stamp_cap", 0) + 1
            if id(gap) not in boosted:
                boosted.add(id(gap))
                gap["priority_score"] = (
                    gap.get("priority_score", 0) + SEED_PRIORITY_BOOST
                )

    summary: dict[str, Any] = {
        "schema_version": 1,
        "sources": sources,
        "loaded": len(seeds),
        "matched": matched,
        "boosted_gaps": len(boosted),
        "missed": len(misses),
        "conflicts": conflicts,
        "skipped": skips,
    }
    if checklist is not None:
        # Present only when the caller supplied the resolution space,
        # so checklist-less intakes keep the plain two-bucket receipt.
        summary["already_covered"] = already_covered
    if fid_seeds:
        # Per-route identity-join accounting, present only when a
        # seed actually carried a fid — fid-less intakes keep the
        # historical receipt shape byte-identical.
        summary["fid"] = {
            "seeds": fid_seeds,
            "joined_exact": fid_exact,
            "joined_fuzzy": fid_fuzzy,
            "name_fallback": fid_fallback,
            "misses": fid_miss_reasons,
        }
    if rereview:
        # Third and fourth buckets, present only under the consent
        # flag so the flag-off receipt stays byte-identical to the
        # two-bucket intake. ``rereview_already_satisfied``: seeds
        # whose forced review this run already completed (resume
        # segments) — the key is back to normal covered semantics.
        summary["rereview_scheduled"] = rereview_scheduled
        summary["rereview_already_satisfied"] = rereview_satisfied
    if misses or scheduled_rows or fallback_rows:
        # Pointer for reviewers: the per-miss records live in the
        # addrmap ledger, not in this receipt.
        from core.binary.addrmap import MISSES_FILENAME
        summary["misses_ledger"] = MISSES_FILENAME
    try:
        from core.json import save_json
        save_json(Path(out_dir) / INTAKE_SUMMARY_FILENAME, summary)
    except OSError:
        logger.warning("hypothesis-seed intake receipt write failed",
                       exc_info=True)
    if misses or scheduled_rows or fallback_rows:
        # The addrmap miss ledger is the ONE place cross-tool join
        # residue lands (escape/clip/caps live there). The FULL miss
        # list goes in: every seed contributes at most ONE row (miss,
        # scheduled, or fid-fallback — mutually exclusive), so the
        # loader's record cap (MAX_SEED_RECORDS, 200) keeps the total
        # under the ledger's per-operation cap (500) — the ledger's
        # per-operation count always equals this receipt's ``missed``
        # plus ``rereview_scheduled`` plus fid ``name_fallback``
        # counts, no divergence under floods.
        try:
            from core.binary.addrmap import record_fid_misses
            record_fid_misses(
                Path(out_dir), "audit-seed-intake",
                misses + scheduled_rows + fallback_rows,
            )
        except Exception:  # noqa: BLE001 — miss log never fails intake
            logger.warning("hypothesis-seed miss recording failed",
                           exc_info=True)
    if seeds or skips:
        # Operator-visible ingest banner naming the RESOLVED sources:
        # an external artifact just influenced review order and prompt
        # content, and a planted seed file must not be discoverable
        # only by reading the run dir. Paths are escaped at capture in
        # load_seed_files.
        if rereview:
            logger.info(
                "hypothesis-seed intake: %d external hypothesis seeds "
                "ingested from %s — %d matched (%d gaps boosted), "
                "%d scheduled for re-review, %d already satisfied, "
                "%d already covered this run, "
                "%d missed (%d conflicts), skips=%s",
                len(seeds),
                ", ".join(s["path"] for s in sources)
                or "no readable source",
                matched, len(boosted), rereview_scheduled,
                rereview_satisfied, already_covered,
                len(misses), conflicts, skips or {},
            )
        elif checklist is not None:
            logger.info(
                "hypothesis-seed intake: %d external hypothesis seeds "
                "ingested from %s — %d matched (%d gaps boosted), "
                "%d already covered this run, "
                "%d missed (%d conflicts), skips=%s",
                len(seeds),
                ", ".join(s["path"] for s in sources)
                or "no readable source",
                matched, len(boosted), already_covered,
                len(misses), conflicts, skips or {},
            )
        else:
            logger.info(
                "hypothesis-seed intake: %d external hypothesis seeds "
                "ingested from %s — %d matched (%d gaps boosted), "
                "%d missed (%d conflicts), skips=%s",
                len(seeds),
                ", ".join(s["path"] for s in sources)
                or "no readable source",
                matched, len(boosted), len(misses), conflicts, skips or {},
            )
    if fid_seeds:
        logger.info(
            "hypothesis-seed intake: identity joins — %d seed(s) "
            "carried a fid: %d resolved exact, %d fuzzy, %d joined by "
            "name/address fallback, fid misses=%s",
            fid_seeds, fid_exact, fid_fuzzy, fid_fallback,
            fid_miss_reasons or {},
        )
    return summary
