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
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

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
) -> tuple[list[SeedRecord], dict[str, int], list[dict[str, str]]]:
    """Load and validate seed files.

    Returns ``(seeds, skip_counts, sources)``. Every failure mode is
    a counted skip, never an exception: the intake is an enrichment
    and a hostile or truncated file must cost only its own records.

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
            if len(seeds) >= MAX_SEED_RECORDS:
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


def _match_gap(
    seed: SeedRecord,
    by_name: dict[tuple[str, str], dict],
    by_addr: dict[tuple[str, int], dict],
) -> tuple[dict | None, str]:
    """Resolve one seed against the queue → ``(gap, miss_reason)``.

    The audit's real binary join is the ``binary:<stem>`` file
    sentinel plus the function's address (core.inventory.
    binary_builder — checklist items carry no fid), so address wins,
    then a non-placeholder name. Both keys are FILE-scoped: the same
    address in a different binary, or the same function name in a
    different file, is a miss, never a cross-file join. The seed's
    fid is identity metadata for producers/miss records; it grew no
    join key here because the queue side has none to compare against.

    Miss reasons are differentiated for the producer:
    ``address_name_conflict`` — the address key and the name key
    resolve to DIFFERENT gaps (a cross-base address collision would
    otherwise silently misdirect the claim; refusing keeps the trace
    visible), ``placeholder_name_refused`` — the only name offered is
    a tool-synthetic placeholder (actionable producer error: emit a
    real name or a checklist-space address), ``no_matching_gap`` —
    genuinely unknown to the queue.
    """
    addr_gap = None
    if seed.address is not None:
        addr_gap = by_addr.get((seed.file, seed.address))
    name_gap = None
    name_is_placeholder = bool(
        seed.function and _looks_placeholder(seed.function),
    )
    if seed.function and not name_is_placeholder:
        name_gap = by_name.get((seed.file, seed.function))
    if (
        addr_gap is not None
        and name_gap is not None
        and addr_gap is not name_gap
    ):
        return None, "address_name_conflict"
    if addr_gap is not None:
        return addr_gap, ""
    if name_gap is not None:
        return name_gap, ""
    if name_is_placeholder:
        return None, "placeholder_name_refused"
    return None, "no_matching_gap"


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
    keys: set[str] = set()
    for seed in seeds:
        entry, _reason = _match_gap(seed, by_name, by_addr)
        if entry is not None:
            keys.add(make_function_key(entry["file"], entry["name"]))
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

    ``checklist`` (rereview mode only, ignored otherwise): a seed
    that misses the gap queue is resolved against the checklist and,
    when its key already carries a completed seed-forced review in
    the run journal (:func:`_satisfied_rereview_keys`), counted as
    ``rereview_already_satisfied`` — honest accounting for resume
    segments — instead of a ``no_matching_gap`` miss. Satisfied
    seeds write NO ledger row: the join already succeeded once and
    was recorded; re-recording it every segment would accumulate a
    fid-misses operation per resume.
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
    rereview_scheduled = 0
    rereview_satisfied = 0
    conflicts = 0
    misses: list[dict[str, Any]] = []
    scheduled_rows: list[dict[str, Any]] = []
    # Rereview-mode satisfaction classifier: a queue-missing seed
    # whose checklist resolution lands on a key the run journal
    # already re-reviewed under this consent (completed seed_rereview
    # row) is "already satisfied", not a miss. Built once, only when
    # the caller passed the checklist under the flag.
    cl_by_name: dict = {}
    cl_by_addr: dict = {}
    satisfied_keys: set[str] = set()
    if rereview and checklist is not None and seeds:
        cl_by_name, cl_by_addr = _checklist_indexes(checklist)
        satisfied_keys = _satisfied_rereview_keys(Path(out_dir))
    if seeds:
        by_name, by_addr = _gap_indexes(gaps)
        for seed in seeds:
            gap, miss_reason = _match_gap(seed, by_name, by_addr)
            if gap is None:
                if (
                    miss_reason == "no_matching_gap"
                    and satisfied_keys
                ):
                    entry, _cl_reason = _match_gap(
                        seed, cl_by_name, cl_by_addr,
                    )
                    if entry is not None:
                        from core.coverage.journal import (
                            make_function_key,
                        )
                        if make_function_key(
                            entry["file"], entry["name"],
                        ) in satisfied_keys:
                            rereview_satisfied += 1
                            continue
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
                misses.append(miss)
                continue
            if rereview and gap.get("seed_rereview"):
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
    if rereview:
        # Third and fourth buckets, present only under the consent
        # flag so the flag-off receipt stays byte-identical to the
        # two-bucket intake. ``rereview_already_satisfied``: seeds
        # whose forced review this run already completed (resume
        # segments) — the key is back to normal covered semantics.
        summary["rereview_scheduled"] = rereview_scheduled
        summary["rereview_already_satisfied"] = rereview_satisfied
    if misses or scheduled_rows:
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
    if misses or scheduled_rows:
        # The addrmap miss ledger is the ONE place cross-tool join
        # residue lands (escape/clip/caps live there). The FULL miss
        # list goes in: the loader's record cap (MAX_SEED_RECORDS,
        # 200) keeps misses + scheduled rows under the ledger's own
        # per-operation cap (500), so the ledger's per-operation
        # count always equals this receipt's ``missed`` (plus
        # ``rereview_scheduled`` rows under the flag) — no divergence
        # under floods.
        try:
            from core.binary.addrmap import record_fid_misses
            record_fid_misses(
                Path(out_dir), "audit-seed-intake",
                misses + scheduled_rows,
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
                "%d missed (%d conflicts), skips=%s",
                len(seeds),
                ", ".join(s["path"] for s in sources)
                or "no readable source",
                matched, len(boosted), rereview_scheduled,
                rereview_satisfied, len(misses), conflicts, skips or {},
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
    return summary
