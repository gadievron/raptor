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
#: rationale together.
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
