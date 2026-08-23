"""Rank witnesses by how well they match a given finding.

Stage E (and any future consumer that wants "the most relevant
witness for this finding") needs to pick from the witness set
discovered by :mod:`core.witness.discovery`. The matching is
purely structural — no LLM judgment — driven by the
``outcome_detail`` fields the witness producers populate.

Ranking (higher score → better match):

  10  Exact finding-id match
       ``outcome_detail["finding_id"] == finding.id``
       The producer (e.g. crash_agent / agent.py) recorded this
       witness specifically for this finding.

  7   CWE + file match
       ``outcome_detail["cwe_id"] == finding.cwe_id`` AND
       ``outcome_detail["file_path"] == finding.file``
       Same bug class, same source file — strong proxy when ids
       differ (e.g. /fuzz witness vs /validate finding-id).

  4   File match
       ``outcome_detail["file_path"] == finding.file``
       Same source file, possibly different CWE — useful when
       one file has multiple findings.

  2   Same target binary
       The witness's ``target_binary_hash`` EQUALS the finding's
       binary content hash — computed from the ON-DISK binary at the
       finding's ``binary_path`` when it exists and is readable
       (streamed SHA-256, bounded); a declared hash field on the
       finding/feasibility record is only consulted when no on-disk
       hash is obtainable (declared fields are copy-paste
       satisfiable, so they never override — and never rescue — the
       on-disk content). Fuzz witnesses lean on this (no
       source-level ids — they were produced before any LLM
       classification). When the finding side has no hash and no
       readable binary, this criterion awards nothing.

  0   No structured signal
       Falls through; consumer can still use the witness as a
       last-resort but should treat the verdict cautiously.

Ties broken by:

  1. Source preference: ``LLM_EMIT_RUN`` > ``FUZZ`` > others
     (LLM emit was synthesised against the finding's bug class
     explicitly; fuzz is generic crash evidence).
  2. Observed-outcome richness: ``SANITIZER_REPORT`` >
     ``EXIT_SIGNAL`` > others (sanitizer reports identify the
     bug class; raw signals are correct but less specific).
  3. ``bytes_hash`` lex order (deterministic tie-breaker).

Note: the score thresholds are deliberately conservative. A
finding may have zero matches — that's a "no witness available"
signal, not an error.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from collections.abc import Iterable

from core.witness.types import Witness, WitnessOutcome, WitnessSource

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class WitnessMatch:
    """A scored witness candidate for a given finding."""
    witness: Witness
    store_root: Any  # Path, but Any to avoid import cycle
    score: int
    reason: str

    @property
    def is_real(self) -> bool:
        """True iff the match score is above the "no structured
        signal" threshold. Consumers may want to skip score-0
        matches entirely."""
        return self.score > 0


def _source_priority(src: WitnessSource) -> int:
    if src is WitnessSource.LLM_EMIT_RUN:
        return 2
    if src is WitnessSource.FUZZ:
        return 1
    return 0


def _outcome_priority(outcome: WitnessOutcome) -> int:
    if outcome is WitnessOutcome.SANITIZER_REPORT:
        return 3
    if outcome is WitnessOutcome.EXIT_SIGNAL:
        return 2
    if outcome is WitnessOutcome.FLAG_CAPTURED:
        return 4  # rare but most-specific
    return 1


def score_witness_for_finding(
    witness: Witness,
    finding: dict[str, Any],
) -> tuple[int, str]:
    """Return ``(score, reason)`` for one witness against one
    finding. Consumers loop this over a witness list and pick
    the maxima via :func:`best_match_for_finding`."""
    detail = witness.outcome_detail if isinstance(witness.outcome_detail, dict) else {}

    finding_id = finding.get("id")
    finding_cwe = finding.get("cwe_id") or finding.get("cwe")
    finding_file = finding.get("file") or finding.get("file_path")
    binary_path = _finding_binary_path(finding)

    if finding_id and detail.get("finding_id") == finding_id:
        return 10, "exact finding-id match"

    if (finding_cwe and detail.get("cwe_id") == finding_cwe
            and finding_file and detail.get("file_path") == finding_file):
        return 7, "cwe + file match"

    if finding_file and detail.get("file_path") == finding_file:
        return 4, "file match"

    # Binary-hash fallback for fuzz witnesses (no finding_id /
    # source structure). Awards ONLY on actual hash equality: the
    # old "hash-pending" rule scored 2 whenever both sides were
    # merely truthy, so any witness with any binary hash matched
    # any finding that named any binary path. The ON-DISK content
    # hash is authoritative when obtainable — a declared hash field
    # is copy-paste satisfiable, so it is consulted only when no
    # on-disk hash exists and never awards against a contradicting
    # on-disk hash.
    if witness.target_binary_hash:
        witness_hash = str(witness.target_binary_hash).lower()
        on_disk = _on_disk_binary_hash(binary_path)
        if on_disk is not None:
            if on_disk.lower() == witness_hash:
                return 2, "same target binary (on-disk hash match)"
        else:
            declared = _declared_binary_hash(finding)
            if declared and declared.lower() == witness_hash:
                return 2, "same target binary (hash match)"

    return 0, "no structured signal"


# (path, mtime, size) → sha256 — scoring loops every witness against
# every finding, so the same binary would otherwise be re-hashed per
# pair.
_binary_hash_memo: dict[tuple[str, float, int], str] = {}

# Bound on the on-disk hash read. Streamed in 1 MiB chunks (bounded
# memory); anything past this cap is not a plausible target binary and
# only serves to stall the scoring loop — treated as unhashable.
_MAX_BINARY_HASH_BYTES = 1 << 30


def _finding_binary_path(finding: dict[str, Any]) -> str | None:
    """The finding side's binary path (finding or feasibility record)."""
    value = finding.get("binary_path")
    if isinstance(value, str) and value:
        return value
    feasibility = finding.get("feasibility")
    if isinstance(feasibility, dict):
        value = feasibility.get("binary_path")
        if isinstance(value, str) and value:
            return value
    return None


def _declared_binary_hash(finding: dict[str, Any]) -> str | None:
    """A DECLARED hash field on the finding / feasibility record.

    Copy-paste satisfiable — only usable when no on-disk hash is
    obtainable, and never against a contradicting on-disk hash.
    """
    feasibility = finding.get("feasibility")
    containers = [finding]
    if isinstance(feasibility, dict):
        containers.append(feasibility)
    for container in containers:
        for key in ("target_binary_hash", "binary_sha256", "binary_hash"):
            value = container.get(key)
            if isinstance(value, str) and value:
                return value
    return None


def _on_disk_binary_hash(binary_path: str | None) -> str | None:
    """SHA-256 of the ON-DISK binary at *binary_path*, or None.

    Streamed, bounded read. None when the path is absent, unreadable,
    or implausibly large (the caller may then fall back to a declared
    hash field).
    """
    if not binary_path:
        return None
    try:
        p = Path(binary_path)
        st = p.stat()
        if st.st_size > _MAX_BINARY_HASH_BYTES:
            logger.debug(
                "witness matching: finding binary %s exceeds the "
                "%d-byte hash bound — treating as unhashable",
                binary_path, _MAX_BINARY_HASH_BYTES,
            )
            return None
        memo_key = (str(p), st.st_mtime, st.st_size)
        cached = _binary_hash_memo.get(memo_key)
        if cached:
            return cached
        h = hashlib.sha256()
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        digest = h.hexdigest()
        _binary_hash_memo[memo_key] = digest
        return digest
    except OSError:
        logger.debug(
            "witness matching: cannot hash finding binary %s",
            binary_path, exc_info=True,
        )
        return None


def best_match_for_finding(
    witnesses: Iterable[tuple[Any, Witness]],
    finding: dict[str, Any],
) -> WitnessMatch | None:
    """Pick the best-ranked witness for ``finding`` from an
    iterable of ``(store_root, Witness)`` pairs.

    Returns ``None`` when no candidate scores above 0 (i.e. no
    structured signal — caller should treat as "no witness").

    Tie-break order: source > outcome > bytes_hash. See module
    docstring for rationale.
    """
    candidates: list[WitnessMatch] = []
    for store_root, w in witnesses:
        score, reason = score_witness_for_finding(w, finding)
        if score == 0:
            continue
        candidates.append(WitnessMatch(
            witness=w, store_root=store_root,
            score=score, reason=reason,
        ))

    if not candidates:
        return None

    candidates.sort(
        key=lambda m: (
            -m.score,
            -_source_priority(m.witness.source),
            -_outcome_priority(m.witness.observed_outcome),
            m.witness.bytes_hash,
        ),
    )
    return candidates[0]
