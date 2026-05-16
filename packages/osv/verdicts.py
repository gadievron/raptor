"""Oracle verdict types for CVE commit verification.

A verdict is the outcome of comparing a pipeline's pick
``(picked_slug, picked_sha)`` for a given ``cve_id`` against what
an external source (OSV, NVD) carries.

Verdicts are ordered by *confidence that we got the right answer*:

    MATCH_EXACT          — oracle has this exact (slug, sha); we're right.
    MATCH_RANGE          — oracle has our sha in a ranges.events.fixed
                           event; looser but still strong evidence.
    MIRROR_DIFFERENT_SLUG— same sha, different legitimate upstream slug
                           (e.g. ``bminor/glibc`` vs ``sourceware/glibc``).
                           Still counts as a pass (same commit content).
    DISPUTE              — oracle has a different sha for the same slug.
                           Our pick might be wrong, or the oracle might
                           be stale. Needs human triage.
    ORPHAN               — oracle has no commit data for this CVE.
                           Unverifiable; don't penalize.
    LIKELY_HALLUCINATION — oracle has commits, ours isn't among them.
                           Strong signal that we picked a plausible-
                           looking-but-wrong SHA.

``LIKELY_HALLUCINATION`` is the failure class the SHA-existence
invariant (commit_exists) cannot catch: a SHA that exists in *some*
repo but not the one associated with the CVE.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Verdict(str, Enum):
    MATCH_EXACT = "match_exact"
    MATCH_RANGE = "match_range"
    MIRROR_DIFFERENT_SLUG = "mirror_different_slug"
    DISPUTE = "dispute"
    ORPHAN = "orphan"
    LIKELY_HALLUCINATION = "likely_hallucination"

    @property
    def is_pass(self) -> bool:
        return self in (Verdict.MATCH_EXACT, Verdict.MATCH_RANGE, Verdict.MIRROR_DIFFERENT_SLUG)


@dataclass(frozen=True, slots=True)
class OracleVerdict:
    """Per-CVE verdict with the evidence that drove it."""

    cve_id: str
    picked_slug: str
    picked_sha: str
    verdict: Verdict
    source: str             # "osv" | "nvd" | "none"
    expected_slugs: tuple[str, ...] = field(default_factory=tuple)
    expected_shas: tuple[str, ...] = field(default_factory=tuple)
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "picked_slug": self.picked_slug,
            "picked_sha": self.picked_sha,
            "verdict": self.verdict.value,
            "source": self.source,
            "expected_slugs": list(self.expected_slugs),
            "expected_shas": list(self.expected_shas),
            "notes": self.notes,
            "is_pass": self.verdict.is_pass,
        }
