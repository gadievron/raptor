"""Evidence fusion for /audit context assembly.

Merges corroborating signals from different evidence sources into
single, stronger evidence items before injection into the LLM prompt.
When a contract violation and a negative-space flag both point at the
same call site, they fuse into one item with higher confidence.

Fusion rules:
- Same call site, same concern: merge descriptions, upgrade confidence
- Same function, complementary evidence: combine into evidence summary

There is NO contradiction detection: items grouped under the same
concern key are always merged as corroborating — opposing signals are
not flagged. If disagreement surfacing is ever needed, FusedEvidence
would need a polarity/contradiction field rendered by
to_prompt_section.

This reduces prompt size (fewer items) while increasing signal strength
(corroborated evidence is more trustworthy).
"""

from __future__ import annotations

import logging
import re as _re_module
from dataclasses import dataclass

from .evidence_grade import (
    Confidence,
    EvidenceSource,
    GradedEvidence,
)

_re_compile = _re_module.compile

logger = logging.getLogger(__name__)

_MAX_FUSED_ITEMS = 15


@dataclass
class FusedEvidence:
    """A fused evidence item from multiple sources."""

    description: str
    sources: list[EvidenceSource]
    confidence: Confidence
    corroboration_count: int
    detail: str | None = None

    def to_prompt_section(self) -> str:
        src_tags = ", ".join(
            s.value.split(":")[-1] for s in self.sources
        )
        return (
            f"- [{self.confidence.value.upper()}] "
            f"({src_tags}) {self.description}"
        )


def fuse_evidence(
    mechanical_evidence: list[GradedEvidence],
    spec_evidence: list[GradedEvidence],
    negative_space: list[GradedEvidence],
    contract_evidence: list[GradedEvidence],
    typestate_evidence: list[GradedEvidence],
) -> list[FusedEvidence]:
    """Fuse evidence from multiple capability sources.

    Groups by concern and merges corroborating signals. Two signals
    corroborate when they point at the same concern (same callee,
    same missing check, same state violation).
    """
    all_items: list[tuple[str, GradedEvidence]] = []

    for ev in mechanical_evidence:
        key = _extract_concern_key(ev)
        all_items.append((key, ev))
    for ev in spec_evidence:
        key = _extract_concern_key(ev)
        all_items.append((key, ev))
    for ev in negative_space:
        key = _extract_concern_key(ev)
        all_items.append((key, ev))
    for ev in contract_evidence:
        key = _extract_concern_key(ev)
        all_items.append((key, ev))
    for ev in typestate_evidence:
        key = _extract_concern_key(ev)
        all_items.append((key, ev))

    groups: dict[str, list[GradedEvidence]] = {}
    for key, ev in all_items:
        groups.setdefault(key, []).append(ev)

    fused: list[FusedEvidence] = []
    for key, group in groups.items():
        if len(group) == 1:
            ev = group[0]
            fused.append(FusedEvidence(
                description=ev.description,
                sources=[ev.source],
                confidence=ev.confidence,
                corroboration_count=1,
                detail=ev.detail,
            ))
        else:
            fused.append(_merge_group(group))

    fused.sort(key=lambda f: (
        {"high": 0, "medium": 1, "low": 2}.get(f.confidence.value, 3),
        -f.corroboration_count,
    ))

    return fused[:_MAX_FUSED_ITEMS]


def _merge_group(group: list[GradedEvidence]) -> FusedEvidence:
    """Merge a group of corroborating evidence items."""
    sources = list({ev.source for ev in group})
    descriptions = [ev.description for ev in group]
    details = [ev.detail for ev in group if ev.detail]

    has_mechanical = any(
        s.value.startswith("mechanical:")
        or s.value.startswith("dynamic:")
        for s in sources
    )
    has_llm = any(s.value.startswith("llm:") for s in sources)

    if has_mechanical:
        confidence = Confidence.HIGH
    elif has_llm and len(group) >= 2:
        confidence = Confidence.MEDIUM
    else:
        best = min(
            (ev.confidence for ev in group),
            key=lambda c: {"high": 0, "medium": 1, "low": 2}.get(c.value, 3),
        )
        confidence = best

    merged_desc = descriptions[0]
    if len(descriptions) > 1:
        extra = "; ".join(d for d in descriptions[1:] if d != merged_desc)
        if extra:
            merged_desc = f"{merged_desc} + {extra}"

    return FusedEvidence(
        description=merged_desc[:300],
        sources=sources,
        confidence=confidence,
        corroboration_count=len(group),
        detail="; ".join(details)[:200] if details else None,
    )


_CALL_SITE_RE = _re_compile(
    r"(?:at |line |:)(\d+)\b"
)
_CALLEE_RE = _re_compile(
    r"(?:calls?|callee|→|->)\s*[`'\"]?(\w+)[`'\"]?"
)


def _extract_concern_key(ev: GradedEvidence) -> str:
    """Extract a grouping key from evidence for fusion.

    Uses structural identity (file:line, callee name) when available
    in the evidence text, falling back to keyword matching.
    """
    desc = ev.description
    detail = ev.detail or ""
    combined = f"{desc} {detail}"
    lower = combined.lower()

    line_match = _CALL_SITE_RE.search(combined)
    callee_match = _CALLEE_RE.search(combined)
    if line_match and callee_match:
        return f"site:{callee_match.group(1)}@L{line_match.group(1)}"
    if callee_match:
        return f"callee:{callee_match.group(1)}"
    if line_match:
        return f"line:{line_match.group(1)}"

    for prefix in ("missing ", "no ", "absent "):
        if lower.startswith(prefix):
            return f"missing:{lower[len(prefix):50]}"

    for keyword in ("overflow", "injection", "xss", "sqli", "rce",
                     "double_free", "use_after_free", "null",
                     "format_string", "race", "toctou",
                     "auth", "authentication", "authorization"):
        if keyword in lower:
            return f"concern:{keyword}"

    return f"item:{desc[:50]}"


def format_fused_evidence(fused: list[FusedEvidence]) -> str:
    """Render fused evidence for the LLM prompt."""
    if not fused:
        return ""

    lines = ["### Pre-review evidence (fused)"]
    for item in fused:
        lines.append(item.to_prompt_section())
    return "\n".join(lines)


def compute_injection_priority(
    confidence: Confidence,
    is_corroborated: bool = False,
) -> int:
    """Compute the injection priority for a section.

    Returns a PromptSection priority value:
    - 0: never shed (high confidence or corroborated)
    - 1: shed last (medium confidence)
    - 2: shed under pressure (low confidence)
    """
    if confidence == Confidence.HIGH:
        return 0
    if confidence == Confidence.MEDIUM or is_corroborated:
        return 1
    return 2
