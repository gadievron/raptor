"""Unified evidence primitives for RAPTOR.

Every finding, observation, and annotation across RAPTOR carries an
evidence tier that grades how close the observation is to ground truth.
This module is the canonical home for that vocabulary.

Tier ordering (strongest to weakest):
    OBSERVED_RUNTIME  — Frida/runtime instrumentation saw it happen
    REPLAYED_CRASH    — ASan/fuzz witness reproduced the bug
    SMT_PROVED        — Z3/SMT solver proved the constraint (un)satisfiable
    XREF_BACKED       — CPG/dataflow/call-graph structural guarantee
    HEADER_BACKED     — ELF/Mach-O headers, symbol tables, AST extraction
    DECOMPILER_INFERRED — decompiled pseudo-code (approximate)
    HEURISTIC         — LLM inference, naming heuristic, pattern match
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class EvidenceTier(str, Enum):
    """How close an observation is to ground truth."""

    OBSERVED_RUNTIME = "observed_runtime"
    REPLAYED_CRASH = "replayed_crash"
    SMT_PROVED = "smt_proved"
    XREF_BACKED = "xref_backed"
    HEADER_BACKED = "header_backed"
    DECOMPILER_INFERRED = "decompiler_inferred"
    HEURISTIC = "heuristic"


# Ordered strongest-to-weakest for comparison.
TIER_RANK: dict[EvidenceTier, int] = {
    EvidenceTier.OBSERVED_RUNTIME: 6,
    EvidenceTier.REPLAYED_CRASH: 5,
    EvidenceTier.SMT_PROVED: 4,
    EvidenceTier.XREF_BACKED: 3,
    EvidenceTier.HEADER_BACKED: 2,
    EvidenceTier.DECOMPILER_INFERRED: 1,
    EvidenceTier.HEURISTIC: 0,
}


def stronger(a: EvidenceTier, b: EvidenceTier) -> EvidenceTier:
    """Return whichever tier is closer to ground truth."""
    return a if TIER_RANK[a] >= TIER_RANK[b] else b


@dataclass(frozen=True)
class EvidenceRecord:
    """One mechanically attributable observation.

    ``confidence`` is intentionally a label, not a score. A consumer should
    not turn a heuristic into a proof by doing arithmetic over it.
    """

    id: str
    kind: str
    source: str
    summary: str
    tier: EvidenceTier
    confidence: str
    reproducible: bool
    tool: str
    location: Optional[str] = None
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "source": self.source,
            "summary": self.summary,
            "tier": self.tier.value,
            "confidence": self.confidence,
            "reproducible": self.reproducible,
            "tool": self.tool,
            "location": self.location,
            "data": dict(self.data),
        }


def evidence_id(binary_sha256: str, kind: str, source: str, data: Any) -> str:
    """Stable evidence id bound to the binary bytes and observation."""
    payload = json.dumps(
        {
            "binary_sha256": binary_sha256,
            "kind": kind,
            "source": source,
            "data": data,
        },
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8", "surrogateescape")
    return f"evidence:{hashlib.sha256(payload).hexdigest()[:20]}"


def make_evidence(
    binary_sha256: str,
    *,
    kind: str,
    source: str,
    summary: str,
    tier: EvidenceTier,
    confidence: str,
    reproducible: bool,
    tool: str,
    location: Optional[str] = None,
    data: Optional[dict[str, Any]] = None,
) -> EvidenceRecord:
    payload = dict(data or {})
    return EvidenceRecord(
        id=evidence_id(binary_sha256, kind, source, payload),
        kind=kind,
        source=source,
        summary=summary,
        tier=tier,
        confidence=confidence,
        reproducible=reproducible,
        tool=tool,
        location=location,
        data=payload,
    )


__all__ = [
    "EvidenceRecord",
    "EvidenceTier",
    "TIER_RANK",
    "evidence_id",
    "make_evidence",
    "stronger",
]
