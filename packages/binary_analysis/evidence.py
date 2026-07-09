"""Evidence primitives for black-box binary analysis.

The binary pipeline is deliberately stricter than a source-code map. A
decompiler can suggest a shape, but it cannot prove attacker control or a
trust-boundary bypass on its own. Every record emitted by this package carries
the observation that justified it and the strength of that observation.
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
    "evidence_id",
    "make_evidence",
]
