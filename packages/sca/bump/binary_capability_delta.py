"""SCA bump capability-delta finding wrapper.

The substrate (``CapabilityDelta`` + ``diff_binary_capabilities``)
lives at :mod:`core.binary.capability_diff` — consumer-agnostic.
This module wraps a delta in the SCA-specific
:class:`SupplyChainFinding` shape so the bump pipeline's verdict
ladder can consume it.

When the target binary adds dangerous capability buckets that
current didn't have:
  * adds exec or network capability → severity ``high``
    (RCE / exfil-flavoured)
  * adds any other dangerous capability → severity ``medium``

The verdict ladder then:
  * high alone → Block
  * two mediums → Block (compound red flag)

Co-Authored-By: Natalie Somersall <natalie.somersall@gmail.com>
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.binary import diff_binary_capabilities
from ..models import (
    Confidence,
    Dependency,
    PinStyle,
    Severity,
    SupplyChainFinding,
)

logger = logging.getLogger(__name__)


def binary_capability_delta_finding(
    *,
    ecosystem: str,
    name: str,
    current_version: str,
    target_version: str,
    current_binary: Path,
    target_binary: Path,
) -> Optional[SupplyChainFinding]:
    """Run the capability diff via :mod:`core.binary` and wrap a
    finding when target adds dangerous capabilities. Returns
    ``None`` when:

      * radare2 unavailable / binaries unanalysable (detector
        gracefully skipped)
      * no new dangerous capabilities (empty delta)
    """
    delta = diff_binary_capabilities(current_binary, target_binary)
    if delta is None or delta.is_empty():
        return None

    severity: Severity = "high" if delta.high_severity() else "medium"
    buckets_added = delta.added_buckets()
    detail_parts: List[str] = []
    if buckets_added:
        detail_parts.append(
            "new dangerous-import buckets: "
            + ", ".join(buckets_added)
        )
    detail = "; ".join(detail_parts)

    placeholder_dep = Dependency(
        ecosystem=ecosystem,
        name=name,
        version=target_version,
        declared_in=Path("/<bump>"),
        scope="main",
        is_lockfile=False,
        pin_style=PinStyle.EXACT,
        direct=True,
        purl=f"pkg:{ecosystem.lower()}/{name}@{target_version}",
        parser_confidence=Confidence(
            "high",
            reason="bump-evaluator synthetic dep",
        ),
    )

    # Evidence shape mirrors ``image_capability_drift`` where the
    # field names overlap (added_buckets / new_dangerous_imports)
    # so consumers can reason about both signals identically, plus
    # bump-specific context (versions) and the fingerprint
    # identifiers for each side so downstream tooling can correlate
    # against the SBOM ``raptor:cap_fp:*`` properties.
    evidence: Dict[str, Any] = {
        "current_version": current_version,
        "target_version": target_version,
        "current_binary": str(current_binary),
        "target_binary": str(target_binary),
        "new_dangerous_imports": delta.new_dangerous_imports,
        "added_buckets": buckets_added,
    }
    cur_fp = delta.current_fingerprint
    tgt_fp = delta.target_fingerprint
    if cur_fp is not None:
        evidence["current_fingerprint"] = {
            "binary_sha256": cur_fp.binary_sha256,
            "buckets": sorted(cur_fp.capability_buckets.keys()),
            "arch": cur_fp.arch,
            "bits": cur_fp.bits,
            "format": cur_fp.binary_format,
        }
    if tgt_fp is not None:
        evidence["target_fingerprint"] = {
            "binary_sha256": tgt_fp.binary_sha256,
            "buckets": sorted(tgt_fp.capability_buckets.keys()),
            "arch": tgt_fp.arch,
            "bits": tgt_fp.bits,
            "format": tgt_fp.binary_format,
        }

    return SupplyChainFinding(
        finding_id=(
            f"sca:bump:binary_capability_delta:"
            f"{ecosystem}:{name}@{target_version}"
        ),
        kind="binary_capability_delta",
        dependency=placeholder_dep,
        detail=detail or "target binary adds dangerous capabilities",
        evidence=evidence,
        severity=severity,
        confidence=Confidence(
            "medium",
            reason=(
                "radare2 import analysis; static signal only, "
                "no runtime confirmation"
            ),
        ),
    )


__all__ = [
    "binary_capability_delta_finding",
]
