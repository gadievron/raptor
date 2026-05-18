"""Diff two binaries' capability surfaces.

Substrate for "did this bump / drift / new build add dangerous
capabilities". The diff operates on the import-bucket view only —
``dangerous_sinks`` (cross-reference-derived) is intentionally
out of scope here; that signal requires ``BinaryUnderstand``
from :mod:`packages.binary_analysis.radare2_understand` and has
a different output shape.

Two consumers today:
- ``packages.sca.bump.binary_capability_delta`` — wraps the
  delta in a ``SupplyChainFinding`` for the bump pipeline.
- Future drift-detection — compares scan-time fingerprints
  across runs.

Both share this primitive so the bucket / severity semantics
stay consistent.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from core.binary.fingerprint import (
    BUCKETS,  # noqa: F401  — re-exported for downstream parity
    HIGH_SEVERITY_BUCKETS,
    CapabilityFingerprint,
    bucket_imports,  # noqa: F401  — re-exported for downstream parity
)

logger = logging.getLogger(__name__)


@dataclass
class CapabilityDelta:
    """Capability-surface diff between two binaries.

    ``new_dangerous_imports`` — imports in target that weren't in
    current, grouped by bucket. Only buckets with additions
    appear. Sorted lists for stable rendering.

    ``current_path`` / ``target_path`` — the binaries that were
    compared. Informational; not load-bearing for evidence.
    """

    new_dangerous_imports: Dict[str, List[str]] = field(
        default_factory=dict,
    )
    current_path: Optional[Path] = None
    target_path: Optional[Path] = None
    current_fingerprint: Optional[CapabilityFingerprint] = None
    target_fingerprint: Optional[CapabilityFingerprint] = None

    def is_empty(self) -> bool:
        """True when target adds no capabilities current didn't have."""
        return not self.new_dangerous_imports

    def high_severity(self) -> bool:
        """True when any added bucket is exec or network."""
        return any(
            bucket in HIGH_SEVERITY_BUCKETS
            for bucket in self.new_dangerous_imports
        )

    def added_buckets(self) -> List[str]:
        """Sorted list of bucket names with new entries."""
        return sorted(self.new_dangerous_imports.keys())


def diff_binary_capabilities(
    current_binary: Path,
    target_binary: Path,
) -> Optional[CapabilityDelta]:
    """Compare two binaries' capability surfaces.

    Implemented as a thin diff over two
    :func:`core.binary.fingerprint.capability_fingerprint` calls
    — the fingerprint primitive owns tier dispatch (try ELF
    parser first, fall back to radare2), so this function
    inherits the same operational properties: sub-millisecond on
    Linux ELF binaries, falls back to radare2 for PE / Mach-O,
    works on hosts without r2pipe for the ELF case.

    Returns ``None`` when:
      * Either binary can't be fingerprinted (unreadable / not
        ELF + no radare2 / radare2 fails)

    Returns an *empty* :class:`CapabilityDelta` (``is_empty()``)
    when both fingerprint cleanly but target adds nothing new —
    the caller can distinguish "couldn't compare" (None) from
    "no change" (empty delta).
    """
    from core.binary.fingerprint import capability_fingerprint

    current_fp = capability_fingerprint(current_binary)
    if current_fp is None:
        logger.debug(
            "core.binary.capability_diff: could not fingerprint "
            "current %s", current_binary,
        )
        return None
    target_fp = capability_fingerprint(target_binary)
    if target_fp is None:
        logger.debug(
            "core.binary.capability_diff: could not fingerprint "
            "target %s", target_binary,
        )
        return None

    new_imports: Dict[str, List[str]] = {}
    for bucket_name, target_fns in target_fp.capability_buckets.items():
        target_set = set(target_fns)
        current_set = set(
            current_fp.capability_buckets.get(bucket_name, []),
        )
        added = target_set - current_set
        if added:
            new_imports[bucket_name] = sorted(added)

    return CapabilityDelta(
        new_dangerous_imports=new_imports,
        current_path=current_binary,
        target_path=target_binary,
        current_fingerprint=current_fp,
        target_fingerprint=target_fp,
    )


__all__ = [
    "CapabilityDelta",
    "diff_binary_capabilities",
]
