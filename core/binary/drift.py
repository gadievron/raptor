"""Capability drift between two fingerprints.

Where :func:`core.binary.capability_diff.diff_binary_capabilities`
asks "what does target ADD over current" (unidirectional —
appropriate for bump capability-delta where the operator
proposes a forward change), :func:`detect_drift` asks "what
CHANGED between previous and now" (bidirectional — additions
+ removals + metadata shifts). Both signals come from the
fingerprint primitive but consumers want different framing:

- Bumps: "is the proposed upgrade introducing dangerous caps"
- Drift: "did the image we've been pulling silently change"

A re-tagged ``alpine:3.18`` whose registry-side digest moves
to bytes with different capabilities is exactly the
drift case — there's no version bump for the bumper to catch,
but a stored-fingerprint comparison surfaces it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from core.binary.fingerprint import (
    CapabilityFingerprint,
    HIGH_SEVERITY_BUCKETS,
)


@dataclass
class FingerprintDrift:
    """Difference between two fingerprints of the same logical
    binary at different points in time.

    Field semantics:
    - ``new_buckets`` — buckets in current that weren't in
      previous (capabilities added). Each value is the sorted
      list of newly-added function names.
    - ``removed_buckets`` — buckets in previous that aren't in
      current. Same shape.
    - ``hash_changed`` — bytes differ (binary_sha256 doesn't
      match). True is the trigger for everything else; without
      this, no drift could exist.
    - ``arch_changed`` / ``bits_changed`` / ``format_changed`` —
      metadata-level changes. Format change is a strong signal
      (the operator switched between ELF/PE/Mach-O); arch/bits
      changes flag accidental multi-arch confusion.
    """

    hash_changed: bool = False
    arch_changed: bool = False
    bits_changed: bool = False
    format_changed: bool = False
    new_buckets: Dict[str, List[str]] = field(default_factory=dict)
    removed_buckets: Dict[str, List[str]] = field(default_factory=dict)

    def is_empty(self) -> bool:
        """True when previous and current are capability-
        equivalent. ``hash_changed`` alone (bytes changed but
        capabilities didn't) is NOT considered drift — that's
        the legitimate-rebuild case, suppressed."""
        return not (
            self.new_buckets
            or self.removed_buckets
            or self.arch_changed
            or self.bits_changed
            or self.format_changed
        )

    def high_severity(self) -> bool:
        """True when ANY added bucket is exec or network — the
        strongest signal that a re-tagged image now does
        something dangerous it previously didn't."""
        return any(
            bucket in HIGH_SEVERITY_BUCKETS
            for bucket in self.new_buckets
        )

    def added_buckets(self) -> List[str]:
        return sorted(self.new_buckets.keys())

    def removed_bucket_names(self) -> List[str]:
        return sorted(self.removed_buckets.keys())


def detect_drift(
    previous: CapabilityFingerprint,
    current: CapabilityFingerprint,
) -> FingerprintDrift:
    """Diff two fingerprints. Returns a :class:`FingerprintDrift`
    summarising every dimension of change. Always returns a
    drift object (never None) — callers use ``is_empty()`` to
    distinguish "no drift" from "drift detected".

    Bytes-unchanged is the no-op case (``is_empty()`` returns
    True without comparing buckets). For meaningfully-different
    bytes, we walk every bucket in both directions.
    """
    if previous.binary_sha256 == current.binary_sha256:
        # Same bytes → no drift by definition. Short-circuit so
        # the bucket walk is skipped (and we don't surface
        # legitimate filesystem-level differences like
        # binary_path).
        return FingerprintDrift()

    drift = FingerprintDrift(hash_changed=True)

    if previous.arch != current.arch:
        drift.arch_changed = True
    if previous.bits != current.bits:
        drift.bits_changed = True
    if previous.binary_format != current.binary_format:
        drift.format_changed = True

    prev_buckets = previous.capability_buckets
    cur_buckets = current.capability_buckets

    # Additions: in current, not in previous (or expanded entries).
    for bucket, cur_items in cur_buckets.items():
        cur_set = set(cur_items)
        prev_set = set(prev_buckets.get(bucket, []))
        added = cur_set - prev_set
        if added:
            drift.new_buckets[bucket] = sorted(added)

    # Removals: in previous, not in current.
    for bucket, prev_items in prev_buckets.items():
        prev_set = set(prev_items)
        cur_set = set(cur_buckets.get(bucket, []))
        removed = prev_set - cur_set
        if removed:
            drift.removed_buckets[bucket] = sorted(removed)

    return drift


__all__ = [
    "FingerprintDrift",
    "detect_drift",
]
