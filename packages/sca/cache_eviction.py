"""Public age/size cleanup API for the SCA disk cache.

Implementation is shared with automatic maintenance so manual cleanup also
respects scan leases, persistent state, and whole stress-project boundaries.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from .cache_budget import EvictionResult, prune_cache

if TYPE_CHECKING:
    from pathlib import Path

DEFAULT_MAX_AGE_DAYS = 30


def evict_stale(
    cache_root: Path, *, max_age_days: int = DEFAULT_MAX_AGE_DAYS,
    now: float | None = None, max_bytes: int | None = None,
    stress_max_bytes: int | None = None, stress_max_age_days: int = 7,
    dry_run: bool = False,
) -> EvictionResult:
    return prune_cache(
        cache_root, max_age_days=max_age_days, now=now, max_bytes=max_bytes,
        stress_max_bytes=stress_max_bytes,
        stress_max_age_days=stress_max_age_days, dry_run=dry_run,
    )


__all__ = ['DEFAULT_MAX_AGE_DAYS', 'EvictionResult', 'evict_stale']
