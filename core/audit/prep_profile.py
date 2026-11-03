"""Diagnostic prep timings, separate from spend and scheduling decisions."""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, TypeVar

from core.json import save_json

logger = logging.getLogger(__name__)
T = TypeVar("T")


@dataclass
class PrepProfile:
    """Bounded-by-call-sites aggregates for one config instance.

    Inclusive step times can overlap or nest; do not sum them as elapsed
    run time. The report is replaced on resume with the current config's
    measurements. No source text, per-file rows, or verdict authority.
    """

    _steps: dict[str, dict[str, Any]] = field(default_factory=dict, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def record(
        self, name: str, elapsed: float, failed: bool, cache_hit: bool | None = None,
    ) -> None:
        with self._lock:
            row = self._steps.setdefault(name, {
                "calls": 0, "errors": 0, "wall_time_s": 0.0,
                "max_wall_time_s": 0.0,
            })
            row["calls"] += 1
            row["errors"] += int(failed)
            row["wall_time_s"] += elapsed
            row["max_wall_time_s"] = max(row["max_wall_time_s"], elapsed)
            if cache_hit is not None:
                counter = "cache_hits" if cache_hit else "cache_misses"
                row[counter] = row.get(counter, 0) + 1

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "scope": "config_instance",
                "timing": "inclusive; concurrent and nested steps may overlap",
                "steps": {name: dict(row) for name, row in sorted(self._steps.items())},
            }

    def write(self, out_dir) -> None:
        try:
            save_json(out_dir / "prep-profile.json", self.snapshot())
        except Exception:
            logger.debug("prep profile write failed", exc_info=True)


def profile_call(config, step: str, fn: Callable[..., T], /, *args, **kwargs) -> T:
    """Execute unchanged; timing failures cannot change its result/exception."""
    profile = getattr(config, "prep_profile", None)
    if not isinstance(profile, PrepProfile):
        return fn(*args, **kwargs)
    try:
        started = time.perf_counter()
    except Exception:
        return fn(*args, **kwargs)
    failed = True
    try:
        result = fn(*args, **kwargs)
        failed = False
        return result
    finally:
        try:
            cache_lookup = step.endswith(("_cache_lookup", ".cache_lookup"))
            cache_hit = result is not None if cache_lookup and not failed else None
            profile.record(step, time.perf_counter() - started, failed, cache_hit)
        except Exception:
            logger.debug("prep profile recording failed", exc_info=True)
