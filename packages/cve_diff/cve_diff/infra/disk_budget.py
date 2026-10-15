"""
Disk-budget guard.

On the 712-CVE benchmark the reference project filled its disk to 95% before
crashing mid-run. The plan's structural invariant #7: "checked at every stage
entry; abort at 80% disk." That is this module.

Uses ``shutil.disk_usage`` (stdlib) — pre-2026-05-02 used
``psutil.disk_usage`` which has the same return shape
(``namedtuple(total, used, free)``) but required an extra runtime
dependency. Drop-in replacement.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

DEFAULT_LIMIT_PCT = 80.0
# A disk past the percentage limit is still fine while this much is free:
# on large disks 80% used can leave hundreds of GiB available.
DEFAULT_MIN_FREE_BYTES = 20 * 1024**3


class DiskBudgetExceeded(RuntimeError):
    pass


@dataclass(frozen=True)
class DiskStatus:
    path: str
    used_pct: float
    limit_pct: float
    free_bytes: int = 0
    min_free_bytes: int = DEFAULT_MIN_FREE_BYTES

    @property
    def ok(self) -> bool:
        return self.used_pct < self.limit_pct or self.free_bytes >= self.min_free_bytes


def check(
    path: str | Path = "/",
    limit_pct: float = DEFAULT_LIMIT_PCT,
    min_free_bytes: int = DEFAULT_MIN_FREE_BYTES,
) -> DiskStatus:
    usage = shutil.disk_usage(str(path))
    pct = 100.0 * usage.used / usage.total
    return DiskStatus(
        path=str(path), used_pct=pct, limit_pct=limit_pct,
        free_bytes=usage.free, min_free_bytes=min_free_bytes,
    )


def assert_ok(
    path: str | Path = "/",
    limit_pct: float = DEFAULT_LIMIT_PCT,
    min_free_bytes: int = DEFAULT_MIN_FREE_BYTES,
) -> None:
    status = check(path=path, limit_pct=limit_pct, min_free_bytes=min_free_bytes)
    if not status.ok:
        msg = (
            f"disk usage on {status.path} is {status.used_pct:.1f}% "
            f"(limit {status.limit_pct:.0f}%) with {status.free_bytes / 1024**3:.1f} GiB free "
            f"(need {status.min_free_bytes / 1024**3:.0f} GiB); aborting before further work."
        )
        raise DiskBudgetExceeded(msg)
