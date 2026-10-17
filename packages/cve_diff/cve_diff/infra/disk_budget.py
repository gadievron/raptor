"""Disk-budget guard for pipeline operations that can grow the filesystem.

An explicit percentage is a hard ceiling. The default policy permits usage
above 80% while at least 20 GiB remains available, avoiding false alarms on
large filesystems without weakening an operator-supplied limit.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

DEFAULT_LIMIT_PCT = 80.0
DEFAULT_MIN_FREE_BYTES = 20 * 1024**3


class DiskBudgetExceeded(RuntimeError):
    pass


@dataclass(frozen=True)
class DiskStatus:
    path: str
    used_pct: float
    limit_pct: float
    free_bytes: int = 0
    min_free_bytes: int | None = DEFAULT_MIN_FREE_BYTES

    @property
    def ok(self) -> bool:
        return self.used_pct < self.limit_pct or (
            self.min_free_bytes is not None
            and self.free_bytes >= self.min_free_bytes
        )


def check(
    path: str | Path = "/",
    limit_pct: float | None = None,
) -> DiskStatus:
    usage = shutil.disk_usage(str(path))
    pct = 100.0 * usage.used / usage.total
    effective_limit_pct = DEFAULT_LIMIT_PCT if limit_pct is None else limit_pct
    return DiskStatus(
        path=str(path),
        used_pct=pct,
        limit_pct=effective_limit_pct,
        free_bytes=usage.free,
        min_free_bytes=DEFAULT_MIN_FREE_BYTES if limit_pct is None else None,
    )


def assert_ok(
    path: str | Path = "/",
    limit_pct: float | None = None,
) -> None:
    status = check(path=path, limit_pct=limit_pct)
    if not status.ok:
        usage = (
            f"disk usage on {status.path} is {status.used_pct:.1f}% "
            f"(limit {status.limit_pct:.0f}%)"
        )
        if status.min_free_bytes is None:
            msg = f"{usage}; aborting before further work."
        else:
            msg = (
                f"{usage} with {status.free_bytes / 1024**3:.1f} GiB free "
                f"(need {status.min_free_bytes / 1024**3:.0f} GiB); "
                "aborting before further work."
            )
        raise DiskBudgetExceeded(msg)
