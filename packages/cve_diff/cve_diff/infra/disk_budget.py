"""
Disk-budget guard.

On the 712-CVE benchmark the reference project filled its disk to 95% before
crashing mid-run. The plan's structural invariant #7: "checked at every stage
entry; abort at 80% disk." That is this module.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import psutil

DEFAULT_LIMIT_PCT = 80.0


class DiskBudgetExceeded(RuntimeError):
    pass


@dataclass(frozen=True)
class DiskStatus:
    path: str
    used_pct: float
    limit_pct: float

    @property
    def ok(self) -> bool:
        return self.used_pct < self.limit_pct


def check(path: str | Path = "/", limit_pct: float = DEFAULT_LIMIT_PCT) -> DiskStatus:
    usage = psutil.disk_usage(str(path))
    pct = 100.0 * usage.used / usage.total
    return DiskStatus(path=str(path), used_pct=pct, limit_pct=limit_pct)


def assert_ok(path: str | Path = "/", limit_pct: float = DEFAULT_LIMIT_PCT) -> None:
    status = check(path=path, limit_pct=limit_pct)
    if not status.ok:
        raise DiskBudgetExceeded(
            f"disk usage on {status.path} is {status.used_pct:.1f}% "
            f"(limit {status.limit_pct:.0f}%); aborting before further work."
        )
