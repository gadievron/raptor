"""``raptor-sca clean-cache`` — reclaim disk space from stale cache entries.

The OSV / KEV / EPSS / registry cache lives at ``~/.raptor/cache/sca/``
(or wherever ``--cache-root`` points). Entries are individually keyed,
indefinitely retained, and refreshed on TTL miss. This subcommand
removes entries older than ``--max-age`` days.

Was previously the ``--clean-cache`` mode of ``libexec/raptor-sca-gate``;
moved here as a top-level subcommand because cache cleanup is a
separate concern from CI threshold evaluation.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from . import SCA_CACHE_ROOT
from .cache_eviction import DEFAULT_MAX_AGE_DAYS, evict_stale


def main(argv: Sequence[str]) -> int:
    args = _parse_args(argv)
    cache_root = (Path(args.cache_root).resolve()
                  if args.cache_root else SCA_CACHE_ROOT)
    max_age = args.max_age if args.max_age is not None else DEFAULT_MAX_AGE_DAYS
    if max_age <= 0:
        print(
            f"raptor-sca clean-cache: --max-age must be positive, got {max_age}",
            file=sys.stderr,
        )
        return 2
    try:
        res = evict_stale(cache_root, max_age_days=max_age)
    except Exception as e:                  # noqa: BLE001
        print(f"raptor-sca clean-cache: cache eviction failed: {e}",
              file=sys.stderr)
        return 3

    mb = res.bytes_freed / (1024 * 1024)
    extras = f", {res.errors} errors" if res.errors else ""
    print(
        f"raptor-sca clean-cache: cleaned {res.files_removed}/"
        f"{res.files_scanned} entries ({mb:.1f} MB), "
        f"removed {res.dirs_removed} empty dirs"
        + extras
        + f" from {cache_root}"
    )
    return 0


def _parse_args(argv: Sequence[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="raptor-sca clean-cache",
        description="Delete stale entries from the OSV / KEV / EPSS / "
                    "registry cache.",
    )
    p.add_argument(
        "--max-age", type=int, default=None, metavar="DAYS",
        help=f"delete entries older than DAYS (default: {DEFAULT_MAX_AGE_DAYS})",
    )
    p.add_argument(
        "--cache-root",
        help="override default cache root (~/.raptor/cache/sca)",
    )
    return p.parse_args(argv)


__all__ = ["main"]
