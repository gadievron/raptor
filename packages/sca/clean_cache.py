"""``raptor-sca clean-cache`` — reclaim stale and over-budget cache data.

The OSV / KEV / EPSS / registry cache lives at ``~/.raptor/cache/sca/``
(or wherever ``--cache-root`` points). Entries are individually keyed,
refreshed on TTL miss. This subcommand applies the same age/size policy
as automatic scan maintenance, with an optional non-destructive preview.

Was previously the ``--clean-cache`` mode of ``libexec/raptor-sca-gate``;
moved here as a top-level subcommand because cache cleanup is a
separate concern from CI threshold evaluation.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import sca_cache_root
from .cache_eviction import DEFAULT_MAX_AGE_DAYS, evict_stale
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence


def main(argv: Sequence[str]) -> int:
    # Escaping-console chokepoint: this subcommand runs as its own
    # libexec-dispatched process; with no logging config,
    # logging.lastResort would relay WARNING+ foreign text
    # (cache-path OSError text) to the TTY with a plain formatter.
    from .cli import _configure_logging  # local import: avoid cycle
    _configure_logging(0)
    args = _parse_args(argv)
    cache_root = (Path(args.cache_root).resolve()
                  if args.cache_root else sca_cache_root())
    max_age = args.max_age if args.max_age is not None else DEFAULT_MAX_AGE_DAYS
    if max_age <= 0:
        print(
            f"raptor-sca clean-cache: --max-age must be positive, got {max_age}",
            file=sys.stderr,
        )
        return 2
    from core.tuning import load_tuning
    tuning = load_tuning()
    max_mb = args.max_size_mb if args.max_size_mb is not None else tuning.sca_cache_max_mb
    stress_mb = (args.stress_max_size_mb if args.stress_max_size_mb is not None
                 else tuning.sca_stress_cache_max_mb)
    if max_mb < 0 or stress_mb < 0 or args.stress_max_age <= 0:
        print("raptor-sca clean-cache: budgets must be nonnegative and "
              "stress retention must be positive", file=sys.stderr)
        return 2
    try:
        res = evict_stale(
            cache_root, max_age_days=max_age,
            max_bytes=max_mb * 1024**2 if max_mb else None,
            stress_max_bytes=stress_mb * 1024**2,
            stress_max_age_days=args.stress_max_age, dry_run=args.dry_run,
        )
    except Exception as e:                  # noqa: BLE001
        print(f"raptor-sca clean-cache: cache eviction failed: {e}",
              file=sys.stderr)
        return 3

    if res.busy:
        print("raptor-sca clean-cache: cache is in use; no entries removed")
        return 1
    mb = res.bytes_freed / (1024 * 1024)
    extras = f", {res.errors} errors" if res.errors else ""
    print(
        f"raptor-sca clean-cache: {'would clean' if args.dry_run else 'cleaned'} {res.files_removed}/"
        f"{res.files_scanned} entries ({mb:.1f} MB), "
        f"removed {res.dirs_removed} empty dirs"
        + extras
        + f" from {cache_root}"
    )
    print(f"Disposable cache remaining{' (projected)' if args.dry_run else ''}: "
          f"{res.bytes_remaining / 1024**2:.1f} MiB")
    return 1 if res.errors or res.budget_exceeded else 0


def _parse_args(argv: Sequence[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="raptor-sca clean-cache",
        description="Reclaim stale and over-budget SCA cache data.",
    )
    p.add_argument(
        "--max-age", type=int, default=None, metavar="DAYS",
        help=f"delete entries older than DAYS (default: {DEFAULT_MAX_AGE_DAYS})",
    )
    p.add_argument(
        "--cache-root",
        help="override default cache root (~/.raptor/cache/sca)",
    )
    p.add_argument('--max-size-mb', type=int, metavar='MIB',
                   help='disposable disk budget (default: tuning.json sca_cache_max_mb; '
                        '0 disables size pruning)')
    p.add_argument('--stress-max-size-mb', type=int, metavar='MIB',
                   help='idle stress checkout budget (default: tuning.json '
                        'sca_stress_cache_max_mb; 0 removes all idle checkouts)')
    p.add_argument('--stress-max-age', type=int, default=7, metavar='DAYS',
                   help='retention for whole idle stress project directories (default: 7)')
    p.add_argument('--dry-run', action='store_true',
                   help='report projected cleanup without deleting cache data')
    return p.parse_args(argv)


__all__ = ["main"]
