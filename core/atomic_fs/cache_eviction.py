"""Conservative count-based eviction for flat disposable file caches."""
from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Iterable


def file_generation(info: os.stat_result) -> tuple[int, ...]:
    """Identity and write metadata, excluding access time changed by readers."""
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def evict_oldest_files(paths: Iterable[Path], max_entries: int) -> None:
    """Evict unchanged oldest files/links; keep other nodes and link targets.

    Failed or refreshed candidates do not stop later removals. A concurrent
    removal frees a quota slot, while a replacement still occupies one.
    """
    if not isinstance(max_entries, int) or isinstance(max_entries, bool) or max_entries < 0:
        raise ValueError("max_entries must be a nonnegative integer")
    candidates = []
    seen = set()
    try:
        for path in paths:
            if path in seen:
                continue
            seen.add(path)
            try:
                info = path.lstat()
            except OSError:
                continue
            if stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
                candidates.append((info.st_mtime_ns, path, file_generation(info)))
    except OSError:
        return  # An incomplete listing cannot establish the count.
    candidates.sort(key=lambda row: (row[0], row[1].name))
    remaining = len(candidates)
    for _, path, generation in candidates:
        if remaining <= max_entries:
            break
        try:
            current = path.lstat()
            if file_generation(current) != generation:
                if not (stat.S_ISREG(current.st_mode) or stat.S_ISLNK(current.st_mode)):
                    remaining -= 1  # The replacement no longer consumes file quota.
                continue
            path.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            continue
        # lstat distinguishes absence from a replacement dangling link.
        try:
            current = path.lstat()
        except FileNotFoundError:
            remaining -= 1
        except OSError:
            continue
        else:
            if not (stat.S_ISREG(current.st_mode) or stat.S_ISLNK(current.st_mode)):
                remaining -= 1
