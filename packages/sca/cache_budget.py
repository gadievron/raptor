"""Cooperative disk-cache maintenance, separate from advisory TTL validity.

Scans hold shared leases; maintenance requires an exclusive, nonblocking
lease. Never evict persistent drift baselines or an open SQLite database.
Stress project directories are indivisible eviction units. Budgets are soft:
active scans can exceed them, and protected state is outside the budget.
"""
from __future__ import annotations

import contextlib
import logging
import os
import re
import shutil
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from core.atomic_fs.fs_lock import validate_lock_fd

logger = logging.getLogger(__name__)
_LOCK = ".cache-budget.lock"
_STAMP = ".cache-budget-last-run"
_INTERVAL = 600


@dataclass
class EvictionResult:
    files_scanned: int = 0
    files_removed: int = 0
    bytes_freed: int = 0
    errors: int = 0
    dirs_removed: int = 0
    bytes_remaining: int = 0
    budget_exceeded: bool = False
    busy: bool = False


@dataclass
class _Unit:
    path: Path
    size: int
    written: float
    used: float
    files: int = 1
    directory: bool = False
    stress: bool = False


_ENVELOPE_HEADER = re.compile(
    rb'\A\{\s*"written_at"\s*:\s*(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?),'
    rb'\s*"ttl_seconds"\s*:\s*(-?\d+)\s*,'
)


def _expired(unit: _Unit, now: float) -> bool:
    """Read only the bounded header emitted by JsonCache, not its payload.

    O_NOATIME keeps maintenance from making cold entries look recently used.
    Unknown formats remain eligible for age/LRU eviction, without claiming
    to know their validity. Content-addressed TTL_FOREVER entries never expire.
    """
    if unit.directory or unit.path.suffix != '.json':
        return False
    try:
        fd = os.open(unit.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                     | getattr(os, 'O_NOATIME', 0))
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                return False
            match = _ENVELOPE_HEADER.match(os.read(fd, 256))
        finally:
            os.close(fd)
        if match:
            written, ttl = float(match[1]), int(match[2])
            return ttl >= 0 and now - written > ttl
    except (OSError, ValueError, OverflowError):
        pass
    return False


@contextlib.contextmanager
def _lock(root: Path, *, shared: bool = False) -> Iterator[bool]:
    # Never evict when locking is unavailable. In particular, do not adopt
    # a foreign-uid, symlinked, or non-regular lock inode.
    import fcntl

    fd = None
    try:
        try:
            if root.is_symlink():
                raise OSError("cache root is a symlink")
            root.mkdir(parents=True, exist_ok=True)
            path = root / _LOCK
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW
                         | os.O_CLOEXEC | os.O_NONBLOCK, 0o600)
            validate_lock_fd(fd, path)
        except OSError as exc:
            logger.debug("SCA cache lease unavailable: %s", exc)
            yield False
            return
        mode = fcntl.LOCK_SH if shared else fcntl.LOCK_EX
        deadline = time.monotonic() + 30
        while True:
            try:
                fcntl.flock(fd, mode | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if not shared:
                    yield False
                    return
                if time.monotonic() >= deadline:
                    raise TimeoutError("SCA cache maintenance remained busy for 30s")
                time.sleep(0.05)
        yield True
    finally:
        if fd is not None:
            os.close(fd)


def _walk(root: Path, result: EvictionResult) -> Iterator[tuple[Path, os.stat_result]]:
    """Do not follow links, including directory links planted inside clones."""
    stack = [root]
    while stack:
        directory = stack.pop()
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    st = entry.stat(follow_symlinks=False)
                    if stat.S_ISDIR(st.st_mode):
                        stack.append(Path(entry.path))
                    elif stat.S_ISREG(st.st_mode):
                        yield Path(entry.path), st
        except OSError:
            result.errors += 1


def _units(root: Path, result: EvictionResult) -> list[_Unit]:
    units = []
    # Generic cache files. Leave operational sidecars, immutable user state,
    # and SQLite DBs (including WAL/SHM companions) alone.
    stack = [root]
    while stack:
        directory = stack.pop()
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    p = Path(entry.path)
                    if entry.name.startswith('.') or entry.name.endswith('.lock'):
                        continue
                    if directory == root and entry.name in {'fingerprints', 'stress', 'inventory'}:
                        continue
                    st = entry.stat(follow_symlinks=False)
                    if stat.S_ISDIR(st.st_mode):
                        stack.append(p)
                    elif stat.S_ISREG(st.st_mode):
                        if any(s in entry.name for s in ('.sqlite', '.db')):
                            continue
                        units.append(_Unit(p, st.st_size, st.st_mtime,
                                           max(st.st_atime, st.st_mtime)))
        except OSError:
            result.errors += 1

    # Inventory checklists can have shards: reclaim a whole target inventory,
    # never leave a manifest referring to a partially evicted shard set.
    for namespace, stress in ((root / 'inventory', False),
                              (root / 'stress' / 'clones', True)):
        if namespace.is_symlink() or not namespace.is_dir():
            continue
        if stress and (root / 'stress').is_symlink():
            continue
        for project in namespace.iterdir():
            if project.is_symlink() or not project.is_dir():
                continue
            st = project.stat()
            size, count, newest, used = 0, 0, st.st_mtime, st.st_mtime
            for _, info in _walk(project, result):
                size += info.st_size
                count += 1
                newest = max(newest, info.st_mtime)
                used = max(used, info.st_atime, info.st_mtime)
            units.append(_Unit(project, size, newest, used, count, True, stress))
    result.files_scanned = sum(u.files for u in units)
    return units


def prune_cache(
    root: Path, *, max_age_days: int = 30, max_bytes: int | None = None,
    stress_max_bytes: int | None = None, stress_max_age_days: int = 7,
    dry_run: bool = False, now: float | None = None,
) -> EvictionResult:
    """Reclaim aged entries, then expired/LRU entries down to 80% of budget.

    Access times are an approximate LRU on relatime/noatime filesystems.
    The dry run uses the same selection but leaves all data untouched.
    Results count logical bytes; actual freed blocks can differ.
    """
    result = EvictionResult()
    if not root.exists():
        return result
    if max_age_days <= 0 or stress_max_age_days <= 0:
        raise ValueError('cache retention must be positive')
    if any(n is not None and n < 0 for n in (max_bytes, stress_max_bytes)):
        raise ValueError('cache budgets must be nonnegative')
    with _lock(root) as locked:
        if not locked:
            result.busy = True
            return result
        return _prune_locked(root, result, max_age_days, max_bytes,
                             stress_max_bytes, stress_max_age_days, dry_run,
                             time.time() if now is None else now)


def _prune_locked(
    root: Path, result: EvictionResult, max_age_days: int,
    max_bytes: int | None, stress_max_bytes: int | None,
    stress_max_age_days: int, dry_run: bool, now: float,
) -> EvictionResult:
    units = _units(root, result)
    remaining = sum(u.size for u in units)
    stress_remaining = sum(u.size for u in units if u.stress)
    removed: set[Path] = set()

    def remove(unit: _Unit) -> None:
        nonlocal remaining, stress_remaining
        if unit.path in removed:
            return
        try:
            if not dry_run:
                # A cooperative writer cannot race this pass. Refuse static
                # symlinks even if the cache came from an untrusted archive.
                if any(p.is_symlink() for p in [unit.path, *unit.path.parents]
                       if p != root.parent):
                    raise OSError('symlink in cache path')
                if unit.directory:
                    shutil.rmtree(unit.path)
                else:
                    unit.path.unlink()
        except OSError:
            result.errors += 1
            return
        removed.add(unit.path)
        remaining -= unit.size
        if unit.stress:
            stress_remaining -= unit.size
        if unit.directory:
            result.dirs_removed += 1
        result.files_removed += unit.files
        result.bytes_freed += unit.size

    for unit in units:
        days = stress_max_age_days if unit.stress else max_age_days
        if unit.written < now - days * 86400:
            remove(unit)
    if stress_max_bytes is not None and (stress_remaining > stress_max_bytes
                                         or stress_max_bytes == 0):
        for unit in sorted((u for u in units if u.stress), key=lambda u: u.used):
            if stress_max_bytes and stress_remaining <= int(stress_max_bytes * .8):
                break
            remove(unit)
    if max_bytes is not None and remaining > max_bytes:
        candidates = [u for u in units if u.path not in removed]
        for unit in sorted(candidates, key=lambda u: (not _expired(u, now), u.used)):
            if remaining <= int(max_bytes * .8):
                break
            remove(unit)

    # rmdir only empties generic namespaces; never recurse into state or
    # touch surviving stress checkouts. Dry runs don't mutate directories.
    if not dry_run:
        parents = {p for u in units if u.path in removed for p in u.path.parents
                   if p != root and root in p.parents}
        for p in sorted(parents, key=lambda p: len(p.parts), reverse=True):
            try:
                p.rmdir()
                result.dirs_removed += 1
            except OSError:
                pass
    result.bytes_remaining = remaining
    result.budget_exceeded = (
        (max_bytes is not None and remaining > max_bytes)
        or (stress_max_bytes is not None and stress_remaining > stress_max_bytes)
    )
    return result


@contextlib.contextmanager
def cache_session(root: Path, *, maintain: bool = True) -> Iterator[None]:
    """Pin cache contents through a scan, including abandoned stress workers.

    After the final concurrent scan releases its lease, attempt throttled
    maintenance. Offline scans pin entries but never evict their input data.
    """
    try:
        with _lock(root, shared=True):
            yield
    finally:
        if maintain:
            maintain_cache(root)


def maintain_cache(root: Path) -> None:
    from core.tuning import load_tuning

    try:
        tuning = load_tuning()
        if tuning.sca_cache_max_mb == 0:
            return
        with _lock(root) as locked:
            if not locked:
                return
            stamp = root / _STAMP
            now = time.time()
            if stamp.exists() and now - stamp.lstat().st_mtime < _INTERVAL:
                return
            result = _prune_locked(
                root, EvictionResult(), 30, tuning.sca_cache_max_mb * 1024**2,
                tuning.sca_stress_cache_max_mb * 1024**2, 7, False, now,
            )
            # Avoid opening a caller-planted symlink for the throttle stamp.
            from core.atomic_fs import write_text_atomically
            write_text_atomically(stamp, str(now))
            if result.files_removed or result.errors:
                logger.info('SCA cache: freed %.1f MiB; %.1f MiB remain (%d errors)',
                            result.bytes_freed / 1024**2,
                            result.bytes_remaining / 1024**2, result.errors)
            if result.budget_exceeded:
                logger.warning('SCA cache remains over its disk budget; '
                               'some entries could not be removed')
    except (OSError, ValueError) as exc:
        logger.warning('SCA cache maintenance skipped: %s', exc)
