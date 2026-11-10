"""Pool pruning — keep N most recent per dedup bucket.

Implementation-time
tuning item #2: "LabeledAttempt deduplication — hash by
(finding_id, exploit_code_sha, model); keep N most recent per bucket.
N = 5 to start."

Without this the pool grows unbounded. Operators running /exploit
repeatedly on the same finding accumulate one record per attempt
forever, even when the model + exploit code are identical.

Pruning is **explicit** — not automatic on write. The store's atomic-
append discipline is the simpler invariant; an opt-in pruner runs
periodically (cron / CLI / before each run, as the operator chooses).

Bucket key: ``(finding_id, exploit_code_sha, model)`` after the plan.
That deliberately allows multiple records per finding when the model
or the exploit text differ (different prompt versions, different
attack shapes). Two identical attempts by the same model collapse
together.

For records with no exploit code (CodeQL adjudications, web records),
the bucket key uses an empty string for the code SHA — operators
typically annotate those via :func:`set_failure_mode` rather than
re-fire, so they don't accumulate the way sandbox records do.
"""

from __future__ import annotations

import contextlib
import hashlib
import math
import logging
import os
import stat
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from core.json import loads

from .store import project_pool_path
from .types import LabeledAttempt
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

__all__ = ["PruneReport", "prune_pool"]

_log = logging.getLogger(__name__)


# Default N — keeps 5 most recent records per dedup bucket. Per the
# plan: "N = 5 to start." Tuned later from real-target dogfood data.
_DEFAULT_N = 5


@dataclass(frozen=True)
class PruneReport:
    """Statistics from one prune pass."""

    records_seen: int = 0
    buckets: int = 0
    records_kept: int = 0
    records_removed: int = 0
    removed_paths: tuple[Path, ...] = field(default_factory=tuple)


def _bucket_key(record: LabeledAttempt) -> tuple[str, str, str]:
    """``(finding_id, exploit_code_sha, model)`` per the plan."""
    sb = record.sandbox_evidence
    if sb is not None and sb.exploit_code:
        code_sha = hashlib.sha256(
            sb.exploit_code.encode("utf-8"),
        ).hexdigest()
    else:
        code_sha = ""  # CodeQL / web records bucket together by id
    return (
        record.finding_id,
        code_sha,
        record.producing_model,
    )


def _record_ts(record: LabeledAttempt) -> float:
    """ISO-8601 → POSIX timestamp. Records produced by the bridge are
    always parseable (validated at construction).

    Naive timestamps are interpreted as UTC — the same rule
    ``retrieval._record_age_days`` applies — so a bucket mixing naive
    (legacy writer) and aware records orders the same on every host;
    letting ``timestamp()`` apply the LOCAL zone to naive values would
    skew them by the UTC offset and prune the wrong victim.
    """
    ts = datetime.fromisoformat(record.timestamp)
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts.timestamp()


_MAX_RECORD_BYTES = 8 * 1024 * 1024
_DIR_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
_FILE_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_NONBLOCK", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)


@contextlib.contextmanager
def _directory(path, *, parent=None):
    descriptor = os.open(path, _DIR_FLAGS, dir_fd=parent)
    try:
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise OSError("pool node is not a real directory")
        yield descriptor
    finally:
        try:
            os.close(descriptor)
        except OSError:
            _log.debug("pool directory close failed", exc_info=True)


def _directory_id(info):
    return info.st_dev, info.st_ino


def _file_version(info):
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _read_record(directory, name):
    from core.source.streams import owned_fd, preserving_stream_error

    adopted = False

    def close_record(value):
        try:
            os.close(value)
        except OSError:
            # Validation cleanup is best-effort; an adopted read needs a
            # successful close before its bytes can be admitted.
            if adopted:
                raise

    descriptor = os.open(name, _FILE_FLAGS, dir_fd=directory)
    with owned_fd(descriptor, close_fd=close_record):
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > _MAX_RECORD_BYTES:
            return None
        stream = os.fdopen(descriptor, "rb", closefd=False)
        adopted = True
        with preserving_stream_error(stream):
            raw = stream.read(_MAX_RECORD_BYTES + 1)
            after = os.fstat(stream.fileno())
        if len(raw) > _MAX_RECORD_BYTES or _file_version(before) != _file_version(
            after
        ):
            return None
        return raw, _file_version(before)


@dataclass(frozen=True)
class _Candidate:
    path: Path
    directory_id: tuple[int, int]
    version: tuple[int, ...]
    digest: bytes
    timestamp: float


def _restore_record(directory, quarantine, candidate):
    """Restore an unremoved candidate without overwriting a new publication."""
    try:
        info = os.stat(quarantine, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return
    try:
        if stat.S_ISDIR(info.st_mode):
            # Unexpected directory replacement: keep all data, never delete it.
            try:
                os.stat(candidate.path.name, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                os.rename(
                    quarantine,
                    candidate.path.name,
                    src_dir_fd=directory,
                    dst_dir_fd=directory,
                )
                return
        else:
            os.link(
                quarantine,
                candidate.path.name,
                src_dir_fd=directory,
                dst_dir_fd=directory,
                follow_symlinks=False,
            )
            os.unlink(quarantine, dir_fd=directory)
            return
    except OSError:
        pass
    _log.warning(
        "unremoved pool record retained for recovery at %s",
        candidate.path.parent / quarantine,
    )


def _remove_candidate(pool, pool_fd, pool_id, candidate):
    try:
        current_root = os.stat(pool, follow_symlinks=False)
        if (
            not stat.S_ISDIR(current_root.st_mode)
            or _directory_id(current_root) != pool_id
        ):
            return False
        with _directory(candidate.path.parent.name, parent=pool_fd) as directory:
            if _directory_id(os.fstat(directory)) != candidate.directory_id:
                return False
            current = os.stat(
                candidate.path.name, dir_fd=directory, follow_symlinks=False
            )
            if _file_version(current) != candidate.version:
                return False
            # Rename first, then verify the node actually acquired. A record
            # replaced between stat and rename is restored instead of deleted.
            quarantine = ".prune-" + uuid.uuid4().hex + ".tmp"
            removed = False
            try:
                os.rename(
                    candidate.path.name,
                    quarantine,
                    src_dir_fd=directory,
                    dst_dir_fd=directory,
                )
                contents = _read_record(directory, quarantine)
                if contents is None:
                    return False
                raw, version = contents
                # Rename updates ctime. Other identity/version fields and the
                # complete bounded payload must still match the scanned record.
                if (
                    version[:-1] != candidate.version[:-1]
                    or hashlib.sha256(raw).digest() != candidate.digest
                ):
                    return False
                os.unlink(quarantine, dir_fd=directory)
                removed = True
                return True
            finally:
                if not removed:
                    try:
                        _restore_record(directory, quarantine, candidate)
                    except OSError:
                        _log.warning(
                            "pool record recovery incomplete for %s",
                            candidate.path,
                            exc_info=True,
                        )
    except OSError:
        _log.debug("pool record removal skipped for %s", candidate.path, exc_info=True)
    return False


def prune_pool(
    project_dir: Path, *, n_per_bucket: int = _DEFAULT_N, dry_run: bool = False
) -> PruneReport:
    """Keep N recent readable records per bucket without following pool links.

    Actual removals alone are reported, except dry-run lists planned removals.
    Kept counts scanned candidates this invocation did not remove; concurrent
    external changes mean it is not a fresh filesystem census. Invalid or
    unreadable records remain untouched. Empty directories are tidied only
    after this invocation removed records from that same directory identity.
    """
    if (
        isinstance(n_per_bucket, bool)
        or not isinstance(n_per_bucket, int)
        or n_per_bucket < 0
    ):
        raise ValueError("n_per_bucket must be a non-negative integer")
    pool = project_pool_path(project_dir)
    try:
        with _directory(pool) as pool_fd:
            return _prune_open_pool(pool, pool_fd, n_per_bucket, dry_run)
    except FileNotFoundError:
        return PruneReport()
    except OSError:
        _log.warning("pool pruning could not inspect %s", pool, exc_info=True)
        return PruneReport()


def _prune_open_pool(pool, pool_fd, n_per_bucket, dry_run):
    pool_id = _directory_id(os.fstat(pool_fd))
    buckets = {}
    seen = 0
    with os.scandir(pool_fd) as entries:
        names = sorted(entry.name for entry in entries)
    for name in names:
        try:
            with _directory(name, parent=pool_fd) as directory:
                identity = _directory_id(os.fstat(directory))
                with os.scandir(directory) as entries:
                    files = sorted(
                        entry.name
                        for entry in entries
                        if entry.name.endswith(".json")
                        and not entry.name.startswith(".")
                    )
                for filename in files:
                    try:
                        loaded = _read_record(directory, filename)
                        if loaded is None:
                            continue
                        raw, version = loaded
                        record = LabeledAttempt.from_dict(loads(raw))
                        key = _bucket_key(record)
                        timestamp = _record_ts(record)
                        if not math.isfinite(timestamp):
                            raise ValueError("non-finite record timestamp")
                        candidate = _Candidate(
                            pool / name / filename,
                            identity,
                            version,
                            hashlib.sha256(raw).digest(),
                            timestamp,
                        )
                        buckets.setdefault(key, []).append(candidate)
                        seen += 1
                    except (
                        OSError,
                        ValueError,
                        KeyError,
                        TypeError,
                        AttributeError,
                        OverflowError,
                        RecursionError,
                    ):
                        _log.debug(
                            "skipping unreadable record %s",
                            pool / name / filename,
                            exc_info=True,
                        )
        except OSError:
            _log.debug(
                "skipping unreadable signature directory %s", pool / name, exc_info=True
            )
    removed = []
    emptied = {}
    for candidates in buckets.values():
        candidates.sort(key=lambda candidate: candidate.timestamp, reverse=True)
        for candidate in candidates[n_per_bucket:]:
            if dry_run or _remove_candidate(pool, pool_fd, pool_id, candidate):
                removed.append(candidate.path)
                emptied[candidate.path.parent.name] = candidate.directory_id
    if not dry_run:
        for name, identity in emptied.items():
            try:
                current = os.stat(name, dir_fd=pool_fd, follow_symlinks=False)
                if stat.S_ISDIR(current.st_mode) and _directory_id(current) == identity:
                    os.rmdir(name, dir_fd=pool_fd)
            except OSError:
                # Not empty, replaced, inaccessible, or already removed.
                _log.debug(
                    "signature directory cleanup skipped for %s",
                    pool / name,
                    exc_info=True,
                )
    return PruneReport(
        records_seen=seen,
        buckets=len(buckets),
        records_kept=seen - len(removed),
        records_removed=len(removed),
        removed_paths=tuple(removed),
    )
