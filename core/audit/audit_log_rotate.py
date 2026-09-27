"""Owner-runnable rotation remedy for oversized audit-log trails.

Pre-rotation installs appended ``.audit-log.jsonl`` unbounded; a
trail past the per-shard read budget degrades to a bounded
newest-tail read (see :func:`core.audit.record.load_audit_log_disclosed`).
:func:`rotate_audit_log` restores full readability by re-splitting
the trail's existing bytes VERBATIM into a contiguous shard set with
every shard under the writer's roll threshold:

- Rows are never rewritten, reordered, or dropped — the
  concatenation of the shards after rotation is byte-identical to
  the concatenation before it (verified before the swap; on mismatch
  nothing is replaced). Per-row integrity stamps are bound to the
  run DIRECTORY, not the file name, so every previously-verifying
  row still verifies after the split.
- Splits happen only at line boundaries; a torn final line (crashed
  writer) stays torn at the end of the last shard, exactly as the
  tolerant reader already handles it.
- Originals are preserved as ``<name>.pre-rotate`` backups
  (first-free naming — an existing backup is never overwritten).
- LIVE runs are refused via the journal-compaction gate
  (:func:`core.coverage.journal_compact.refuse_live_run`): a
  concurrent appender racing the swap could land rows on a pre-swap
  inode (the backup) and silently lose them. The gate fails closed
  on an unreadable run record and stays permissive when no record
  exists (foreign / legacy dirs).

Crash window: between moving the originals to their backups and
renaming the new shards into place, the trail lives only in the
backups. Re-running rotate after such a crash is a no-op on the
missing trail — recovery is renaming the ``.pre-rotate`` files back,
then re-running.

CLI: ``raptor-audit audit-log rotate <out-dir>``.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import IO

from core.audit.record import (
    _AUDIT_LOG_MAX_BYTES,
    _AUDIT_LOG_MAX_SHARDS,
    _AUDIT_LOG_SHARD_ROLL_BYTES,
    _audit_log_orphan_names,
    _audit_log_shard_name,
    audit_log_paths,
)

logger = logging.getLogger(__name__)

_BACKUP_SUFFIX = ".pre-rotate"
_TMP_PREFIX = ".audit-log-rotate.tmp."
#: Streaming read granularity. Trade-off, both directions: LOWER
#: multiplies syscalls on multi-GiB trails; HIGHER grows the largest
#: single buffer the rewrite holds (it never materialises a whole
#: line or file). 1 MiB matches the loader's per-line budget, so a
#: legitimate row always arrives in one chunk.
_CHUNK_BYTES = 1024 * 1024


class RotateRefused(RuntimeError):
    """Rotation refused — nothing was modified."""


@dataclass(frozen=True)
class RotateStats:
    """Before/after accounting for one rotation."""

    rotated: bool
    shards_before: int
    shards_after: int
    bytes_total: int
    backups: tuple[str, ...] = ()
    #: Non-contiguous numbered shard files, left untouched.
    orphan_shards: tuple[str, ...] = ()
    #: True when the shard-count bound forced the final shard to
    #: absorb the remainder and it is still over the read budget.
    final_shard_over_budget: bool = False


def _backup_path(shard_path: Path) -> Path:
    """First free ``.pre-rotate`` name — an existing backup is never
    overwritten (it may be the only copy of a previous generation)."""
    base = shard_path.with_name(shard_path.name + _BACKUP_SUFFIX)
    if not base.exists():
        return base
    n = 2
    while True:
        candidate = base.with_name(f"{base.name}.{n}")
        if not candidate.exists():
            return candidate
        n += 1


def rotate_audit_log(out_dir: Path) -> RotateStats:
    """Re-split the audit-log trail at *out_dir* so every shard is
    under the writer's roll threshold. No-op (``rotated=False``) when
    no shard exceeds the per-shard read budget.

    Raises :class:`RotateRefused` when the run is still in flight,
    when its run record is unreadable, or when the rewrite's byte
    accounting does not reconcile (originals stay in place).
    """
    out_dir = Path(out_dir)
    from core.coverage.journal_compact import CompactRefused, refuse_live_run
    try:
        refuse_live_run(out_dir)
    except CompactRefused as exc:
        raise RotateRefused(str(exc)) from exc

    all_paths = audit_log_paths(out_dir)
    existing = [p for p in all_paths if p.is_file()]
    orphans = tuple(_audit_log_orphan_names(out_dir, len(all_paths)))
    sizes = {p: p.stat().st_size for p in existing}
    total = sum(sizes.values())
    if not existing or not any(
        s > _AUDIT_LOG_MAX_BYTES for s in sizes.values()
    ):
        return RotateStats(
            rotated=False,
            shards_before=len(existing),
            shards_after=len(existing),
            bytes_total=total,
            orphan_shards=orphans,
        )

    # ── pass 1: stream the trail into bounded temp shards ──────────
    temps: list[Path] = []
    written = 0
    current: IO[bytes] | None = None
    current_size = 0
    mid_line = False

    def _open_next() -> None:
        nonlocal current, current_size
        if current is not None:
            current.flush()
            os.fsync(current.fileno())
            current.close()
        idx = len(temps) + 1
        tmp = out_dir / f"{_TMP_PREFIX}{idx:03d}"
        # O_EXCL: a leftover temp from an interrupted rotate must not
        # be silently absorbed into this one's accounting.
        fd = os.open(
            tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
            0o644,
        )
        current = os.fdopen(fd, "wb")
        current_size = 0
        temps.append(tmp)

    try:
        _open_next()
        for src in existing:
            with src.open("rb") as fh:
                while True:
                    chunk = fh.readline(_CHUNK_BYTES)
                    if not chunk:
                        break
                    # Roll only at line starts so no line ever splits
                    # across shards; the shard-count bound makes the
                    # final shard absorb the remainder (same absorb
                    # semantics as the live appender at its bound).
                    if (
                        not mid_line
                        and current_size >= _AUDIT_LOG_SHARD_ROLL_BYTES
                        and len(temps) < _AUDIT_LOG_MAX_SHARDS
                    ):
                        _open_next()
                    assert current is not None  # _open_next ran first
                    current.write(chunk)
                    current_size += len(chunk)
                    written += len(chunk)
                    mid_line = not chunk.endswith(b"\n")
        assert current is not None
        current.flush()
        os.fsync(current.fileno())
        current.close()
        current = None
    except BaseException:
        if current is not None:
            current.close()
        for tmp in temps:
            tmp.unlink(missing_ok=True)
        raise

    final_over = bool(
        temps and temps[-1].stat().st_size > _AUDIT_LOG_MAX_BYTES)

    # Byte reconciliation BEFORE any original moves: a rewrite that
    # cannot prove it copied every byte must not replace anything.
    if written != total:
        for tmp in temps:
            tmp.unlink(missing_ok=True)
        raise RotateRefused(
            f"rotate at {out_dir}: byte accounting mismatch "
            f"(read {total}, wrote {written}) — a shard changed size "
            "mid-rewrite (concurrent appender?). Nothing was "
            "replaced; stop the writer and retry."
        )

    # ── pass 2: swap — originals to backups, temps into place ──────
    backups: list[str] = []
    for p in existing:
        backup = _backup_path(p)
        os.rename(p, backup)
        backups.append(backup.name)
    for i, tmp in enumerate(temps):
        os.rename(tmp, out_dir / _audit_log_shard_name(i + 1))
    try:
        dir_fd = os.open(out_dir, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except OSError:
        pass  # best-effort directory durability

    if final_over:
        logger.warning(
            "audit log rotate at %s: shard bound (%d) reached — the "
            "final shard absorbed the remainder and is still over the "
            "read budget (its tail reads bounded). The trail is "
            "larger than the shard set can hold.",
            out_dir, _AUDIT_LOG_MAX_SHARDS,
        )
    if orphans:
        logger.warning(
            "audit log rotate at %s: %d non-contiguous shard file(s) "
            "left untouched (not part of the trail): %s",
            out_dir, len(orphans), ", ".join(orphans),
        )
    return RotateStats(
        rotated=True,
        shards_before=len(existing),
        shards_after=len(temps),
        bytes_total=total,
        backups=tuple(backups),
        orphan_shards=orphans,
        final_shard_over_budget=bool(final_over),
    )
