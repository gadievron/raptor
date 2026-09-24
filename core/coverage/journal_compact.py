"""On-disk compaction for ``review-journal.jsonl``.

A multi-segment resumed audit re-emits every reused verdict as a
fresh journal row per segment (per-segment completeness —
``core.audit.verdict_reuse``), so a long resume chain's journal is
dominated by duplicate re-emission rows and can cross the loader's
retained-entry budget. The loader prunes those duplicates in MEMORY
(``core.coverage.journal._prune_reemission_rows``); this module is
the durable, operator-invokable twin that rewrites the FILE —
``raptor-audit journal compact <out-dir>``.

Loss contract (identical to the load-time prune, via the shared
``_reemission_identity`` rule): a row is dropped only when it is a
``reused`` re-emission, carries zero cost, bears no
correction/feedback fields, is not a claim (finding/suspicious) or
provisional row, AND a newer row with the identical
(key, site, source_hash, verdict, model, strategy-hash) identity
survives. Consequences:

* the final verdict per function is byte-identical before/after
  (kept rows are copied VERBATIM, so row MACs stay valid);
* ``journal_spend_usd`` — the resume budget floor — cannot decrease:
  only ``cost_usd``-less/zero rows are droppable;
* corrections, lessons, claim rows, error/dark rows, markers, and
  every unparseable line are kept as-is (never delete data the
  reader refuses — it is evidence of something).

Safety: refuses to compact a run whose recorded worker process is
alive; holds the journal appenders' ``flock`` across both passes and
the swap; backs the original up as ``review-journal.jsonl.pre-compact``
(hardlink — zero copy, never deleted) before an atomic
tempfile+rename replace.
"""

from __future__ import annotations

import contextlib
import logging
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any

from core.json import loads

from . import journal as _journal
from .journal import (
    JOURNAL_FILENAME,
    _entry_from_dict,
    _reemission_identity,
)

try:
    import fcntl
    _HAS_FCNTL = True
except ImportError:
    _HAS_FCNTL = False

logger = logging.getLogger(__name__)


def auto_compact_threshold_bytes() -> int:
    """Resume auto-compacts the journal at segment start once it
    exceeds this (half the loader's retained-byte budget):
    per-segment completeness keeps re-emitting reused rows by design,
    so without a standing trim a long resume chain drifts toward the
    loader budget and, past it, toward the spend-authorizing refusal.
    Derived at CALL time so it always tracks the loader budget."""
    return _journal._MAX_JOURNAL_BYTES // 2


#: Bound on the pass-1 identity map. Real journals carry one identity
#: per reviewed site (tens of thousands); a journal with more
#: distinct re-emission identities than this is not a journal this
#: tool understands — refuse rather than grow unbounded state over a
#: hostile file.
_MAX_IDENTITIES = 2_000_000

_BACKUP_SUFFIX = ".pre-compact"
_DISCARD_CHUNK = 1 << 20


class CompactRefused(RuntimeError):
    """Compaction refused — nothing was modified."""


@dataclass
class CompactStats:
    """Before/after accounting for one compaction."""

    journal_path: str
    backup_path: str
    rows_before: int = 0
    rows_after: int = 0
    bytes_before: int = 0
    bytes_after: int = 0
    dropped_reemissions: int = 0
    kept_unparseable: int = 0
    spend_usd_before: float = 0.0
    spend_usd_after: float = 0.0

    @property
    def ratio(self) -> float:
        return (
            self.bytes_before / self.bytes_after
            if self.bytes_after else 1.0
        )


def _refuse_live_run(out_dir: Path) -> None:
    """Refuse when the run's recorded worker is still alive — a live
    appender racing the rewrite could land a row on the pre-swap
    inode (the backup) instead of the compacted journal."""
    try:
        from core.run.metadata import (
            STATUS_RUNNING,
            _tool_pid_alive,
            load_run_metadata,
        )
        meta = load_run_metadata(Path(out_dir))
    except Exception:  # noqa: BLE001 — metadata read is best-effort
        return
    if not meta:
        return
    if meta.get("status") == STATUS_RUNNING \
            and _tool_pid_alive(meta.get("tool_pid")):
        raise CompactRefused(
            f"run at {out_dir} is still in flight (recorded worker "
            "process is alive) — refusing to compact a live run's "
            "journal. Wait for it to stop, or kill it first."
        )


def _backup_path(journal_path: Path) -> Path:
    """First free ``.pre-compact`` name — an existing backup is never
    overwritten (it may be the only copy of a previous generation)."""
    base = journal_path.with_name(journal_path.name + _BACKUP_SUFFIX)
    if not base.exists():
        return base
    n = 2
    while True:
        candidate = base.with_name(f"{base.name}.{n}")
        if not candidate.exists():
            return candidate
        n += 1


def _iter_lines(fh: IO[bytes]):
    """Yield ``(raw_line, overlong)`` with bounded materialisation.

    An over-long line (past ``_MAX_JOURNAL_LINE_BYTES``) is yielded in
    CHUNKS — ``(chunk, True)`` until its newline — so pass 2 can copy
    it verbatim without ever buffering it whole. Pass 1 counts it as
    one unparseable row and otherwise ignores the chunks.
    """
    while True:
        line = fh.readline(_journal._MAX_JOURNAL_LINE_BYTES + 1)
        if not line:
            return
        if (len(line) <= _journal._MAX_JOURNAL_LINE_BYTES
                or line.endswith(b"\n")):
            yield line, False
            continue
        yield line, True
        while True:
            chunk = fh.readline(_DISCARD_CHUNK)
            if not chunk:
                return
            yield chunk, True
            if chunk.endswith(b"\n"):
                break


def _row_cost(raw: dict[str, Any]) -> float:
    cost = raw.get("cost_usd")
    if isinstance(cost, (int, float)) and not isinstance(cost, bool):
        try:
            return max(0.0, float(cost))
        except (OverflowError, ValueError):
            return 0.0
    return 0.0


def compact_journal(out_dir: Path) -> CompactStats:
    """Atomically rewrite the run's journal without its duplicate
    re-emission rows. Returns before/after stats; raises
    :class:`CompactRefused` (file untouched) when the run is live,
    the journal is absent/unreadable, or the file's identity
    population exceeds the tool's bounds.
    """
    out_dir = Path(out_dir)
    journal_path = out_dir / JOURNAL_FILENAME
    _refuse_live_run(out_dir)

    from core.source import open_regular
    fh = open_regular(journal_path, "rb")
    if fh is None:
        raise CompactRefused(
            f"no readable review journal at {journal_path} — nothing "
            "to compact"
        )

    stats = CompactStats(
        journal_path=str(journal_path), backup_path="",
    )
    tmp_fd: int | None = None
    tmp_path: Path | None = None
    try:
        with fh:
            # Exclusive flock across BOTH passes and the swap: the
            # appenders (core.coverage.journal.append_entry) take the
            # same lock per row, so no cooperating writer can slip a
            # row between the pass-1 census and the pass-2 copy.
            if _HAS_FCNTL:
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            try:
                stats.bytes_before = os.fstat(fh.fileno()).st_size

                # ── pass 1: newest line per droppable identity ──
                # winner[identity] = (ts, line_no) — newest ts wins,
                # later-in-file wins ties (the append-order
                # convention every latest-wins consumer applies).
                winner: dict[tuple, tuple[str, int]] = {}
                line_no = -1
                in_overlong = False
                for raw_line, overlong in _iter_lines(fh):
                    if overlong:
                        if not in_overlong:
                            line_no += 1
                            stats.rows_before += 1
                            stats.kept_unparseable += 1
                            in_overlong = True
                        if raw_line.endswith(b"\n"):
                            in_overlong = False
                        continue
                    line_no += 1
                    stripped = raw_line.strip()
                    if not stripped:
                        continue
                    stats.rows_before += 1
                    ident, raw = _classify(stripped)
                    if raw is not None:
                        stats.spend_usd_before += _row_cost(raw)
                    else:
                        stats.kept_unparseable += 1
                    if ident is None:
                        continue
                    if len(winner) >= _MAX_IDENTITIES \
                            and ident not in winner:
                        raise CompactRefused(
                            f"journal at {journal_path} carries more "
                            f"than {_MAX_IDENTITIES} distinct "
                            "re-emission identities — refusing to "
                            "compact a file this tool cannot bound"
                        )
                    ts = str(raw.get("ts", "")) if raw else ""
                    prev = winner.get(ident)
                    if prev is None or (ts, line_no) >= prev:
                        winner[ident] = (ts, line_no)

                # ── pass 2: verbatim copy of every kept line ──
                fh.seek(0)
                tmp_fd, tmp_name = tempfile.mkstemp(
                    prefix=".~compact-", suffix=".jsonl",
                    dir=str(out_dir),
                )
                tmp_path = Path(tmp_name)
                with os.fdopen(tmp_fd, "wb") as out:
                    tmp_fd = None      # ownership moved to `out`
                    line_no = -1
                    in_overlong = False
                    for raw_line, overlong in _iter_lines(fh):
                        if overlong:
                            if not in_overlong:
                                line_no += 1
                                stats.rows_after += 1
                                in_overlong = True
                            if raw_line.endswith(b"\n"):
                                in_overlong = False
                            out.write(raw_line)   # kept verbatim
                            continue
                        line_no += 1
                        stripped = raw_line.strip()
                        if not stripped:
                            continue              # blank filler line
                        ident, raw = _classify(stripped)
                        kept_line = winner.get(ident) if ident else None
                        if ident is not None and kept_line is not None \
                                and kept_line[1] != line_no:
                            stats.dropped_reemissions += 1
                            continue
                        out.write(raw_line)
                        stats.rows_after += 1
                        if raw is not None:
                            stats.spend_usd_after += _row_cost(raw)
                    out.flush()
                    os.fsync(out.fileno())
                stats.bytes_after = tmp_path.stat().st_size

                # Loss-contract hard stop: droppable rows are zero-
                # cost by rule, so the journal spend floor must be
                # bit-identical. Refuse the swap otherwise.
                if stats.spend_usd_after < stats.spend_usd_before:
                    raise CompactRefused(
                        "compaction would lower the journal spend "
                        f"floor ({stats.spend_usd_before} -> "
                        f"{stats.spend_usd_after}) — refusing; "
                        "original journal untouched"
                    )

                # ── backup (hardlink, never deleted), then swap ──
                backup = _backup_path(journal_path)
                os.link(str(journal_path), str(backup))
                stats.backup_path = str(backup)
                os.rename(str(tmp_path), str(journal_path))
                tmp_path = None
                dir_fd = os.open(str(out_dir), os.O_RDONLY)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
            finally:
                if _HAS_FCNTL:
                    with contextlib.suppress(OSError):
                        fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
    finally:
        if tmp_fd is not None:
            with contextlib.suppress(OSError):
                os.close(tmp_fd)
        if tmp_path is not None:
            with contextlib.suppress(OSError):
                tmp_path.unlink()
    return stats


def _classify(stripped: bytes) -> tuple[tuple | None, dict | None]:
    """(droppable-identity | None, parsed row | None) for one line.

    Identity is non-None only for rows the shared re-emission rule
    marks droppable; the parsed dict comes back for every valid row
    so both passes can account spend/ts without re-parsing.
    """
    try:
        raw = loads(stripped)
    except Exception:  # noqa: BLE001 — row containment boundary
        return None, None
    if not isinstance(raw, dict):
        return None, None
    try:
        entry = _entry_from_dict(raw)
    except Exception:  # noqa: BLE001 — row containment boundary
        return None, raw if isinstance(raw, dict) else None
    return _reemission_identity(entry), raw
