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

Superseding tier (``--supersede``, opt-in): the duplicate prune above
is lossless by contract, so a journal dominated by DISTINCT-bodied
live review rows (a multi-segment mega-audit re-reviewing the same
sites across passes) can stay over the loader budget with the plain
compact a no-op — permanently wedging the spend-authorizing resume.
The superseding tier keeps only the NEWEST row per review identity
(:func:`_supersede_identity` — site, source hash, verdict, model,
strategy set, producer; exactly the granularity every latest-wins
consumer collapses to) and archives the full original journal beside
the live file (``.pre-supersede`` family). Rows whose loss any
consumer could observe are retained outright: claim rows
(finding/suspicious), corrections (``validate_verdict``/``lesson``),
provisional rows, error/dark rows, and unparseable lines. The journal
spend floor is preserved bit-exactly: each dropped cost-bearing row is
replaced IN PLACE by a tiny synthetic spend-carrier row bearing the
identical ``cost_usd`` value, so the loader's sequential sum sees the
same value sequence (:func:`_spend_carrier_line`) — and the pre-swap
hard stop re-derives the after-floor by parsing the WRITTEN file
(:func:`_file_spend`), so both an omitted and a value-corrupted
carrier refuse the swap.

Safety: refuses to compact a run whose recorded worker process is
alive; holds the journal appenders' ``flock`` across both passes and
the swap; backs the original up as ``review-journal.jsonl.pre-compact``
(``.pre-supersede`` for the superseding tier; hardlink — zero copy,
never deleted) before an atomic tempfile+rename replace.
"""

from __future__ import annotations

import contextlib
import json
import logging
import math
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any

# The loader's per-value spend clamp ceiling — imported (not
# mirrored) so the compactor's floor accounting can never drift from
# the loader's ``journal_spend_usd`` view. Module-level import is
# cycle-free: ``core.audit.resume`` imports only ``core.json`` at
# module scope.
from core.audit.resume import _MAX_SPEND_EVIDENCE_USD
from core.json import loads

from . import journal as _journal
from .journal import (
    JOURNAL_FILENAME,
    ReviewJournalEntry,
    _canonical_strategy_hash,
    _entry_from_dict,
    _reemission_identity,
    entry_producer,
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
_BACKUP_SUFFIX_SUPERSEDE = ".pre-supersede"
_DISCARD_CHUNK = 1 << 20

#: Reserved identity of synthetic spend-carrier rows. The bracketed
#: function name cannot collide with a real identifier in any target
#: language, and the empty file component never matches an inventory
#: path — so a carrier can never satisfy a resume lookup, earn
#: coverage, or shadow a real function's verdict even before its
#: ``error`` verdict excludes it from every authority path.
SPEND_CARRIER_FUNCTION = "[journal-spend-carrier]"
#: Strategy tag stamped on every spend-carrier row — the machine
#: marker consumers can key on (see :func:`is_spend_carrier`).
SPEND_CARRIER_STRATEGY = "superseded-spend-carrier"
#: ``error_class`` stamped on spend-carrier rows.
SPEND_CARRIER_ERROR_CLASS = "spend_carrier"


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
    dropped_superseded: int = 0
    spend_carriers: int = 0
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


def _backup_path(journal_path: Path, suffix: str = _BACKUP_SUFFIX) -> Path:
    """First free ``.pre-compact`` / ``.pre-supersede`` name — an
    existing backup is never overwritten (it may be the only copy of a
    previous generation)."""
    base = journal_path.with_name(journal_path.name + suffix)
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
    """Bounded per-row cost, matching the spend loader's clamp
    (``core.audit.resume._spend_value``): non-finite values clamp,
    never sum raw. On stdlib-json installs a planted ``1e400`` parses
    to ``inf`` (the row quarantines at load, but the compactor
    accounts unparseable-dict rows too), and an ``inf`` on BOTH sides
    of the pre-swap floor check degenerates it to ``inf == inf`` —
    silently accepting any forged carrier value. The clamp keeps
    every contribution finite so the check stays sensitive."""
    cost = raw.get("cost_usd")
    if isinstance(cost, (int, float)) and not isinstance(cost, bool):
        try:
            v = float(cost)
        except (OverflowError, ValueError):
            return 0.0
        if not math.isfinite(v):
            v = _MAX_SPEND_EVIDENCE_USD if v > 0 else 0.0
        return min(max(0.0, v), _MAX_SPEND_EVIDENCE_USD)
    return 0.0


def _file_spend(path: Path) -> float:
    """Sequential journal spend re-derived by PARSING *path*.

    The pre-swap floor check must verify the bytes actually written,
    not an accumulator fed from the source rows: a value-corrupting
    bug in the carrier writer (or any future rewrite arm) would leave
    a source-fed after-sum equal to the before-sum while the on-disk
    floor drifted. Same per-row accounting as the census —
    ``_row_cost`` over parsed rows in file order; unparseable and
    over-long lines contribute nothing, matching the loader's
    ``journal_spend_usd`` view."""
    total = 0.0
    with path.open("rb") as fh:
        for raw_line, overlong in _iter_lines(fh):
            if overlong:
                continue
            stripped = raw_line.strip()
            if not stripped:
                continue
            _entry, raw = _classify(stripped)
            if raw is not None:
                total += _row_cost(raw)
    return total


def is_spend_carrier(entry: Any) -> bool:
    """True for synthetic spend-carrier rows written by the
    superseding tier. Accepts a :class:`ReviewJournalEntry` or a raw
    journal dict — the machine marker is the carrier strategy tag."""
    if isinstance(entry, dict):
        strategies = entry.get("strategies")
    else:
        strategies = getattr(entry, "strategies", None)
    return SPEND_CARRIER_STRATEGY in (strategies or [])


def _supersede_identity(entry: ReviewJournalEntry) -> tuple | None:
    """Superseding-tier identity for a row, or ``None`` when the row
    must be retained outright.

    A row is superseded only by a NEWER row with the identical
    identity — the granularity every latest-wins consumer collapses
    to, which is also the project index's storage key
    (``index_key``: site, model, strategy hash, producer), plus the
    ``source_hash`` and ``verdict`` the loader's duplicate-prune
    identity carries. Anything a consumer reads from NON-latest rows
    is excluded from superseding entirely:

    * claim rows (``finding``/``suspicious``) — distinct emissions can
      record distinct findings and re-validation evidence;
    * corrections and feedback (``validate_verdict``/``lesson``) —
      survival stats and FP feedback read them from non-latest rows;
    * ``provisional`` rows — not a settled verdict;
    * ``error``/``dark`` rows — unresolved/retry states whose
      disappearance would change what a resume re-reviews;
    * spend-carrier rows from a previous superseding pass.

    ``verdict`` stays in the identity even though only benign
    verdicts are droppable, so a key's presence in ``reviewed_set``
    (which screens by verdict) is preserved exactly.
    """
    if entry.verdict not in ("clean", "dormant"):
        return None
    if entry.validate_verdict or entry.lesson or entry.provisional:
        return None
    return (
        entry.key, entry.line_start or 0, entry.source_hash,
        entry.verdict, entry.model or "",
        _canonical_strategy_hash(entry.strategies),
        entry_producer(entry),
    )


def _spend_carrier_line(entry: ReviewJournalEntry,
                        raw: dict[str, Any]) -> bytes | None:
    """One synthetic spend-carrier line for a superseded row, or
    ``None`` when the row carries no cost.

    The carrier preserves the dropped row's ``cost_usd`` VALUE and its
    position in the file, so the loader's sequential spend sum
    (``journal_spend_usd``) sees the identical value sequence — the
    spend floor is preserved bit-exactly, not merely to the cent. The
    row is loader-compatible by construction (built through the entry
    dataclass and MAC-stamped like a live append) and inert
    everywhere: ``error`` verdict (excluded from ``reviewed_set``,
    coverage import, drift, and every reuse fold), reserved
    file/function identity, and a ``[mechanical]`` body prefix so the
    single counting rule (``is_mechanical_echo``) keeps it out of
    review counts.
    """
    cost = raw.get("cost_usd")
    if not isinstance(cost, (int, float)) or isinstance(cost, bool) \
            or cost == 0:
        return None
    carrier = ReviewJournalEntry(
        ts=entry.ts,
        run_id=entry.run_id,
        file="",
        function=SPEND_CARRIER_FUNCTION,
        verdict="error",
        source_hash="",
        strategies=[SPEND_CARRIER_STRATEGY],
        body=(
            "[mechanical] spend carrier: preserves the cost of a "
            "review row dropped by `journal compact --supersede`; "
            "the full row is in the review-journal.jsonl"
            f"{_BACKUP_SUFFIX_SUPERSEDE}* archive"
        ),
        cost_usd=cost,
        error_class=SPEND_CARRIER_ERROR_CLASS,
    )
    from core.coverage import journal_mac
    row = carrier.to_dict()
    row.pop(journal_mac.TOKEN_KEY, None)
    token = journal_mac.mint_row(row)
    if token:
        row[journal_mac.TOKEN_KEY] = token
    return (
        json.dumps(row, separators=(",", ":"), allow_nan=False) + "\n"
    ).encode("utf-8")


def compact_journal(out_dir: Path, *,
                    supersede: bool = False) -> CompactStats:
    """Atomically rewrite the run's journal without its duplicate
    re-emission rows. Returns before/after stats; raises
    :class:`CompactRefused` (file untouched) when the run is live,
    the journal is absent/unreadable, or the file's identity
    population exceeds the tool's bounds.

    ``supersede=True`` additionally drops every superseded row —
    non-newest per :func:`_supersede_identity` — replacing each
    cost-bearing one with a spend-carrier row in place, and archives
    the original under the ``.pre-supersede`` name family instead of
    ``.pre-compact``. Opt-in only: this tier is lossy on the LIVE
    file (full history stays in the archive) and is never applied by
    the resume auto-compact.
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
                # Sweep tmp files leaked by a pre-rename kill of an
                # earlier compaction (own prefix only, bounded). Safe
                # under the held flock: a cooperating compactor holds
                # it across its tmp's whole lifetime, so anything
                # matching here is stale.
                for stale in sorted(
                        out_dir.glob(".~compact-*.jsonl"))[:16]:
                    with contextlib.suppress(OSError):
                        stale.unlink()

                stats.bytes_before = os.fstat(fh.fileno()).st_size

                # ── pass 1: newest line per droppable identity ──
                # winner[identity] = (ts, line_no) — newest ts wins,
                # later-in-file wins ties (the append-order
                # convention every latest-wins consumer applies).
                # The superseding tier keeps its own map: the two
                # rules have different droppability contracts, and a
                # row can be droppable under both.
                winner: dict[tuple, tuple[str, int]] = {}
                sup_winner: dict[tuple, tuple[str, int]] = {}
                # Reemission identity of each elected sup-winner row
                # (None for live rows) — consumed by the post-census
                # reconciliation below.
                sup_winner_rident: dict[tuple, tuple | None] = {}

                def _note_winner(
                    table: dict[tuple, tuple[str, int]],
                    ident: tuple, ts: str, line_no: int,
                ) -> bool:
                    if len(table) >= _MAX_IDENTITIES \
                            and ident not in table:
                        raise CompactRefused(
                            f"journal at {journal_path} carries more "
                            f"than {_MAX_IDENTITIES} distinct "
                            "row identities — refusing to "
                            "compact a file this tool cannot bound"
                        )
                    prev = table.get(ident)
                    if prev is None or (ts, line_no) >= prev:
                        table[ident] = (ts, line_no)
                        return True
                    return False

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
                    entry, raw = _classify(stripped)
                    if raw is not None:
                        stats.spend_usd_before += _row_cost(raw)
                    else:
                        stats.kept_unparseable += 1
                    if entry is None:
                        continue
                    ts = str(raw.get("ts", "")) if raw else ""
                    ident = _reemission_identity(entry)
                    if ident is not None:
                        _note_winner(winner, ident, ts, line_no)
                    if supersede:
                        sident = _supersede_identity(entry)
                        if sident is not None and _note_winner(
                                sup_winner, sident, ts, line_no):
                            sup_winner_rident[sident] = ident

                # A sup-winner the dedup arm will itself drop (only a
                # cross-producer reused twin can outrank it — the
                # dedup identity lacks the producer axis, every other
                # axis is shared) must not authorize superseding: its
                # siblings would be dropped against a winner that
                # never lands, leaving the identity with ZERO
                # surviving rows (a live audit review row lost to a
                # finding-grade twin — the re-spend direction). Skip
                # superseding such identities this pass; the dedup arm
                # still removes the duplicate, and a subsequent
                # --supersede converges.
                for sident, rident in sup_winner_rident.items():
                    if rident is None:
                        continue
                    kept = winner.get(rident)
                    if kept is not None \
                            and kept[1] != sup_winner[sident][1]:
                        del sup_winner[sident]

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
                        entry, raw = _classify(stripped)
                        ident = (
                            _reemission_identity(entry)
                            if entry is not None else None
                        )
                        kept_line = winner.get(ident) if ident else None
                        if ident is not None and kept_line is not None \
                                and kept_line[1] != line_no:
                            stats.dropped_reemissions += 1
                            continue
                        if supersede and entry is not None:
                            sident = _supersede_identity(entry)
                            sup_kept = (
                                sup_winner.get(sident)
                                if sident is not None else None
                            )
                            if sup_kept is not None \
                                    and sup_kept[1] != line_no:
                                stats.dropped_superseded += 1
                                carrier = _spend_carrier_line(
                                    entry, raw or {})
                                if carrier is not None:
                                    out.write(carrier)
                                    stats.rows_after += 1
                                    stats.spend_carriers += 1
                                continue
                        out.write(raw_line)
                        stats.rows_after += 1
                    out.flush()
                    os.fsync(out.fileno())
                stats.bytes_after = tmp_path.stat().st_size

                # Loss-contract hard stop, verified against the BYTES
                # WRITTEN: the after-sum is re-derived by parsing the
                # tmp file, never carried over from the source rows —
                # a source-fed accumulator is blind to a
                # value-corrupting bug in the carrier writer (both
                # sums would agree while the on-disk floor drifted).
                # Plain tier: droppable rows are zero-cost by rule, so
                # the floor cannot decrease. Superseding tier: carriers
                # reproduce every dropped cost value in place, so the
                # re-parsed floor must be bit-identical; any mismatch
                # refuses the swap.
                stats.spend_usd_after = _file_spend(tmp_path)
                floor_broken = (
                    stats.spend_usd_after != stats.spend_usd_before
                    if supersede
                    else stats.spend_usd_after < stats.spend_usd_before
                )
                if floor_broken:
                    raise CompactRefused(
                        "compaction would change the journal spend "
                        f"floor ({stats.spend_usd_before} -> "
                        f"{stats.spend_usd_after}) — refusing; "
                        "original journal untouched"
                    )

                # ── backup (hardlink, never deleted), then swap ──
                backup = _backup_path(
                    journal_path,
                    _BACKUP_SUFFIX_SUPERSEDE if supersede
                    else _BACKUP_SUFFIX,
                )
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


def _classify(
    stripped: bytes,
) -> tuple[ReviewJournalEntry | None, dict | None]:
    """(parsed entry | None, parsed row | None) for one line.

    The entry is non-None only for rows the loader would accept —
    droppability under either tier's identity rule is decided by the
    callers; the parsed dict comes back for every valid JSON row so
    both passes can account spend/ts without re-parsing.
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
    return entry, raw
