"""Cross-session JVM heap admission ledger.

Every joern JVM RAPTOR spawns (the query server, joern-parse
frontends) carries an ``-Xmx`` sized by the tuning derivation, and
the derivation assumes an otherwise-idle host. Run N sessions
concurrently and each derives the same near-host-sized heap
independently: the committed Xmx sum crosses physical RAM and the
kernel OOM-kills whichever JVM happens to grow last — correlated
mid-run server deaths under fleet load, each session convinced its
own limits were fine.

The ledger arbitrates at SPAWN time, not at derivation time: a
spawner reserves its heap in a flock-guarded host-global file BEFORE
exec, and the grant is clamped to what the host budget minus live
reservations can still carry. Rows are keyed on
``(pid, /proc starttime)``: a reservation whose owner died — crashed
session, OOM-killed JVM, hard external kill — is evicted at the next
admission, so leaked reservations self-heal without any release
protocol (``release()`` still exists for prompt reclaim, and the
shared query server relies on eviction: the session that finally
kills it at refcount zero is usually not the one that booted it).

Only DERIVED heaps are clamped. An explicit operator heap is an
assertion — the same both-directions rule the retry-at-derived-max
path follows: it is REGISTERED so other spawners see the pressure,
but never reduced.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import tempfile
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from core.fs_lock import artifact_lock

logger = logging.getLogger(__name__)

_LEDGER_PATH = (
    Path.home() / ".local" / "share" / "raptor" / "joern-heap-ledger.json"
)

# Grant floor (MB) when the budget is exhausted. Both directions
# matter: lower and the granted JVM cannot boot the REPL or hold any
# real CPG — the spawn just converts host memory pressure into a
# guaranteed in-JVM OOM loop; higher and every over-budget grant
# pushes an already-exhausted host further past physical RAM, when
# the floor's only job is to keep the joern channel bootable at all
# (losing the channel outright costs the run more than one modestly
# overcommitted small JVM).
_HEAP_GRANT_FLOOR_MB = 1024


def _host_budget_mb() -> int | None:
    """Host-wide heap budget: 100% of physical RAM, or None when RAM
    is undetectable (no clamping — admission degrades to registration).

    Both directions: above 100% re-opens the correlated-OOM incident
    this module exists for (the committed Xmx sum may exceed RAM, so
    every JVM believes it can grow past physical memory); below 100%
    would cap a SINGLE session on an idle host under what the static
    derivation already grants — the one-session case must be
    unaffected (committed=0 → full grant), and the derivation's own
    per-JVM ceiling already leaves host headroom.
    """
    try:
        pages = os.sysconf("SC_PHYS_PAGES")
        page_size = os.sysconf("SC_PAGE_SIZE")
    except (ValueError, OSError, AttributeError):
        return None
    if pages <= 0 or page_size <= 0:
        return None
    return (pages * page_size) // (1024 * 1024)


def _pid_starttime(pid: int) -> int | None:
    """Kernel start time of *pid* (field 22 of ``/proc/<pid>/stat``).

    The pid-reuse defense for ledger rows: a recycled pid gets a new
    starttime, so a stale row never rides a stranger's pid. None when
    unreadable (process gone, or no procfs on this platform).
    """
    try:
        stat = Path(f"/proc/{pid}/stat").read_bytes()
        # Split AFTER the comm field — comm may contain spaces and
        # parens, but the kernel renders it as the last ") " pair.
        return int(stat.rsplit(b") ", 1)[1].split()[19])
    except (OSError, ValueError, IndexError):
        return None


def _row_live(row: dict) -> bool:
    """A row is live while its recorded (pid, starttime) still names
    a running process."""
    pid = row.get("pid")
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        return False
    starttime = _pid_starttime(pid)
    if starttime is not None:
        # The recorded starttime must MATCH — a row without one (or
        # with a crafted null) would otherwise live as long as its
        # pid number stays occupied by anyone, defeating the
        # pid-reuse defense the key exists for. Rows this module
        # writes always carry the spawn-time value on Linux; a None
        # here means the pid was already dead at write time.
        return row.get("starttime") == starttime
    if Path("/proc").is_dir():
        # procfs exists but the pid's entry is gone: dead.
        return False
    # No procfs (non-Linux): degrade to a liveness signal without the
    # pid-reuse defense.
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True
    return True


def _row_mb(row: dict) -> int:
    """A row's committed MB: a real non-negative int, else 0.

    The ledger file is same-uid writable, so admission must not trust
    row schema it did not write: a crafted negative ``mb`` would make
    the committed sum deeply negative and reopen the correlated-OOM
    overcommit the ledger exists to prevent (and ``bool`` is an
    ``int`` subtype, so ``True`` rows must not count as 1 MB)."""
    mb = row.get("mb")
    if isinstance(mb, bool) or not isinstance(mb, int):
        return 0
    return max(0, mb)


def _read_rows(path: Path) -> list[dict]:
    """Ledger rows on disk; a missing or corrupt file is an empty
    ledger (the ledger is arbitration state, not a record of truth —
    live JVMs re-register on their next spawn, dead ones should not
    survive corruption anyway)."""
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        return []
    rows = data.get("rows") if isinstance(data, dict) else None
    if not isinstance(rows, list):
        return []
    return [r for r in rows if isinstance(r, dict)]


def _write_rows(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".heap-ledger-")
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump({"version": 1, "rows": rows}, fh)
        os.replace(tmp, path)
    except OSError:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


@dataclass
class HeapReservation:
    """A live admission grant. ``granted_mb`` is the -Xmx the spawn
    may actually claim; it equals ``requested_mb`` unless the budget
    clamped a derived heap."""

    row_id: str
    requested_mb: int
    granted_mb: int
    ledger_path: Path

    def release(self) -> None:
        """Return the reservation promptly (idempotent). Never
        required for correctness — a dead owner's row is evicted at
        the next admission."""
        try:
            with artifact_lock(
                self.ledger_path, subject="joern JVM heap ledger",
            ):
                rows = [
                    r for r in _read_rows(self.ledger_path)
                    if r.get("id") != self.row_id and _row_live(r)
                ]
                _write_rows(self.ledger_path, rows)
        except OSError:
            logger.debug("heap ledger release failed", exc_info=True)

    def rebind(self, pid: int) -> None:
        """Re-key the row to *pid* (the booted JVM member).

        The shared query server outlives its spawner, so a row keyed
        on the spawner would evict — and free heap that is still
        committed — the moment the spawning session exits. Rebinding
        to the JVM itself ties the reservation to the memory's actual
        lifetime.
        """
        try:
            with artifact_lock(
                self.ledger_path, subject="joern JVM heap ledger",
            ):
                rows = _read_rows(self.ledger_path)
                for row in rows:
                    if row.get("id") == self.row_id:
                        row["pid"] = pid
                        row["starttime"] = _pid_starttime(pid)
                _write_rows(self.ledger_path, rows)
        except OSError:
            logger.debug("heap ledger rebind failed", exc_info=True)


def reserve_heap_mb(
    requested_mb: int,
    *,
    derived: bool,
    pid: int | None = None,
    ledger_path: Path | None = None,
) -> HeapReservation:
    """Admit a JVM spawn of *requested_mb* against the host budget.

    Dead rows are evicted, live rows are summed, and the grant is
    clamped (derived heaps only) to the remaining budget — never
    below :data:`_HEAP_GRANT_FLOOR_MB`, and never refused: a small
    overcommitted JVM beats losing the joern channel. The new row is
    keyed on *pid* (default: this process) until :meth:`rebind`.
    """
    pid = os.getpid() if pid is None else pid
    path = _LEDGER_PATH if ledger_path is None else ledger_path
    granted = requested_mb
    row_id = uuid.uuid4().hex
    try:
        granted = _admit_locked(
            path, requested_mb, derived=derived, pid=pid, row_id=row_id,
        )
    except OSError:
        # The ledger is advisory bookkeeping: a full or read-only
        # state dir must not kill the JVM boot it was arbitrating
        # (release/rebind already degrade the same way). The grant
        # falls back to the unclamped derivation — exactly the
        # pre-ledger behaviour.
        logger.warning(
            "joern heap ledger unavailable — granting %d MB "
            "unclamped (admission bookkeeping skipped)",
            granted, exc_info=True,
        )
    return HeapReservation(
        row_id=row_id,
        requested_mb=requested_mb,
        granted_mb=granted,
        ledger_path=path,
    )


def _admit_locked(
    path: Path, requested_mb: int, *,
    derived: bool, pid: int, row_id: str,
) -> int:
    """The locked admission transaction; returns the granted MB."""
    granted = requested_mb
    with artifact_lock(path, subject="joern JVM heap ledger"):
        rows = [r for r in _read_rows(path) if _row_live(r)]
        committed = sum(_row_mb(r) for r in rows)
        budget = _host_budget_mb()
        if budget is not None and committed + requested_mb > budget:
            available = budget - committed
            if derived:
                granted = min(requested_mb, max(available,
                                                _HEAP_GRANT_FLOOR_MB))
                if available < _HEAP_GRANT_FLOOR_MB:
                    logger.warning(
                        "joern heap ledger: budget exhausted — %d MB "
                        "already committed by %d live JVM "
                        "reservation(s) against a %d MB host budget; "
                        "granting the %d MB floor so the channel "
                        "still boots (host now overcommitted)",
                        committed, len(rows), budget, granted,
                    )
                else:
                    logger.warning(
                        "joern heap ledger: derived -Xmx clamped "
                        "%d → %d MB (%d MB committed by %d live JVM "
                        "reservation(s) against a %d MB host budget)",
                        requested_mb, granted, committed, len(rows),
                        budget,
                    )
            else:
                logger.warning(
                    "joern heap ledger: explicit -Xmx %d MB exceeds "
                    "the remaining host budget (%d MB committed of "
                    "%d MB) — granted unreduced (operator assertion), "
                    "expect memory pressure",
                    requested_mb, committed, budget,
                )
        rows.append({
            "id": row_id,
            "pid": pid,
            "starttime": _pid_starttime(pid),
            "mb": granted,
            "derived": derived,
            "created_at": time.time(),
        })
        _write_rows(path, rows)
    return granted


@contextlib.contextmanager
def heap_admission(
    requested_mb: int | None,
    *,
    derived: bool,
    ledger_path: Path | None = None,
) -> Iterator[int | None]:
    """Reserve for the duration of a synchronous JVM run (the
    joern-parse frontend). Yields the granted -Xmx MB — the requested
    value unless a derived heap was clamped; None in, None out."""
    if requested_mb is None:
        yield None
        return
    reservation = reserve_heap_mb(
        requested_mb, derived=derived, ledger_path=ledger_path,
    )
    try:
        yield reservation.granted_mb
    finally:
        reservation.release()
