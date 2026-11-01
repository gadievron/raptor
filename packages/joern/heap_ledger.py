"""Cross-session Joern memory admission.

Production spawns reserve Xmx plus native headroom before exec. A parser
reserves both its driver and frontend JVM. Capacity exhaustion refuses a
spawn; explicit heaps are never silently reduced. This is bookkeeping, not a
kernel memory limit.

Each new reservation has a private file lock inherited by the JVM. Kernel
lock lifetime, rather than a PID meaningful in only one namespace, proves
whether that reservation remains live. PID/birth metadata remains diagnostic
and supports legacy rows. Historical advisory callers retain their explicit
warn-and-continue behavior without writing unverified ledger state.
"""

from __future__ import annotations

import contextlib
import ctypes
import sys
import errno
import json
import logging
import os
import stat
import tempfile
import time
import uuid
from collections.abc import Iterator
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path

from core.atomic_fs.fs_lock import artifact_lock
from .resource_lifetime import Lifetime, discard, held

logger = logging.getLogger(__name__)

# Test-override seam: when set (tests monkeypatch a tmp path here) it
# wins over the env-derived default. Production leaves it None so
# ``_ledger_path()`` re-reads ``XDG_DATA_HOME`` on every call — an env
# pin installed AFTER this module is imported still redirects the
# ledger instead of being silently ignored by an import-time snapshot.
# The unset-env default is the shared host-global arbitration point;
# every spawner must resolve the SAME file for admission to arbitrate
# anything, so the default path is a cross-consumer contract.
_LEDGER_PATH: Path | None = None


def _ledger_path() -> Path:
    """Ledger location, resolved at call time:
    ``$XDG_DATA_HOME/raptor/joern-heap-ledger.json`` (default
    ``~/.local/share/raptor/joern-heap-ledger.json``)."""
    if _LEDGER_PATH is not None:
        return _LEDGER_PATH
    xdg = os.environ.get("XDG_DATA_HOME")
    base = Path(xdg) if xdg else Path.home() / ".local" / "share"
    return base / "raptor" / "joern-heap-ledger.json"

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
    budget = (pages * page_size) // (1024 * 1024)
    # A container or delegated scope may have much less memory than the
    # physical host. Include every visible ancestor ceiling, not only the
    # current leaf (which commonly says 'max').
    try:
        row = next(line for line in Path("/proc/self/cgroup").read_text().splitlines()
                   if line.startswith("0::"))
        root = Path("/sys/fs/cgroup")
        relative = Path(row[3:].lstrip("/"))
        if ".." not in relative.parts:
            current = root / relative
            while current == root or root in current.parents:
                try:
                    value = (current / "memory.max").read_text().strip()
                    if value != "max":
                        budget = min(budget, int(value) // (1024 * 1024))
                except (OSError, ValueError):
                    pass
                if current == root:
                    break
                current = current.parent
    except (OSError, StopIteration):
        pass
    return budget


class _DarwinProcessInfo(ctypes.Structure):
    # XNU sys/proc_info.h, proc_bsdinfo (PROC_PIDTBSDINFO=3).
    # https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/proc_info.h
    _fields_ = [("identifiers", ctypes.c_uint32 * 12),
                ("command", ctypes.c_char * 16), ("name", ctypes.c_char * 32),
                ("details", ctypes.c_uint32 * 6),
                ("seconds", ctypes.c_uint64), ("microseconds", ctypes.c_uint64)]


def _darwin_starttime(pid):
    try:
        function = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True).proc_pidinfo
        function.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64,
                             ctypes.c_void_p, ctypes.c_int]
        function.restype = ctypes.c_int
        info = _DarwinProcessInfo()
        size = ctypes.sizeof(info)
        if function(pid, 3, 0, ctypes.byref(info), size) != size:
            return None
        if info.identifiers[3] != pid or not info.seconds:
            return None
        return info.seconds * 1_000_000 + info.microseconds
    except (OSError, AttributeError):
        return None


def _pid_starttime(pid: int) -> int | None:
    """Kernel start time of *pid* (field 22 of ``/proc/<pid>/stat``).

    The pid-reuse defense for ledger rows: a recycled pid gets a new
    starttime, so a stale row never rides a stranger's pid. None when
    unreadable (process gone, or no procfs on this platform).
    """
    if sys.platform == "darwin":
        return _darwin_starttime(pid)
    try:
        stat = Path(f"/proc/{pid}/stat").read_bytes()
        # Split AFTER the comm field — comm may contain spaces and
        # parens, but the kernel renders it as the last ") " pair.
        return int(stat.rsplit(b") ", 1)[1].split()[19])
    except (OSError, ValueError, IndexError):
        return None


def _row_live(row: dict, *, ledger_path=None) -> bool:
    """A row is live while its recorded (pid, starttime) still names
    a running process."""
    if row.get("lease") is True:
        return held(_ledger_path() if ledger_path is None else ledger_path, row.get("id"))
    pid = row.get("pid")
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        return False
    boot, namespace = _kernel_context()
    if row.get("boot") is not None and boot is not None and row["boot"] != boot:
        return False
    if row.get("pid_namespace") is not None and namespace is not None and row["pid_namespace"] != namespace:
        # A nested /proc cannot prove that another namespace's PID died.
        # Retain its charge instead of admitting overlapping heaps.
        return True
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


def _kernel_context():
    try:
        return (Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
                Path("/proc/self/ns/pid").stat().st_ino)
    except OSError:
        return None, None


def _read_rows(path: Path, *, required=False) -> list[dict]:
    """Read verified reservations; only a missing ledger is empty.

    Corruption must never erase existing reservations during admission.
    Advisory callers may decline bookkeeping, but cannot overwrite it.
    """
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
                raise ValueError("unsafe heap ledger")
            raw = stream.read(1024 * 1024 + 1)
            if len(raw) > 1024 * 1024:
                raise ValueError("oversized heap ledger")
            data = json.loads(raw)
    except FileNotFoundError:
        return []
    except (OSError, ValueError) as error:
        raise OSError(errno.EINVAL, "Joern heap ledger cannot be verified") from error
    rows = data.get("rows") if isinstance(data, dict) else None
    if not isinstance(rows, list):
        raise OSError(errno.EINVAL, "invalid Joern heap ledger rows")
    if required and any(not isinstance(row, dict) or type(row.get("mb")) is not int or row["mb"] < 0 for row in rows):
        raise OSError(errno.EINVAL, "invalid Joern heap reservation")
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
    require_capacity: bool = False
    lifetime: Lifetime | None = None

    @property
    def pass_fds(self):
        return self.lifetime.pass_fds if self.lifetime is not None else ()

    def release(self) -> None:
        """Close this holder; a surviving child retains the kernel charge."""
        if self.lifetime is not None:
            self.lifetime.close()
        try:
            with artifact_lock(self.ledger_path, subject="joern JVM heap ledger", required=True):
                rows = _read_rows(self.ledger_path, required=self.require_capacity)
                remaining = []
                for row in rows:
                    live = _row_live(row, ledger_path=self.ledger_path)
                    if row.get("id") == self.row_id and self.lifetime is None:
                        live = False  # legacy advisory reservations release explicitly
                    if live:
                        remaining.append(row)
                    elif row.get("lease") is True:
                        discard(self.ledger_path, row.get("id"))
                _write_rows(self.ledger_path, remaining)
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
                self.ledger_path, subject="joern JVM heap ledger", required=True,
            ):
                rows = _read_rows(self.ledger_path, required=self.require_capacity)
                for row in rows:
                    if row.get("id") == self.row_id:
                        row["pid"] = pid
                        row["starttime"] = _pid_starttime(pid)
                        row["boot"], row["pid_namespace"] = _kernel_context()
                _write_rows(self.ledger_path, rows)
        except OSError:
            logger.debug("heap ledger rebind failed", exc_info=True)


def reserve_heap_mb(
    requested_mb: int,
    *,
    derived: bool,
    pid: int | None = None,
    ledger_path: Path | None = None,
    require_capacity: bool = False,
    simultaneous_jvms: int = 1,
) -> HeapReservation:
    """Admit a JVM spawn of *requested_mb* against the host budget.

    Dead rows are evicted, live rows are summed, and the grant is
    clamped (derived heaps only) to the remaining budget — never
    below :data:`_HEAP_GRANT_FLOOR_MB`, and never refused: a small
    overcommitted JVM beats losing the joern channel. The new row is
    keyed on *pid* (default: this process) until :meth:`rebind`.
    """
    if type(requested_mb) is not int or requested_mb <= 0:
        raise ValueError("Joern heap must be a positive number of megabytes")
    if type(simultaneous_jvms) is not int or simultaneous_jvms < 1:
        raise ValueError("simultaneous JVM count must be positive")
    pid = os.getpid() if pid is None else pid
    path = _ledger_path() if ledger_path is None else ledger_path
    granted = requested_mb
    lifetime = None
    row_id = uuid.uuid4().hex
    try:
        granted, lifetime = _admit_locked(
            path, requested_mb, derived=derived, pid=pid, row_id=row_id,
            require_capacity=require_capacity, simultaneous_jvms=simultaneous_jvms,
        )
    except OSError:
        if require_capacity:
            raise
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
        require_capacity=require_capacity, lifetime=lifetime,
    )


def _admit_locked(
    path: Path, requested_mb: int, *,
    derived: bool, pid: int, row_id: str,
    require_capacity: bool = False,
    simultaneous_jvms: int = 1,
) -> tuple[int, Lifetime | None]:
    """Return the admitted heap and its kernel-held lifetime."""
    granted = requested_mb
    lifetime = None
    with artifact_lock(path, subject="joern JVM heap ledger", required=True):
        rows = []
        for row in _read_rows(path, required=require_capacity):
            if _row_live(row, ledger_path=path):
                rows.append(row)
            elif row.get("lease") is True:
                discard(path, row.get("id"))
        committed = sum(_row_mb(r) for r in rows)
        budget = _host_budget_mb()
        if require_capacity:
            # Reserve native/metaspace/thread headroom as well as Xmx.
            # This is admission bookkeeping, not a kernel memory limit.
            if budget is None:
                raise OSError(errno.ENOSPC, "Joern memory budget is unavailable")
            available = budget - committed
            maximum_heap = max(0, (available // simultaneous_jvms - 256) * 4 // 5)
            if derived:
                granted = min(requested_mb, maximum_heap)
                if granted < min(requested_mb, _HEAP_GRANT_FLOOR_MB):
                    raise OSError(errno.ENOSPC, "Joern memory capacity exhausted")
            elif requested_mb > maximum_heap:
                raise OSError(errno.ENOSPC, "explicit Joern heap exceeds available capacity")
            accounted_mb = simultaneous_jvms * (granted + (granted + 3) // 4 + 256)
        else:
            accounted_mb = None
        if not require_capacity and budget is not None and committed + requested_mb > budget:
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
        boot, namespace = _kernel_context()
        rows.append({
            "id": row_id,
            "pid": pid,
            "starttime": _pid_starttime(pid),
            "mb": accounted_mb if accounted_mb is not None else granted,
            "derived": derived,
            "created_at": time.time(),
            "boot": boot,
            "pid_namespace": namespace,
        })
        if require_capacity:
            lifetime = Lifetime.create(path, row_id)
            rows[-1]["lease"] = True
        try:
            _write_rows(path, rows)
        except BaseException:
            if lifetime is not None:
                lifetime.close()
                discard(path, row_id)
            raise
    return granted, lifetime



_active_reservation: ContextVar[HeapReservation | None] = ContextVar("joern_heap_admission", default=None)


def reservation_fds():
    reservation = _active_reservation.get()
    return reservation.pass_fds if reservation is not None else ()


def reservation_paths():
    reservation = _active_reservation.get()
    lifetime = reservation.lifetime if reservation is not None else None
    return [str(lifetime.path)] if lifetime is not None else []


@contextlib.contextmanager
def heap_admission(
    requested_mb: int | None,
    *,
    derived: bool,
    ledger_path: Path | None = None,
    require_capacity: bool = False,
    simultaneous_jvms: int = 1,
) -> Iterator[int | None]:
    """Reserve for the duration of a synchronous JVM run (the
    joern-parse frontend). Yields the granted -Xmx MB — the requested
    value unless a derived heap was clamped; None in, None out."""
    if requested_mb is None:
        yield None
        return
    reservation = reserve_heap_mb(
        requested_mb, derived=derived, ledger_path=ledger_path,
        require_capacity=require_capacity, simultaneous_jvms=simultaneous_jvms,
    )
    token = _active_reservation.set(reservation)
    try:
        yield reservation.granted_mb
    finally:
        _active_reservation.reset(token)
        reservation.release()
