"""Orchestrator-lifetime exclusive lock on an audit run directory.

One audit orchestrator per run directory, for the orchestrator's WHOLE
process lifetime. The hazard is real and specific: a SIGTERM-drained
orchestrator keeps running until its salvage (journal flush, salvage
report, lifecycle transition) completes — and a ``raptor-audit resume``
issued against the same run directory during that drain used to start
happily. Two orchestrators then co-write one run's journal and ledgers:
the append-only rows stay individually coherent, but every function is
paid for twice and the two segments interleave mixed-version state.
Nothing in the pre-existing lock family covered this window:

* ``core.project.oplock`` (``.op.lock``) serialises mutating
  project-manager subcommands and the run-START contention window only
  — its own doctrine says a run's LIFETIME is deliberately not a flock
  there, because the stub-driven lifecycle spans processes. The audit
  orchestrator is the opposite shape: one process from start to exit,
  which is exactly what a held flock represents faithfully.
* ``core.fs_lock.artifact_lock`` / ``packages.binary_analysis
  ._artifact_lock`` / ``core.inventory._checklist_lock`` / the journal
  appenders' flock cover single read-modify-write windows, not a
  process lifetime — and their degrade-on-unopenable posture (fine for
  best-effort writers) would hand a run-dir writer a kill switch for
  the mutual exclusion here, where an existing-but-unopenable lock
  path fails CLOSED instead. The ``O_NOFOLLOW`` spelling is
  ``fs_lock``'s.
* ``core.run.metadata`` run liveness (``status=running`` + a live
  ``tool_pid``) is advisory and comm/pid-reuse-weak: ``resume`` MUST
  proceed on ``interrupted``/``failed`` runs, so status alone can never
  arbitrate "is another orchestrator alive on this directory NOW".

So this module composes the two proven idioms instead of inventing a
third:

* **flock discipline** from ``core.project.oplock`` /
  ``_artifact_lock``: an exclusive ``flock`` on a sibling lock file
  that is NEVER unlinked (unlink-after-unlock splits lockers across
  two inodes), holder diagnostics stamped AFTER acquisition, bounded
  and terminal-sanitised holder reads. The flock is held for the whole
  process lifetime — a SIGTERM drain keeps it, by construction, until
  actual exit; a crash releases it in the kernel with nothing to leak.
* **v2 identity-stamp liveness** from the session run ledger
  (``core.project.sessions``): the stamp carries pid + ``starttime`` +
  ``boot_id`` + ``pidns`` + ``machine_id``, so a recycled pid never
  reads live, a prior-boot stamp of this machine is provably dead, and
  a stamp this reader cannot verify (other machine / boot / pid
  namespace) is INDETERMINATE — never silently reclaimed. The stamp
  adjudicates the states a bare flock cannot: a free flock behind a
  stamp whose process is provably alive (holder on a no-fcntl platform,
  or a holder that lost its fd) refuses; a free flock behind an
  unverifiable stamp fails closed with the manual remedy named.

Deliberately NO comm gate on the holder pid (unlike the session
registry's ``claude``-shaped check): the holder is a Python
orchestrator, not a claude binary — the identity discriminator is
``starttime`` + ``boot_id``, same as ``core.run.metadata`` uses for
``tool_pid``-class processes.

Who takes this lock: ``raptor-audit run`` and ``raptor-audit resume``,
once each, at startup, per process. Who must NOT: the lifecycle stubs
(the orchestrator invokes ``raptor-run-lifecycle complete``/``fail`` as
child processes mid-hold — a stub taking the lock would deadlock
against its own parent), read-only consumers (``report`` / ``journal``
/ ``gaps`` / ``/review`` / coverage readers), the in-process pipeline
tail (validate post-pass, ensemble passes, review passes — same
process, lock already held; in-process re-acquisition is a no-op by
design), the journal append/compact seams (they keep their own RMW
flocks and live-run refusal), and the corpus runner (calls
``run_audit_pipeline`` in-process on scratch directories with its own
serialisation).
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import fcntl
    _HAS_FCNTL = True
except ImportError:                                    # pragma: no cover
    _HAS_FCNTL = False

logger = logging.getLogger(__name__)

RUN_LOCK_NAME = ".audit-run.lock"

#: Byte cap for the holder-stamp read. A legitimate stamp is <400
#: bytes; the lock file is writable by anything with run-dir access,
#: so the diagnostic read must not slurp a planted payload. Too low
#: and a legitimate future stamp field pushes parses into the
#: "malformed → fail closed" arm; too high just buffers more of a
#: planted file before the parse rejects it — 64 KiB matches the
#: sibling locks' bound.
_STAMP_MAX_CHARS = 64 * 1024


class AuditRunLocked(RuntimeError):
    """The run directory is (or may be) owned by another orchestrator.

    ``str(exc)`` is the operator-facing refusal; ``holder`` carries the
    parsed stamp fields when available.
    """

    def __init__(self, message: str, holder: dict | None = None) -> None:
        super().__init__(message)
        self.holder = holder or {}


class RunLockHandle:
    """A held run lock. The orchestrator never releases it — process
    exit is the release (that is the point: a SIGTERM drain keeps the
    lock through salvage until the process actually dies).
    ``release()`` exists for tests and for refusal paths inside
    ``acquire_run_lock`` itself."""

    def __init__(self, fd: int, lock_path: Path) -> None:
        self.fd = fd
        self.lock_path = lock_path

    @property
    def held(self) -> bool:
        return self.fd >= 0

    def release(self) -> None:
        if self.fd < 0:
            return
        if _HAS_FCNTL:
            with contextlib.suppress(OSError):
                fcntl.flock(self.fd, fcntl.LOCK_UN)
        with contextlib.suppress(OSError):
            os.close(self.fd)
        self.fd = -1
        with contextlib.suppress(ValueError):
            _HELD.remove(self)


#: Handles acquired by this process — referenced here so the fd (and
#: with it the flock) provably lives exactly as long as the process,
#: whatever the caller does with the return value. Also the authority
#: for self-held detection (`_held_by_this_process`): process-local
#: state a run-dir writer cannot forge, unlike the holder stamp.
#: Fork-shared: a fork() child inherits this registry AND the flock'd
#: open file description, so the child counts as holder and
#: re-acquires as self-held — semantically honest (it genuinely
#: shares the flock), but a deliberate widening to keep in mind if
#: worker-side acquisition ever appears (today's only callers are
#: orchestrator top-level and never fork before re-acquiring).
_HELD: list[RunLockHandle] = []


def _held_by_this_process(lock_path: Path) -> bool:
    """True when a handle registered by THIS process still holds the
    lock at *lock_path*. Resolved-path comparison, so re-entry through
    a different spelling of the run dir still matches (the lock file
    itself is never a symlink — planted symlinks refuse before any
    handle is registered)."""
    wanted = os.path.realpath(lock_path)
    return any(
        handle.held and os.path.realpath(handle.lock_path) == wanted
        for handle in _HELD
    )


def run_lock_path(out_dir: Path) -> Path:
    return Path(out_dir) / RUN_LOCK_NAME


def _identity_fields() -> dict[str, str]:
    """This process's identity stamp (ledger v2 vocabulary), plus
    ``machine_id`` so a prior-boot stamp of this machine is provably
    dead after a reboot (``_prior_boot_entry``)."""
    from core.project import sessions as _sessions
    fields = _sessions._identity_for(os.getpid())
    if fields is None:
        # Own /proc unreadable on Linux (pathological). Stamp sentinels
        # anyway: a lock with a weak stamp still refuses via the flock
        # while we live; after a crash it reads indeterminate → the
        # fail-closed manual remedy. Refusing to RUN here would be the
        # wrong fail direction for a diagnostics field.
        fields = {
            "starttime": _sessions._STARTTIME_SENTINEL,
            "boot_id": _sessions._platform_boot_sentinel(),
        }
    machine = _sessions.machine_id()
    if machine:
        fields["machine_id"] = machine
    return fields


def read_holder(lock_path: Path) -> dict:
    """Parse the holder stamp — bounded, tolerant. ``{}`` on absent /
    empty / unreadable / malformed / truncated content (callers decide
    the fail direction; the flock, not the content, is the mutual
    exclusion while the holder lives)."""
    from core.source import read_text_capped
    got = read_text_capped(lock_path, _STAMP_MAX_CHARS)
    if got is None:
        return {}
    text, truncated = got
    if truncated or not text.strip():
        return {}
    try:
        data = json.loads(text)
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def _holder_pid(holder: dict) -> int | None:
    pid = holder.get("pid")
    if isinstance(pid, str) and pid.isascii() and pid.isdigit():
        # Digit-length cap BEFORE int(): CPython refuses int() on huge
        # digit strings (the int_max_str_digits DoS guard), so a
        # planted multi-KB pid string would escape as ValueError
        # through every liveness path. 20 digits covers 2^64; no
        # pid_t is wider.
        if len(pid) > 20:
            return None
        pid = int(pid)  # stringified pid: tolerate like the run metadata
    if (isinstance(pid, int) and not isinstance(pid, bool)
            and 0 < pid and pid.bit_length() <= 63):
        # bit_length cap: JSON carries arbitrary-precision ints — a
        # planted astronomically-large pid must not reach kill()/
        # describe strings (same defence class as sessions'
        # OverflowError arm, applied before the boundary).
        return pid
    return None


def describe_holder(holder: dict) -> str:
    """One operator-facing fragment. The stamp is FILE CONTENT (any
    writer in the run dir can forge it), so text fields are terminal-
    sanitised and the pid coerced — no raw escape bytes reach the
    operator's terminal via a refusal message."""
    from core.security.log_sanitisation import sanitise_for_terminal
    pid = _holder_pid(holder)
    pid_s = str(pid) if pid is not None else "unknown"
    op = sanitise_for_terminal(str(holder.get("operation") or "unknown"),
                               max_len=64)
    since = sanitise_for_terminal(str(holder.get("since") or "unknown"),
                                  max_len=64)
    return f"pid {pid_s}, {op}, started {since}"


def holder_liveness(holder: dict) -> tuple[str, str]:
    """Identity-stamped liveness verdict for a holder stamp:
    ``("alive" | "dead" | "indeterminate", reason)``.

    Mirrors ``core.run.metadata._session_liveness_for_meta`` on the
    session-ledger identity vocabulary, minus the claude-comm gate
    (the holder is a Python orchestrator process):

    * provably dead — pid not running, live pid whose ``starttime``
      mismatches the stamp (recycled pid: NEVER reads live), or a
      stamp from a prior boot of this same machine;
    * alive — live pid whose ``starttime`` matches the stamp;
    * indeterminate — everything unverifiable: no/malformed stamp,
      missing identity fields, foreign boot/machine/pid namespace,
      an off-Linux sentinel stamp over a running pid, or an unreadable
      live ``starttime``.
    """
    from core.project import sessions as _sessions
    pid = _holder_pid(holder)
    if pid is None:
        return "indeterminate", "holder stamp is missing or malformed"
    start = holder.get("starttime")
    boot = holder.get("boot_id")
    if not start or not boot:
        return "indeterminate", "holder stamp carries no identity fields"
    fields = {"starttime": str(start), "boot_id": str(boot)}
    for key in ("pidns", "machine_id"):
        value = holder.get(key)
        if value:
            fields[key] = str(value)
    if _sessions._prior_boot_entry(fields):
        return "dead", ("stamped during a prior boot of this machine — "
                        "its process cannot be alive anywhere")
    if _sessions._foreign_entry(fields):
        return "indeterminate", ("stamped on another boot, machine, or "
                                 "pid namespace — liveness is not "
                                 "verifiable from here")
    if not _sessions._pid_running(pid):
        return "dead", f"pid {pid} is not running"
    if _sessions._sentinel_stamp(fields):
        return "indeterminate", (f"pid {pid} is running but this platform "
                                 "records no process identity — cannot "
                                 "prove it is the stamped orchestrator")
    live_start = _sessions.proc_starttime(pid)
    if live_start is None:
        return "indeterminate", (f"pid {pid} is running but its start "
                                 "time is unreadable — identity unproven")
    if live_start != str(start):
        return "dead", (f"pid {pid} was recycled — the running process's "
                        "start time does not match the stamp")
    return "alive", f"pid {pid} is running and matches the stamp"


def _live_holder_message(out_dir: Path, holder: dict) -> str:
    return (
        f"audit run directory {out_dir} is owned by a live audit "
        f"orchestrator ({describe_holder(holder)}) — refusing to start "
        "a second orchestrator on the same run: two orchestrators "
        "co-writing one run's journal and ledgers means double LLM "
        "spend and mixed-version artifacts. Wait for the holder to "
        "exit (a SIGTERM-drained orchestrator keeps this lock through "
        "its salvage until it actually exits), or verify the holder "
        "pid before retrying — and if that pid is provably NOT an "
        "audit orchestrator working this run directory (a forged or "
        "wrong stamp), delete the lock file and retry. Only delete "
        "after verifying: removing the file under a genuinely live "
        "holder splits lockers across two inodes."
    )


def _stamp(fd: int, operation: str) -> None:
    """Write the holder stamp AFTER acquiring. Failure is logged, not
    raised — while this process lives the flock is the mutual
    exclusion; the stamp only degrades post-crash adjudication."""
    record: dict = {
        "pid": os.getpid(),
        "operation": operation,
        "since": datetime.now(timezone.utc).isoformat(),
    }
    record.update(_identity_fields())
    try:
        payload = (json.dumps(record) + "\n").encode("utf-8")
        os.ftruncate(fd, 0)
        os.lseek(fd, 0, os.SEEK_SET)
        os.write(fd, payload)
    except (OSError, ValueError):
        logger.warning("audit run-lock stamp write failed for fd %d "
                       "(mutual exclusion unaffected while this process "
                       "lives)", fd, exc_info=True)


def _warn_proceeding_unlocked(lock_path: Path, exc: OSError) -> None:
    # Fail direction argued both ways: refusing on a genuine cannot-
    # create would brick runs (and salvage-era resumes) on transient
    # lock-file trouble the run itself may survive, while proceeding
    # unserialised merely restores the pre-lock behaviour — and
    # LOUDLY. An unwritable run dir kills the run moments later
    # anyway (journal, ledgers). Same degrade posture as the sibling
    # RMW locks, plus the warning they don't need. Existing-but-
    # unopenable entries do NOT come here — those fail closed (see
    # the planted-artifact split in acquire_run_lock).
    print(
        f"warning: cannot create the audit run lock at {lock_path} "
        f"({exc.__class__.__name__}) — proceeding WITHOUT run-dir "
        "mutual exclusion; a concurrent orchestrator on this "
        "directory would not be refused",
        file=sys.stderr,
    )


def _planted_artifact_message(lock_path: Path, detail: str) -> str:
    return (
        f"audit run lock path {lock_path} exists but is not an "
        f"openable regular file ({detail}) — refusing to proceed: a "
        "planted symlink, directory, or special file here can "
        "capture the lock onto a foreign inode or disable the run's "
        "mutual exclusion entirely. Inspect the artifact, remove it "
        "if you did not create it, and retry."
    )


def _prior_run_terminal(out_dir: Path) -> bool:
    """True when the run dir's own metadata says the previous holder
    CONCLUDED (any non-running status). The lock file is never
    unlinked, so every finished run leaves its (now dead) stamp
    behind — a loud reclaim line on each later reuse of the directory
    would cry wolf. A dead stamp over ``status=running`` (a crash) or
    over unreadable/absent metadata stays LOUD: that reclaim is
    genuinely diagnostic. Best-effort — any read trouble keeps the
    loud direction."""
    try:
        from core.run.metadata import STATUS_RUNNING, load_run_metadata
        meta = load_run_metadata(Path(out_dir))
    except Exception:  # noqa: BLE001 — diagnostics tier, never raises
        return False
    if not meta:
        return False
    status = meta.get("status")
    return isinstance(status, str) and bool(status) \
        and status != STATUS_RUNNING


def acquire_run_lock(out_dir: Path, operation: str) -> RunLockHandle:
    """Acquire the exclusive orchestrator lock on *out_dir* for the
    rest of this process's lifetime. Raises :class:`AuditRunLocked`
    (callers print and exit non-zero — never a silent queue) when the
    directory is, or may be, owned by another live orchestrator.

    Decision table:

    * already held by this process (the ``_HELD`` handle registry —
      process-local state, unlike the stamp, which is file content any
      run-dir writer can forge) → return a no-op handle, so in-process
      flows (ensemble passes, the validate post-pass) can never
      deadlock or refuse against their own orchestrator — even when
      the first acquisition's stamp write failed.
    * flock refused → a live foreign process holds it: refuse, naming
      the stamped holder (the stamp is diagnostics for the refusal
      text only — it never decides self-held).
    * flock acquired, prior stamp provably dead → reclaim (one stderr
      notice): a crashed run must not brick ``resume``.
    * flock acquired, prior stamp alive → refuse: a live holder that
      is not holding its flock (no-fcntl writer, lost fd) is still a
      live orchestrator.
    * flock acquired, prior stamp indeterminate → refuse with the
      manual remedy: fail-open reclaim is reserved for PROVEN death.

    Without ``fcntl`` the stamp adjudication alone enforces the lock —
    the acquisition window is not atomic there (documented weaker
    residual, same shape as the session ledger's off-Linux stamps).
    """
    out_dir = Path(out_dir)
    lock_path = run_lock_path(out_dir)
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        _warn_proceeding_unlocked(lock_path, exc)
        return RunLockHandle(-1, lock_path)
    # O_NOFOLLOW: the lock path lives in a run directory other
    # principals can write — a planted symlink would otherwise
    # redirect BOTH the stamp write and the process-lifetime flock
    # onto a foreign inode (e.g. another run's lock file, capturing
    # that run's mutual exclusion for this process's lifetime, or an
    # attacker-named create through a dangling link).
    try:
        fd = os.open(
            str(lock_path),
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
    except OSError as exc:
        # Split by what the path IS, not by errno alone. An entry that
        # EXISTS but cannot be opened as a regular file — symlink
        # (ELOOP under O_NOFOLLOW), directory, FIFO/device, mode-0
        # file — is a planted-artifact shape: degrading to "proceed
        # unlocked" there would hand any run-dir writer a kill switch
        # for the mutual exclusion itself. Fail CLOSED with the
        # remedy. Only a genuine cannot-create (nothing at the path:
        # ENOSPC, EROFS, quota, vanished parent) keeps the loud
        # degrade below.
        entry_exists = False
        with contextlib.suppress(OSError):
            os.lstat(str(lock_path))
            entry_exists = True
        if entry_exists:
            raise AuditRunLocked(
                _planted_artifact_message(
                    lock_path,
                    f"open refused: {exc.strerror or exc.__class__.__name__}",
                )
            ) from None
        _warn_proceeding_unlocked(lock_path, exc)
        return RunLockHandle(-1, lock_path)
    # fstat on the OPEN fd (no TOCTOU): O_NOFOLLOW only guards the
    # final component's symlink case — a hard-linked device or a FIFO
    # still opens. Only a regular file may carry the lock.
    try:
        st_mode = os.fstat(fd).st_mode
    except OSError:
        st_mode = None
    if st_mode is None or not stat.S_ISREG(st_mode):
        os.close(fd)
        raise AuditRunLocked(
            _planted_artifact_message(lock_path, "not a regular file"))
    # Self-held detection BEFORE any stamp bytes are read, from the
    # process-local handle registry only: the stamp is forgeable file
    # content, so "pid + starttime match ours" proves nothing — a
    # hostile run-dir writer copying this process's identity into the
    # stamp while a foreign process holds the flock must earn that
    # holder's refusal, never a proceed. Covers the no-fcntl platforms
    # and the re-entry whose first acquisition's stamp write failed.
    if _held_by_this_process(lock_path):
        # First acquisition's fd keeps the flock — in-process re-entry
        # (ensemble passes, the validate post-pass) is a no-op.
        os.close(fd)
        return RunLockHandle(-1, lock_path)
    # O_CLOEXEC matters: the orchestrator execs tool children (semgrep,
    # codeql, the lifecycle stubs). An inherited lock fd would keep the
    # flock alive in a child after the orchestrator died — a dead
    # holder that never reads dead.
    if _HAS_FCNTL:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            holder = read_holder(lock_path)
            os.close(fd)
            raise AuditRunLocked(
                _live_holder_message(out_dir, holder), holder) from None
    # flock held (or no fcntl): adjudicate whatever stamp is behind it.
    prior = read_holder(lock_path)
    stale_bytes = False
    try:
        stale_bytes = os.fstat(fd).st_size > 0
    except OSError:
        stale_bytes = True
    if prior or stale_bytes:
        verdict, reason = holder_liveness(prior)
        if verdict == "alive":
            # Self-held was already ruled out from the handle registry
            # above, so an alive stamp here — even one naming this very
            # process — is a foreign live holder or a forged identity:
            # the documented alive-stamp fail direction (refuse).
            _release_fd(fd)
            raise AuditRunLocked(
                _live_holder_message(out_dir, prior), prior)
        if verdict == "indeterminate":
            _release_fd(fd)
            raise AuditRunLocked(
                f"audit run lock {lock_path} names a holder whose "
                f"liveness cannot be verified "
                f"({describe_holder(prior)}; {reason}) — failing "
                "closed rather than risk a second live orchestrator "
                "on this run. If you have verified that no audit "
                "orchestrator is running against this directory, "
                "delete the lock file and retry.",
                prior,
            )
        if _prior_run_terminal(out_dir):
            # Concluded run's leftover stamp — the normal end state of
            # every directory reuse, not a diagnostic event.
            logger.debug(
                "reclaiming stale audit run lock on %s (%s; %s)",
                out_dir, describe_holder(prior), reason,
            )
        else:
            print(
                f"reclaiming stale audit run lock on {out_dir} "
                f"({describe_holder(prior)}; {reason})",
                file=sys.stderr,
            )
    # Register BEFORE stamping: the registry is the self-held
    # authority, so it must hold the handle even when the stamp write
    # fails (logged, not raised) — otherwise a later in-process
    # re-entry would refuse against its own orchestrator.
    handle = RunLockHandle(fd, lock_path)
    _HELD.append(handle)
    _stamp(fd, operation)
    return handle


def _release_fd(fd: int) -> None:
    if _HAS_FCNTL:
        with contextlib.suppress(OSError):
            fcntl.flock(fd, fcntl.LOCK_UN)
    with contextlib.suppress(OSError):
        os.close(fd)
