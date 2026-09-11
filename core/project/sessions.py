"""Session registry — which sessions have which project active.

``~/.local/share/raptor/sessions.d/<pid>`` maps a live Claude Code
session to its project state, written by the launcher at exec time
(bash — see bin/raptor) and by ``/project use`` (here). Each entry is
KEY=VALUE lines so both writers speak the same format.

Two entry generations coexist:

* **v1 (advisory)** — ``project=`` + ``since=`` only. Written by
  pre-series launchers/CLIs. Consulted ONLY for awareness lines
  ("project X is also active in session pid N"); never authoritative.
* **v2 (authoritative)** — adds ``v=2`` plus an identity stamp
  (``starttime`` from ``/proc/<pid>/stat`` field 22, ``boot_id``,
  ``pidns`` = the inode of ``/proc/self/ns/pid``) and a launcher-minted
  ``token``. The ``project=`` field IS the session's project binding,
  resolved ahead of the ``.active`` symlink by the active-project
  chokepoints. ``project=-`` is the bound-to-none sentinel: the session
  is authoritatively projectless and does NOT fall through to the
  symlink. (``-`` can never pass project-name validation, so a torn or
  legacy empty value stays *invalid* rather than becoming a meaningful
  state.)

Authority demands what the advisory registry never needed:

* **Identity, not just liveness.** A recycled PID backed by another
  *claude* process passes any comm check by construction. v2 reads
  require the live process's starttime + boot_id to match the stamp,
  and the reader's pid namespace to match ``pidns`` — a reader inside a
  same-kernel container (shared ``$HOME``, shared boot_id, host pids
  invisible) treats host entries as FOREIGN: never authoritative,
  never pruned. Off-Linux there is no procfs identity: entries carry
  platform sentinels (``starttime=0``, ``boot_id=none-<platform>``) and
  are accepted on comm-checked liveness alone — a documented weaker
  residual.
* **Atomic, lock-disciplined writes.** Entry writes are tmp+rename;
  ledger read-modify-writes additionally hold a sibling ``.run.lock``
  flock (rename atomicity protects readers, not concurrent writers).
* **No writer-side comm gate.** The launcher seeds pre-exec while comm
  is still the shell (pid + starttime survive the exec into claude;
  comm flips after). The old bash-pid hazard is structurally
  unreachable: ``resolve_session_pid()`` only returns claude-shaped or
  token-verified pids. Explicit-pid callers are trusted internal
  surfaces.

A sibling file ``sessions.d/<pid>.run`` is the session's RUN LEDGER:
one line per run — ``<status> <epoch> <run-id> <abs-run-dir>`` with
status in running|completed|failed|cancelled|interrupted — appended at
lifecycle start and CAS-marked in place on finish (only the matching
run-id's line changes). Live records drive exact coverage-hook
attribution; finished records give sibling discovery a "runs this
session produced" tier. Run-dir paths are rejected if they contain any
whitespace or non-printable character: ``str.splitlines`` splits on
U+2028-class separators, so a crafted path could otherwise forge a
second, clean-looking record.
"""

from __future__ import annotations

import contextlib
import functools
import logging
import os
import re
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

logger = logging.getLogger(__name__)

SESSIONS_DIR = Path.home() / ".local" / "share" / "raptor" / "sessions.d"

#: Bound-to-none sentinel — rejected by _NAME_RE, so it can never
#: collide with a real project name.
NONE_SENTINEL = "-"

ENTRY_VERSION = "2"

#: Env vars exported by the launcher. The PID names the session; the
#: token must match the entry's ``token`` field for the env path to be
#: believed (an attacker guessing a live claude PID gains nothing
#: without the token, which lives in a 0700 directory).
ENV_SESSION_PID = "RAPTOR_SESSION_PID"
ENV_SESSION_TOKEN = "RAPTOR_SESSION_TOKEN"

#: Mirror of ProjectManager._validate_name's character class. Kept
#: local so this module stays importable without core.project.project
#: (core.startup consults it at banner time).
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

#: The full v2 key list, shared by both writers (the bash seeder in
#: bin/raptor mirrors this order). Unknown keys are dropped on rewrite
#: BY DESIGN — the list is the schema.
ENTRY_KEYS = ("v", "project", "since", "starttime", "boot_id", "pidns",
              "token", "seeded_by")

#: Identity keys preserved/refreshed on rewrite (subset of ENTRY_KEYS).
_IDENTITY_KEYS = ("starttime", "boot_id", "pidns")

#: Off-Linux sentinel stamps — platform-tagged so the foreign rule can
#: distinguish "no identity available" from "identity from elsewhere".
_STARTTIME_SENTINEL = "0"

#: Run-ledger cap — oldest FINISHED records beyond this are pruned;
#: running records are exempt (but zombie-corrected, see _write_ledger).
_LEDGER_CAP = 32

_MAX_ENTRY_BYTES = 64 * 1024  # defensive read bound

_RUN_STATUSES = ("running", "completed", "failed", "cancelled",
                 "interrupted")

_RUN_LINE_RE = re.compile(
    r"^(running|completed|failed|cancelled|interrupted) (\d+) (\S+) (/.+)$")

#: Pin-witness record: ``pin <epoch> <run-id> <project|-> <abs-dir>``.
#: Written beside the running record at start. sessions.d sits OUTSIDE
#: the sandbox write grant, so this is the out-of-grant witness the
#: privileged project-store writers verify the (attacker-influenced)
#: run marker against. Both ledger consumers (the bash hook and the
#: python twin) skip these lines by their status filter.
_PIN_LINE_RE = re.compile(r"^pin (\d+) (\S+) (\S+) (/.+)$")


# ---------------------------------------------------------------------------
# process identity
# ---------------------------------------------------------------------------

def _pid_running(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OverflowError:
        # A pid beyond the platform's pid_t (a planted huge-digit
        # filename or ledger field) cannot be a live process — and
        # OverflowError is not an OSError, so it crashed callers.
        return False
    except OSError:
        return False
    return True


def _comm(pid: int) -> str | None:
    """Process comm — /proc on Linux, ps(1) elsewhere; None if unreadable."""
    if sys.platform == "linux":
        try:
            # errors="replace": comm is attacker-arbitrary bytes
            # (prctl PR_SET_NAME, any uid) — a strict decode raised
            # UnicodeDecodeError out of every identity check, letting
            # one hostile process name poison the whole registry
            # (read_sessions, session_binding, resolve_session_pid).
            return Path(f"/proc/{pid}/comm").read_text(
                encoding="utf-8", errors="replace").strip()
        except OSError:
            return None
    try:
        from core.run.metadata import _read_comm_ps
        return _read_comm_ps(pid)
    except Exception:  # noqa: BLE001 — identity probe, never fatal
        return None


def _claude_shaped(comm: str | None) -> bool:
    """ONE comm predicate for walker, liveness, and readers."""
    return comm is not None and comm.startswith("claude")


def proc_starttime(pid: int) -> str | None:
    """``starttime`` (field 22 of ``/proc/<pid>/stat``) — the standard
    PID-reuse discriminator. None off-Linux or when unreadable."""
    if sys.platform != "linux":
        return None
    try:
        # errors="replace": the comm field embedded in stat is
        # attacker-arbitrary bytes — see _comm.
        stat = Path(f"/proc/{pid}/stat").read_text(
            encoding="utf-8", errors="replace")
    except OSError:
        return None
    close_paren = stat.rfind(")")
    if close_paren < 0:
        return None
    fields = stat[close_paren + 2:].split()
    idx = 22 - 3  # fields[0] is stat field 3
    if len(fields) <= idx:
        return None
    return fields[idx]


@functools.lru_cache(maxsize=1)
def boot_id() -> str | None:
    """Kernel boot id (per KERNEL — containers on one host share it,
    which is why ``pidns`` exists as a second axis). None off-Linux.

    Process-constant, so cached: identity checks run per-entry in
    read_sessions sweeps and per-record in ledger paths."""
    if sys.platform != "linux":
        return None
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text(
            encoding="utf-8").strip()
    except OSError:
        return None


@functools.lru_cache(maxsize=1)
def pidns_id() -> str | None:
    """Inode of this process's pid namespace, or None when unavailable
    (process-constant, so cached — a process never changes pid ns).

    Two processes sharing a kernel but not a pid namespace must never
    prune or trust each other's entries — pid liveness is meaningless
    across the boundary.
    """
    if sys.platform != "linux":
        return None
    try:
        st = os.stat("/proc/self/ns/pid")
    except OSError:
        return None
    return str(st.st_ino)


def _platform_boot_sentinel() -> str:
    return f"none-{sys.platform}"


def _sentinel_stamp(fields: dict[str, str]) -> bool:
    return (fields.get("starttime") == _STARTTIME_SENTINEL
            and str(fields.get("boot_id", "")).startswith("none-"))


def _foreign_entry(fields: dict[str, str]) -> bool:
    """Entry owned by a different boot, machine, or pid namespace —
    never authoritative HERE, never pruned HERE.

    Also foreign: an entry carrying a REAL boot_id that this reader
    cannot verify (e.g. macOS reader, Linux-stamped entry).
    """
    stamp_boot = fields.get("boot_id", "")
    if not stamp_boot:
        return False  # v1 — handled by advisory rules
    if _sentinel_stamp(fields):
        # Sentinel-stamped (off-Linux writer). A Linux reader treats it
        # as foreign (cannot corroborate); the writing platform accepts
        # it on liveness (see _identity_matches).
        return sys.platform == "linux"
    live_boot = boot_id()
    if live_boot is None:
        return True  # real stamp, unverifiable reader → foreign
    if stamp_boot != live_boot:
        return True
    stamp_ns = fields.get("pidns", "")
    live_ns = pidns_id()
    if stamp_ns and live_ns and stamp_ns != live_ns:
        return True  # same kernel, different pid namespace
    return False


def _identity_matches(pid: int, fields: dict[str, str]) -> bool:
    """Does the LIVE process at *pid* match the entry's identity stamp?

    v1 entries (no stamp) never match — advisory only. Sentinel-stamped
    entries (off-Linux writers, read on their own platform) are accepted
    on comm-checked liveness alone — the documented weaker residual.
    """
    stamp_start = fields.get("starttime")
    stamp_boot = fields.get("boot_id")
    if not stamp_start or not stamp_boot:
        return False
    if _foreign_entry(fields):
        return False
    if not _pid_running(pid) or not _claude_shaped(_comm(pid)):
        return False
    if _sentinel_stamp(fields):
        return True  # off-Linux: liveness-strength
    live_start = proc_starttime(pid)
    if live_start is None:
        return False  # identity unknown on a Linux reader → not proven
    return stamp_start == live_start


def mint_token() -> str:
    return secrets.token_hex(16)


# ---------------------------------------------------------------------------
# session resolution (ONE shared resolver — env first, then tree walk)
# ---------------------------------------------------------------------------

def _env_session_pid() -> int | None:
    """Validated env-credential path: pid digits AND entry token match
    AND identity stamp matches the live process. Anything less returns
    None (the tree walk may still succeed)."""
    raw = os.environ.get(ENV_SESSION_PID, "")
    token = os.environ.get(ENV_SESSION_TOKEN, "")
    # isascii() first: str.isdigit accepts Unicode digits ("²") that
    # int() then rejects — and the whole leg is wrapped because a
    # malformed credential (surrogates in the token break
    # compare_digest with TypeError) must degrade to the walk, never
    # crash a best-effort resolver called from start_run.
    if not raw.isascii() or not raw.isdigit() or not token:
        return None
    try:
        pid = int(raw)
        fields = _parse_entry(SESSIONS_DIR / str(pid))
        if not fields:
            return None
        entry_token = fields.get("token", "")
        if not entry_token or not secrets.compare_digest(
                entry_token, token):
            return None
        if not _identity_matches(pid, fields):
            return None
        return pid
    except (ValueError, TypeError, OSError):
        return None


def _walk_session_pid() -> int | None:
    """Tree walk: collect ALL claude-shaped ancestors; prefer the one
    whose entry PASSES IDENTITY MATCHING (a merely entry-bearing
    recycled pid must not win), else the outermost.

    RAPTOR dispatches nested ``claude -p`` skill children; the nearest
    claude ancestor of a helper under one of those is the *subagent*,
    which owns no entry. Preferring the identity-verified entry-bearing
    (else outermost) ancestor keeps one logical session = one identity.
    """
    from core.run.metadata import _read_ppid
    candidates: list[int] = []
    pid = os.getpid()
    for hop in range(20):
        try:
            pid = os.getppid() if hop == 0 else _read_ppid(pid)
        except (OSError, ValueError, IndexError):
            break
        if pid <= 1:
            break
        if _claude_shaped(_comm(pid)):
            candidates.append(pid)
    for cand in candidates:  # nearest-first: first with a VALID entry wins
        fields = _parse_entry(SESSIONS_DIR / str(cand))
        if fields and _identity_matches(cand, fields):
            return cand
    if candidates:
        return candidates[-1]  # outermost
    return None


def resolve_session_pid() -> int | None:
    """The owning session's pid: validated env credential first (works
    across PID namespaces and beneath nested claude processes), tree
    walk second, None outside any session."""
    pid = _env_session_pid()
    if pid is not None:
        return pid
    try:
        return _walk_session_pid()
    except Exception:  # noqa: BLE001 — resolution is best-effort by contract
        logger.debug("session pid walk failed", exc_info=True)
        return None


def session_pid() -> int | None:
    """Back-compat alias used by the advisory writers."""
    return resolve_session_pid()


# ---------------------------------------------------------------------------
# entry IO
# ---------------------------------------------------------------------------

def _parse_entry(path: Path) -> dict[str, str]:
    fields: dict[str, str] = {}
    try:
        if path.stat().st_size > _MAX_ENTRY_BYTES:
            return fields
        # utf-8-sig: a BOM would prefix the first key ("\ufeffv"), and
        # the entry would read as v1/advisory — symlink fallthrough
        # instead of this session's own binding.
        for line in path.read_text(encoding="utf-8-sig").splitlines():
            key, sep, value = line.partition("=")
            if sep:
                # First occurrence wins — the authoritative tie-break
                # for a (should-be-impossible) duplicated key.
                fields.setdefault(key.strip(), value.strip())
    except (OSError, UnicodeDecodeError):
        pass
    return fields


def _atomic_write(path: Path, content: str) -> None:
    """tmp+rename in the entry's directory (the set_active pattern);
    pid+tid suffix so concurrent writers get distinct slots."""
    import threading
    tmp = path.with_name(
        f".{path.name}.tmp.{os.getpid()}.{threading.get_ident()}")
    tmp.write_text(content, encoding="utf-8")
    with contextlib.suppress(OSError):
        tmp.chmod(0o600)
    os.rename(str(tmp), str(path))


def _ensure_dir() -> bool:
    try:
        # 0700: which project each session works on is operator
        # telemetry — not for other local users. chmod covers a dir
        # created looser by an older writer.
        SESSIONS_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
        SESSIONS_DIR.chmod(0o700)
    except OSError:
        return False
    return True


# _parse_entry uses setdefault, so the FIRST occurrence of a duplicate
# key wins — with append-style corruption, the original (earlier)
# binding is the one authoritative readers see. Deliberate tie-break.


def _clean_value(value: str) -> str:
    """Field values are one printable line — control characters would
    corrupt the KEY=VALUE format (and could forge extra keys)."""
    return "".join(c for c in value if c.isprintable())


def _entry_content(project: str, fields: dict[str, str]) -> str:
    merged = dict(fields)
    merged["v"] = ENTRY_VERSION
    merged["project"] = project
    merged["since"] = datetime.now(timezone.utc).isoformat()
    lines = []
    for key in ENTRY_KEYS:
        value = merged.get(key, "")
        if value:
            lines.append(f"{key}={_clean_value(str(value))}")
    return "\n".join(lines) + "\n"


def _identity_for(pid: int) -> dict[str, str] | None:
    """The identity stamp for *pid*, with off-Linux sentinels.

    Returns None on Linux when the pid's starttime is unreadable (pid
    gone, procfs race): an entry stamped without it could never pass an
    authoritative read — writers must refuse rather than write a doomed
    entry.
    """
    start = proc_starttime(pid)
    boot = boot_id()
    if sys.platform == "linux" and (start is None or boot is None):
        # A Linux entry stamped with a real starttime but a sentinel
        # boot_id is not sentinel-shaped: every reader (including this
        # writer) classifies it foreign — never authoritative, never
        # prunable. Refuse rather than write a doomed entry.
        return None
    fields: dict[str, str] = {
        "starttime": start if start is not None else _STARTTIME_SENTINEL,
        "boot_id": boot if boot is not None else _platform_boot_sentinel(),
    }
    ns = pidns_id()
    if ns is not None:
        fields["pidns"] = ns
    return fields


def record_session(project: str | None, pid: int | None = None,
                   token: str | None = None,
                   seeded_by: str | None = None) -> int | None:
    """Bind this session to *project* (None REMOVES the entry — the
    launcher seed-cleanup path; in-session ``/project none`` binds the
    NONE_SENTINEL instead, see :func:`bind_session`).

    v2 semantics: versioned, identity-stamped, atomic. An existing
    entry's identity fields are preserved ONLY after verifying them
    against the live pid — a stale (recycled-pid) stamp is refreshed,
    never propagated. Name validation failures refuse loudly (return
    None + warning): an entry an authoritative reader would reject must
    not be written.
    """
    if pid is None:
        pid = resolve_session_pid()
    if pid is None:
        return None
    if project is None:
        try:
            # Entry first: ledger writers gate on it, so once it is
            # gone no new append can resurrect the ledger. The ledger
            # itself is unlinked UNDER its lock — an in-flight
            # finisher's read-modify-write completes before, not
            # across, the removal. Unlinking the lock file last is
            # safe: writers verify their fd still names the path
            # after acquiring and retry when it doesn't.
            (SESSIONS_DIR / str(pid)).unlink(missing_ok=True)
            with _ledger_lock(pid):
                (SESSIONS_DIR / f"{pid}.run").unlink(missing_ok=True)
            (SESSIONS_DIR / f"{pid}.run.lock").unlink(missing_ok=True)
        except OSError:
            return None
        return pid
    if project != NONE_SENTINEL and not _NAME_RE.match(project):
        logger.warning(
            "sessions: refusing to bind invalid project name %r", project)
        return None
    if not _ensure_dir():
        return None
    entry = SESSIONS_DIR / str(pid)
    # The per-pid ledger lock doubles as the ENTRY RMW lock: without
    # it, delete/rename's binding rewrites and a concurrent
    # /project use are a lost-update race (both read, both write,
    # last-writer-wins with a stale decision).
    with _ledger_lock(pid):
        return _record_session_locked(project, pid, token, seeded_by,
                                      entry)


def _record_session_locked(project: str, pid: int,
                           token: str | None, seeded_by: str | None,
                           entry: Path) -> int | None:
    """The under-lock half of record_session — *project* is never None
    here (the removal path returns before the lock)."""
    fields = _parse_entry(entry)
    have_valid_stamp = bool(fields) and _identity_matches(pid, fields)
    if not have_valid_stamp:
        identity = _identity_for(pid)
        if identity is None:
            logger.warning(
                "sessions: refusing to bind pid %d — identity "
                "unreadable, the entry could never verify", pid)
            return None
        # A stale stamp means the old entry belonged to a DIFFERENT
        # process (recycled pid): its token and seeded_by are that
        # dead session's credentials and must not be re-minted onto
        # this one — a propagated stale token would keep validating
        # the env credential for whoever held it.
        env_pid = os.environ.get(ENV_SESSION_PID, "")
        env_tok = os.environ.get(ENV_SESSION_TOKEN, "")
        # Computed BEFORE the pops below — the token comparison needs
        # the old entry's value.
        _own_repair = (env_tok and env_pid.isascii() and env_pid.isdigit()
                       and int(env_pid) == pid
                       and fields.get("token") == env_tok)
        fields.pop("token", None)
        fields.pop("seeded_by", None)
        # The token match is the discriminator: a dead predecessor's
        # entry carries a DIFFERENT token than this session's env
        # credential, so a recycled pid can never keep the
        # predecessor's ledger; own-corruption that destroyed the
        # token field falls back to the safe wipe.
        if _own_repair:
            # The caller IS this session (its own env credential names
            # this pid): restore credential continuity — the drop is
            # for DEAD predecessors' tokens, not the live session
            # repairing its own corrupt entry.
            fields["token"] = env_tok
        fields.update(identity)
        # Same reasoning for the run ledger: the dead session's run
        # records must not become THIS session's attribution and
        # sibling-discovery history. ONLY a positively-recycled v2
        # entry qualifies — a v1 entry has no stamp, so this same live
        # session upgrading from a v1 launcher would wipe its own
        # in-flight ledger; and a live session repairing ITS OWN
        # corrupt entry (env credential names this pid) keeps its
        # records and pin witnesses — the same evidence that re-mints
        # the token above. Cleared under the ledger lock (a straggling
        # finisher of the old session may be mid-CAS); the lock FILE
        # stays — unlinking a held lock splits it.
        if (not _own_repair
                and fields.get("v") == ENTRY_VERSION
                and (SESSIONS_DIR / f"{pid}.run").exists()):
            # Caller already holds this pid's ledger lock.
            with contextlib.suppress(OSError):
                (SESSIONS_DIR / f"{pid}.run").unlink(missing_ok=True)
    if token:
        fields["token"] = token
    if seeded_by:
        if seeded_by in ("flag", "auto", "bookmark", "use", "create",
                         "adopt"):
            fields["seeded_by"] = seeded_by
        else:
            logger.warning(
                "sessions: dropping unknown seeded_by %r", seeded_by)
    try:
        _atomic_write(entry, _entry_content(project, fields))
    except OSError:
        return None
    return pid


def rebind_session_if(pid: int, expected: str,
                      new_project: str | None) -> bool:
    """Atomically re-point *pid*'s binding to *new_project* ONLY if it
    still names *expected* — the delete/rename rewrite primitive. The
    snapshot-then-write shape it replaces was a lost-update race: a
    session that switched projects between the snapshot and the write
    was clobbered with a decision made against its old binding.
    ``new_project=None`` binds the none sentinel."""
    entry = SESSIONS_DIR / str(pid)
    with _ledger_lock_nb(pid) as held:
        if not held:
            logger.warning(
                "sessions: pid %d's ledger lock is held — skipping "
                "its binding rewrite (%r); re-bind it with "
                "'/project use' from that session", pid, expected)
            return False
        fields = _parse_entry(entry)
        if (fields.get("v") != ENTRY_VERSION
                or fields.get("project") != expected):
            return False
        return _record_session_locked(
            NONE_SENTINEL if new_project is None else new_project,
            pid, None, None, entry) is not None


def bind_session(project: str | None, pid: int | None = None,
                 seeded_by: str | None = None) -> int | None:
    """In-session binding write: ``None`` means bound-to-none (sentinel
    ``-``), NOT entry removal. This is what ``/project none`` calls."""
    return record_session(
        NONE_SENTINEL if project is None else project, pid=pid,
        seeded_by=seeded_by)


def session_binding(pid: int | None = None) -> tuple[str | None, str]:
    """The session's authoritative project binding.

    Returns ``(project_name_or_None, state)`` with state one of:

    * ``"bound"``    — v2 entry names a valid project name (existence is
      the caller's next check; a missing project file must read as
      authoritative none, never symlink fallthrough).
    * ``"none"``     — v2 entry carries the bound-to-none sentinel, OR a
      v2 entry is corrupt/invalid (fail toward projectless, never
      toward another layer's project).
    * ``"advisory"`` — v1 (unversioned) entry: pre-series session;
      symlink layer applies.
    * ``"absent"``   — no session, no entry, foreign entry, or identity
      mismatch: symlink layer applies.
    """
    if pid is None:
        pid = resolve_session_pid()
    if pid is None:
        return None, "absent"
    entry_path = SESSIONS_DIR / str(pid)
    fields = _parse_entry(entry_path)
    if not fields:
        # Distinguish "no entry" (symlink layer applies) from "entry
        # exists but is unreadable/oversized/undecodable" — byte-level
        # corruption of OUR OWN entry must fail toward projectless,
        # never toward another layer's project.
        try:
            if entry_path.exists():
                return None, "none"
        except OSError:
            return None, "none"
        return None, "absent"
    if fields.get("v") != ENTRY_VERSION:
        return None, "advisory"
    if not _identity_matches(pid, fields):
        return None, "absent"
    name = fields.get("project")
    if name == NONE_SENTINEL:
        return None, "none"
    if not name or not _NAME_RE.match(name):
        logger.warning(
            "sessions: corrupt binding for pid %d (%r) — treating as "
            "authoritatively projectless", pid, name)
        return None, "none"
    return name, "bound"


def _pid_from_name(name: str) -> int | None:
    """Canonical pid from a session filename stem, or None.

    Three requirements, each load-bearing for the prune passes that
    lock/unlink ``<pid>.run`` / ``<pid>.run.lock`` by the DERIVED pid:

    * ASCII-only — ``str.isdigit`` accepts Unicode digits; ``int('²')``
      then raises mid-prune (superscripts), and locale digits would
      alias an ASCII pid's files.
    * digits-only — everything else in the dir (ledgers, locks, tmp
      slots) is skipped.
    * exact round-trip — a planted ``'007'`` must never lock or unlink
      LIVE pid 7's ledger and lock files.
    """
    if not (name.isascii() and name.isdigit()):
        return None
    try:
        pid = int(name)
    except ValueError:  # pragma: no cover — excluded by the checks above
        return None
    if str(pid) != name:
        return None
    return pid


def _entry_state(pid: int, fields: dict[str, str]) -> str:
    """Classification for enumeration surfaces: live | stale | foreign
    | advisory | unknown.

    ``stale`` is the ONLY prunable state and requires positive
    evidence: a v2 entry whose pid is dead, or alive with a
    positively mismatching stamp. A live pid whose starttime is
    unreadable (procfs EPERM, hidepid) is ``unknown`` — skipped, never
    pruned. v1 entries are never prunable here (``v1-stale``, skipped
    from normal reads but left on disk): they carry no stamp, so a
    namespace-blind reader (this python runs inside sandboxes and
    containers) cannot distinguish "dead" from "alive in a pid
    namespace I can't see" — the launcher's bash prune, which runs
    where sessions run, owns v1 cleanup.
    """
    if _foreign_entry(fields):
        return "foreign"
    if fields.get("v") != ENTRY_VERSION:
        return "advisory" if _pid_running(pid) else "v1-stale"
    if _identity_matches(pid, fields):
        return "live"
    if (sys.platform == "linux" and _pid_running(pid)
            and proc_starttime(pid) is None):
        return "unknown"
    return "stale"


def read_sessions(prune: bool = True,
                  include_stale: bool = False) -> dict[int, dict]:
    """Registered sessions, pruning dead entries on the way.

    Prune predicate: a v2 entry is pruned only
    when it is NOT foreign AND (its pid is positively dead, or alive
    with a positively mismatching stamp). "Identity unknown" is never
    pruned. v1 entries are NEVER pruned by this reader (see
    _entry_state — the launcher's bash prune owns v1 cleanup); orphan
    ledgers whose entry is gone are reaped.

    With ``include_stale=True``, dead/stale/foreign entries are RETURNED
    (with ``fields["_state"]`` set) instead of skipped — the
    ``/project sessions`` rendering surface. Pruning still applies to
    prunable rows unless ``prune=False``.
    """
    sessions: dict[int, dict] = {}
    try:
        children = list(SESSIONS_DIR.iterdir())
    except OSError:
        return sessions
    for f in children:
        name = f.name
        pid = _pid_from_name(name)
        if pid is None:
            continue  # .run ledgers, locks, tmp slots, non-canonical
            # digit strings ('007' would alias pid 7's ledger/lock;
            # a non-ASCII digit crashes int()) — not ours here
        fields = _parse_entry(f)
        state = _entry_state(pid, fields)
        prunable = state == "stale"
        if prunable and prune:
            # Same ordering discipline as entry removal in
            # record_session: entry first (kills the writers' gate),
            # ledger under its lock, lock file last (writers
            # verify-after-lock, so this unlink cannot split it).
            # The whole removal runs UNDER the ledger lock with a
            # re-check: a recycled pid can re-register (fresh entry +
            # ledger) between the state probe above and the unlinks —
            # the fresh session's files must survive.
            with contextlib.suppress(OSError):
                removed = False
                with _ledger_lock(pid):
                    if _entry_state(pid, _parse_entry(f)) == "stale":
                        f.unlink(missing_ok=True)
                        (SESSIONS_DIR / f"{pid}.run").unlink(
                            missing_ok=True)
                        removed = True
                if removed:
                    (SESSIONS_DIR / f"{pid}.run.lock").unlink(
                        missing_ok=True)
        if state in ("live", "advisory") or include_stale:
            if include_stale:
                fields = dict(fields)
                fields["_state"] = state
            sessions[pid] = fields
    if prune:
        # Reap ORPHAN ledgers: a `.run` whose sibling entry file is
        # gone has no owner, no reader (the hook resolves through the
        # entry-backed credential), and no writer (ledger writers gate
        # on the entry) — but it WOULD be inherited on pid reuse if a
        # recycled pid re-registered before its record_session refresh
        # cleared it. Entry-less means the writers' gate already
        # refuses, so removal races nothing.
        for f in children:
            if not f.name.endswith(".run"):
                continue
            stem = f.name[:-len(".run")]
            # stem must round-trip through int: a planted '007.run'
            # would otherwise lock/unlink pid 7's files.
            if (_pid_from_name(stem) is None
                    or (SESSIONS_DIR / stem).exists()):
                continue
            with contextlib.suppress(OSError):
                with _ledger_lock(int(stem)):
                    # Re-check UNDER the lock: a recycled pid can
                    # re-register (entry + fresh ledger) between the
                    # orphan check above and this acquisition — the
                    # fresh session's first records must survive.
                    if (SESSIONS_DIR / stem).exists():
                        continue
                    f.unlink(missing_ok=True)
                (SESSIONS_DIR / f"{stem}.run.lock").unlink(missing_ok=True)
        # Lone lock files (entry AND ledger gone — a crash between the
        # three-file removal's unlinks) are never reaped by the passes
        # above, which key on entries and ledgers.
        for f in children:
            if not f.name.endswith(".run.lock"):
                continue
            stem = f.name[:-len(".run.lock")]
            if (_pid_from_name(stem) is None
                    or (SESSIONS_DIR / stem).exists()
                    or (SESSIONS_DIR / f"{stem}.run").exists()):
                continue
            with contextlib.suppress(OSError):
                with _ledger_lock_nb(int(stem)) as held:
                    if held and not (SESSIONS_DIR / stem).exists() \
                            and not (SESSIONS_DIR / f"{stem}.run").exists():
                        f.unlink(missing_ok=True)
    return sessions


# ---------------------------------------------------------------------------
# advisory surfaces (unchanged semantics)
# ---------------------------------------------------------------------------

def other_sessions(project: str, exclude_pid: int | None = None) -> list[dict]:
    """Live sessions (other than *exclude_pid*) with *project* active."""
    from core.security.log_sanitisation import sanitise_for_terminal
    out = []
    for pid, fields in sorted(read_sessions().items()):
        if exclude_pid is not None and pid == exclude_pid:
            continue
        if fields.get("project") == project:
            # Entry fields are FILE CONTENT — sanitise anything that
            # can reach the awareness line (`project` matched a
            # validated name exactly, so it is already clean).
            out.append({
                "pid": pid,
                "since": sanitise_for_terminal(
                    str(fields.get("since") or "unknown"), max_len=64),
            })
    return out


def awareness_lines(project: str, exclude_pid: int | None = None) -> list[str]:
    """The canonical awareness wording, one line per other session."""
    return [
        f"project {project} is also active in session pid {e['pid']} "
        f"(since {e['since']})"
        for e in other_sessions(project, exclude_pid)
    ]


# ---------------------------------------------------------------------------
# run ledger
# ---------------------------------------------------------------------------

def _ledger_path(pid: int) -> Path:
    return SESSIONS_DIR / f"{pid}.run"


@contextlib.contextmanager
def _ledger_lock_nb(pid: int,
                    attempts: int = 20,
                    interval: float = 0.05) -> Iterator[bool]:
    """Bounded, non-blocking variant for BEST-EFFORT sweeps
    (witness rewrites, CAS rebinds): yields True holding the lock, or
    False after ~attempts*interval seconds — a single wedged holder
    (SIGSTOP'd process, dead NFS client) must not hang a rename that
    is itself holding the project op lock, behind which every run
    start on the project queues silently.
    """
    try:
        import fcntl
        import time as _time
    except ImportError:
        yield True
        return
    if not _ensure_dir():
        yield True
        return
    lock_path = SESSIONS_DIR / f"{pid}.run.lock"
    for _ in range(attempts):
        try:
            fd = os.open(str(lock_path), os.O_WRONLY | os.O_CREAT, 0o600)
        except OSError:
            logger.warning(
                "sessions: ledger lock open failed for pid %d — "
                "proceeding UNLOCKED (best-effort data)", pid,
                exc_info=True)
            yield True
            return
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(fd)
            _time.sleep(interval)
            continue
        try:
            held = os.fstat(fd)
            current = os.stat(str(lock_path))
            same = (held.st_ino == current.st_ino
                    and held.st_dev == current.st_dev)
        except OSError:
            same = False
        if same:
            try:
                yield True
            finally:
                with contextlib.suppress(OSError):
                    fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)
            return
        os.close(fd)
    yield False


@contextlib.contextmanager
def _ledger_lock(pid: int) -> Iterator[None]:
    """flock a sibling ``.run.lock`` across a ledger read-modify-write
    (the ``_metadata_lock`` idiom — rename atomicity protects readers,
    not concurrent writers; two parallel lifecycle starts in one
    session must not lose each other's records). Degrades to a no-op
    without fcntl. The lock file is deliberately left behind (unlink
    after unlock races — see core.run.metadata._metadata_lock)."""
    try:
        import fcntl
    except ImportError:
        yield
        return
    if not _ensure_dir():
        yield
        return
    # NFS note: flock on an NFS-mounted HOME is only as reliable as
    # the NFS implementation — same posture as the metadata/project
    # file locks. Any OSError below degrades to an UNLOCKED
    # read-modify-write; that is logged, never silent.
    lock_path = SESSIONS_DIR / f"{pid}.run.lock"
    # Verify-after-lock: the prune paths (read_sessions, the launcher
    # sweep, record_session removal) UNLINK lock files of sessions they
    # can prove dead — but a finishing run of that session may hold the
    # flock right then. A later writer would open the PATH, get a fresh
    # inode, and lock it: two writers each "holding" the lock. After
    # acquiring, re-stat the path; if our fd's inode is no longer what
    # the path names, release and retry against the current file.
    for _ in range(5):
        try:
            fd = os.open(str(lock_path), os.O_WRONLY | os.O_CREAT, 0o600)
        except OSError:
            yield
            return
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
        except OSError:
            os.close(fd)
            logger.warning(
                "sessions: ledger lock acquisition failed for pid %d "
                "— proceeding UNLOCKED (best-effort data)", pid,
                exc_info=True)
            yield
            return
        try:
            held = os.fstat(fd)
            current = os.stat(str(lock_path))
            same = (held.st_ino == current.st_ino
                    and held.st_dev == current.st_dev)
        except OSError:
            same = False  # path unlinked under us — retry
        if same:
            try:
                yield
            finally:
                with contextlib.suppress(OSError):
                    fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)
            return
        os.close(fd)
    # Persistent swapping (hostile or pathological): proceed unlocked
    # rather than deadlock — the ledger is an aid, never critical.
    logger.debug("sessions: ledger lock for pid %d kept vanishing — "
                 "proceeding without it", pid)
    yield


def _read_ledger(pid: int) -> list[dict]:
    return _read_ledger_full(pid)[0]


#: Byte budget for a ledger file — sized so the record cap (32) plus a
#: witness per record at PATH_MAX-ish paths fits with headroom. The
#: writer enforces it by evicting oldest finished records.
_MAX_LEDGER_BYTES = 512 * 1024


def _read_ledger_full(
        pid: int) -> tuple[list[dict], list[dict], list[str]]:
    """(run records, pin-witness records, unknown lines) for *pid*.

    Unknown line types are carried verbatim so a FUTURE format's
    records survive an old reader's rewrite (mixed-version deployments
    sharing one HOME must not destroy each other's state).
    """
    records: list[dict] = []
    pins: list[dict] = []
    unknown: list[str] = []
    path = _ledger_path(pid)
    try:
        # Dedicated ledger budget: the entry cap (64KB) silently
        # zeroed large-but-legitimate ledgers (32 records + witnesses
        # with long paths exceed it), which blinded every python
        # consumer — including the pin tamper-witness — while the bash
        # hook kept reading, and the next RMW wiped the history.
        if path.stat().st_size > _MAX_LEDGER_BYTES:
            logger.warning(
                "sessions: ledger for pid %d exceeds %d bytes — "
                "treating as empty (records preserved on disk)",
                pid, _MAX_LEDGER_BYTES)
            return records, pins, unknown
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return records, pins, unknown
    for line in text.splitlines():
        if not line.strip():
            continue
        m = _RUN_LINE_RE.match(line)
        if m:
            records.append({
                "status": m.group(1),
                "epoch": int(m.group(2)),
                "run_id": m.group(3),
                "run_dir": m.group(4),
            })
            continue
        m = _PIN_LINE_RE.match(line)
        if m:
            pins.append({
                "epoch": int(m.group(1)),
                "run_id": m.group(2),
                "project": m.group(3),
                "run_dir": m.group(4),
            })
            continue
        unknown.append(line)
    return records, pins, unknown


def _zombie_correct(records: list[dict]) -> None:
    """Status-correct stale ``running`` records in place: a record whose
    dir is gone, or whose run metadata is terminal, is not running —
    without this, crashed runs' lines accumulate forever, the cap
    evicts all real history, and the 64KB read bound eventually zeroes
    the ledger."""
    import time as _time
    _now = int(_time.time())
    for r in records:
        # A record stamped under a skewed-ahead clock out-competes
        # every legitimate run in the hooks' newest-running selection
        # until it terminates — clamp absurd epochs on rewrite.
        if r["epoch"] > _now + 86400:
            r["epoch"] = _now
        if r["status"] != "running":
            continue
        run_dir = Path(r["run_dir"])
        meta = run_dir / ".raptor-run.json"
        if not meta.is_file():
            r["status"] = "failed"
            continue
        try:
            if meta.stat().st_size > _MAX_ENTRY_BYTES * 16:
                continue  # attacker-influenced file — never slurp GBs
            from core.json import load_json
            data = load_json(meta)
            status = (data or {}).get("status", "")
        except Exception:  # noqa: BLE001 — correction is best-effort
            continue
        if status and status != "running":
            r["status"] = status if status in _RUN_STATUSES else "failed"


def _write_ledger(pid: int, records: list[dict],
                  pins: list[dict] | None = None,
                  unknown: list[str] | None = None) -> bool:
    # Entry gate UNDER the caller's lock: once the entry file is gone
    # (session removal, prune — both remove the entry FIRST), no writer
    # may recreate or rewrite the ledger. This closes the resurrection
    # window where a straggling finisher that passed the pre-lock gate
    # rewrites a just-removed ledger under a recycled pid's fresh
    # session — foreign history and foreign pin witnesses included.
    if not (SESSIONS_DIR / str(pid)).exists():
        return False
    _zombie_correct(records)
    finished = [r for r in records if r["status"] != "running"]
    if len(records) > _LEDGER_CAP and finished:
        drop = min(len(records) - _LEDGER_CAP, len(finished))
        keep_finished = finished[drop:]
        records = [r for r in records
                   if r["status"] == "running" or r in keep_finished]

    pins = list(pins or [])
    if pins:
        alive = {(r["run_id"], r["run_dir"]) for r in records}
        # A witness survives while its record does OR its run dir
        # still exists: in-grant metadata can zombie-flip a LIVE
        # run's record to finished and cap-evict it — the witness
        # (the tamper defense) must not die with that trick.
        pins = [p for p in pins
                if (p["run_id"], p["run_dir"]) in alive
                or Path(p["run_dir"]).exists()]
    # Unknown (future-format) lines survive rewrites; order preserved,
    # appended after the pins. They are evicted only under BYTE
    # PRESSURE (below, last in the eviction order) — an unconditional
    # cap destroyed a future format's state while far under budget.
    unknown = list(unknown or [])

    def _render() -> list[str]:
        out = [
            f"{r['status']} {r['epoch']} {r['run_id']} {r['run_dir']}"
            for r in records
        ]
        out.extend(
            f"pin {p['epoch']} {p['run_id']} "
            f"{p['project']} {p['run_dir']}"
            for p in pins
        )
        out.extend(unknown)
        return out

    lines = _render()
    # Byte budget — the writer GUARANTEES an under-budget file (an
    # over-budget ledger reads as EMPTY and the next RMW would wipe
    # every record AND every witness). Eviction order: oldest
    # finished records, then oldest witnesses (they otherwise
    # accumulate one per pinned start for as long as run dirs live),
    # then unknown lines.
    def _over() -> bool:
        return sum(len(ln) + 1 for ln in lines) > _MAX_LEDGER_BYTES

    while _over() and any(r["status"] != "running" for r in records):
        for i, r in enumerate(records):
            if r["status"] != "running":
                del records[i]
                break
        lines = _render()
    # Pin eviction is status-aware: a LIVE run's witness is the
    # tamper defense — evict finished/record-less pins first, oldest
    # first, and a running record's witness only as the last resort.
    # (Liveness here comes from the zombie-corrected records, which
    # trust the run marker's status — an in-grant zombie-flip can
    # demote a live run's witness into the evict-first class, but the
    # BYTE PRESSURE itself cannot be attacker-created: the ledger is
    # outside the write grant.)
    _running = {(r["run_id"], r["run_dir"]) for r in records
                if r["status"] == "running"}
    while _over() and pins:
        for i, pn in enumerate(pins):
            if (pn["run_id"], pn["run_dir"]) not in _running:
                del pins[i]
                break
        else:
            pins.pop(0)
        lines = _render()
    while _over() and unknown:
        unknown.pop(0)
        lines = _render()
    # Belt-and-braces: the format must stay one-line. A bad line is
    # SKIPPED, not fatal — one unprintable future-format line must not
    # freeze every finish CAS forever.
    _bad = [ln for ln in lines
            if "\n" in ln or not ln.isprintable()]
    if _bad:
        logger.warning("sessions: dropping %d unprintable ledger "
                       "line(s)", len(_bad))
        lines = [ln for ln in lines if ln not in _bad]
    try:
        if not _ensure_dir():
            return False
        _atomic_write(_ledger_path(pid),
                      "\n".join(lines) + ("\n" if lines else ""))
    except OSError:
        return False
    return True


def _valid_run_dir(run_dir: str) -> bool:
    """Vet a resolved run dir for the one-line ledger grammar.

    Non-printables are rejected everywhere (``str.splitlines`` splits
    on the U+2028 class, so a crafted component could forge a second
    ledger record — ``isprintable`` covers that class plus newlines and
    tabs). Exotic printable spaces (U+00A0 etc.) are rejected
    everywhere too. A PLAIN space is legal in parent components — the
    run-dir field is last on the line and greedy, so an operator's
    ``/home/u/My Projects/...`` tree must not silently lose ledger
    attribution — but never in the basename, which doubles as the
    space-delimited run-id field."""
    if not run_dir.startswith("/") or not run_dir.isprintable():
        return False
    if any(c.isspace() and c != " " for c in run_dir):
        return False
    name = Path(run_dir).name
    if not name:
        return False  # '/' — empty basename cannot be a run-id field
    return " " not in name


def ledger_record_start(run_dir: str | os.PathLike[str],
                        pid: int | None = None,
                        pin_project: str | None = None,
                        record_pin: bool = False,
                        pin_source: str | None = None) -> None:
    """Append a running record for *run_dir* (basename = run id) and,
    when ``record_pin`` is set, the pin-witness line the privileged
    project-store writers verify the run marker against
    (``pin_project=None`` = pinned projectless, written as ``-``).

    Best-effort: failures are logged at debug and swallowed — the
    ledger is an attribution/discovery aid, never lifecycle-critical.
    """
    import time
    if pid is None:
        pid = resolve_session_pid()
    if pid is None:
        return
    resolved = str(Path(run_dir).resolve())
    if not _valid_run_dir(resolved):
        logger.debug("sessions: ledger refused run dir %r", resolved)
        return
    # Ledger records belong to REGISTERED sessions only: without an
    # entry there is no owner, no prune path (sweeps remove ledgers
    # alongside their entry), and no reader (the hook resolves via the
    # entry-backed credential). Unregistered contexts — bare shells,
    # test processes — must not accrete orphan ledgers. A v2 entry
    # whose stamp does NOT verify is a recycled pid's leftover: refuse
    # too — records written over it would be wiped by the next
    # identity refresh anyway, taking this run's attribution with
    # them.
    _entry_fields = _parse_entry(SESSIONS_DIR / str(pid))
    if not _entry_fields:
        logger.debug("sessions: no registry entry for pid %d — "
                     "ledger skipped", pid)
        return
    if (_entry_fields.get("v") == ENTRY_VERSION
            and not _identity_matches(pid, _entry_fields)):
        logger.debug("sessions: stale entry stamp for pid %d — "
                     "ledger skipped", pid)
        return
    run_id = Path(resolved).name
    pin_value = NONE_SENTINEL if pin_project is None else pin_project
    if record_pin and pin_value != NONE_SENTINEL \
            and not _NAME_RE.match(pin_value):
        record_pin = False  # never write a witness readers reject
    if pin_source and pin_source.isalpha():
        pin_value = f"{pin_value}:{pin_source}"
    with _ledger_lock(pid):
        if not _parse_entry(SESSIONS_DIR / str(pid)):
            return  # entry pruned since the pre-lock gate — no orphan
        # Dedup requires run-id AND dir (the finish CAS doctrine): two
        # live runs whose dirs share a basename must not erase each
        # other's records.
        epoch = int(time.time())
        records, pins, unknown = _read_ledger_full(pid)
        records = [r for r in records
                   if not (r["run_id"] == run_id
                           and r["run_dir"] == resolved)]
        records.append({
            "status": "running",
            "epoch": epoch,
            "run_id": run_id,
            "run_dir": resolved,
        })
        if record_pin:
            # Replace this run's witness only when we carry a new pin
            # — a resume/re-append (record_pin=False) must PRESERVE the
            # original start's witness, not strip it.
            pins = [p for p in pins
                    if not (p["run_id"] == run_id
                            and p["run_dir"] == resolved)]
            pins.append({
                "epoch": epoch,
                "run_id": run_id,
                "project": pin_value,
                "run_dir": resolved,
            })
        if not _write_ledger(pid, records, pins, unknown):
            logger.debug("sessions: ledger start write failed for %s",
                         resolved)


def ledger_record_finish(run_dir: str | os.PathLike[str], status: str,
                         pid: int | None = None) -> None:
    """CAS-mark *run_dir*'s record with its TRUE terminal status — only
    a running line matching BOTH the run id and the recorded absolute
    dir changes; a concurrent sibling run's record is never touched
    (the guarded-clear doctrine). The dir match matters most on the
    resume path, where the target pid comes from child-writable run
    metadata: a forged ``session_pid`` plus a COLLIDING run-id
    basename must not let one run mark another session's different
    run interrupted.
    """
    if status not in _RUN_STATUSES or status == "running":
        status = "failed"
    if pid is None:
        pid = resolve_session_pid()
    if pid is None:
        return
    # Same registered-session gate as start — and checked BEFORE the
    # lock, so an unregistered context never even creates a lock file.
    # A v2 entry with a stale stamp is a recycled pid's leftover:
    # refuse, like the start writer does.
    _fin_fields = _parse_entry(SESSIONS_DIR / str(pid))
    if not _fin_fields:
        return
    if (_fin_fields.get("v") == ENTRY_VERSION
            and not _identity_matches(pid, _fin_fields)):
        return
    run_id = Path(str(run_dir)).name
    try:
        resolved = str(Path(run_dir).resolve())
    except OSError:
        resolved = str(run_dir)
    with _ledger_lock(pid):
        records, pins, unknown = _read_ledger_full(pid)
        hit = False
        for r in records:
            if (r["run_id"] == run_id and r["status"] == "running"
                    and r["run_dir"] == resolved):
                r["status"] = status
                hit = True
        if hit and not _write_ledger(pid, records, pins, unknown):
            logger.debug("sessions: ledger finish write failed for %s",
                         run_dir)


def ledger_record_resume(run_dir: str | os.PathLike[str],
                         prior_session_pid: int | None = None,
                         pid: int | None = None,
                         pin_project: str | None = None,
                         pin_source: str | None = None,
                         record_pin: bool = False) -> None:
    """Resume wiring: append a running record to the
    RESUMING session's ledger — carrying the (verified) pin as this
    session's witness for segment 2+ when ``record_pin`` — and
    CAS-mark the original owner's line ``interrupted`` so its
    session's hook stops attributing to a run it no longer owns."""
    ledger_record_start(run_dir, pid=pid, pin_project=pin_project,
                        pin_source=pin_source, record_pin=record_pin)
    if prior_session_pid is None:
        return
    resolved_own = pid if pid is not None else resolve_session_pid()
    if prior_session_pid == resolved_own:
        return
    ledger_record_finish(run_dir, "interrupted", pid=prior_session_pid)


def ledger_pin_witness(
        run_dir: str | os.PathLike[str],
        pid: int | None = None,
) -> tuple[bool, str | None, str | None]:
    """The session ledger's pin witness for *run_dir*:
    ``(found, project_or_None, source_or_None)``.

    The witness is written at start by the (unsandboxed) owning
    process into sessions.d — OUTSIDE any sandbox write grant — so a
    privileged project-store writer can verify the run marker's pin
    against it: a child that rewrote or deleted the marker cannot
    touch this record. ``found=False`` (no session, pre-witness run,
    cap-evicted) means unverifiable — callers keep their existing
    posture. Best-effort: any failure reads as no witness.
    """
    explicit_pid = pid is not None
    if pid is None:
        pid = resolve_session_pid()
    if pid is None:
        return False, None, None
    if explicit_pid:
        # An explicitly-named pid (e.g. the prior owner recorded in
        # child-writable run metadata) must correspond to a REGISTERED
        # session whose identity verifies — otherwise a forged pid
        # points the lookup at an arbitrary stale/orphan ledger and
        # its pins would read as authority.
        fields = _parse_entry(SESSIONS_DIR / str(pid))
        if not fields:
            return False, None, None
        if (fields.get("v") == ENTRY_VERSION
                and not _identity_matches(pid, fields)):
            return False, None, None
    try:
        resolved = str(Path(run_dir).resolve())
    except OSError:
        return False, None, None
    try:
        _records, pins, _unknown = _read_ledger_full(pid)
    except Exception:  # noqa: BLE001 — witness is an aid, never a gate
        return False, None, None
    for p in reversed(pins):
        if p["run_dir"] == resolved:
            project, _, source = p["project"].partition(":")
            return (True,
                    None if project == NONE_SENTINEL else project,
                    source or None)
    return False, None, None


def ledger_rewrite_pin_project(old_name: str, new_name: str) -> None:
    """Re-point pin witnesses (and any recorded runs' markers outside
    the project dir) from *old_name* to *new_name* across ALL local
    sessions' ledgers — the rename counterpart of the marker rewrite.
    Without this, a witness naming the old project DISAGREES with the
    legitimately re-pointed marker and the tamper check suppresses
    every later projection of the renamed project's runs.

    Best-effort per ledger; same-uid files only (0600 under our own
    sessions.d)."""
    try:
        children = list(SESSIONS_DIR.iterdir())
    except OSError:
        return
    for f in children:
        if not f.name.endswith(".run"):
            continue
        stem = f.name[:-len(".run")]
        if _pid_from_name(stem) is None:
            continue
        pid = int(stem)
        try:
            with _ledger_lock_nb(pid) as held:
                if not held:
                    logger.warning(
                        "sessions: pid %d's ledger lock is held — "
                        "skipping its witness rewrite (%r→%r); its "
                        "runs may log witness-disagreement warnings "
                        "until re-pointed", pid, old_name, new_name)
                    continue
                records, pins, unknown = _read_ledger_full(pid)
                hit = False
                for p in pins:
                    project, sep, source = p["project"].partition(":")
                    if project == old_name:
                        p["project"] = f"{new_name}{sep}{source}"
                        hit = True
                if hit:
                    _write_ledger(pid, records, pins, unknown)
        except Exception:  # noqa: BLE001 — per-ledger best-effort
            logger.debug("sessions: witness rewrite failed for pid %s",
                         stem, exc_info=True)


def ledger_pinned_dirs(project: str) -> list[dict]:
    """Every surviving pin WITNESS naming *project* across all local
    ledgers — regardless of whether the run RECORD survived the cap.
    The rename marker-rewrite needs this: a witness outlives its
    cap-evicted record while the run dir exists, and a rename that
    only saw witnessed RECORDS re-pointed the witness but left the
    marker on the old name — manufacturing a permanent
    witness/marker 'tamper' disagreement on a legitimate run.
    Each dict carries ``run_dir``/``run_id``/``source``.
    """
    out: list[dict] = []
    try:
        children = list(SESSIONS_DIR.iterdir())
    except OSError:
        return out
    for f in children:
        if not f.name.endswith(".run"):
            continue
        stem = f.name[:-len(".run")]
        if _pid_from_name(stem) is None:
            continue
        if not (SESSIONS_DIR / stem).exists():
            continue  # orphan ledger — never steers discovery
        try:
            _records, pins, _unknown = _read_ledger_full(int(stem))
        except Exception:  # noqa: BLE001
            continue
        for p in pins:
            name, _, source = p["project"].partition(":")
            if name == project:
                out.append({"run_dir": p["run_dir"],
                            "run_id": p["run_id"],
                            "source": source or None})
    return out


def ledger_repair_witnesses_for_dir(run_dir, new_project: str,
                                    missing) -> None:
    """Re-point pin witnesses for *run_dir* whose project name is
    MISSING (per the *missing* predicate) to *new_project* — the
    repair half of ``project add`` for rename crashes and skipped
    ledgers: witness=old(missing) vs marker=new reads as tamper and
    suppresses the run's projections. Best-effort per ledger.
    """
    try:
        resolved = str(Path(run_dir).resolve())
        children = list(SESSIONS_DIR.iterdir())
    except OSError:
        return
    for f in children:
        if not f.name.endswith(".run"):
            continue
        stem = f.name[:-len(".run")]
        if _pid_from_name(stem) is None:
            continue
        pid = int(stem)
        try:
            with _ledger_lock_nb(pid) as held:
                if not held:
                    continue
                records, pins, unknown = _read_ledger_full(pid)
                hit = False
                for pn in pins:
                    name, sep, source = pn["project"].partition(":")
                    if (pn["run_dir"] == resolved
                            and name not in (new_project, NONE_SENTINEL)
                            and _NAME_RE.match(name)
                            and missing(name)):
                        pn["project"] = f"{new_project}{sep}{source}"
                        hit = True
                if hit:
                    _write_ledger(pid, records, pins, unknown)
                    logger.info(
                        "sessions: repaired stale witness(es) for "
                        "%s (now %r)", resolved, new_project)
        except Exception:  # noqa: BLE001 — per-ledger best-effort
            logger.debug("sessions: witness repair failed for pid %s",
                         stem, exc_info=True)


def ledger_runs_pinned_to(project: str) -> list[dict]:
    """Every session-ledger run record whose pin witness names
    *project* — the discovery surface for runs pinned to a project but
    living OUTSIDE its output dir (``--project P --out /elsewhere``).
    Each dict carries ``status``/``run_dir``/``run_id``. Best-effort.
    """
    out: list[dict] = []
    try:
        children = list(SESSIONS_DIR.iterdir())
    except OSError:
        return out
    for f in children:
        if not f.name.endswith(".run"):
            continue
        stem = f.name[:-len(".run")]
        if _pid_from_name(stem) is None:
            continue
        if not (SESSIONS_DIR / stem).exists():
            continue  # orphan ledger — never steers discovery
        try:
            records, pins, _unknown = _read_ledger_full(int(stem))
        except Exception:  # noqa: BLE001
            continue
        witnessed = {(p["run_id"], p["run_dir"])
                     for p in pins
                     if p["project"].partition(":")[0] == project}
        out.extend(r for r in records
                   if (r["run_id"], r["run_dir"]) in witnessed)
    return out


def ledger_runs(pid: int | None = None,
                status: str | None = None) -> list[dict]:
    """This session's run records, newest-first; optionally filtered."""
    if pid is None:
        pid = resolve_session_pid()
    if pid is None:
        return []
    records = _read_ledger(pid)
    if status is not None:
        records = [r for r in records if r["status"] == status]
    return sorted(records, key=lambda r: r["epoch"], reverse=True)
