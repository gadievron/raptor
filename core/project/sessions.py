"""Session-awareness registry — which sessions have which project active.

``~/.local/share/raptor/sessions.d/<pid>`` maps a live Claude Code
session to the project it had active, written by the launcher at exec
time (bash — see bin/raptor) and by ``/project use`` (here). Each
entry is KEY=VALUE lines so both writers speak the same format:

    project=myapp
    since=2026-08-20T12:34:56+00:00

This is ADVISORY ONLY — never lock-based, never consulted for
contention decisions (the op lock and run metadata own those). Its
single purpose is the awareness line — "project X is also active in
session pid N (since T)" — surfaced in exactly two places: launcher
startup (stderr, before exec) and project switch (``use`` output).
Contention messages never repeat it.

Entries are pruned by pid-liveness at read time. Liveness is a plain
``kill(pid, 0)`` — PID reuse can briefly keep a stale entry alive,
which at worst yields one spurious advisory line; the safe direction
for an awareness hint.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

SESSIONS_DIR = Path.home() / ".local" / "share" / "raptor" / "sessions.d"


def _pid_running(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def session_pid() -> int | None:
    """The owning Claude Code session's pid, or None outside a session.

    A bare-terminal ``raptor project use`` has no session to register —
    its CLI process dies immediately and the entry would just be prune
    fodder."""
    try:
        from core.run.metadata import _get_session_pid
        return _get_session_pid()
    except Exception:  # noqa: BLE001 — advisory feature, never fatal
        return None


def record_session(project: str | None, pid: int | None = None) -> int | None:
    """Bind this session to *project* (None clears the binding).

    Returns the pid the entry was written under, or None when no
    session pid could be resolved (nothing recorded). Best-effort:
    failures are silent — the registry is advisory."""
    if pid is None:
        pid = session_pid()
    if pid is None:
        return None
    try:
        # 0700: which project each session is working on is operator
        # telemetry — not for other local users. chmod covers a dir
        # created looser by an older writer (mkdir mode only applies
        # at creation).
        SESSIONS_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
        SESSIONS_DIR.chmod(0o700)
        entry = SESSIONS_DIR / str(pid)
        if project is None:
            entry.unlink(missing_ok=True)
        else:
            entry.write_text(
                f"project={project}\n"
                f"since={datetime.now(timezone.utc).isoformat()}\n",
                encoding="utf-8",
            )
    except OSError:
        return None
    return pid


def _parse_entry(path: Path) -> dict:
    fields: dict[str, str] = {}
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            key, sep, value = line.partition("=")
            if sep:
                fields.setdefault(key.strip(), value.strip())
    except (OSError, UnicodeDecodeError):
        pass
    return fields


def read_sessions(prune: bool = True) -> dict[int, dict]:
    """All registered sessions, pruning dead-pid entries on the way."""
    sessions: dict[int, dict] = {}
    try:
        children = list(SESSIONS_DIR.iterdir())
    except OSError:
        return sessions
    for f in children:
        name = f.name
        if not name.isdigit():
            continue  # not ours to manage
        pid = int(name)
        if not _pid_running(pid):
            if prune:
                try:
                    f.unlink(missing_ok=True)
                except OSError:
                    pass
            continue
        sessions[pid] = _parse_entry(f)
    return sessions


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
