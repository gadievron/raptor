"""Codex logical-session namespaces; the legacy PID registry stays unchanged.

PID stamps prove process liveness, not conversation identity. Each Codex root
gets a private directory below sessions.d/codex. Explicit directory overrides
are internal, call-scoped traversal aids for box-wide ledger operations.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps
import hashlib
import os
from pathlib import Path
import re
import stat

_directory_override: ContextVar[Path | None] = ContextVar("session_directory", default=None)


def validate_id(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value):
        raise ValueError("invalid Codex session identifier")
    return value


def current_id() -> str | None:
    value = os.environ.get("RAPTOR_CODEX_CONTEXT_ID")
    return validate_id(value) if value else None


def directory(base: Path, session_id: str | None = None) -> Path:
    if session_id is None:
        return base
    key = hashlib.sha256(validate_id(session_id).encode()).hexdigest()
    return base / "codex" / key


def selected_directory(base: Path) -> Path:
    override = _directory_override.get()
    return override if override is not None else directory(base, current_id())


@contextmanager
def using_directory(path: Path):
    token = _directory_override.set(Path(path))
    try:
        yield
    finally:
        _directory_override.reset(token)


def directories(base: Path):
    """Enumerate only private, same-user directories; never follow aliases."""
    yield base
    parent = base / "codex"
    try:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            return
        for path in sorted(parent.iterdir()):
            if not re.fullmatch(r"[0-9a-f]{64}", path.name):
                continue
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and not info.st_mode & 0o077:
                yield path
    except OSError:
        return


def across_scopes(combine="list"):
    """Reuse existing locked ledger operations in every logical namespace."""
    def decorate(function):
        @wraps(function)
        def wrapped(*args, **kwargs):
            from core.project import sessions
            result = [] if combine == "list" else 0 if combine == "sum" else None
            for path in directories(sessions._base_sessions_dir()):
                with using_directory(path):
                    value = function(*args, **kwargs)
                    if combine == "list":
                        result.extend(value)
                    elif combine == "sum":
                        result += value
            return result
        return wrapped
    return decorate
