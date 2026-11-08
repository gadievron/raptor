"""Conservative session-title policy and per-frontend request bookkeeping.

A request is not confirmation: only the title returned by a later frontend
hook acknowledges it. Unknown custom titles permanently yield to the operator.
This state is display metadata, never project or session authority.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import stat

from core.atomic_fs.fs_lock import sidecar_flock
from core.json import load_json, loads, save_json
from core.project import registry_home
from core.security.capped_read import _read_capped_or_raise
from core.security.log_sanitisation import sanitise_for_terminal


def context_title(project: str | None, target: str | None) -> str:
    def label(value):
        return sanitise_for_terminal(value[:256]).strip()[:48]
    parts = ['raptor', label(project) if project else 'projectless']
    if target:
        name = target.replace('\\', '/').rstrip('/').rsplit('/', 1)[-1]
        if name:
            parts.append(label(name))
    return ' · '.join(parts)


def _initial_state() -> dict:
    return dict(v=1, requested=None, confirmed=None, attempts=0, manual=False)


def state_directory() -> Path:
    """Keep display state beside the persistent project registry.

    Protected launches use fresh credential/ledger directories but link their
    projects directory to the operator's shared registry. Resolve that link
    so title ownership and manual preferences survive launch cleanup/resume.
    The final title directory itself remains subject to the private-directory
    checks below; it must never be adopted through a symlink.
    """
    return registry_home.projects_dir().resolve().parent / '.session-titles'


def _legacy_state(directory: Path, name: str) -> dict | None:
    try:
        parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    try:
        info = os.fstat(parent)
        if (info.st_uid != os.geteuid() or info.st_mode & 0o077):
            raise PermissionError('legacy title state directory must be private')
        try:
            # The existing hardened reader returns bytes and the stat of the
            # same inode while preserving the descriptor-relative parent pin.
            raw, info = _read_capped_or_raise(Path(name), 4096, follow_symlinks=False, dir_fd=parent)
        except FileNotFoundError:
            return None
    finally:
        os.close(parent)
    if info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise PermissionError('legacy title state file must be private')
    value = loads(raw, max_bytes=4096)
    if not isinstance(value, dict):
        raise ValueError('invalid legacy title state')
    return value


def title_request(state: dict, desired: str, current: str | None) -> tuple[dict, str | None]:
    """Pure transition, serialized by the caller; None means no custom title."""
    if (not isinstance(state, dict) or set(state) != set(_initial_state())
            or type(state['v']) is not int or state['v'] != 1
            or type(state['manual']) is not bool
            or type(state['attempts']) is not int or not 0 <= state['attempts'] <= 3
            or any(value is not None and (not isinstance(value, str) or len(value) > 256)
                   for value in (state['requested'], state['confirmed']))):
        raise ValueError('invalid title request state')
    updated = dict(state)
    if updated['manual']:
        return updated, None
    managed = {updated['requested'], updated['confirmed']}
    if current and current not in managed:
        updated['manual'] = True
        return updated, None
    if current and current == updated['requested']:
        updated['confirmed'] = current
        updated['attempts'] = 0
    if current == desired:
        return updated, None
    if updated['requested'] != desired:
        updated['requested'] = desired
        updated['attempts'] = 0
    if updated['attempts'] >= 3:
        return updated, None
    updated['attempts'] += 1
    return updated, desired


def request_title(directory: Path, frontend: str, session_id: str, desired: str,
                  current: str | None, *, legacy_directory: Path | None = None) -> str | None:
    """Atomic, bounded request update; independent sessions use independent locks."""
    if (not re.fullmatch(r'[a-z][a-z0-9-]{0,31}', frontend)
            or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', session_id)):
        raise ValueError('invalid frontend session identity')
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = directory.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_mode & 0o077):
        raise PermissionError('title state directory must be private')
    # Hash the frontend-native identity; never choose another session by mtime,
    # project bookmark, process-name matching, or a shared current-session file.
    key = hashlib.sha256(session_id.encode('ascii')).hexdigest()
    path = directory / f'{frontend}-{key}.json'
    with sidecar_flock(path.with_suffix('.lock'), required=True, deadline_s=.05,
                       subject='session title'):
        existing = load_json(path, strict=True, max_bytes=4096)
        state = existing
        if state is None and legacy_directory is not None and legacy_directory != directory:
            state = _legacy_state(legacy_directory, path.name)
        if state is None:
            state = _initial_state()
        updated, requested = title_request(state, desired, current)
        if updated != existing:
            save_json(path, updated, mode=0o600)
        return requested
