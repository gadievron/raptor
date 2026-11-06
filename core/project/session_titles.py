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
from core.json import load_json, save_json
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
                  current: str | None) -> str | None:
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
        state = _initial_state() if existing is None else existing
        updated, requested = title_request(state, desired, current)
        if updated != existing:
            save_json(path, updated, mode=0o600)
        return requested
