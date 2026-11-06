"""Best-effort Claude session naming through documented hook output only."""
from __future__ import annotations

import os
from pathlib import Path
import sys

from core.json import dumps_display, loads
from core.project import registry_home, sessions
from core.project.session_titles import context_title, request_title


def _context() -> tuple[str | None, str | None] | None:
    # SessionStart/turn hooks inherit the launcher's authenticated binding.
    # Never borrow another terminal's machine-wide active-project bookmark.
    pid = sessions.resolve_session_pid()
    if pid is None:
        return None
    project, state = sessions.session_binding(pid)
    if state not in {'bound', 'none'}:
        return None
    if project is None:
        # Projectless work still has a session-owned run ledger. Its target is
        # display metadata only: never use it to bind a project or authorize work.
        from core.json import load_json
        runs = sessions.ledger_runs(pid)
        if runs:
            _, latest = max(enumerate(runs), key=lambda pair: (pair[1]['epoch'], pair[0]))
            found, pinned, _ = sessions.ledger_pin_witness(latest['run_dir'], pid=pid)
            if found and pinned is None:
                record = load_json(Path(latest['run_dir']) / '.raptor-run.json',
                                   strict=True, max_bytes=1024 * 1024)
                if isinstance(record, dict) and isinstance(record.get('target_path'), str):
                    return None, record['target_path']
        target = os.environ.get('RAPTOR_SESSION_TARGET')
        return None, target if target and Path(target).is_absolute() else None
    from core.json import load_json
    record = load_json(registry_home.projects_dir() / f'{project}.json',
                       strict=True, max_bytes=1024 * 1024)
    if not isinstance(record, dict) or not isinstance(record.get('target'), str):
        return None
    return project, record['target']


def hook_output(payload) -> dict:
    if not isinstance(payload, dict):
        return {}
    event = payload.get('hook_event_name')
    if event not in {'SessionStart', 'UserPromptSubmit'}:
        return {}
    if event == 'SessionStart' and payload.get('source') not in {'startup', 'resume', 'fork'}:
        return {}
    # Older clients may omit current-title feedback. Never rewrite on a turn
    # without it: an unobservable manual rename must not be overwritten.
    if event == 'UserPromptSubmit' and 'session_title' not in payload:
        return {}
    current = payload.get('session_title')
    if current is not None and (not isinstance(current, str) or len(current) > 4096):
        return {}
    identity = payload.get('session_id')
    if not isinstance(identity, str):
        return {}
    context = _context()
    if context is None:
        return {}
    desired = context_title(*context)
    requested = request_title(registry_home.sessions_dir() / '.titles', 'claude',
                              identity, desired, current)
    if requested is None:
        return {}
    return {'hookSpecificOutput': {'hookEventName': event, 'sessionTitle': requested}}


def main() -> int:
    try:
        data = sys.stdin.buffer.read(65537)
        if len(data) > 65536:
            return 0
        output = hook_output(loads(data, max_bytes=65536))
        if output:
            print(dumps_display(output))
    except (OSError, ValueError, TypeError, RuntimeError, RecursionError):
        # Naming is optional: corrupt state, a busy lock, disk pressure or a
        # missing project must never interrupt launch, resume or a user turn.
        pass
    return 0
