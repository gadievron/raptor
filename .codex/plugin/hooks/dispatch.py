"""Delegate cached plugin hooks to the installation selected by the launcher.

The installed plugin owns this adapter. RAPTOR owns the maintained lifecycle
handlers. Neither hook cwd, git, payload data nor RAPTOR_DIR selects code.
"""
import argparse
import os
from pathlib import Path
import sys

_HANDLERS = {
    'session-start': ('.codex/hooks/session_start.py',),
    'subagent-start': ('libexec/raptor-session-init', '--codex-subagent-context'),
    'outcome': ('libexec/raptor-lifecycle-hook', 'codex-outcome'),
    'stop': ('libexec/raptor-lifecycle-hook', 'codex-stop'),
    'end': ('libexec/raptor-lifecycle-hook', 'codex-end'),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('event', choices=_HANDLERS)
    event = parser.parse_args().event
    anchor = os.environ.get('RAPTOR_CODEX_HOOK_ROOT')
    if not anchor:
        # User-installed plugins can be enabled outside RAPTOR. They must not
        # initialize a session or affect unrelated ordinary Codex workflows.
        return 0
    if not Path(anchor).is_absolute():
        sys.stderr.write('RAPTOR: invalid launcher hook root; restart through bin/raptor --codex\n')
        return 2
    try:
        root = Path(anchor).resolve(strict=True)
        relative, *arguments = _HANDLERS[event]
        script = root / relative
        if not script.is_file():
            raise FileNotFoundError
        os.chdir(root)
        # Plugin locations belong to the native adapter, not target or
        # framework subprocess environments. The existing strip policy owns
        # RAPTOR_CODEX_HOOK_ROOT at the later target boundary.
        for key in ('PLUGIN_ROOT', 'PLUGIN_DATA', 'CLAUDE_PLUGIN_ROOT', 'CLAUDE_PLUGIN_DATA'):
            os.environ.pop(key, None)
        os.environ.update(CODEX='1', RAPTOR_CODEX_HOOK='1', _RAPTOR_TRUSTED='1')
        os.execv(sys.executable, [sys.executable, '-I', str(script), *arguments])
    except OSError:
        sys.stderr.write('RAPTOR: launcher installation unavailable; restart through bin/raptor --codex\n')
        return 2


if __name__ == '__main__':
    sys.exit(main())
