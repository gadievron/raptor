"""Run the configured hook commands from real checkout subdirectories."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tomllib

import pytest

from core.testing.gitrepo import git_run, init_scratch_repo

ROOT = Path(__file__).resolve().parents[3]
HOOKS = tomllib.loads((ROOT / '.codex/config.toml').read_text())['hooks']


@pytest.mark.parametrize('worktree', [False, True])
def test_all_hooks_enter_the_current_checkout_root(tmp_path, worktree):
    primary = init_scratch_repo(tmp_path)
    git_run(primary, 'commit', '--allow-empty', '-m', 'fixture')
    root = primary
    if worktree:
        root = tmp_path / "worktree with spaces ' $(false)"
        git_run(primary, 'worktree', 'add', '--detach', str(root))
    nested = root / 'core/subdirectory'
    nested.mkdir(parents=True)
    # These stubs test path resolution and argv, not startup or hook payloads.
    body = ('import json, os, sys\n'
            'print(json.dumps({"cwd": os.getcwd(), "argv": sys.argv[1:], '
            '"hook": os.environ.get("RAPTOR_CODEX_HOOK")}))\n')
    for relative in ('.codex/hooks/session_start.py', 'libexec/raptor-session-init',
                     'libexec/raptor-lifecycle-hook'):
        script = root / relative
        script.parent.mkdir(parents=True, exist_ok=True)
        script.write_text(f'#!{sys.executable}\n' + body)
        script.chmod(0o755)
    expected = {'SessionStart': [], 'SubagentStart': ['--codex-subagent-context'],
                'Stop': ['codex-stop'], 'SessionEnd': ['codex-end'],
                'PostToolUse': ['codex-outcome']}
    for event, groups in HOOKS.items():
        result = subprocess.run(
            ['/bin/sh', '-c', groups[0]['hooks'][0]['command']], cwd=nested,
            env={**os.environ, 'GIT_CONFIG_GLOBAL': '/dev/null',
                 'GIT_CONFIG_SYSTEM': '/dev/null'},
            input='{}', text=True, capture_output=True, timeout=10)
        assert result.returncode == 0, (event, result.stderr)
        assert json.loads(result.stdout) == {
            'cwd': str(root), 'argv': expected[event], 'hook': '1'}


def test_hook_refuses_a_non_checkout_cwd(tmp_path):
    command = HOOKS['SessionStart'][0]['hooks'][0]['command']
    result = subprocess.run(['/bin/sh', '-c', command], cwd=tmp_path,
                            capture_output=True, text=True, timeout=10)
    assert result.returncode != 0
    assert not result.stdout
