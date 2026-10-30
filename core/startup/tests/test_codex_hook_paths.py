"""Hook executable selection must not follow cwd into another repository."""
import json
import os
from pathlib import Path
import subprocess
import sys
import shutil

import pytest

from core.testing.gitrepo import git_run, init_scratch_repo

ROOT = Path(__file__).resolve().parents[3]
HOOKS = json.loads((ROOT / '.codex/plugin/hooks/hooks.json').read_text())['hooks']
EXPECTED = {'SessionStart': [], 'SubagentStart': ['--codex-subagent-context'],
            'Stop': ['codex-stop'], 'SessionEnd': ['codex-end'],
            'PostToolUse': ['codex-outcome']}


@pytest.fixture
def plugin_env(tmp_path):
    installed = tmp_path / "installed plugin with spaces ' $(false)"
    shutil.copytree(ROOT / '.codex/plugin', installed)
    return {'PLUGIN_ROOT': str(installed), 'PLUGIN_DATA': str(tmp_path / 'plugin-data'),
            'CLAUDE_PLUGIN_ROOT': str(installed), 'CLAUDE_PLUGIN_DATA': 'private'}


def _scripts(root, marker=None):
    body = ('import json, os, sys\n'
            'print(json.dumps({"cwd": os.getcwd(), "argv": sys.argv[1:], '
            '"hook": os.environ.get("RAPTOR_CODEX_HOOK"), "payload": sys.stdin.read(), '
            '"plugin_env": any(k in os.environ for k in '
            '("PLUGIN_ROOT", "PLUGIN_DATA", "CLAUDE_PLUGIN_ROOT", "CLAUDE_PLUGIN_DATA"))}))\n')
    if marker is not None:
        body = f'from pathlib import Path\nPath({str(marker)!r}).touch()\n' + body
    for relative in ('.codex/hooks/session_start.py', 'libexec/raptor-session-init',
                     'libexec/raptor-lifecycle-hook'):
        script = root / relative
        script.parent.mkdir(parents=True, exist_ok=True)
        script.write_text(f'#!{sys.executable}\n' + body)
        script.chmod(0o755)


def _fire(event, cwd, env):
    return subprocess.run(
        ['/bin/sh', '-c', HOOKS[event][0]['hooks'][0]['command']], cwd=cwd,
        env=env, input='{}', text=True, capture_output=True, timeout=10)


@pytest.mark.parametrize('worktree', [False, True])
@pytest.mark.parametrize('cwd_kind', ['subdirectory', 'nested-repo', 'other-repo',
                                      'outside-repo', 'submodule'])
def test_all_hooks_use_the_launcher_owner_despite_foreign_cwd(tmp_path, plugin_env, worktree, cwd_kind):
    primary = init_scratch_repo(tmp_path)
    git_run(primary, 'commit', '--allow-empty', '-m', 'fixture')
    owner = primary
    if worktree:
        owner = tmp_path / "owner with spaces ' $(false)"
        git_run(primary, 'worktree', 'add', '--detach', str(owner))
    _scripts(owner)
    if cwd_kind == 'subdirectory':
        cwd = owner / 'core/subdirectory'
        cwd.mkdir(parents=True)
    elif cwd_kind == 'nested-repo':
        cwd = init_scratch_repo(owner, 'target')
    elif cwd_kind == 'other-repo':
        cwd = init_scratch_repo(tmp_path, 'target')
    elif cwd_kind == 'submodule':
        source = init_scratch_repo(tmp_path, 'submodule-source')
        git_run(source, 'commit', '--allow-empty', '-m', 'fixture')
        git_run(owner, '-c', 'protocol.file.allow=always', 'submodule', 'add',
                str(source), 'modules/target')
        cwd = owner / 'modules/target'
    else:
        cwd = tmp_path / 'outside-git'
        cwd.mkdir()
    marker = tmp_path / 'target-script-executed'
    _scripts(cwd, marker)
    env = {**os.environ, **plugin_env, 'RAPTOR_CODEX_HOOK_ROOT': str(owner),
           'RAPTOR_DIR': str(cwd), 'GIT_DIR': str(primary / '.git'),
           'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_SYSTEM': '/dev/null'}
    for event, arguments in EXPECTED.items():
        result = _fire(event, cwd, env)
        assert result.returncode == 0, (event, result.stderr)
        assert json.loads(result.stdout) == {
            'cwd': str(owner), 'argv': arguments, 'hook': '1',
            'payload': '{}', 'plugin_env': False}
        assert not marker.exists(), event


@pytest.mark.parametrize('anchor', [None, '', 'relative', 'missing-absolute'])
def test_missing_or_relative_anchor_never_falls_back_to_target_code(tmp_path, plugin_env, anchor):
    target = init_scratch_repo(tmp_path)
    marker = tmp_path / 'target-script-executed'
    _scripts(target, marker)
    env = {**os.environ, **plugin_env, 'RAPTOR_DIR': str(target)}
    env.pop('RAPTOR_CODEX_HOOK_ROOT', None)
    if anchor is not None:
        env['RAPTOR_CODEX_HOOK_ROOT'] = (str(tmp_path / 'missing-installation')
                                         if anchor == 'missing-absolute' else anchor)
    for event in EXPECTED:
        result = _fire(event, target, env)
        if anchor:
            assert result.returncode != 0, event
            assert 'bin/raptor --codex' in result.stderr
        else:
            assert result.returncode == 0, event
            assert not result.stderr
        assert not result.stdout
        assert not marker.exists(), event


def test_unrelated_codex_session_does_not_even_start_an_interpreter(tmp_path, plugin_env):
    marker = tmp_path / 'interpreter-started'
    tools = tmp_path / 'tools'
    tools.mkdir()
    python = tools / 'python3'
    python.write_text(f'#!{sys.executable}\nfrom pathlib import Path\n'
                      f'Path({str(marker)!r}).touch()\nraise SystemExit(93)\n')
    python.chmod(0o755)
    env = {**plugin_env, 'PATH': str(tools), 'RAPTOR_DIR': str(tmp_path)}
    for event in EXPECTED:
        result = _fire(event, tmp_path, env)
        assert result.returncode == 0, result.stderr
        assert not marker.exists()


@pytest.mark.parametrize('path_prefix', ['.', ''])
def test_target_cwd_cannot_supply_hook_python(tmp_path, plugin_env, path_prefix):
    owner = tmp_path / 'owner'
    target = tmp_path / 'target'
    target.mkdir()
    _scripts(owner)
    marker = tmp_path / 'target-python-executed'
    python = target / 'python3'
    python.write_text(f'#!{sys.executable}\nfrom pathlib import Path\n'
                      f'Path({str(marker)!r}).touch()\nraise SystemExit(93)\n')
    python.chmod(0o755)
    env = {**os.environ, **plugin_env, 'RAPTOR_CODEX_HOOK_ROOT': str(owner),
           'PATH': path_prefix + os.pathsep + os.environ['PATH']}
    for event in EXPECTED:
        result = _fire(event, target, env)
        assert not marker.exists(), event
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout)['cwd'] == str(owner)


def test_plugin_python_ignores_target_import_paths(tmp_path, plugin_env):
    owner = tmp_path / 'owner'
    target = tmp_path / 'target'
    target.mkdir()
    _scripts(owner)
    marker = tmp_path / 'target-module-imported'
    for module in ('sitecustomize.py', 'argparse.py'):
        (target / module).write_text('from pathlib import Path\n'
                                   f'Path({str(marker)!r}).touch()\n'
                                   'raise RuntimeError("target module imported")\n')
    env = {**os.environ, **plugin_env, 'RAPTOR_CODEX_HOOK_ROOT': str(owner),
           'PYTHONPATH': str(target)}
    for event in EXPECTED:
        result = _fire(event, target, env)
        assert result.returncode == 0, result.stderr
        assert not marker.exists(), event
