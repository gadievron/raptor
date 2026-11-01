"""The real launcher requires explicit approval for non-interactive downgrade."""
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture
def launcher(tmp_path):
    install = tmp_path / 'install'
    for folder in ('bin', 'core/security', 'libexec'):
        (install / folder).mkdir(parents=True)
    for name in ('bin/raptor', 'core/security/_dangerous_env_strip.sh',
                 'core/security/launch_scratch.py', 'core/security/scratch_lifecycle.py',
                 'core/security/scratch_supervisor.py'):
        shutil.copyfile(ROOT / name, install / name)
    # Simulate an unavailable optional backend without depending on the CI host
    # having or lacking delegation. The real launcher/supervisor still run.
    (install / 'core/security/cgroup_scope.py').write_text('raise ImportError("no cgroup backend")\n')
    for name in ('raptor-cc-trust-check', 'raptor-startup-check'):
        path = install / 'libexec' / name
        path.write_text('#!/bin/bash\nexit 0\n')
        path.chmod(0o755)
    stubs = tmp_path / 'stubs'
    stubs.mkdir()
    receipt = tmp_path / 'frontend.json'
    frontend = stubs / 'claude'
    frontend.write_text(f'#!{sys.executable}\n' +
                        'import json,pathlib,sys\n' +
                        f'pathlib.Path({str(receipt)!r}).write_text(json.dumps(sys.argv[1:]))\n')
    frontend.chmod(0o755)
    home = tmp_path / 'home'
    home.mkdir()
    scratch = tmp_path / 'scratch'
    scratch.mkdir()
    env = {'HOME': str(home), 'TMPDIR': str(scratch), 'PATH': str(stubs) + ':/usr/bin:/bin',
           'TERM': 'dumb'}
    return install / 'bin/raptor', env, receipt


@pytest.mark.parametrize('args', [[], ['--', '--allow-degraded-cleanup']])
def test_noninteractive_launcher_refuses_unapproved_downgrade(launcher, args):
    script, env, receipt = launcher
    result = subprocess.run(['/bin/bash', str(script), *args], env=env,
                            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10)
    assert result.returncode == 126, result.stderr
    assert '--allow-degraded-cleanup' in result.stderr
    assert not receipt.exists()


def test_explicit_approval_is_consumed_by_raptor_not_forwarded(launcher):
    script, env, receipt = launcher
    result = subprocess.run(['/bin/bash', str(script), '--allow-degraded-cleanup'], env=env,
                            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert '--allow-degraded-cleanup' not in json.loads(receipt.read_text())
    assert 'explicitly approved' in result.stderr


def test_direct_project_status_does_not_start_a_frontend_session(launcher):
    script, env, receipt = launcher
    helper = script.parent.parent / 'libexec/raptor-project-manager'
    helper.write_text('#!/bin/sh\necho STATUS-ONLY\n')
    helper.chmod(0o755)
    result = subprocess.run(['/bin/bash', str(script), 'project', 'status'], env=env,
                            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert 'STATUS-ONLY' in result.stdout
    assert not receipt.exists()
    assert not (Path(env['HOME']) / '.local/state/raptor/scratch-lifecycle').exists()
    assert not list(Path(env['TMPDIR']).glob('raptor-*/session-*'))


def test_hidden_stage_cannot_bypass_approval_without_a_live_authority(launcher):
    script, env, receipt = launcher
    result = subprocess.run(['/bin/bash', str(script), '--_scratch-session-stage'], env=env,
                            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10)
    assert result.returncode == 126
    assert not receipt.exists()
