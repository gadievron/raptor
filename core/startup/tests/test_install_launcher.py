"""Exercise the shared launcher policy boundary with a local frontend stub."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[3]


@pytest.mark.skipif(sys.platform != 'linux', reason='Linux protection bootstrap')
def test_protection_bootstrap_skips_environment_site_hooks(tmp_path):
    import venv
    environment = tmp_path / 'python-environment'
    venv.EnvBuilder(with_pip=False, symlinks=True).create(environment)
    marker = tmp_path / 'site-hook-ran'
    site = next(environment.glob('lib/python*/site-packages'))
    (site / 'probe.pth').write_text(
        f'import pathlib; pathlib.Path({str(marker)!r}).write_text("executed")\n')
    install = tmp_path / 'install'
    for name in ('bin/raptor', 'core/security/_dangerous_env_strip.sh',
                 'core/security/launch_scratch.py', 'core/security/scratch_lifecycle.py',
                 'core/security/scratch_supervisor.py', 'core/security/cgroup_scope.py',
                 'core/security/log_sanitisation.py'):
        destination = install / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, destination)
    (install / 'core/startup').mkdir()
    # Bootstrap oracle only: exit before namespace setup or frontend execution.
    (install / 'core/startup/install_guard.py').write_text(
        'import json,sys\nprint(json.dumps([sys.flags.no_site, sys.dont_write_bytecode]))\n')
    stubs = tmp_path / 'stubs'
    stubs.mkdir()
    frontend = stubs / 'claude'
    frontend.write_text('#!/bin/sh\nexit 99\n')
    frontend.chmod(0o755)
    home = tmp_path / 'home'
    home.mkdir()
    scratch = tmp_path / 'scratch'
    scratch.mkdir()
    env = {'HOME': str(home), 'TMPDIR': str(scratch),
           'PATH': f'{environment}/bin:{stubs}:/usr/bin:/bin'}
    # Prove this interpreter would load the hook without -S.
    control = subprocess.run([str(environment / 'bin/python3'), '-I', '-c', 'pass'],
                             env=env, capture_output=True, text=True, timeout=10)
    assert control.returncode == 0, control.stderr
    assert marker.exists()
    marker.unlink()
    result = subprocess.run(['/bin/bash', str(install / 'bin/raptor'), '--protect-install'],
                            env=env, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == [1, True]
    assert not marker.exists()


@pytest.mark.parametrize('args,blocked', [([], False), (['--continue'], False), (['--model', '--protect-install'], False), (['--', '--protect-install'], False), (['--protect-install'], True), (['--protect-install', '--continue'], True)])
def test_install_protection_is_explicit_opt_in(tmp_path, args, blocked, request):
    if blocked:
        request.getfixturevalue("require_install_mounts")
    install = tmp_path / 'install'
    for folder in ('bin', 'core/security', 'core/startup', 'libexec'):
        (install / folder).mkdir(parents=True)
    for name in ('bin/raptor', 'core/security/_dangerous_env_strip.sh', 'core/security/launch_scratch.py', 'core/security/scratch_lifecycle.py',
                 'core/security/scratch_supervisor.py', 'core/security/cgroup_scope.py', 'core/security/log_sanitisation.py', 'core/startup/install_guard.py', 'core/startup/_install_namespace.py'):
        shutil.copyfile(ROOT / name, install / name)
    (install / 'source.py').write_text('VALUE = 1\n')
    for name, body in (
        ('raptor-cc-trust-check', 'exit 0'),
        ('raptor-startup-check', "printf 'RAPTOR_RESOLVED_PROJECT=-\\nRAPTOR_SEEDED_BY=bookmark\\n'"),
    ):
        path = install / 'libexec' / name
        path.write_text('#!/bin/bash\n' + body + '\n')
        path.chmod(0o755)
    stubs = tmp_path / 'stubs'
    stubs.mkdir()
    frontend = stubs / 'claude'
    frontend.write_text(f'#!{sys.executable}\n' + '''
import json, os
from pathlib import Path
root = Path(os.environ['RAPTOR_DIR'])
try:
    (root / 'source.py').write_text('updated')
    blocked = False
except OSError as exc:
    if exc.errno not in (13, 30): raise
    blocked = True
(root / 'out').mkdir(exist_ok=True)
(root / 'out/result').write_text('ok')
print(json.dumps({'blocked': blocked, 'pid': os.getpid(), 'session': os.environ.get('RAPTOR_SESSION_PID')}))
''')
    frontend.chmod(0o755)
    home = tmp_path / 'home'
    home.mkdir()
    scratch = tmp_path / 'scratch'
    scratch.mkdir()
    env = {'HOME': str(home), 'TMPDIR': str(scratch),
           'PATH': str(stubs) + ':/usr/bin:/bin:' + os.path.dirname(sys.executable),
           'CLAUDE_CONFIG_DIR': str(home / '.claude')}
    result = subprocess.run(['/bin/bash', str(install / 'bin/raptor'), '--allow-degraded-cleanup', *args],
                            cwd=home, env=env, capture_output=True, text=True, timeout=20)
    if blocked and result.returncode == 126 and ('ABI 3+ is unavailable' in result.stderr or 'requires Linux' in result.stderr):
        assert 'No frontend was started' in result.stderr
        assert not (install / 'out/result').exists()
        pytest.skip('Landlock unavailable; launcher failed closed')
    assert result.returncode == 0, result.stderr
    payload = next(json.loads(line) for line in result.stdout.splitlines() if line.startswith('{'))
    assert payload['blocked'] is blocked
    assert (install / 'out/result').read_text() == 'ok'

    assert int(payload['session']) == payload['pid']


@pytest.mark.parametrize('extra', [[], ['--continue'], ['--', '--model', 'claude'], ['--model', '--protect-install']])
def test_protected_reexec_preserves_frontend_arguments(tmp_path, extra):
    install = tmp_path / 'install'
    for folder in ('bin', 'core/security', 'core/startup', 'libexec'):
        (install / folder).mkdir(parents=True)
    for name in ('bin/raptor', 'core/security/_dangerous_env_strip.sh', 'core/security/launch_scratch.py', 'core/security/scratch_lifecycle.py',
                 'core/security/scratch_supervisor.py', 'core/security/cgroup_scope.py', 'core/security/log_sanitisation.py'):
        shutil.copyfile(ROOT / name, install / name)
    scratch_module = install / 'core/security/launch_scratch.py'
    scratch_module.write_text(scratch_module.read_text().replace(
        "if require_sealed and value['protected'] and not os.fstatvfs(meta).f_flag & os.ST_RDONLY:",
        "if False:  # fake guard for argument-ordering test only"))
    # This test exercises re-exec/session ordering only. Kernel enforcement has
    # separate real-host tests; this stub must never claim to enforce it.
    (install / 'core/startup/install_guard.py').write_text("""
import os, sys
if sys.argv[1:] == ['--verify']: sys.exit(0)
assert sys.argv[1:3] == ['--frontend', 'claude']
command = sys.argv[sys.argv.index('--') + 1:]
os.execvp(command[0], command)
""")
    for name, body in [('raptor-cc-trust-check', 'exit 0'), ('raptor-startup-check', 'exit 0')]:
        path = install / 'libexec' / name
        path.write_text('#!/bin/bash\n' + body + '\n')
        path.chmod(0o755)
    stubs = tmp_path / 'stubs'
    stubs.mkdir()
    frontend = stubs / 'claude'
    frontend.write_text(f'#!{sys.executable}\n' + """
import json, os, sys
print(json.dumps({'args': sys.argv[1:], 'pid': os.getpid(),
                  'session': os.environ.get('RAPTOR_SESSION_PID')}))
""")
    frontend.chmod(0o755)
    home = tmp_path / 'home'
    home.mkdir()
    env = {'HOME': str(home), 'PATH': str(stubs) + ':/usr/bin:/bin:' + os.path.dirname(sys.executable),
           'TMPDIR': str(tmp_path)}
    result = subprocess.run(['/bin/bash', str(install / 'bin/raptor'), '--allow-degraded-cleanup', '--protect-install', *extra],
                            cwd=home, env=env, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    payload = next(json.loads(line) for line in result.stdout.splitlines() if line.startswith('{'))
    assert int(payload['session']) == payload['pid']
    assert payload['args'].count('--protect-install') == int(extra == ['--model', '--protect-install'])
    assert '--_protected-install-stage' not in payload['args']
    if extra[:1] == ['--']:
        assert payload['args'][-3:-1] == extra[1:]
    elif extra == ['--continue']:
        assert '--continue' in payload['args']
    elif extra:
        assert payload['args'][payload['args'].index('--model') + 1] == '--protect-install'
