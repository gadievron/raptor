"""Exercise real shell entry points from a target with a hostile packages tree."""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture
def hostile_target(tmp_path):
    target = tmp_path/'target with spaces'
    (target/'packages/frida').mkdir(parents=True)
    marker = target/'executed'
    (target/'packages/__init__.py').write_text(
        f'from pathlib import Path\nPath({str(marker)!r}).write_text("bad")\n')
    (target/'packages/frida/__init__.py').write_text('')
    for name in ('cli', 'sandboxed', 'patch_oracle'):
        (target/'packages/frida'/(name+'.py')).write_text('raise RuntimeError("target code loaded")\n')
    home, scratch = tmp_path/'home', tmp_path/'scratch'
    home.mkdir()
    scratch.mkdir()
    env = dict(HOME=str(home), TMPDIR=str(scratch), _RAPTOR_TRUSTED='1',
               PATH=str(Path(sys.executable).parent)+os.pathsep+os.defpath)
    return target, marker, env


@pytest.mark.parametrize('helper,arguments', [
    ('raptor-frida', ['--help']),
    ('raptor-frida', ['--list-templates']),
    ('raptor-frida-patch-verify', ['--help']),
])
def test_query_wrappers_ignore_target_packages(hostile_target, helper, arguments):
    target, marker, env = hostile_target
    reply = subprocess.run([str(ROOT/'libexec'/helper), *arguments], env=env, cwd=target,
                           capture_output=True, text=True, timeout=15)
    assert reply.returncode == 0, reply.stderr
    assert not marker.exists(), 'wrapper executed target packages before sandbox setup'
    assert reply.stdout.strip()


@pytest.mark.parametrize('mode', ['attach', 'spawn', 'unsafe-attach', 'patch-verify'])
def test_active_wrapper_keeps_arguments_and_safe_module_startup(hostile_target, tmp_path, mode):
    target, marker, env = hostile_target
    tools = tmp_path/'tools'
    tools.mkdir()
    receipt = tmp_path/'argv.json'
    # Record the trusted module launch; never attach to or spawn a real target.
    python = tools/'python3'
    python.write_text('#!'+sys.executable+'\nimport json, os, pathlib, sys\n'
                      f'pathlib.Path({str(receipt)!r}).write_text(json.dumps([sys.argv[1:], os.getcwd()]))\n')
    python.chmod(0o700)
    env['PATH'] = str(tools)+os.pathsep+env['PATH']
    output = tmp_path/'output'
    if mode == 'patch-verify':
        helper, arguments = 'raptor-frida-patch-verify', ['--before', 'before.bin', '--after', 'after.bin']
    else:
        helper, arguments = 'raptor-frida', ['--target', '1234', '--template', 'api-trace']
        if mode != 'attach':
            arguments.append('--'+mode)
    reply = subprocess.run([str(ROOT/'libexec'/helper), *arguments, '--out', str(output)],
                           env=env, cwd=target, capture_output=True, text=True, timeout=15)
    assert reply.returncode == 0, reply.stderr
    argv, cwd = json.loads(receipt.read_text())
    assert argv[:2] == ['-P', '-m']
    assert cwd == str(target), 'relative operator inputs must keep their original base'
    assert not marker.exists()
    if mode == 'patch-verify':
        assert argv[2] == 'packages.frida.patch_oracle'
        assert argv[argv.index('--before')+1] == 'before.bin'
    elif mode == 'unsafe-attach':
        assert argv[2] == 'packages.frida.cli'
        assert '--unsafe-attach' in argv, 'metadata must retain the explicit bypass'
        assert argv[argv.index('--target')+1] == '1234'
    else:
        assert argv[2] == 'packages.frida.sandboxed'
        assert ('--spawn' in argv) == (mode == 'spawn')
        assert argv[argv.index('--')+1:argv.index('--')+5] == [
            'python3', '-P', '-m', 'packages.frida.cli']
