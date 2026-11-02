"""Slow real rr checks against owned fixtures only; no host process attachment."""
import json
import os
import signal
import shutil
import socket
import subprocess
import sys
from types import SimpleNamespace

import pytest

from packages.binary_analysis.rr_replay import replay

pytestmark = [pytest.mark.slow, pytest.mark.integration,
              pytest.mark.skipif(sys.platform != 'linux', reason='rr requires Linux')]


def _owned_run(command, *, timeout, **kwargs):
    # Prep/filter-compatibility runs operate on owned programs outside the
    # replay API. Give these test processes the same bounded cleanup care.
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, start_new_session=True, **kwargs) as process:
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=10)
            raise
        return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


@pytest.fixture
def recording(tmp_path, monkeypatch):
    if not shutil.which('rr') or not shutil.which('cc'):
        pytest.skip('rr and C compiler required')
    home = tmp_path/'home'
    home.mkdir()
    scratch = tmp_path/'scratch'
    scratch.mkdir()
    monkeypatch.setenv('HOME', str(home))
    monkeypatch.setenv('TMPDIR', str(scratch))
    monkeypatch.setenv('RR_TMPDIR', str(scratch))
    source = tmp_path/'owned.c'
    source.write_text('volatile int rr_marker = 0;\nint main(void) {\n'
                      'rr_marker = 1;\nrr_marker = 2;\nreturn 0;\n}\n')
    binary = tmp_path/'owned'
    build = _owned_run(['cc', '-g', '-O0', str(source), '-o', str(binary)],
                           timeout=30)
    assert build.returncode == 0, build.stderr
    trace = tmp_path/'recording'
    env = dict(PATH='/usr/bin:/bin', HOME=str(home), TMPDIR=str(scratch),
               RR_TMPDIR=str(scratch), LANG='C')
    result = _owned_run(['rr', 'record', '-o', str(trace), str(binary)], env=env,
                            cwd=tmp_path, timeout=45)
    if result.returncode != 0:
        pytest.skip('rr recording prerequisite unavailable: '+result.stderr[-1000:])
    result = _owned_run(['rr', 'pack', str(trace)], env=env,
                            cwd=tmp_path, timeout=45)
    assert result.returncode == 0, result.stderr
    return trace, env


@pytest.mark.parametrize('debugger', [False, True])
def test_real_recording_replays_under_rr_filter(recording, tmp_path, debugger):
    from core.sandbox.seccomp import _make_seccomp_preexec
    trace, env = recording
    # Isolate syscall compatibility from namespace availability. This is an
    # owned recording; the separate test below checks full containment.
    command = ['rr', 'replay', '--serve-files', str(trace)]
    commands = None
    if debugger:
        command += ['--', '-nx', '-iex', 'set auto-load off']
        commands = ('set confirm off\nbreak main\ncontinue\nnext\nnext\nreverse-next\n'
                    'printf "RR_REVERSE_MARKER=%d\\n", rr_marker\ncontinue\nquit\n')
    else:
        command.insert(2, '-a')
    # Commands go through a temporary input file to keep the owned-process
    # wrapper independent of subprocess.run's input convenience argument.
    command_file = tmp_path/'gdb-commands'
    command_file.write_text(commands or '')
    with command_file.open() as stdin:
        result = _owned_run(command, stdin=stdin,
            env=env, cwd=tmp_path, timeout=45,
            preexec_fn=_make_seccomp_preexec('rr', deny_fd_exec=True, allow_unix_sockets=True))
    assert result.returncode == 0, result.stderr
    if debugger:
        assert 'RR_REVERSE_MARKER=1' in result.stdout, result.stdout+result.stderr


@pytest.mark.parametrize('interactive', [False, True])
def test_real_reverse_replay_has_filesystem_and_network_containment(recording, tmp_path, monkeypatch, interactive):
    from core.sandbox.probes import check_mount_available
    if not check_mount_available():
        pytest.skip('native mount namespaces required')
    trace, _ = recording
    secret = tmp_path/'private-secret'
    secret.write_text('unchanged')
    forbidden = tmp_path/'private-write'
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen()
    probe = f'''
import os, socket
try:
    open({str(secret)!r}).read()
except OSError:
    pass
else:
    raise AssertionError('host private file read')
try:
    connection = socket.create_connection(('127.0.0.1', {listener.getsockname()[1]}), timeout=1)
except OSError:
    pass
else:
    connection.close()
    raise AssertionError('host network reached')
try:
    open({str(forbidden)!r}, 'w').write('shadow')
except OSError:
    pass
assert '_RAPTOR_TRUSTED' not in os.environ
print('RR_FS_NETWORK_OK')
'''
    commands = ('set confirm off\nset pagination off\nbreak main\ncontinue\n'
                'next\nnext\nreverse-next\nprintf "RR_REVERSE_MARKER=%d\\n", rr_marker\n'
                'python exec('+json.dumps(probe)+')\ncontinue\nquit\n')
    try:
        if interactive:
            from packages.binary_analysis import rr_replay as module
            command_file = tmp_path/'interactive-commands'
            command_file.write_text(commands)
            output_file = tmp_path/'interactive-output'
            with command_file.open() as stdin, output_file.open('w') as stdout:
                monkeypatch.setattr(module, 'sys', SimpleNamespace(
                    platform='linux', stdin=stdin, stdout=stdout, stderr=stdout))
                result = replay(trace, timeout=90)
            output = output_file.read_text()
        else:
            result = replay(trace, commands=commands.encode(), timeout=90)
            output = (result.stdout+result.stderr).decode(errors='replace')
    finally:
        listener.close()
    assert result.returncode == 0, output
    assert 'RR_REVERSE_MARKER=1' in output, output
    assert 'RR_FS_NETWORK_OK' in output, output
    assert result.sandbox_info['mount_ns_active'], result.sandbox_info
    assert result.sandbox_info['restrict_reads'], result.sandbox_info
    assert secret.read_text() == 'unchanged'
    assert not forbidden.exists(), 'host private directory modified'
