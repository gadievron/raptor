"""Explicit output pipes preserve native capture and uncaptured stream ownership."""
import subprocess
import sys

import pytest

from core.sandbox import sandbox
from core.sandbox.tests.capability import requires_landlock, requires_mount, requires_userns


pytestmark = [pytest.mark.slow, pytest.mark.linux_native, requires_landlock,
              requires_mount, requires_userns,
              pytest.mark.skipif(sys.platform != 'linux', reason='Linux native output capture')]
COMMAND = ['/bin/sh', '-c', 'printf owned-out; printf owned-err >&2']


@pytest.mark.parametrize('text', [False, True], ids=['bytes', 'text'])
def test_explicit_stdout_pipe_merges_stderr(tmp_path, text):
    target, output = tmp_path / 'target', tmp_path / 'output'
    target.mkdir()
    output.mkdir()
    with sandbox(profile='strict', target=str(target), output=str(output)) as run:
        positive = run(COMMAND, capture_output=True, text=text, timeout=15)
        assert positive.returncode == 0
        assert positive.stdout == ('owned-out' if text else b'owned-out')
        assert positive.stderr == ('owned-err' if text else b'owned-err')
        assert positive.sandbox_info['mount_ns_active'] is True
        actual = run(COMMAND, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                     text=text, timeout=15)
    assert actual.returncode == 0
    assert actual.stdout == ('owned-outowned-err' if text else b'owned-outowned-err')
    assert actual.stderr is None
    assert actual.sandbox_info['mount_ns_active'] is True


@pytest.mark.parametrize('mode', ['stdout', 'stderr', 'both'])
@pytest.mark.parametrize('text', [False, True], ids=['bytes', 'text'])
def test_explicit_pipes_capture_only_requested_streams(tmp_path, capfd, mode, text):
    target, output = tmp_path / 'target', tmp_path / 'output'
    target.mkdir()
    output.mkdir()
    flags = {name: subprocess.PIPE for name in ('stdout', 'stderr')
             if mode in (name, 'both')}
    with sandbox(profile='strict', target=str(target), output=str(output)) as run:
        actual = run(COMMAND, text=text, timeout=15, **flags)
    inherited = capfd.readouterr()
    assert actual.returncode == 0 and actual.sandbox_info['mount_ns_active'] is True
    for name, marker in (('stdout', 'owned-out'), ('stderr', 'owned-err')):
        value = getattr(actual, name)
        if name in flags:
            assert value == (marker if text else marker.encode())
        else:
            assert value is None
            assert marker in (inherited.out if name == 'stdout' else inherited.err)


@pytest.mark.parametrize('redirect', ['stdout', 'stderr'])
def test_uncaptured_file_stream_remains_borrowed(tmp_path, redirect):
    target, output = tmp_path / 'target', tmp_path / 'output'
    target.mkdir()
    output.mkdir()
    path = output / 'redirected'
    captured = 'stderr' if redirect == 'stdout' else 'stdout'
    with path.open('wb') as stream:
        with sandbox(profile='strict', target=str(target), output=str(output)) as run:
            actual = run(COMMAND, timeout=15, **{redirect: stream, captured: subprocess.PIPE})
        assert not stream.closed
    assert actual.returncode == 0 and actual.sandbox_info['mount_ns_active'] is True
    assert getattr(actual, redirect) is None
    assert getattr(actual, captured) == (b'owned-err' if captured == 'stderr' else b'owned-out')
    assert path.read_bytes() == (b'owned-out' if redirect == 'stdout' else b'owned-err')


def test_explicit_pipe_timeout_reports_only_captured_stream(tmp_path):
    target, output = tmp_path / 'target', tmp_path / 'output'
    target.mkdir()
    output.mkdir()
    with sandbox(profile='strict', target=str(target), output=str(output)) as run:
        positive = run(['/bin/sh', '-c', 'printf ready'], capture_output=True, timeout=15)
        assert positive.stdout == b'ready' and positive.sandbox_info['mount_ns_active'] is True
        with pytest.raises(subprocess.TimeoutExpired) as caught:
            run(['/bin/sh', '-c', 'printf timeout-out; exec /bin/sleep 30'],
                stdout=subprocess.PIPE, timeout=1)
    assert caught.value.output == b'timeout-out'
    assert caught.value.stderr is None
