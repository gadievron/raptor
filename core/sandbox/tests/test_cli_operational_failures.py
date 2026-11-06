"""Operational CLI failures retain bounded diagnostics and meaningful status."""
import errno
import subprocess

import pytest

from core.sandbox import calibrate, calibrate_cli, observe_cli
from core.testing.state_isolation import pin_user_state_dirs


@pytest.fixture(autouse=True)
def owned_state(tmp_path, monkeypatch):
    pin_user_state_dirs(monkeypatch, tmp_path / 'state')
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'data'))
    monkeypatch.setattr(calibrate, '_CACHE_DIR', tmp_path / 'cache')


def cli_case(cli, tmp_path, monkeypatch, failure, json_output):
    import core.sandbox as sandbox

    calls = []

    def unavailable(*args, **kwargs):
        calls.append((args, kwargs))
        raise failure

    if cli == 'observe':
        monkeypatch.setattr(sandbox, 'run', unavailable)
        module = observe_cli
        args = ['--out', str(tmp_path / 'run')]
        suffix = ['--', 'owned-tool']
    else:
        # Exercise the real cache, identity and probe dispatch; only execution
        # is replaced because this test owns the CLI exception boundary.
        binary = tmp_path / 'tool'
        binary.write_bytes(b'owned fixture; never executed')
        monkeypatch.setattr(sandbox, 'run', unavailable)
        module = calibrate_cli
        args = ['--bin', str(binary), '--force']
        suffix = []
    if json_output:
        args.append('--json')
    return module, args + suffix, calls


@pytest.mark.parametrize('json_output', [False, True], ids=['text', 'json'])
def test_calibration_timeout_is_a_cli_outcome(tmp_path, monkeypatch, capsys, json_output):
    failure = subprocess.TimeoutExpired(['private-argv-\x1b[31m'], 0.25,
                                        output=b'private output', stderr=b'private error')
    module, args, calls = cli_case('calibrate', tmp_path, monkeypatch, failure, json_output)
    assert module._cli_main(args + ['--timeout', '0.25']) == 124
    assert len(calls) == 1
    assert calls[0][1]['timeout'] == 0.25
    captured = capsys.readouterr()
    assert captured.out == ''
    assert '--timeout 0.25' in captured.err
    assert 'private' not in captured.err
    assert not list(tmp_path.rglob('*.json'))


@pytest.mark.parametrize('json_output', [False, True], ids=['text', 'json'])
@pytest.mark.parametrize('code', [errno.EACCES, errno.ENOEXEC, errno.EIO],
                         ids=['permission', 'format', 'io'])
@pytest.mark.parametrize('cli', ['observe', 'calibrate'])
def test_execution_os_errors_are_cli_outcomes(tmp_path, monkeypatch, capsys, json_output, code, cli):
    failure = OSError(code, 'owned-\x1b[31m\r\u202e', 'owned tool')
    module, args, calls = cli_case(cli, tmp_path, monkeypatch, failure, json_output)
    assert module._cli_main(args) == 70
    assert len(calls) == 1
    captured = capsys.readouterr()
    assert captured.out == ''
    assert 'owned-' in captured.err
    assert all(char not in captured.err for char in ('\x1b', '\r', '\u202e'))
    assert not list(tmp_path.rglob('*.json'))


@pytest.mark.parametrize('json_output', [False, True], ids=['text', 'json'])
@pytest.mark.parametrize('kind', ['file', 'parent-file'], ids=['existing-file', 'non-directory-parent'])
def test_observe_output_directory_failure_precedes_execution(tmp_path, monkeypatch, capsys, json_output, kind):
    import core.sandbox as sandbox

    obstruction = tmp_path / 'owned-\x1b[31m\r\u202e'
    obstruction.write_bytes(b'keep this owned file')
    run = obstruction if kind == 'file' else obstruction / 'run'
    def unexpected_execution(*args, **kwargs):
        pytest.fail('output preparation failure must stop before execution')
    monkeypatch.setattr(sandbox, 'run', unexpected_execution)
    args = ['--out', str(run)] + (['--json'] if json_output else []) + ['--', 'owned-tool']
    assert observe_cli._cli_main(args) == 70
    captured = capsys.readouterr()
    assert captured.out == ''
    assert 'cannot prepare observe directory' in captured.err
    assert 'owned-' in captured.err
    assert all(char not in captured.err for char in ('\x1b', '\r', '\u202e'))
    assert obstruction.read_bytes() == b'keep this owned file'
