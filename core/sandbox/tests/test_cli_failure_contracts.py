"""Operator CLIs reject invalid budgets and preserve failure distinctions."""
import json
import signal
import subprocess
from pathlib import Path

import pytest

from core.sandbox import calibrate, calibrate_cli, observe_cli
from core.sandbox.errors import (
    SANDBOX_ENGAGE_EXIT_CODE,
    SandboxDisableRefusedError,
    SandboxFloorError,
    SandboxSetupError,
)
from core.sandbox.tiers import ContainmentTier
from core.testing.state_isolation import pin_user_state_dirs


@pytest.fixture(autouse=True)
def owned_state(tmp_path):
    with pytest.MonkeyPatch.context() as monkeypatch:
        pin_user_state_dirs(monkeypatch, tmp_path / 'state')
        monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'data'))
        monkeypatch.setattr(calibrate, '_CACHE_DIR', tmp_path / 'cache')
        yield


@pytest.fixture
def monkeypatch(owned_state):
    """Undo body patches before restoring the file-owned state."""
    with pytest.MonkeyPatch.context() as patch:
        yield patch


@pytest.mark.parametrize('module', [observe_cli, calibrate_cli], ids=['observe', 'calibrate'])
@pytest.mark.parametrize('value', ['nan', 'NaN', 'inf', '-inf', '1e309', '0', '-1'],
                         ids=['nan', 'mixed-nan', 'infinity', 'negative-infinity', 'overflow', 'zero', 'negative'])
def test_invalid_timeout_is_an_argument_error(module, value, capsys):
    with pytest.raises(SystemExit) as error:
        module._build_parser().parse_args(['--timeout=' + value])
    assert error.value.code == 2
    assert '--timeout' in capsys.readouterr().err


@pytest.mark.parametrize('module', [observe_cli, calibrate_cli], ids=['observe', 'calibrate'])
@pytest.mark.parametrize('value', ['0.001', '1', '30', '1e3'],
                         ids=['fraction', 'one', 'default-value', 'exponent'])
def test_finite_positive_timeout_is_preserved(module, value):
    assert module._build_parser().parse_args(['--timeout=' + value]).timeout == float(value)


@pytest.mark.parametrize('return_code', [-signal.SIGTERM, -signal.SIGKILL, -signal.SIGINT,
                                       0, 1, 3, 42, 137, 255],
                         ids=['terminated', 'killed', 'interrupted', 'success', 'failure', 'engage-code-from-child', 'custom', 'encoded-signal', 'maximum'])
@pytest.mark.parametrize('json_output', [False, True], ids=['text', 'json'])
def test_observe_shell_status_preserves_raw_metadata(tmp_path, monkeypatch, capsys, return_code, json_output):
    import core.sandbox as sandbox

    run = tmp_path / 'run'

    def completed(cmd, **kwargs):
        directory = Path(kwargs['output']) / '.audit'
        directory.mkdir(mode=0o700)
        (directory / '.sandbox-observe.jsonl').write_text(json.dumps({
            'type': 'audit_summary', 'nonce': 'owned', 'dropped_by_category': {},
        }) + '\n')
        result = subprocess.CompletedProcess(cmd, return_code, stdout=b'', stderr=b'')
        result.sandbox_info = {'observe_nonce': 'owned', 'nonce_delivery': 'in_process'}
        return result

    monkeypatch.setattr(sandbox, 'run', completed)
    args = ['--out', str(run)] + (['--json'] if json_output else []) + ['--', 'owned-tool']
    status = observe_cli._cli_main(args)
    assert status == (128 - return_code if return_code < 0 else return_code)
    output = capsys.readouterr().out
    if json_output:
        payload = json.loads(output)
        assert payload['return_code'] == return_code
        assert payload['capture_incomplete'] is False
        assert payload['nonce_trusted'] is True
    else:
        assert f'command exit code: {return_code}' in output


def _failure(kind):
    message = 'owned setup failure\x1b[31m'
    instructions = 'repair the owned configuration'
    if kind == 'floor':
        return SandboxFloorError(message, instructions,
                                 achievable=ContainmentTier.BARE,
                                 floor=ContainmentTier.MOUNT_NS)
    if kind == 'disable':
        return SandboxDisableRefusedError(message, instructions)
    if kind == 'interrupt':
        return KeyboardInterrupt('owned interruption')
    return SandboxSetupError(message, instructions)


@pytest.mark.parametrize('cli', ['observe', 'calibrate'])
@pytest.mark.parametrize('kind', ['setup', 'floor', 'disable', 'interrupt', 'long-setup', 'long-disable'])
def test_cli_setup_failures_remain_distinct(tmp_path, monkeypatch, capsys, cli, kind):
    import core.sandbox as sandbox

    actual_kind = kind.removeprefix('long-')
    failure = _failure(actual_kind)
    if kind.startswith('long-'):
        failure.reason = 'owned setup failure' + 'x' * 1000
    calls = []

    def refused(*args, **kwargs):
        calls.append((args, kwargs))
        raise failure

    if cli == 'observe':
        monkeypatch.setattr(sandbox, 'run', refused)
        module = observe_cli
        args = ['--out', str(tmp_path / 'run'), '--json', '--', 'owned-tool']
    else:
        binary = tmp_path / 'tool'
        binary.write_text('owned file; never executed')
        monkeypatch.setattr(calibrate, 'load_or_calibrate', refused)
        module = calibrate_cli
        args = ['--bin', str(binary), '--force', '--json']

    if actual_kind == 'interrupt':
        with pytest.raises(KeyboardInterrupt) as error:
            module._cli_main(args)
        assert error.value is failure
    elif actual_kind == 'disable':
        with pytest.raises(SystemExit) as error:
            module._cli_main(args)
        assert error.value.code == 2
    else:
        assert module._cli_main(args) == SANDBOX_ENGAGE_EXIT_CODE
    assert len(calls) == 1
    captured = capsys.readouterr()
    assert captured.out == ''
    if actual_kind != 'interrupt':
        assert 'owned setup failure' in captured.err
        assert 'repair the owned configuration' in captured.err
        assert '\x1b' not in captured.err
    assert not list(tmp_path.rglob('sandbox-triage*.json'))


@pytest.mark.parametrize('module,examples', [
    pytest.param(observe_cli, (
        'raptor-sandbox-observe -- /usr/bin/true',
        'raptor-sandbox-observe --json --timeout 15 -- /usr/bin/true',
    ), id='observe'),
    pytest.param(calibrate_cli, (
        'raptor-sandbox-calibrate --bin /usr/bin/true --json --timeout 15',
        'raptor-sandbox-calibrate --bin /usr/bin/true --show',
    ), id='calibrate'),
])
def test_help_includes_usage_examples_and_timeout_domain(module, examples):
    help_text = module._build_parser().format_help()
    example_text = help_text.split('Examples:', 1)[1]
    assert all(example in example_text for example in examples)
    assert 'Positive finite wall-clock' in help_text
