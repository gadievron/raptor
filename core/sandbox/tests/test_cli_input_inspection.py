"""CLI metadata checks report inaccessible inputs before performing any work."""

import errno
import json

import pytest

from core.sandbox import calibrate as cal, calibrate_cli, summary, triage
from core.testing.sandbox_state_scope import isolated_sandbox_state
from core.testing.state_isolation import pin_user_state_dirs


MODES = [
    (summary, [], 1),
    (summary, ['--sweep'], 1),
    (triage, [], 1),
    (triage, ['--json'], 1),
    (triage, ['--deep'], 1),
    (triage, ['--json', '--deep'], 1),
    (calibrate_cli, ['--show'], 70),
    (calibrate_cli, ['--clear'], 70),
]
IDS = ['summary', 'sweep', 'triage', 'triage-json', 'triage-deep',
       'triage-json-deep', 'cache-show', 'cache-clear']
CONTROL = 'owned-\x1b[31m\r\n\x85\u202e'


@pytest.fixture
def owned(tmp_path):
    with isolated_sandbox_state(()), pytest.MonkeyPatch.context() as patch:
        pin_user_state_dirs(patch, tmp_path / 'state')
        patch.setenv('XDG_DATA_HOME', str(tmp_path / 'data'))
        cache = tmp_path / 'cache'
        cache.mkdir()
        patch.setattr(cal, '_CACHE_DIR', cache)
        yield tmp_path


@pytest.fixture
def monkeypatch(owned):
    with pytest.MonkeyPatch.context() as patch:
        yield patch


def arguments(module, flags, path):
    return ['--bin', str(path), *flags] if module is calibrate_cli else [*flags, str(path)]


def refuse_later_work(monkeypatch):
    calls = []

    def unexpected(*args, **kwargs):
        calls.append(True)
        raise AssertionError('input inspection must stop before downstream work')

    monkeypatch.setattr(summary, 'summarize_and_write', unexpected)
    monkeypatch.setattr(triage, 'triage_run', unexpected)
    monkeypatch.setattr(cal, 'clear_cache', unexpected)
    monkeypatch.setattr(cal, '_sha256_file', unexpected)
    monkeypatch.setattr(cal, 'load_or_calibrate', unexpected)
    return calls


def fail_inspection(monkeypatch, module, target, error):
    """Model pre-3.14 pathlib errors on the consumer's native Path subclass."""
    calls = []

    class InputPath(type(target)):
        def is_dir(self):
            if module is not calibrate_cli and self == target:
                calls.append(self)
                raise error
            return super().is_dir()

        def exists(self, **kwargs):
            if module is calibrate_cli and self == target:
                calls.append(self)
                raise error
            return super().exists(**kwargs)

    monkeypatch.setattr(module, 'Path', InputPath)
    return calls


@pytest.mark.parametrize('module,flags,status', MODES, ids=IDS)
@pytest.mark.parametrize('error_number', [errno.EACCES, errno.EIO, errno.ENAMETOOLONG])
@pytest.mark.parametrize('layout', ['control', 'long'])
def test_inspection_error_is_bounded_and_stops_work(owned, monkeypatch, capsys,
                                                   module, flags, status, error_number, layout):
    target = owned / CONTROL
    if layout == 'long':
        target = target / ('a' * 100) / ('b' * 100)
    target.mkdir(parents=True)
    sentinel = target / 'owned-sentinel'
    sentinel.write_bytes(b'preserve existing input')
    calls = refuse_later_work(monkeypatch)
    error = OSError(error_number, CONTROL + 'x' * 1000, str(target))
    inspected = fail_inspection(monkeypatch, module, target, error)
    assert module._cli_main(arguments(module, flags, target)) == status
    captured = capsys.readouterr()
    assert captured.out == ''
    assert 'cannot inspect' in captured.err
    assert all(c.isprintable() or c == '\n' for c in captured.err)
    assert len(captured.err) < 900
    assert 'Traceback' not in captured.err
    assert len(inspected) == 1
    assert calls == []
    assert sentinel.read_bytes() == b'preserve existing input'
    assert list(target.iterdir()) == [sentinel]


@pytest.mark.parametrize('module,flags,status', MODES, ids=IDS)
@pytest.mark.parametrize('error_type', [KeyboardInterrupt, SystemExit, GeneratorExit])
def test_inspection_cancellation_propagates(owned, monkeypatch, module, flags, status, error_type):
    target = owned / 'cancelled'
    error = error_type('owned cancellation')
    calls = refuse_later_work(monkeypatch)
    inspected = fail_inspection(monkeypatch, module, target, error)
    with pytest.raises(error_type) as caught:
        module._cli_main(arguments(module, flags, target))
    assert caught.value is error
    assert len(inspected) == 1
    assert calls == []
    assert not target.exists()


@pytest.mark.parametrize('module,flags,status', MODES, ids=IDS)
def test_missing_input_keeps_existing_status_and_message(owned, monkeypatch, capsys, module, flags, status):
    target = owned / 'missing'
    calls = refuse_later_work(monkeypatch)
    expected = 64 if module is calibrate_cli else 1
    assert module._cli_main(arguments(module, flags, target)) == expected
    captured = capsys.readouterr()
    assert captured.out == ''
    assert ('not found' if module is calibrate_cli else 'is not a directory') in captured.err
    assert 'cannot inspect' not in captured.err
    assert calls == []


@pytest.mark.parametrize('module,flags,status', MODES[:6], ids=IDS[:6])
def test_regular_file_is_still_not_a_run_directory(owned, monkeypatch, capsys, module, flags, status):
    target = owned / 'plain-file'
    target.write_bytes(b'preserve')
    calls = refuse_later_work(monkeypatch)
    assert module._cli_main(arguments(module, flags, target)) == 1
    captured = capsys.readouterr()
    assert captured.out == ''
    assert 'is not a directory' in captured.err
    assert calls == []
    assert target.read_bytes() == b'preserve'


@pytest.mark.parametrize('module,flags,status', MODES[:6], ids=IDS[:6])
def test_empty_run_directory_keeps_existing_success(owned, capsys, module, flags, status):
    target = owned / 'empty-run'
    target.mkdir()
    assert module._cli_main(arguments(module, flags, target)) == 0
    captured = capsys.readouterr()
    assert captured.err == ''
    if module is triage and '--json' in flags:
        assert json.loads(captured.out) is None
    else:
        assert 'no denials recorded' in captured.out or 'Swept 0' in captured.out or 'no sandbox telemetry' in captured.out
    assert list(target.iterdir()) == []


@pytest.mark.parametrize('mode', ['--show', '--clear'])
def test_healthy_cache_only_modes_do_not_execute_binary(owned, monkeypatch, capsys, mode):
    tool = owned / 'tool'
    tool.write_bytes(b'owned identity; never executed')
    binary_hash, env_sig = cal._sha256_file(tool), cal._env_signature(())
    fingerprint = cal._fingerprint(binary_hash, env_sig)
    profile = cal.SandboxProfile(str(tool), binary_hash, env_sig, 'owned-time', probe_args=['--version'])
    cal._save_to_cache(fingerprint, profile)
    calls = []

    def unexpected(*args, **kwargs):
        calls.append(True)
        raise AssertionError('cache-only modes must not execute a binary')

    monkeypatch.setattr(cal, 'load_or_calibrate', unexpected)
    assert calibrate_cli._cli_main(['--bin', str(tool), mode, '--json']) == 0
    captured = capsys.readouterr()
    assert captured.err == ''
    if mode == '--show':
        assert json.loads(captured.out)['binary_sha256'] == binary_hash
        assert cal._cache_path_for(fingerprint).exists()
    else:
        assert 'cleared 1 profile(s)' in captured.out
        assert not cal._cache_path_for(fingerprint).exists()
    assert calls == []
    assert tool.read_bytes() == b'owned identity; never executed'
