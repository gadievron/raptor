"""Calibration input diagnostics stop early and retain full cache identity."""

import json
from pathlib import Path
from uuid import uuid4

import pytest

from core.sandbox import calibrate as cal, calibrate_cli as cli
from core.testing.state_isolation import pin_user_state_dirs


CONTROL = 'owned-\x1b[31m\r\n\x85\u202e'
MODES = [[], ['--show'], ['--clear'], ['--force']]


@pytest.fixture
def owned(tmp_path, monkeypatch):
    pin_user_state_dirs(monkeypatch, tmp_path / 'state')
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'data'))
    cache = tmp_path / 'cache'
    cache.mkdir()
    monkeypatch.setattr(cal, '_CACHE_DIR', cache)
    home = tmp_path / 'home'
    home.mkdir()
    monkeypatch.setenv('HOME', str(home))
    tool = home / 'owned-tool'
    tool.write_bytes(b'owned binary identity; never executed')
    return tool, cache


def no_execution(monkeypatch, *, all_work=False):
    calls = []

    def unexpected(*args, **kwargs):
        calls.append(True)
        raise AssertionError('input/cache-only commands must stop before execution')

    monkeypatch.setattr(cal, 'load_or_calibrate', unexpected)
    if all_work:
        monkeypatch.setattr(cal, '_sha256_file', unexpected)
        monkeypatch.setattr(cal, 'clear_cache', unexpected)
    return calls


def assert_expansion_error(capsys, calls):
    captured = capsys.readouterr()
    assert captured.out == ''
    assert 'cannot expand binary path' in captured.err
    assert all(c.isprintable() or c == '\n' for c in captured.err)
    assert len(captured.err) < 800
    assert 'Traceback' not in captured.err
    assert calls == []


@pytest.mark.parametrize('flags', MODES, ids=['default', 'show', 'clear', 'force'])
@pytest.mark.parametrize('json_output', [False, True], ids=['text', 'json'])
@pytest.mark.parametrize('layout', ['control', 'long'])
def test_native_unknown_user_has_usage_status(owned, monkeypatch, capsys, flags, json_output, layout):
    tool, cache = owned
    target = '~raptor-owned-missing-' + uuid4().hex + '/' + CONTROL
    if layout == 'long':
        target += '/' + 'a' * 100 + '/' + 'b' * 100
    # Establish the native precondition without changing pwd or pathlib.
    with pytest.raises(RuntimeError):
        Path(target).expanduser()
    calls = no_execution(monkeypatch, all_work=True)
    args = ['--bin', target, *flags] + (['--json'] if json_output else [])
    assert cli._cli_main(args) == 64
    assert list(cache.iterdir()) == []
    assert tool.read_bytes() == b'owned binary identity; never executed'
    assert_expansion_error(capsys, calls)


@pytest.mark.parametrize('flags', MODES, ids=['default', 'show', 'clear', 'force'])
@pytest.mark.parametrize('json_output', [False, True], ids=['text', 'json'])
def test_expansion_failure_bounds_exception_metadata(owned, monkeypatch, capsys, flags, json_output):
    tool, cache = owned
    error = RuntimeError(CONTROL + 'x' * 2000)

    class UnavailableHome(type(tool)):
        def expanduser(self):
            raise error

    monkeypatch.setattr(cli, 'Path', UnavailableHome)
    calls = no_execution(monkeypatch, all_work=True)
    args = ['--bin', str(tool), *flags] + (['--json'] if json_output else [])
    assert cli._cli_main(args) == 64
    assert list(cache.iterdir()) == []
    assert_expansion_error(capsys, calls)


@pytest.mark.parametrize('flags', MODES, ids=['default', 'show', 'clear', 'force'])
@pytest.mark.parametrize('error_type', [KeyboardInterrupt, SystemExit, GeneratorExit])
def test_expansion_cancellation_propagates(owned, monkeypatch, flags, error_type):
    tool, cache = owned
    error = error_type('owned cancellation')

    class CancelledHome(type(tool)):
        def expanduser(self):
            raise error

    monkeypatch.setattr(cli, 'Path', CancelledHome)
    calls = no_execution(monkeypatch, all_work=True)
    with pytest.raises(error_type) as caught:
        cli._cli_main(['--bin', str(tool), *flags])
    assert caught.value is error
    assert calls == []
    assert list(cache.iterdir()) == []


def keys_for(shape):
    if shape == 'empty':
        return []
    if shape == 'short':
        return ['OWNED_CACHE_ONE', 'OWNED_CACHE_TWO']
    if shape == 'one-long':
        return ['OWNED_CACHE_' + 'a' * 2000]
    if shape == 'many-long':
        return ['OWNED_CACHE_' + str(i) + '_' + 'b' * 100 for i in range(30)]
    return ['OWNED_CACHE_' + 'c' * 2000 + '_tail_a']


def seed(tool, keys, *, marker='owned-time'):
    binary_hash, env_sig = cal._sha256_file(tool), cal._env_signature(keys)
    fingerprint = cal._fingerprint(binary_hash, env_sig)
    profile = cal.SandboxProfile(str(tool), binary_hash, env_sig, marker, probe_args=['--version'])
    cal._save_to_cache(fingerprint, profile)
    return cal._cache_path_for(fingerprint), profile


@pytest.mark.parametrize('json_output', [False, True], ids=['text', 'json'])
@pytest.mark.parametrize('shape', ['one-long', 'many-long', 'different-tail'])
def test_miss_bounds_key_excerpt_and_preserves_full_lookup(owned, monkeypatch, capsys, json_output, shape):
    tool, cache = owned
    keys = keys_for(shape)
    for key in keys:
        monkeypatch.delenv(key, raising=False)
    if shape == 'different-tail':
        old_keys = [keys[0][:-1] + 'b']
    else:
        old_keys = ['OWNED_OTHER_CACHE_KEY']
    for key in old_keys:
        monkeypatch.delenv(key, raising=False)
    saved, profile = seed(tool, old_keys)
    before = saved.read_bytes()
    expected_signature = cal._env_signature(keys)
    assert expected_signature != profile.env_signature
    original = cal._load_matching_cache
    lookups = []

    def capture(binary_hash, env_sig, probe_args):
        lookups.append((binary_hash, env_sig, tuple(probe_args)))
        return original(binary_hash, env_sig, probe_args)

    monkeypatch.setattr(cal, '_load_matching_cache', capture)
    calls = no_execution(monkeypatch)
    args = ['--bin', str(tool), '--show'] + (['--json'] if json_output else [])
    args += [arg for key in keys for arg in ['--env-key', key]]
    assert cli._cli_main(args) == 70
    assert lookups == [(profile.binary_sha256, expected_signature, ('--version',))]
    assert saved.read_bytes() == before
    assert list(cache.iterdir()) == [saved]
    assert calls == []
    captured = capsys.readouterr()
    assert captured.out == ''
    assert 'no cached profile' in captured.err
    assert '(env keys:' in captured.err
    assert 'Run without --show to create one.' in captured.err
    assert all(c.isprintable() or c == '\n' for c in captured.err)
    assert len(captured.err) < 800
    assert '...[+' in captured.err


@pytest.mark.parametrize('json_output', [False, True], ids=['text', 'json'])
@pytest.mark.parametrize('shape', ['empty', 'short'])
def test_ordinary_miss_message_stays_exact(owned, monkeypatch, capsys, json_output, shape):
    tool, cache = owned
    keys = keys_for(shape)
    for key in keys:
        monkeypatch.delenv(key, raising=False)
    calls = no_execution(monkeypatch)
    args = ['--bin', str(tool), '--show'] + (['--json'] if json_output else [])
    args += [arg for key in keys for arg in ['--env-key', key]]
    assert cli._cli_main(args) == 70
    captured = capsys.readouterr()
    assert captured.out == ''
    assert captured.err == (f'raptor-sandbox-calibrate: no cached profile for {tool} '
                            f"(env keys: {keys or '(none)'}). Run without --show to create one.\n")
    assert list(cache.iterdir()) == []
    assert calls == []


@pytest.mark.parametrize('json_output', [False, True], ids=['text', 'json'])
@pytest.mark.parametrize('shape', ['one-long', 'many-long', 'different-tail'])
def test_long_key_cache_hit_keeps_native_identity(owned, monkeypatch, capsys, json_output, shape):
    tool, cache = owned
    keys = keys_for(shape)
    for key in keys:
        monkeypatch.delenv(key, raising=False)
    saved, profile = seed(tool, keys)
    before = saved.read_bytes()
    calls = no_execution(monkeypatch)
    args = ['--bin', str(tool), '--show'] + (['--json'] if json_output else [])
    args += [arg for key in keys for arg in ['--env-key', key]]
    assert cli._cli_main(args) == 0
    captured = capsys.readouterr()
    assert captured.err == ''
    if json_output:
        assert json.loads(captured.out) == json.loads(profile.to_json())
    else:
        assert 'source:        cache' in captured.out
    assert saved.read_bytes() == before
    assert list(cache.iterdir()) == [saved]
    assert calls == []


@pytest.mark.parametrize('mode', ['--show', '--clear'])
@pytest.mark.parametrize('json_output', [False, True], ids=['text', 'json'])
def test_owned_home_expansion_keeps_cache_only_behavior(owned, monkeypatch, capsys, mode, json_output):
    tool, cache = owned
    saved, profile = seed(tool, ())
    before = saved.read_bytes()
    calls = no_execution(monkeypatch)
    args = ['--bin', '~/owned-tool', mode] + (['--json'] if json_output else [])
    assert cli._cli_main(args) == 0
    captured = capsys.readouterr()
    assert captured.err == ''
    assert tool.read_bytes() == b'owned binary identity; never executed'
    assert calls == []
    if mode == '--clear':
        assert 'cleared 1 profile(s)' in captured.out
        assert list(cache.iterdir()) == []
    else:
        assert saved.read_bytes() == before
        assert list(cache.iterdir()) == [saved]
        if json_output:
            assert json.loads(captured.out) == json.loads(profile.to_json())
        else:
            assert 'source:        cache' in captured.out
