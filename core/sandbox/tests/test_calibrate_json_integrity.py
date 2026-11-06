"""Calibration JSON preserves valid text and refuses ambiguous cache records."""
from dataclasses import asdict
import errno
import json
import os

import pytest

from core.sandbox import calibrate as cal, calibrate_cli as cli
from core.testing.state_isolation import pin_user_state_dirs


@pytest.fixture(autouse=True)
def owned_state(tmp_path):
    with pytest.MonkeyPatch.context() as monkeypatch:
        pin_user_state_dirs(monkeypatch, tmp_path / 'state')
        monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'xdg'))
        monkeypatch.setattr(cal, '_CACHE_DIR', tmp_path / 'cache')
        yield


@pytest.fixture
def monkeypatch(owned_state):
    """Undo body patches before restoring the file-owned state."""
    with pytest.MonkeyPatch.context() as patch:
        yield patch


@pytest.fixture
def profile(tmp_path):
    binary = tmp_path / 'owned-tool'
    binary.write_bytes(b'owned fixture; never executed')
    return cal.SandboxProfile(binary_path=str(binary), binary_sha256=cal._sha256_file(binary),
                              env_signature=cal._env_signature([]), captured_at='2026-06-01T00:00:00Z',
                              probe_args=['--version'])


def fingerprint(profile):
    return cal._fingerprint(profile.binary_sha256, profile.env_signature, profile.probe_args)


def ambiguous(profile, scenario):
    value = asdict(profile)
    if scenario in ('nested-port', 'nested-family'):
        value['connect_targets'] = [{'ip': '192.0.2.1', 'port': 443, 'family': 'AF_INET'}]
        raw = json.dumps(value)
        if scenario == 'nested-port':
            return raw.replace('"port": 443', '"port": 80, "port": 443')
        return raw.replace('"family": "AF_INET"', '"family": "AF_INET", "family": "AF_INET"')
    raw = json.dumps(value)
    prefix = {
        'identity': '"binary_path":"/earlier",',
        'equal': '"binary_path":' + json.dumps(value['binary_path']) + ',',
        'escaped': r'"binary_\u0070ath":"/earlier",',
        'argv': '"probe_args":["earlier"],',
    }[scenario]
    return '{' + prefix + raw[1:]


SCENARIOS = ['identity', 'equal', 'escaped', 'argv', 'nested-port', 'nested-family']


@pytest.mark.parametrize('scenario', SCENARIOS)
def test_direct_decoder_refuses_duplicate_members(profile, scenario):
    with pytest.raises(ValueError):
        cal.SandboxProfile.from_json(ambiguous(profile, scenario))


@pytest.mark.parametrize('scenario', SCENARIOS)
def test_cache_treats_ambiguous_profile_as_miss(profile, scenario):
    cal._CACHE_DIR.mkdir(mode=0o700)
    path = cal._cache_path_for(fingerprint(profile))
    raw = ambiguous(profile, scenario)
    path.write_text(raw)
    assert cal._load_matching_cache(profile.binary_sha256, profile.env_signature, profile.probe_args) is None
    assert path.read_text() == raw


def test_show_rejects_ambiguous_cache_without_probing(profile, capsys):
    cal._CACHE_DIR.mkdir(mode=0o700)
    cal._cache_path_for(fingerprint(profile)).write_text(ambiguous(profile, 'identity'))
    assert cli._cli_main(['--bin', profile.binary_path, '--show']) == 70
    assert 'no cached profile' in capsys.readouterr().err


@pytest.mark.parametrize('field', ['binary_path', 'probe_args', 'paths_read', 'paths_written', 'paths_stat'])
def test_surrogate_metadata_round_trips_through_utf8_cache(profile, field):
    value = '/owned/byte-\udcff'
    setattr(profile, field, value if field == 'binary_path' else [value])
    encoded = profile.to_json().encode('utf-8')
    assert cal.SandboxProfile.from_json(encoded.decode('utf-8')) == profile
    key = fingerprint(profile)
    cal._save_to_cache(key, profile)
    assert cal._load_from_cache(key) == profile
    assert cal._cache_path_for(key).stat().st_mode & 0o777 == 0o600
    assert not list(cal._CACHE_DIR.glob('.calibrate-tmp-*'))


@pytest.mark.skipif(not getattr(os, 'supports_bytes_environ', False), reason='requires POSIX byte filenames')
def test_show_json_round_trips_real_non_utf8_binary_filename(tmp_path, capsys):
    binary = tmp_path / os.fsdecode(b'owned-\xff')
    try:
        binary.write_bytes(b'owned fixture; never executed')
    except OSError as exc:
        if exc.errno in (errno.EILSEQ, errno.EINVAL):
            pytest.skip('temporary filesystem rejects non-UTF-8 filenames')
        raise
    profile = cal.SandboxProfile(binary_path=str(binary), binary_sha256=cal._sha256_file(binary),
                                 env_signature=cal._env_signature([]), captured_at='timestamp',
                                 probe_args=['--version'])
    cal._save_to_cache(fingerprint(profile), profile)
    assert cli._cli_main(['--bin', str(binary), '--show', '--json']) == 0
    value = json.loads(capsys.readouterr().out)
    assert os.fsencode(value['binary_path']) == os.fsencode(binary)


def test_existing_utf8_cache_and_unique_nested_objects_remain_supported(profile):
    profile.paths_read = ['/owned/caf\u00e9']
    profile.connect_targets = [cal.ConnectTarget('192.0.2.1', 443, 'AF_INET'),
                               cal.ConnectTarget('192.0.2.2', 443, 'AF_INET')]
    raw = json.dumps(asdict(profile), ensure_ascii=False)
    assert cal.SandboxProfile.from_json(raw) == profile
    cal._CACHE_DIR.mkdir(mode=0o700)
    cal._cache_path_for(fingerprint(profile)).write_bytes(raw.encode('utf-8'))
    assert cal._load_from_cache(fingerprint(profile)) == profile


def test_plain_profile_json_retains_field_values(profile):
    assert json.loads(profile.to_json()) == asdict(profile)
