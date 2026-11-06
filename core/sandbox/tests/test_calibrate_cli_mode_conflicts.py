"""Conflicting calibration modes must fail before reading or clearing the cache."""
import itertools

import pytest

from core.sandbox import calibrate as cal, calibrate_cli as cli
from core.testing.state_isolation import pin_user_state_dirs


MODES = ['--show', '--force', '--clear', '--clear-all']
CONFLICTS = list(itertools.permutations(MODES, 2))


@pytest.fixture(autouse=True)
def owned_state(tmp_path, monkeypatch):
    pin_user_state_dirs(monkeypatch, tmp_path / 'state')
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'data'))
    monkeypatch.setattr(cal, '_CACHE_DIR', tmp_path / 'profiles')


@pytest.fixture
def cache(tmp_path):
    binaries = []
    for name in ['one', 'two']:
        binary = tmp_path / name
        binary.write_bytes(('owned fixture ' + name).encode())
        binary_hash = cal._sha256_file(binary)
        environment = cal._env_signature([])
        profile = cal.SandboxProfile(binary_path=str(binary), binary_sha256=binary_hash,
                                     env_signature=environment,
                                     captured_at='2026-01-01T00:00:00Z',
                                     probe_args=['--version'], paths_read=['/tmp/owned-input'])
        cal._save_to_cache(cal._fingerprint(binary_hash, environment, profile.probe_args), profile)
        binaries.append(binary)
    snapshots = {path.name: path.read_bytes() for path in cal.cache_dir().iterdir()}
    assert len(snapshots) == 2
    return binaries, snapshots


@pytest.mark.parametrize('flags', CONFLICTS,
                         ids=['-then-'.join(flag.removeprefix('--') for flag in pair) for pair in CONFLICTS])
def test_conflicting_modes_are_usage_errors_without_cache_changes(cache, capsys, flags):
    binaries, snapshots = cache
    with pytest.raises(SystemExit) as caught:
        cli._cli_main(['--bin', str(binaries[0]), *flags, '--json'])
    assert caught.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ''
    assert 'not allowed with argument' in captured.err
    assert all(flag in captured.err for flag in flags)
    assert {path.name: path.read_bytes() for path in cal.cache_dir().iterdir()} == snapshots
    assert all(binary.read_bytes().startswith(b'owned fixture ') for binary in binaries)


@pytest.mark.parametrize('mode', [None, *MODES], ids=['default', 'show', 'force', 'clear', 'clear-all'])
@pytest.mark.parametrize('json_output', [False, True], ids=['text', 'json'])
def test_single_modes_keep_normal_option_composition(mode, json_output):
    args = ['--bin', '/owned/tool', '--timeout', '1.5', '--env-key', 'OWNED_ONE',
            '--env-key', 'OWNED_TWO', '--probe-args=--version']
    args += [mode] if mode else []
    if json_output:
        args.append('--json')
    parsed = cli._build_parser().parse_args(args)
    for candidate in MODES:
        assert getattr(parsed, candidate.removeprefix('--').replace('-', '_')) is (candidate == mode)
    assert parsed.timeout == 1.5
    assert parsed.env_keys == ['OWNED_ONE', 'OWNED_TWO']
    assert parsed.probe_args == '--version'
    assert parsed.json_output is json_output
