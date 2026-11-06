"""Human CLI metadata uses the same terminal boundary as observed payloads."""
import errno
import json
import os

import pytest

from core.sandbox import calibrate as cal, calibrate_cli as calibration
from core.sandbox import evidence, observe_cli as observation, observe_profile, summary, triage
from core.sandbox.tests.test_triage_deep import _FakeClient
from core.testing.state_isolation import pin_user_state_dirs


pytestmark = pytest.mark.skipif(os.name != 'posix', reason='requires POSIX control-character filenames')


CONTROL = 'owned-\x1b[31m\r\x85\u202e'


def assert_safe(text):
    for value in ('\x1b', '\r', '\x85', '\u202e'):
        assert value not in text
    assert 'owned-' in text


@pytest.fixture(autouse=True)
def owned_state(tmp_path):
    with pytest.MonkeyPatch.context() as monkeypatch:
        pin_user_state_dirs(monkeypatch, tmp_path / 'state')
        monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'xdg'))
        monkeypatch.setattr(cal, '_CACHE_DIR', tmp_path / 'profiles')
        yield


@pytest.fixture
def monkeypatch(owned_state):
    """Undo body patches before restoring the file-owned state."""
    with pytest.MonkeyPatch.context() as patch:
        yield patch


@pytest.fixture
def binary(tmp_path):
    path = tmp_path / CONTROL
    path.write_bytes(b'owned binary fixture; never executed')
    return path


def profile_for(binary):
    return cal.SandboxProfile(binary_path=str(binary), binary_sha256=cal._sha256_file(binary),
                              env_signature=cal._env_signature([]), captured_at='2026-06-01T00:00:00Z',
                              probe_args=['--version'])


@pytest.mark.parametrize('field', ['binary_sha256', 'env_signature', 'captured_at'])
def test_calibration_formatter_escapes_remaining_metadata(binary, field):
    profile = profile_for(binary)
    setattr(profile, field, CONTROL)
    decoded = cal.SandboxProfile.from_json(profile.to_json())
    assert_safe(calibration._format_human(decoded, cached=True))


def test_calibration_cache_hit_escapes_timestamp_and_preserves_json(binary, capsys):
    profile = profile_for(binary)
    profile.captured_at = CONTROL
    cal._save_to_cache(cal._fingerprint(profile.binary_sha256, profile.env_signature, profile.probe_args), profile)
    assert calibration._cli_main(['--bin', str(binary), '--show']) == 0
    assert_safe(capsys.readouterr().out)
    assert calibration._cli_main(['--bin', str(binary), '--show', '--json']) == 0
    value = json.loads(capsys.readouterr().out)
    assert value['captured_at'] == CONTROL
    assert value['binary_path'] == str(binary)


@pytest.mark.parametrize('branch,expected', [('missing', 64), ('cache-miss', 70), ('clear', 0),
                                             ('clear-error', 70), ('hash-error', 70),
                                             ('probe-missing', 64), ('probe-error', 70)],
                         ids=['missing', 'cache-miss', 'clear', 'clear-error', 'hash-error',
                              'probe-missing', 'probe-error'])
def test_calibration_cli_metadata_errors_and_successes_are_escaped(binary, monkeypatch, capsys, branch, expected):
    args = ['--bin', str(binary)]

    def fail_io(*args, **kwargs):
        raise OSError(errno.EIO, CONTROL)

    def fail_missing(*args, **kwargs):
        raise FileNotFoundError(CONTROL)

    if branch == 'missing':
        args = ['--bin', str(binary.with_name(CONTROL + '-missing'))]
    elif branch in ('cache-miss', 'hash-error'):
        args.append('--show')
        if branch == 'hash-error':
            monkeypatch.setattr(cal, '_sha256_file', fail_io)
    elif branch.startswith('clear'):
        args.append('--clear')
        if branch == 'clear-error':
            monkeypatch.setattr(cal, 'clear_cache', fail_io)
    else:
        monkeypatch.setattr(cal, 'load_or_calibrate', fail_missing if branch == 'probe-missing' else fail_io)
    assert calibration._cli_main(args) == expected
    captured = capsys.readouterr()
    assert_safe(captured.out + captured.err)


def test_observation_summary_escapes_kept_directory_and_preserves_json(binary):
    profile = observe_profile.ObserveProfile()
    rendered = observation._format_summary(profile, run_dir=binary.parent / CONTROL,
                                           kept=True, return_code=0)
    assert_safe(rendered)
    value = json.loads(observation._profile_to_json(profile, run_dir=binary.parent / CONTROL,
                                                   kept=True, return_code=0))
    assert value['run_dir'] == str(binary.parent / CONTROL)


def test_observation_spawn_error_escapes_exception_metadata(tmp_path, monkeypatch, capsys):
    import core.sandbox as sandbox

    def unavailable(*args, **kwargs):
        raise FileNotFoundError(CONTROL)
    monkeypatch.setattr(sandbox, 'run', unavailable)
    assert observation._cli_main(['--out', str(tmp_path / 'run'), '--', 'owned-unused']) == 64
    assert_safe(capsys.readouterr().err)


def signed_summary(run):
    path = evidence.evidence_write_path(run, summary.DENIALS_FILE)
    path.parent.mkdir(mode=0o700, parents=True)
    path.write_text(json.dumps({'type': 'seccomp', 'syscall': 'ptrace', 'profile': 'full'}) + '\n')
    result = summary.summarize_and_write(run)
    assert result['mac']


@pytest.mark.parametrize('branch,expected', [('missing', 1), ('empty', 0), ('report', 4)],
                         ids=['missing', 'empty', 'report'])
def test_triage_cli_escapes_directory_metadata(tmp_path, capsys, branch, expected):
    run = tmp_path / CONTROL
    if branch != 'missing':
        run.mkdir(mode=0o700)
    if branch == 'report':
        signed_summary(run)
    assert triage._cli_main([str(run)]) == expected
    captured = capsys.readouterr()
    assert_safe(captured.out + captured.err)


def test_triage_deep_header_escapes_model_identifier(tmp_path, monkeypatch, capsys):
    from core.llm import factory
    run = tmp_path / 'run'
    signed_summary(run)
    client = _FakeClient('{"assessments":[],"overall_note":"owned note"}')
    client.model_name = CONTROL
    monkeypatch.setattr(factory, 'get_client', lambda: client)
    assert triage._cli_main([str(run), '--deep']) == 4
    out = capsys.readouterr().out
    assert 'Deep assessment' in out
    assert_safe(out)
    assert len(client.calls) == 1


def test_calibration_plain_metadata_keeps_existing_display(binary):
    profile = profile_for(binary)
    text = calibration._format_human(profile, cached=True)
    assert '  captured at:   2026-06-01T00:00:00Z' in text
    assert f'  sha256:        {profile.binary_sha256[:16]}\u2026' in text


def test_triage_json_preserves_original_directory(tmp_path, capsys):
    run = tmp_path / CONTROL
    signed_summary(run)
    assert triage._cli_main([str(run), '--json']) == 4
    value = json.loads(capsys.readouterr().out)
    assert value['run_dir'] == str(run)
