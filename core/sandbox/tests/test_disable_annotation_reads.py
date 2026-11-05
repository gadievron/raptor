"""Display annotations use the same hardened file boundary as telemetry."""
import json
import os

import pytest

from core.sandbox import summary
from core.testing.state_isolation import pin_user_state_dirs


PAYLOAD = json.dumps({
    'cli_sandbox_disabled': True, 'disable_consent': 'interactive-tty',
}).encode('utf-8')


@pytest.fixture(autouse=True)
def owned_state(tmp_path, monkeypatch):
    pin_user_state_dirs(monkeypatch, tmp_path / 'state')
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'xdg'))


@pytest.mark.parametrize('relative', [False, True], ids=['absolute', 'relative'])
def test_final_summary_symlink_is_refused(tmp_path, relative):
    run = tmp_path / 'run'
    run.mkdir()
    destination = tmp_path / 'other-summary.json'
    destination.write_bytes(PAYLOAD)
    path = run / summary.SUMMARY_FILE
    path.symlink_to('../other-summary.json' if relative else destination)
    assert summary.read_cli_disable_annotation(run) is None
    assert path.is_symlink()
    assert destination.read_bytes() == PAYLOAD


@pytest.mark.parametrize('prefix', [b'', b'\xef\xbb\xbf'], ids=['plain', 'bom'])
def test_regular_summary_keeps_annotation(tmp_path, prefix):
    (tmp_path / summary.SUMMARY_FILE).write_bytes(prefix + PAYLOAD + b'\r\n')
    assert summary.read_cli_disable_annotation(tmp_path) == 'interactive-tty'


def test_symlinked_run_directory_remains_supported(tmp_path):
    real = tmp_path / 'real'
    real.mkdir()
    (real / summary.SUMMARY_FILE).write_bytes(PAYLOAD)
    alias = tmp_path / 'alias'
    alias.symlink_to(real, target_is_directory=True)
    assert summary.read_cli_disable_annotation(alias) == 'interactive-tty'


@pytest.mark.parametrize('shape', [
    'missing', 'dangling', 'directory',
    pytest.param('fifo', marks=pytest.mark.skipif(
        not hasattr(os, 'mkfifo'), reason='requires FIFO support')),
])
def test_unreadable_shapes_have_no_annotation(tmp_path, shape):
    path = tmp_path / summary.SUMMARY_FILE
    if shape == 'dangling':
        path.symlink_to(tmp_path / 'missing')
    elif shape == 'directory':
        path.mkdir()
    elif shape == 'fifo':
        os.mkfifo(path, 0o600)
    assert summary.read_cli_disable_annotation(tmp_path) is None


@pytest.mark.parametrize('delta', [-1, 0, 1], ids=['over-limit', 'exact-limit', 'under-limit'])
def test_summary_byte_limit_is_preserved(tmp_path, monkeypatch, delta):
    (tmp_path / summary.SUMMARY_FILE).write_bytes(PAYLOAD)
    monkeypatch.setattr(summary, '_MARKER_MAX_BYTES', len(PAYLOAD) + delta)
    expected = None if delta < 0 else 'interactive-tty'
    assert summary.read_cli_disable_annotation(tmp_path) == expected


@pytest.mark.parametrize('data', [
    pytest.param(b'{bad json}', id='malformed'),
    pytest.param(b'[]', id='nonobject'),
    pytest.param(b'{"cli_sandbox_disabled":NaN}', id='nonfinite'),
    pytest.param(PAYLOAD.replace(b'interactive-tty', b'bad\xff'), id='invalid-utf8'),
    pytest.param(PAYLOAD.decode().encode('utf-16'), id='utf16'),
    pytest.param(b'\xef\xbb\xbf' * 2 + PAYLOAD, id='double-bom'),
])
def test_invalid_documents_remain_refused(tmp_path, data):
    (tmp_path / summary.SUMMARY_FILE).write_bytes(data)
    assert summary.read_cli_disable_annotation(tmp_path) is None
