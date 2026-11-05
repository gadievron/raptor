"""An unreadable count sidecar cannot attest an empty event stream."""
import json
import os

import pytest

from core.sandbox import triage
from core.testing.state_isolation import pin_user_state_dirs


@pytest.fixture(autouse=True)
def owned_state(tmp_path, monkeypatch):
    pin_user_state_dirs(monkeypatch, tmp_path / 'state')
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'xdg'))
    monkeypatch.setattr(triage, '_MAX_INPUT_BYTES', 256)


@pytest.mark.parametrize('allow_legacy', [False, True], ids=['strict', 'legacy'])
@pytest.mark.parametrize('shape', ['garbage', 'array', 'null', 'number', 'text',
                                 'oversized', 'symlink', 'fifo'])
def test_unreadable_sidecar_stays_visible(tmp_path, allow_legacy, shape):
    run = tmp_path / 'run'
    run.mkdir()
    path = run / triage.PROXY_EVENTS_COUNT_FILENAME
    if shape == 'symlink':
        path.symlink_to(run / 'missing')
    elif shape == 'fifo':
        if not hasattr(os, 'mkfifo'):
            pytest.skip('requires FIFO support')
        os.mkfifo(path, 0o600)
    else:
        data = {'garbage': b'{bad', 'array': b'[]', 'null': b'null',
                'number': b'7', 'text': b'"record"', 'oversized': b'x' * 257}[shape]
        path.write_bytes(data)
    report = triage.triage_run(run, allow_legacy=allow_legacy)
    if allow_legacy:
        assert report is None
    else:
        assert report is not None
        assert report['inputs']['integrity']['proxy_events'] == triage._INTEGRITY_TAMPERED
        assert report['inputs']['total_proxy_events'] == 0
        assert 'count sidecar' in json.dumps(report)
        assert 'unreadable' in json.dumps(report)
        assert (run / triage.TRIAGE_FILE).exists()
