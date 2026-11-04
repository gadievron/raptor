"""Live audit decoding matches the warm-up reader and survives damaged bytes."""
import io
import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from core.sandbox import seatbelt_audit as audit


def log_line(path):
    return (json.dumps({'senderImagePath': audit.SANDBOX_KEXT_SENDER,
                        'eventMessage': f'Sandbox: tool(123) deny(1) file-read-data {path}'},
                       ensure_ascii=False) + '\n').encode('utf-8')


@pytest.mark.parametrize('data,paths', [
    (log_line('/tmp/first') + b'\xff\n' + log_line('/tmp/last'),
     ['/tmp/first', '/tmp/last']),
    (log_line('/tmp/PLACEHOLDER').replace(b'PLACEHOLDER', b'\xff') + log_line('/tmp/last'),
     ['/tmp/\ufffd', '/tmp/last']),
    (log_line('/tmp/caf\u00e9'), ['/tmp/caf\u00e9']),
])
def test_live_capture_uses_utf8_and_continues(tmp_path, monkeypatch, caplog, data, paths):
    owner = audit.LogStreamer(tmp_path)
    captured = []
    settings = {}

    def popen(*args, **kwargs):
        settings.update(kwargs)
        stream = io.TextIOWrapper(io.BytesIO(data),
                                  encoding=kwargs.get('encoding'),
                                  errors=kwargs.get('errors'))
        return SimpleNamespace(stdout=stream)

    monkeypatch.setattr(audit.subprocess, 'Popen', popen)
    monkeypatch.setattr(owner, '_warm_up_until_attached', lambda: True)
    monkeypatch.setattr(owner, '_filter_and_append', captured.append)
    with monkeypatch.context() as scoped:
        scoped.setattr(audit.threading, 'Thread', Mock())
        owner.start()
    assert settings['encoding'] == 'utf-8'
    assert settings['errors'] == 'replace'
    owner._read_loop()
    assert [record['path'] for record in captured] == paths
    assert owner._proc.stdout.closed
    assert 'reader thread crashed' not in caplog.text
