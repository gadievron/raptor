"""Refused appends preserve verified sidecar anchors and flags."""
import json
import os
import stat
import threading
from types import SimpleNamespace

import pytest

from core.sandbox import context, proxy, telemetry_mac


@pytest.mark.parametrize('parent_count', [None, 12])
@pytest.mark.parametrize('refusal', ['open', 'nonregular'])
@pytest.mark.parametrize('sidecar_kind', ['verified', 'invalid'])
def test_refusal_retains_state(tmp_path, monkeypatch, refusal, sidecar_kind, parent_count):
    monkeypatch.setattr(context, '_PROXY_STREAM_STATE', {})
    monkeypatch.setattr(context, '_PROXY_PERSIST_LOCK', threading.Lock())
    monkeypatch.setattr(telemetry_mac, 'mint', lambda fields: 'valid')
    monkeypatch.setattr(telemetry_mac, 'verify', lambda fields, token: token == 'valid')
    log = tmp_path / proxy.PROXY_EVENTS_FILENAME
    sidecar = tmp_path / proxy.PROXY_EVENTS_COUNT_FILENAME
    context._PROXY_STREAM_STATE[str(log.resolve())] = {
        "next_seq": parent_count, "flags": set(),
    }
    sidecar.write_text(json.dumps({
        'count': 9, 'flags': ['earlier_failure'],
        'mac': 'valid' if sidecar_kind == 'verified' else 'invalid',
    }))
    with monkeypatch.context() as scoped:
        if refusal == 'open':
            original = os.open

            def refused(path, *args, **kwargs):
                if os.fspath(path) == str(log):
                    raise OSError('append unavailable')
                return original(path, *args, **kwargs)

            scoped.setattr(os, 'open', refused)
        else:
            original = os.fstat
            first = True

            def nonregular(fd):
                nonlocal first
                if first:
                    first = False
                    return SimpleNamespace(st_mode=stat.S_IFIFO | 0o600)
                return original(fd)

            scoped.setattr(os, 'fstat', nonregular)
        context._persist_proxy_events([{'host': 'example.test'}], output=tmp_path)

    persisted = json.loads(sidecar.read_text())
    expected_count = max(parent_count or 0, 9 if sidecar_kind == 'verified' else 0)
    expected_flag = 'earlier_failure' if sidecar_kind == 'verified' else 'count_sidecar_invalid'
    assert persisted['count'] == expected_count
    assert set(persisted['flags']) == {'persist_open_failure', expected_flag}
    state = context._PROXY_STREAM_STATE[str(log.resolve())]
    assert state['next_seq'] == expected_count
    assert state['flags'] == set(persisted['flags'])

    # Losing the disk anchor must not erase what this process already learned.
    sidecar.unlink()
    context._persist_proxy_events([{'host': 'later.test'}], output=tmp_path)
    later = json.loads(sidecar.read_text())
    assert later['count'] == expected_count + 1
    assert expected_flag in later['flags']
    assert json.loads(log.read_text())['seq'] == expected_count
