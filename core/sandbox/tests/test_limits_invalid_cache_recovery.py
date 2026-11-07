"""Corrected resource-limit configurations recover after an empty invalid load."""
import json
from unittest.mock import Mock

import pytest

from core.sandbox import preexec, state


@pytest.fixture
def config(tmp_path, monkeypatch):
    path = tmp_path / 'sandbox.json'
    monkeypatch.setattr(preexec, '_CONFIG_PATH', path)
    monkeypatch.setattr(state, '_user_limits_cache', None)
    monkeypatch.setattr(state, '_user_limits_cache_decided_at', 0.0)
    reader = Mock(wraps=preexec.read_capped_text)
    monkeypatch.setattr(preexec, 'read_capped_text', reader)
    return path, reader


def _expire_failure():
    state._user_limits_cache_decided_at -= preexec._FAIL_TTL_S + 1


@pytest.mark.parametrize('key', ['memory_mb', 'max_file_mb', 'cpu_seconds', 'nproc', 'nofile'])
@pytest.mark.parametrize('invalid', [
    pytest.param(-1, id='negative'),
    pytest.param(True, id='true'),
    pytest.param(False, id='false'),
    pytest.param(1.5, id='float'),
    pytest.param('8', id='string'),
    pytest.param(None, id='null'),
    pytest.param([], id='array'),
])
def test_invalid_only_limits_allow_repair_after_ttl(config, key, invalid):
    path, reader = config
    path.write_text(json.dumps({key: invalid}))
    assert preexec._load_user_limits() == {}
    assert reader.call_count == 1
    path.write_text(json.dumps({key: 8}))
    # The negative cache prevents repeated disk reads before expiry.
    assert preexec._load_user_limits() == {}
    assert reader.call_count == 1
    _expire_failure()
    assert preexec._load_user_limits() == {key: 8}
    assert reader.call_count == 2
    path.unlink()
    assert preexec._load_user_limits() == {key: 8}
    assert reader.call_count == 2


@pytest.mark.parametrize('initial', [
    pytest.param({'cpu_seconds': -1, 'nproc': False}, id='multiple-invalid'),
    pytest.param({'future_setting': 7, 'memory_mb': 'bad'}, id='unknown-and-invalid'),
])
@pytest.mark.parametrize('repaired', [{}, {'memory_mb': 0}], ids=['empty', 'zero-sentinel'])
def test_empty_invalid_cache_can_recover_to_valid_empty_or_disabled_limits(config, initial, repaired):
    path, reader = config
    path.write_text(json.dumps(initial))
    assert preexec._load_user_limits() == {}
    path.write_text(json.dumps(repaired))
    _expire_failure()
    assert preexec._load_user_limits() == repaired
    assert reader.call_count == 2
    path.write_text('{"cpu_seconds": 99}')
    _expire_failure()
    assert preexec._load_user_limits() == repaired
    assert reader.call_count == 2


@pytest.mark.parametrize('initial, expected', [
    pytest.param({}, {}, id='empty'),
    pytest.param({'future_setting': 7}, {}, id='unknown-only'),
    pytest.param({'memory_mb': 0}, {'memory_mb': 0}, id='zero-sentinel'),
    pytest.param({'nproc': 8}, {'nproc': 8}, id='valid-override'),
    pytest.param({'nproc': 8, 'memory_mb': -1}, {'nproc': 8}, id='usable-partial'),
])
def test_usable_and_valid_empty_configs_keep_session_cache(config, initial, expected):
    path, reader = config
    path.write_text(json.dumps(initial))
    assert preexec._load_user_limits() == expected
    path.write_text('{"cpu_seconds":99}')
    _expire_failure()
    assert preexec._load_user_limits() == expected
    assert reader.call_count == 1
