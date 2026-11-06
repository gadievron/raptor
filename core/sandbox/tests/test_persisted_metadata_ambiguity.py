"""Persisted policy metadata must have one unambiguous interpretation."""
import json
import math

import pytest

from core.sandbox import context, host_consent as consent, preexec, proxy, state, telemetry_mac
from core.testing.state_isolation import pin_user_state_dirs


@pytest.fixture(autouse=True)
def owned_state(tmp_path, monkeypatch):
    pin_user_state_dirs(monkeypatch, tmp_path / 'state')
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'data'))
    monkeypatch.setattr(preexec, '_CONFIG_PATH', tmp_path / 'limits.json')
    monkeypatch.setattr(state, '_user_limits_cache', None)
    monkeypatch.setattr(state, '_user_limits_cache_decided_at', 0.0)
    machine = tmp_path / 'machine-id'
    machine.write_text('owned-machine\n')
    monkeypatch.setattr(consent, '_MACHINE_ID_PATH', str(machine))


def marker():
    return {'schema': 1, 'floor': 'ns-only', 'granted_at': '2026-01-01T00:00:00+00:00',
            'kernel_identity': 'owned-kernel', 'machine_id': 'owned-machine'}


def write_marker(path, raw):
    path.write_text(raw)
    path.chmod(0o600)
    return consent._read_marker_record(path)


@pytest.mark.parametrize('extra', [
    '"schema":1', '"floor":"ns-only"', r'"sch\u0065ma":1',
    '"meta":{"x":1,"x":2}', '"meta":{},"meta":{}',
], ids=['schema', 'floor', 'escaped-key', 'nested', 'unknown'])
def test_consent_reader_refuses_duplicate_fields(tmp_path, extra):
    raw = json.dumps(marker())[:-1] + ',' + extra + '}'
    path = tmp_path / 'consent.json'
    record, reason = write_marker(path, raw)
    assert (record, reason) == (None, 'invalid-json')
    assert path.read_text() == raw


@pytest.mark.parametrize('schema', [True, 1.0], ids=['boolean', 'float'])
def test_consent_schema_requires_the_integer_version(tmp_path, schema):
    value = {**marker(), 'schema': schema}
    path = tmp_path / 'consent.json'
    record, reason = write_marker(path, json.dumps(value))
    assert reason is None
    result, reason = consent._validate_record(record)
    assert (result, reason) == (None, 'wrong-schema')
    assert json.loads(path.read_text()) == value


def test_consent_integer_schema_and_unique_future_metadata_remain_valid(tmp_path):
    value = {**marker(), 'meta': {'x': 1}, 'future': True}
    record, reason = write_marker(tmp_path / 'consent.json', json.dumps(value))
    assert reason is None
    result, reason = consent._validate_record(record)
    assert reason is None
    assert isinstance(result, consent.HostConsent)
    assert result.floor == 'ns-only'


@pytest.mark.parametrize('schema', [None, False, 0, 2, '1', [], {}],
                         ids=['null', 'false', 'zero', 'future', 'string', 'array', 'object'])
def test_existing_invalid_consent_schemas_remain_refused(schema):
    assert consent._validate_record({**marker(), 'schema': schema}) == (None, 'wrong-schema')


def sidecar(run, extra=''):
    binding = telemetry_mac.run_binding(run)
    token = telemetry_mac.mint(telemetry_mac.proxy_events_count_fields(2, [], binding))
    assert token
    value = {'count': 2, 'flags': [], 'mac': token}
    raw = json.dumps(value)[:-1] + (',' + extra if extra else '') + '}'
    path = run / proxy.PROXY_EVENTS_COUNT_FILENAME
    path.write_text(raw)
    return path, binding, raw


@pytest.mark.parametrize('kind', ['count', 'flags', 'mac', 'escaped', 'nested'])
def test_sidecar_reader_refuses_ambiguous_but_otherwise_authenticated_input(tmp_path, kind):
    path, binding, raw = sidecar(tmp_path)
    value = json.loads(raw)
    extra = {'count': '"count":2', 'flags': '"flags":[]',
             'mac': '"mac":' + json.dumps(value['mac']),
             'escaped': r'"co\u0075nt":2', 'nested': '"meta":{"x":1,"x":2}'}[kind]
    ambiguous = raw[:-1] + ',' + extra + '}'
    path.write_text(ambiguous)
    assert context._read_proxy_count_sidecar(str(tmp_path), binding) == (None, set(), True)
    assert path.read_text() == ambiguous


@pytest.mark.parametrize('extra', ['', '"meta":{"x":1}', '"future":true'],
                         ids=['ordinary', 'nested-metadata', 'unknown-field'])
def test_unique_authenticated_sidecars_still_round_trip(tmp_path, extra):
    path, binding, raw = sidecar(tmp_path, extra)
    assert context._read_proxy_count_sidecar(str(tmp_path), binding) == (2, set(), False)
    assert path.read_text() == raw


@pytest.mark.parametrize('extra', [
    '"memory_mb":0', '"cpu_seconds":7', r'"cpu_\u0073econds":7',
    '"meta":{"x":1,"x":2}', '"meta":{},"meta":{}',
], ids=['memory', 'cpu', 'escaped-key', 'nested', 'unknown'])
def test_duplicate_limits_use_retryable_defaults_and_allow_repair(extra, monkeypatch):
    raw = '{"memory_mb":128,"cpu_seconds":7,' + extra + '}'
    preexec._CONFIG_PATH.write_text(raw)
    assert preexec._load_user_limits() == {}
    assert math.isfinite(state._user_limits_cache_decided_at)
    assert preexec._CONFIG_PATH.read_text() == raw
    preexec._CONFIG_PATH.write_text('{"cpu_seconds":9}')
    monkeypatch.setattr(state, '_user_limits_cache_decided_at', float('-inf'))
    assert preexec._load_user_limits() == {'cpu_seconds': 9}
    assert math.isinf(state._user_limits_cache_decided_at)


@pytest.mark.parametrize('value,expected', [
    ({'memory_mb': 128, 'cpu_seconds': 0}, {'memory_mb': 128, 'cpu_seconds': 0}),
    ({'cpu_seconds': 7, 'meta': {'x': 1}}, {'cpu_seconds': 7}),
    ({'future': True}, {}),
], ids=['zero-sentinel', 'nested-metadata', 'unknown-only'])
def test_unambiguous_limits_keep_existing_cache_semantics(value, expected):
    preexec._CONFIG_PATH.write_text(json.dumps(value))
    assert preexec._load_user_limits() == expected
    assert math.isinf(state._user_limits_cache_decided_at)
