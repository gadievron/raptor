"""Sequence metadata must be integer positions, never coerced values."""
import pytest

from core.sandbox import telemetry_mac, triage


@pytest.mark.parametrize('seq', [False, True, '0', 0.0, 0.5, None, [], {}, -1, float('inf')])
@pytest.mark.parametrize('with_count', [False, True])
def test_malformed_sequence_is_attributed(seq, with_count, monkeypatch):
    monkeypatch.setattr(telemetry_mac, 'verify', lambda fields, token: token == 'valid')
    event = {'host': 'example.test', 'result': 'allowed', 'seq': seq, 'mac': 'valid'}
    count = {'count': 1, 'flags': [], 'mac': 'valid'} if with_count else None
    usable, rejected, integrity, note = triage._verify_proxy_events([event], 'run', count_record=count)
    assert usable == [event]
    assert rejected == 0
    assert integrity == triage._INTEGRITY_TAMPERED
    assert 'malformed sequence' in note


def test_valid_integer_sequences_still_verify(monkeypatch):
    monkeypatch.setattr(telemetry_mac, 'verify', lambda fields, token: token == 'valid')
    events = [{'host': 'example.test', 'result': 'allowed', 'seq': i, 'mac': 'valid'} for i in range(3)]
    count = {'count': 3, 'flags': [], 'mac': 'valid'}
    assert triage._verify_proxy_events(events, 'run', count_record=count) == (
        events, 0, triage._INTEGRITY_VERIFIED, None)


def test_unnumbered_legacy_stream_is_preserved():
    events = [{'host': 'example.test', 'result': 'allowed'}]
    assert triage._verify_proxy_events(events, 'run', allow_legacy=True) == (
        events, 0, triage._INTEGRITY_LEGACY, None)
