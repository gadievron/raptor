"""Damaged UTF-8 records cannot become rewritten egress observations."""
import json

import pytest

from core.sandbox import egress_summary as summary
from core.sandbox.proxy import PROXY_EVENTS_FILENAME
from core.testing.state_isolation import pin_user_state_dirs


@pytest.fixture(autouse=True)
def owned_state(tmp_path, monkeypatch):
    pin_user_state_dirs(monkeypatch, tmp_path / 'state')


def event(host='example.test', **fields):
    return {'host': host, 'port': 443, 'result': 'allowed',
            'bytes_u2c': 20, 'bytes_c2u': 10, **fields}


def encoded(record):
    return json.dumps(record, ensure_ascii=False).encode('utf-8')


@pytest.mark.parametrize('separator', [b'\n', b'\r\n', b'\r'])
@pytest.mark.parametrize('field', ['host', 'result', 'metadata'])
@pytest.mark.parametrize('damaged', [b'\xff', b'\xc3', b'\xed\xa0\x80'],
                         ids=['invalid-start', 'truncated-sequence', 'surrogate'])
def test_damaged_record_does_not_change_counts_or_hide_neighbors(tmp_path, separator, field, damaged):
    first, last = event('first.test'), event('last.test', result='denied_host')
    bad = encoded(event(**{field: 'damage-marker'})).replace(b'damage-marker', b'bad-' + damaged)
    path = tmp_path / PROXY_EVENTS_FILENAME
    path.write_bytes(separator.join([encoded(first), bad, encoded(last)]))
    result = summary.finalize_egress_summary(tmp_path)
    assert result is not None
    assert result['total_connections'] == 2
    assert result['allowed'] == result['denied'] == 1
    assert result['total_bytes_in'] == 40
    assert result['total_bytes_out'] == 20
    assert [host['host'] for host in result['hosts']] == ['first.test', 'last.test']
    assert json.loads((tmp_path / summary.EGRESS_SUMMARY_FILE).read_text()) == result


def test_all_damaged_records_produce_no_summary(tmp_path):
    (tmp_path / PROXY_EVENTS_FILENAME).write_bytes(encoded(event()).replace(b'example', b'\xff'))
    assert summary.finalize_egress_summary(tmp_path) is None
    assert not (tmp_path / summary.EGRESS_SUMMARY_FILE).exists()


@pytest.mark.parametrize('name', ['snowman \u2603', 'replacement \ufffd',
                                 'separator \u2028', 'separator \u2029'])
def test_valid_unicode_is_preserved(tmp_path, name):
    (tmp_path / PROXY_EVENTS_FILENAME).write_bytes(encoded(event(name)))
    result = summary.finalize_egress_summary(tmp_path)
    assert result is not None
    assert result['hosts'][0]['host'] == name
    assert result['allowed'] == result['total_connections'] == 1


def test_damaged_record_still_consumes_line_budget(tmp_path, monkeypatch):
    good = encoded(event())
    (tmp_path / PROXY_EVENTS_FILENAME).write_bytes(b'{"bad":"\xff"}\n' + good + b'\n' + good)
    monkeypatch.setattr(summary, '_MAX_LINES', 2)
    assert summary.summarise_egress(tmp_path)['total_connections'] == 1


def test_character_budget_and_universal_newlines_are_preserved(tmp_path, monkeypatch):
    line = encoded(event('snowman \u2603'))
    # Existing budget includes the one-character normalized terminator.
    monkeypatch.setattr(summary, '_MAX_LINE_CHARS', len(line.decode('utf-8')) + 1)
    (tmp_path / PROXY_EVENTS_FILENAME).write_bytes(line + b'\r\n')
    assert summary.summarise_egress(tmp_path)['total_connections'] == 1
    monkeypatch.setattr(summary, '_MAX_LINE_CHARS', len(line.decode('utf-8')))
    assert summary.summarise_egress(tmp_path) is None
