"""Oversize JSONL draining preserves the following owned marker row."""
import json

import pytest

from core.dataflow import sanitizer_cut_parity as parity


def marker(name):
    return json.dumps({'finding_id': name, 'lexical_suppressed': False})


def test_complete_oversize_line_keeps_following_record(tmp_path):
    source = tmp_path / 'owned-parity.jsonl'
    payload = (marker('before') + '\n'
               + 'x' * parity._MAX_RECORD_LINE_CHARS + '\n'
               + marker('after') + '\n').encode('ascii')
    source.write_bytes(payload)
    records = parity.read_parity_records(source)
    assert [record.finding_id for record in records] == ['before', 'after']
    assert source.read_bytes() == payload


def test_complete_crlf_oversize_line_keeps_following_record(tmp_path):
    source = tmp_path / 'owned-parity.jsonl'
    payload = ('x' * parity._MAX_RECORD_LINE_CHARS + '\r\n'
               + marker('after') + '\r\n').encode('ascii')
    source.write_bytes(payload)
    assert [r.finding_id for r in parity.read_parity_records(source)] == ['after']
    assert source.read_bytes() == payload


@pytest.mark.parametrize('newline', ['\n', '\r\n'], ids=['lf', 'crlf'])
@pytest.mark.parametrize('overage', [1, 65])
def test_partial_oversize_line_still_drains_before_next_record(tmp_path, newline, overage):
    source = tmp_path / 'owned-parity.jsonl'
    payload = ('x' * (parity._MAX_RECORD_LINE_CHARS + overage) + newline
               + marker('after') + newline).encode('ascii')
    source.write_bytes(payload)
    assert [r.finding_id for r in parity.read_parity_records(source)] == ['after']
    assert source.read_bytes() == payload


@pytest.mark.parametrize('terminator', ['\n', ''], ids=['newline', 'eof'])
def test_valid_record_at_exact_character_cap_is_admitted(tmp_path, terminator):
    source = tmp_path / 'owned-parity.jsonl'
    record = {'finding_id': 'exact', 'lexical_suppressed': False, 'pad': ''}
    padding = parity._MAX_RECORD_LINE_CHARS - len(terminator) - len(json.dumps(record))
    assert padding > 0
    record['pad'] = 'x' * padding
    payload = (json.dumps(record) + terminator).encode('ascii')
    assert len(payload) == parity._MAX_RECORD_LINE_CHARS
    source.write_bytes(payload)
    assert [r.finding_id for r in parity.read_parity_records(source)] == ['exact']
    assert source.read_bytes() == payload


def test_oversize_tail_cannot_be_parsed_as_a_separate_record(tmp_path):
    source = tmp_path / 'owned-parity.jsonl'
    payload = ('x' * (parity._MAX_RECORD_LINE_CHARS + 1)
               + marker('discarded-tail') + '\n'
               + marker('after') + '\n').encode('ascii')
    source.write_bytes(payload)
    assert [r.finding_id for r in parity.read_parity_records(source)] == ['after']
    assert source.read_bytes() == payload


def test_oversize_eof_keeps_prior_record(tmp_path):
    source = tmp_path / 'owned-parity.jsonl'
    payload = (marker('before') + '\n'
               + 'x' * (parity._MAX_RECORD_LINE_CHARS + 65)).encode('ascii')
    source.write_bytes(payload)
    assert [r.finding_id for r in parity.read_parity_records(source)] == ['before']
    assert source.read_bytes() == payload


def test_complete_oversize_lines_do_not_discard_adjacent_valid_rows(tmp_path):
    source = tmp_path / 'owned-parity.jsonl'
    oversize = 'x' * parity._MAX_RECORD_LINE_CHARS + '\n'
    payload = (oversize + marker('first') + '\n'
               + oversize + marker('second') + '\n').encode('ascii')
    source.write_bytes(payload)
    assert [r.finding_id for r in parity.read_parity_records(source)] == ['first', 'second']
    assert source.read_bytes() == payload
