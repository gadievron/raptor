"""Damaged UTF-8 is flagged without changing or discarding valid neighbors."""
import json

import pytest

from core.sandbox import evidence, summary, triage


@pytest.fixture(autouse=True)
def isolated_run(tmp_path, monkeypatch):
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'keys'))
    summary.set_active_run_dir(None)
    yield
    summary.set_active_run_dir(None)


def write_evidence(path, data):
    fd = evidence.EvidenceFile.open(path, summary.DENIALS_FILE)
    try:
        fd.path.write_bytes(data)
    finally:
        fd.close()


@pytest.mark.parametrize('separator', [b'\n', b'\r\n', b'\r'])
@pytest.mark.parametrize('bad', [
    b'{"type":"write","path":"bad\xff"}',
    b'{"ty\xffpe":"write"}',
    b'{"type":"write","path":"bad\xc3"}',
])
def test_bad_record_is_flagged_and_neighbors_survive(tmp_path, separator, bad):
    records = [{'type': 'write', 'path': '/tmp/first'},
               {'type': 'write', 'path': '/tmp/last'}]
    data = separator.join([json.dumps(records[0]).encode(), bad,
                           json.dumps(records[1]).encode()]) + separator
    write_evidence(tmp_path, data)
    result = summary.summarize_and_write(tmp_path)
    assert result['corrupt_lines'] == 1
    assert result['total_denials'] == 2
    assert [r['path'] for r in result['denials']] == ['/tmp/first', '/tmp/last']
    report = triage.triage_run(tmp_path, allow_legacy=False)
    assert report['inputs']['integrity']['sandbox_summary'] == triage._INTEGRITY_TAMPERED


@pytest.mark.parametrize('text', ['separator \u2028', 'separator \u2029', 'replacement \ufffd'])
def test_valid_unicode_survives_unchanged(tmp_path, text):
    write_evidence(tmp_path, json.dumps({'type': 'write', 'path': text}, ensure_ascii=False).encode() + b'\n')
    result = summary.summarize_and_write(tmp_path)
    assert result['denials'][0]['path'] == text
    assert 'corrupt_lines' not in result


@pytest.mark.parametrize('raw,expected', [
    (b'', []), (b'\n', [b'']), (b'a\n', [b'a']),
    (b'a\r\nb\rc\n', [b'a', b'b', b'c']),
    (b'a\n\n', [b'a', b'']), (b'unterminated', [b'unterminated']),
])
def test_byte_line_boundaries_match_file_rules(raw, expected):
    assert list(summary._iter_denial_lines(raw)) == expected
