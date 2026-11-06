"""Partial convenience summaries retain counts without claiming complete input."""
import json
import logging

import pytest

from core.sandbox import egress_summary as egress, proxy
from core.testing.state_isolation import pin_user_state_dirs


@pytest.fixture(autouse=True)
def owned_state(tmp_path):
    with pytest.MonkeyPatch.context() as monkeypatch:
        pin_user_state_dirs(monkeypatch, tmp_path / 'state')
        monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'data'))
        yield


@pytest.fixture
def monkeypatch(owned_state):
    """Undo body patches before restoring fixture-owned state."""
    with pytest.MonkeyPatch.context() as patch:
        yield patch


def event(**fields):
    return {'host': 'owned.test', 'port': 443, 'result': 'allowed',
            'bytes_c2u': 3, 'bytes_u2c': 7, **fields}


def encode(value):
    return json.dumps(value).encode('utf-8')


def write_lines(run, lines, separator=b'\n'):
    path = run / proxy.PROXY_EVENTS_FILENAME
    path.write_bytes(separator.join(lines))
    return path


@pytest.mark.parametrize('failure', sorted(proxy._STATS_FAILED_RESULTS | {'timed_out'}))
def test_known_proxy_failures_keep_reason_labels(tmp_path, failure):
    write_lines(tmp_path, [encode(event(result=failure))] * 2)
    result = egress.finalize_egress_summary(tmp_path)
    assert result['failed'] == result['total_connections'] == 2
    assert result['hosts'][0]['reasons'] == [failure]
    assert not result.get('input_incomplete', False)


@pytest.mark.parametrize('separator', [b'\n', b'\r\n', b'\r'], ids=['lf', 'crlf', 'cr'])
@pytest.mark.parametrize('kind,issue', [
    pytest.param('malformed', 'malformed_record', id='malformed-json'),
    pytest.param('utf8', 'malformed_record', id='damaged-utf8'),
    pytest.param('duplicate', 'malformed_record', id='duplicate-member'),
    pytest.param('nonobject', 'nonobject_record', id='nonobject'),
    pytest.param('fields', 'malformed_fields', id='bad-consumed-field'),
    pytest.param('oversize', 'oversized_record', id='oversized-record'),
])
def test_discarded_input_is_visible_without_losing_neighbors(
        tmp_path, monkeypatch, caplog, separator, kind, issue):
    bad = {
        'malformed': b'{',
        'utf8': b'{"result":"allowed","host":"bad-\xff"}',
        'duplicate': b'{"result":"allowed","result":"denied_host"}',
        'nonobject': b'[]',
        'fields': encode(event(bytes_c2u=-1)),
        'oversize': encode(event(padding='x' * 1000)),
    }[kind]
    if kind == 'oversize':
        monkeypatch.setattr(egress, '_MAX_LINE_CHARS', 256)
    path = write_lines(tmp_path, [encode(event()), bad,
                                  encode(event(result='denied_host'))], separator)
    original = path.read_bytes()
    with caplog.at_level(logging.WARNING, logger=egress.__name__):
        result = egress.finalize_egress_summary(tmp_path)
    assert result['total_connections'] == 2
    assert result['allowed'] == result['denied'] == 1
    assert result['total_bytes_in'] == 14
    assert result['total_bytes_out'] == 6
    assert result.get('input_incomplete') is True
    assert result.get('input_issues') == [issue]
    assert 'partial input' in caplog.text
    assert json.loads((tmp_path / egress.EGRESS_SUMMARY_FILE).read_text()) == result
    assert path.read_bytes() == original


@pytest.mark.parametrize('count,incomplete', [(1, False), (2, False), (3, True)],
                         ids=['under', 'exact', 'over'])
@pytest.mark.parametrize('terminated', [False, True], ids=['unterminated', 'terminated'])
def test_physical_line_budget_reports_only_actual_prefix_loss(
        tmp_path, monkeypatch, count, incomplete, terminated):
    monkeypatch.setattr(egress, '_MAX_LINES', 2)
    data = b'\n'.join([encode(event())] * count) + (b'\n' if terminated else b'')
    (tmp_path / proxy.PROXY_EVENTS_FILENAME).write_bytes(data)
    result = egress.summarise_egress(tmp_path)
    assert result['total_connections'] == min(count, 2)
    assert result.get('input_incomplete', False) is incomplete
    assert result.get('input_issues', []) == (['line_limit'] if incomplete else [])


def test_producer_overflow_marks_partial_input_without_counting_marker(tmp_path):
    write_lines(tmp_path, [encode(event()),
                          encode({'result': 'buffer_overflow', 'dropped': 2}),
                          encode(event(result='denied_host'))])
    result = egress.summarise_egress(tmp_path)
    assert result['total_connections'] == 2
    assert result.get('input_incomplete') is True
    assert result.get('input_issues') == ['producer_overflow']


def test_clean_separators_and_degraded_parser_marker_are_not_record_loss(tmp_path):
    write_lines(tmp_path, [b'', encode(event()), b'  ',
                          encode({'result': 'parser_jail_degraded'}), b''])
    result = egress.summarise_egress(tmp_path)
    assert result['total_connections'] == result['allowed'] == 1
    assert not result.get('input_incomplete', False)
    assert not result.get('input_issues', [])


def test_all_unusable_input_still_produces_no_summary(tmp_path):
    write_lines(tmp_path, [b'{', b'[]', encode(event(bytes_c2u=-1))])
    assert egress.finalize_egress_summary(tmp_path) is None
    assert not (tmp_path / egress.EGRESS_SUMMARY_FILE).exists()


def test_multiple_loss_causes_are_stable_and_deduplicated(tmp_path):
    write_lines(tmp_path, [b'{', encode(event()), b'{', b'[]',
                          encode(event(bytes_c2u=-1)),
                          encode({'result': 'buffer_overflow', 'dropped': 1})])
    result = egress.summarise_egress(tmp_path)
    assert result['total_connections'] == 1
    assert result.get('input_incomplete') is True
    assert result.get('input_issues') == ['malformed_fields', 'malformed_record',
                                          'nonobject_record', 'producer_overflow']
