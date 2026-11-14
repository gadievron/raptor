"""Reader error precedence preserves cancellation and partial-record policy."""
import errno
import io
import json
import os

import pytest

from core.dataflow import sanitizer_cut_parity as parity


@pytest.fixture
def owned_records(tmp_path, monkeypatch):
    source = tmp_path / 'owned-records.jsonl'
    lines = [json.dumps({'finding_id': name, 'lexical_suppressed': False}) + '\n'
             for name in ['before', 'after']]
    source.write_text(''.join(lines), encoding='utf-8')
    state = {'primary': None, 'secondary': None, 'reads': [], 'closes': 0,
             'streams': [], 'descriptors': []}

    class Reader(io.TextIOWrapper):
        def readline(self, size=-1):
            line = super().readline(size)
            state['reads'].append((size, line))
            if state['primary'] is not None and len(state['reads']) == 2:
                raise state['primary']
            return line

        def close(self):
            if self.closed:
                return
            super().close()
            state['closes'] += 1
            if state['secondary'] is not None:
                raise state['secondary']

    class OwnedPath(type(source)):
        def open(self, mode='r', **kwargs):
            assert self == source and mode == 'r'
            stream = Reader(source.open('rb'), **kwargs)
            state['streams'].append(stream)
            state['descriptors'].append(stream.fileno())
            return stream

    def forbidden(*args, **kwargs):
        raise AssertionError('reader qualification must not aggregate, render or decide parity')

    monkeypatch.setattr(parity, 'Path', OwnedPath)
    monkeypatch.setattr(parity, 'aggregate_parity', forbidden)
    monkeypatch.setattr(parity, 'render_parity_report', forbidden)
    monkeypatch.setattr(parity, 'parity_criterion_met', forbidden)
    yield source, state
    assert all(stream.closed for stream in state['streams'])
    assert len(state['streams']) == state['closes'] == 1
    assert state['reads'][:2] == [(parity._MAX_RECORD_LINE_CHARS + 1, line) for line in lines]
    assert state['reads'][2:] == ([] if state['primary'] is not None
                                 else [(parity._MAX_RECORD_LINE_CHARS + 1, '')])
    for fd in state['descriptors']:
        with pytest.raises(OSError) as caught:
            os.fstat(fd)
        assert caught.value.errno == errno.EBADF
    assert source.read_text(encoding='utf-8') == ''.join(lines)


@pytest.mark.parametrize("primary_type", [OSError, ValueError, KeyboardInterrupt])
@pytest.mark.parametrize("close_type", [OSError, ValueError, KeyboardInterrupt])
def test_primary_reader_policy_survives_close_error(owned_records, primary_type, close_type):
    source, state = owned_records
    primary = primary_type('owned second-read failure')
    state.update(primary=primary, secondary=close_type('owned close failure'))
    if primary_type is OSError:
        assert [r.finding_id for r in parity.read_parity_records(source)] == ["before"]
    else:
        with pytest.raises(primary_type) as caught:
            parity.read_parity_records(source)
        assert caught.value is primary


@pytest.mark.parametrize("close_type", [OSError, ValueError, KeyboardInterrupt])
def test_fresh_close_policy_is_unchanged(owned_records, close_type):
    source, state = owned_records
    secondary = close_type('fresh close failure')
    state['secondary'] = secondary
    if close_type is OSError:
        assert [r.finding_id for r in parity.read_parity_records(source)] == ['before', 'after']
    else:
        with pytest.raises(close_type) as caught:
            parity.read_parity_records(source)
        assert caught.value is secondary


def test_healthy_reader_keeps_both_records(owned_records):
    source, state = owned_records
    assert [r.finding_id for r in parity.read_parity_records(source)] == ['before', 'after']
    assert state['closes'] == 1
