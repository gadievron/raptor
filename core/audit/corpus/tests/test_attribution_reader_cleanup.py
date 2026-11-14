"""Error precedence in the owned JSONL reader, without corpus attribution."""
import errno
import io
import os

import pytest

from core.audit.corpus import attribution

_TEXT = '{"owned": 1}\n'


@pytest.fixture
def owned_jsonl(tmp_path, monkeypatch):
    source = tmp_path / 'owned.jsonl'
    source.write_text(_TEXT, encoding='utf-8')
    state = {'primary': None, 'secondary': None, 'lines': [], 'closes': 0,
             'streams': [], 'descriptors': []}

    class Reader(io.TextIOWrapper):
        def __next__(self):
            line = super().__next__()
            state['lines'].append(line)
            if state['primary'] is not None:
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
            stream = Reader(source.open('rb'), encoding='utf-8', **kwargs)
            state['streams'].append(stream)
            state['descriptors'].append(stream.fileno())
            return stream

    def forbidden(*args, **kwargs):
        raise AssertionError('reader qualification must not collect or attribute receipts')

    monkeypatch.setattr(attribution, 'Path', OwnedPath)
    monkeypatch.setattr(attribution, 'build_signal_index', forbidden)
    monkeypatch.setattr(attribution, 'attribute_row', forbidden)
    monkeypatch.setattr(attribution, 'annotate_results', forbidden)
    yield source, state
    assert all(stream.closed for stream in state['streams'])
    assert len(state['streams']) == state['closes'] == 1
    assert state['lines'] == [_TEXT]
    for fd in state['descriptors']:
        with pytest.raises(OSError) as caught:
            os.fstat(fd)
        assert caught.value.errno == errno.EBADF
    assert source.read_text(encoding='utf-8') == _TEXT


@pytest.mark.parametrize("primary_type", [OSError, ValueError, KeyboardInterrupt])
@pytest.mark.parametrize("close_type", [OSError, ValueError, KeyboardInterrupt])
def test_primary_reader_policy_survives_close_error(owned_jsonl, primary_type, close_type):
    source, state = owned_jsonl
    primary = primary_type('owned JSONL read failure')
    state.update(primary=primary, secondary=close_type('owned close failure'))
    if primary_type is OSError:
        assert list(attribution._iter_jsonl(source)) == []
    else:
        with pytest.raises(primary_type) as caught:
            list(attribution._iter_jsonl(source))
        assert caught.value is primary


@pytest.mark.parametrize("close_type", [OSError, ValueError, KeyboardInterrupt])
def test_fresh_close_policy_is_unchanged(owned_jsonl, close_type):
    source, state = owned_jsonl
    secondary = close_type('fresh close failure')
    state['secondary'] = secondary
    if close_type is OSError:
        assert list(attribution._iter_jsonl(source)) == [{'owned': 1}]
    else:
        with pytest.raises(close_type) as caught:
            list(attribution._iter_jsonl(source))
        assert caught.value is secondary


def test_healthy_reader_yields_marker_and_closes(owned_jsonl):
    source, state = owned_jsonl
    assert list(attribution._iter_jsonl(source)) == [{'owned': 1}]
    assert state['closes'] == 1
