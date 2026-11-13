"""Read-error precedence in the owned SARIF chunk reader."""
import io

import pytest

from core.recall import runner


@pytest.fixture
def owned_reader(tmp_path, monkeypatch):
    source = tmp_path / 'owned.sarif'
    source.write_text('{"runs": []}', encoding='utf-8')
    state = {'primary': None, 'secondary': None, 'reads': [], 'closes': 0,
             'streams': []}

    class Reader(io.TextIOWrapper):
        def read(self, size=-1):
            value = super().read(size)
            state['reads'].append(value)
            if state['primary'] is not None:
                raise state['primary']
            return value

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
            return stream

    monkeypatch.setattr(runner, 'Path', OwnedPath)
    monkeypatch.setattr(runner, 'subprocess', None)
    yield source, tmp_path, state
    for stream in state['streams']:
        assert stream.closed


@pytest.mark.parametrize("primary_type", [OSError, ValueError, KeyboardInterrupt])
@pytest.mark.parametrize("close_type", [OSError, ValueError, KeyboardInterrupt])
def test_read_error_survives_close_error(owned_reader, primary_type, close_type):
    source, scratch, state = owned_reader
    primary = primary_type('owned read failure')
    state.update(primary=primary, secondary=close_type('owned close failure'))
    with pytest.raises(primary_type) as caught:
        runner._chunk_oversized_sarif(source, scratch)
    assert caught.value is primary
    assert state['reads'] == ['{"runs": []}']
    assert state['closes'] == 1
    assert all(stream.closed for stream in state['streams'])


@pytest.mark.parametrize("close_type", [OSError, ValueError, KeyboardInterrupt])
def test_fresh_close_error_remains_visible(owned_reader, close_type):
    source, scratch, state = owned_reader
    secondary = close_type('fresh close failure')
    state['secondary'] = secondary
    with pytest.raises(close_type) as caught:
        runner._chunk_oversized_sarif(source, scratch)
    assert caught.value is secondary
    assert state['reads'] == ['{"runs": []}']
    assert state['closes'] == 1


def test_empty_runs_read_and_close_succeed(owned_reader):
    source, scratch, state = owned_reader
    assert runner._chunk_oversized_sarif(source, scratch) == []
    assert state['reads'] == ['{"runs": []}']
    assert state['closes'] == 1
    assert list(scratch.iterdir()) == [source]
