"""Write-error precedence in an owned one-result SARIF chunk."""
import io
import json

import pytest

from core.recall import runner


@pytest.fixture
def owned_chunk(tmp_path, monkeypatch):
    source = tmp_path / 'owned.sarif'
    doc = {'runs': [{'results': [{'ruleId': 'owned'}]}]}
    source.write_text(json.dumps(doc), encoding='utf-8')
    scratch = tmp_path / 'chunks'
    scratch.mkdir()
    output = scratch / 'owned.run0.000.sarif'
    state = {'primary': None, 'secondary': None, 'writes': [], 'closes': 0,
             'streams': []}

    class Writer(io.TextIOWrapper):
        def write(self, text):
            count = super().write(text)
            state['writes'].append(text)
            if state['primary'] is not None:
                raise state['primary']
            return count

        def close(self):
            if self.closed:
                return
            super().close()
            state['closes'] += 1
            if state['secondary'] is not None:
                raise state['secondary']

    def open_owned(path, mode, **kwargs):
        assert path == output and mode == 'w'
        stream = Writer(io.FileIO(output, 'wb'), **kwargs)
        state['streams'].append(stream)
        return stream

    monkeypatch.setattr(runner, 'open', open_owned, raising=False)
    monkeypatch.setattr(runner, 'subprocess', None)
    yield source, scratch, output, doc, state
    assert all(stream.closed for stream in state['streams'])
    assert len(state['streams']) == 1
    assert state['closes'] == 1
    # Actual write and close occur even when the injected write raises.
    assert json.loads(output.read_text(encoding='utf-8')) == doc
    assert len(state['writes']) == 1


@pytest.mark.parametrize("primary_type", [OSError, ValueError, KeyboardInterrupt])
@pytest.mark.parametrize("close_type", [OSError, ValueError, KeyboardInterrupt])
def test_primary_write_policy_survives_close_error(owned_chunk, primary_type, close_type):
    source, scratch, _, _, state = owned_chunk
    primary = primary_type('owned write failure')
    state.update(primary=primary, secondary=close_type('owned close failure'))
    if primary_type is ValueError:
        assert runner._chunk_oversized_sarif(source, scratch) == []
    else:
        with pytest.raises(primary_type) as caught:
            runner._chunk_oversized_sarif(source, scratch)
        assert caught.value is primary


@pytest.mark.parametrize("close_type", [OSError, ValueError, KeyboardInterrupt])
def test_fresh_close_policy_is_unchanged(owned_chunk, close_type):
    source, scratch, _, _, state = owned_chunk
    secondary = close_type('fresh close failure')
    state['secondary'] = secondary
    if close_type is ValueError:
        assert runner._chunk_oversized_sarif(source, scratch) == []
    else:
        with pytest.raises(close_type) as caught:
            runner._chunk_oversized_sarif(source, scratch)
        assert caught.value is secondary


def test_successful_chunk_is_closed_before_return(owned_chunk):
    source, scratch, output, doc, state = owned_chunk
    assert runner._chunk_oversized_sarif(source, scratch) == [output]
    assert all(stream.closed for stream in state['streams'])
    assert json.loads(output.read_text(encoding='utf-8')) == doc
