"""Append-error precedence on an owned calibration file."""
import io
import json
import os

import pytest

from core.audit import forecast
from core.testing.module_bindings import patch_module_attribute


@pytest.fixture
def owned_calibration(tmp_path, monkeypatch):
    target = tmp_path / 'owned.jsonl'
    original = '{"old": true}\n'
    target.write_text(original, encoding='utf-8')
    entry = {'owned': True}
    state = {'primary': None, 'secondary': None, 'writes': [], 'closes': 0,
             'fsyncs': 0, 'streams': []}
    native_fsync = os.fsync

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
        assert path == target and mode == 'a'
        stream = Writer(io.FileIO(target, 'ab'), **kwargs)
        state['streams'].append(stream)
        return stream

    def fsync_owned(fd):
        actual = os.fstat(fd)
        expected = target.stat()
        assert (actual.st_dev, actual.st_ino) == (expected.st_dev, expected.st_ino)
        state['fsyncs'] += 1
        native_fsync(fd)

    monkeypatch.setattr(forecast, 'open', open_owned, raising=False)
    patch_module_attribute(monkeypatch, forecast, 'os', 'fsync', fsync_owned)
    yield target, entry, state
    assert all(stream.closed for stream in state['streams'])
    assert len(state['streams']) == state['closes'] == 1
    assert state['writes'] == [json.dumps(entry, sort_keys=True) + '\n']
    assert target.read_text(encoding='utf-8') == original + state['writes'][0]
    assert state['fsyncs'] == (0 if state['primary'] is not None else 1)


@pytest.mark.parametrize("primary_type", [OSError, ValueError, KeyboardInterrupt])
@pytest.mark.parametrize("close_type", [OSError, ValueError, KeyboardInterrupt])
def test_primary_append_policy_survives_close_error(
        owned_calibration, primary_type, close_type, caplog):
    target, entry, state = owned_calibration
    primary = primary_type('owned append failure')
    state.update(primary=primary, secondary=close_type('owned close failure'))
    if primary_type is OSError:
        assert forecast.append_calibration(target, entry) is None
        assert "calibration append failed" in caplog.text
    else:
        with pytest.raises(primary_type) as caught:
            forecast.append_calibration(target, entry)
        assert caught.value is primary
        assert "calibration append failed" not in caplog.text


@pytest.mark.parametrize("close_type", [OSError, ValueError, KeyboardInterrupt])
def test_fresh_close_policy_is_unchanged(owned_calibration, close_type, caplog):
    target, entry, state = owned_calibration
    secondary = close_type('fresh close failure')
    state['secondary'] = secondary
    if close_type is OSError:
        assert forecast.append_calibration(target, entry) is None
        assert 'calibration append failed' in caplog.text
    else:
        with pytest.raises(close_type) as caught:
            forecast.append_calibration(target, entry)
        assert caught.value is secondary
        assert 'calibration append failed' not in caplog.text


def test_successful_append_flushes_and_syncs_owned_file(owned_calibration):
    target, entry, state = owned_calibration
    assert forecast.append_calibration(target, entry) is None
    assert state['fsyncs'] == state['closes'] == 1
    assert all(stream.closed for stream in state['streams'])
