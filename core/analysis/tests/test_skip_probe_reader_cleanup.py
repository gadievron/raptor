"""Error precedence in the bounded skipped-directory byte probe."""
import io
from pathlib import Path

import pytest

from core.analysis import gadget_oracle

_PAYLOAD = b'<?php inert'


@pytest.fixture
def owned_probe(tmp_path, monkeypatch):
    source = tmp_path / 'owned.txt'
    source.write_bytes(_PAYLOAD)
    state = {'primary': None, 'secondary': None, 'reads': [], 'closes': 0,
             'streams': []}

    class Reader(io.BufferedReader):
        def read(self, size=-1):
            value = super().read(size)
            state['reads'].append((size, value))
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

    def open_owned(path, mode):
        assert Path(path) == source and mode == 'rb'
        stream = Reader(io.FileIO(source, 'rb'))
        state['streams'].append(stream)
        return stream

    def forbidden(*args, **kwargs):
        raise AssertionError('byte predicate must not invoke the oracle')

    monkeypatch.setattr(gadget_oracle, 'open', open_owned, raising=False)
    monkeypatch.setattr(gadget_oracle, 'scan_tree', forbidden)
    yield tmp_path, state
    assert all(stream.closed for stream in state['streams'])
    assert len(state['streams']) == state['closes'] == 1
    assert state['reads'] == [(gadget_oracle._SKIP_PROBE_BYTES, _PAYLOAD)]
    assert source.read_bytes() == _PAYLOAD


@pytest.mark.parametrize("primary_type", [OSError, ValueError, KeyboardInterrupt])
@pytest.mark.parametrize("close_type", [OSError, ValueError, KeyboardInterrupt])
def test_primary_probe_policy_survives_close_error(owned_probe, primary_type, close_type):
    directory, state = owned_probe
    primary = primary_type('owned probe failure')
    state.update(primary=primary, secondary=close_type('owned close failure'))
    if primary_type is OSError:
        assert gadget_oracle._skipped_dir_has_php(str(directory)) is False
    else:
        with pytest.raises(primary_type) as caught:
            gadget_oracle._skipped_dir_has_php(str(directory))
        assert caught.value is primary


@pytest.mark.parametrize("close_type", [OSError, ValueError, KeyboardInterrupt])
def test_fresh_close_policy_is_unchanged(owned_probe, close_type):
    directory, state = owned_probe
    secondary = close_type('fresh close failure')
    state['secondary'] = secondary
    if close_type is OSError:
        assert gadget_oracle._skipped_dir_has_php(str(directory)) is False
    else:
        with pytest.raises(close_type) as caught:
            gadget_oracle._skipped_dir_has_php(str(directory))
        assert caught.value is secondary


def test_healthy_prefix_is_detected_without_oracle(owned_probe):
    directory, state = owned_probe
    assert gadget_oracle._skipped_dir_has_php(str(directory)) is True
    assert state['closes'] == 1
