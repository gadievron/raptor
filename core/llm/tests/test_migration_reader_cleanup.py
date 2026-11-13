"""Read-error precedence for an owned empty migration input."""
import io

import pytest

from core.llm import detection
from core.testing.module_bindings import patch_module_attribute

_TEXT = 'model_list: []\n'


@pytest.fixture
def owned_config(tmp_path, monkeypatch):
    pytest.importorskip('yaml')
    source = tmp_path / 'owned-empty.yaml'
    destination = tmp_path / 'unused.json'
    source.write_text(_TEXT, encoding='utf-8')
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

    def forbidden(*args, **kwargs):
        raise AssertionError('empty input must not probe SDKs or read credentials')

    monkeypatch.setattr(detection, 'Path', OwnedPath)
    monkeypatch.setattr(detection, '_sdk_available', forbidden)
    patch_module_attribute(monkeypatch, detection, 'os', 'getenv', forbidden)
    yield source, destination, state
    assert all(stream.closed for stream in state['streams'])
    assert not destination.exists()
    assert source.read_text(encoding='utf-8') == _TEXT


@pytest.mark.parametrize("primary_type", [OSError, ValueError, KeyboardInterrupt])
@pytest.mark.parametrize("close_type", [OSError, ValueError, KeyboardInterrupt])
def test_primary_read_policy_survives_close_error(owned_config, primary_type, close_type):
    source, destination, state = owned_config
    primary = primary_type('owned read failure')
    state.update(primary=primary, secondary=close_type('owned close failure'))
    if primary_type is KeyboardInterrupt:
        with pytest.raises(KeyboardInterrupt) as caught:
            detection._try_auto_migrate(source, destination)
        assert caught.value is primary
    else:
        assert detection._try_auto_migrate(source, destination) is False
    assert ''.join(state['reads']) == _TEXT
    assert state['closes'] == 1


@pytest.mark.parametrize("close_type", [OSError, ValueError, KeyboardInterrupt])
def test_fresh_close_policy_is_unchanged(owned_config, close_type):
    source, destination, state = owned_config
    secondary = close_type('fresh close failure')
    state['secondary'] = secondary
    if close_type is KeyboardInterrupt:
        with pytest.raises(KeyboardInterrupt) as caught:
            detection._try_auto_migrate(source, destination)
        assert caught.value is secondary
    else:
        assert detection._try_auto_migrate(source, destination) is False
    assert ''.join(state['reads']) == _TEXT
    assert state['closes'] == 1


def test_empty_models_read_closes_without_output(owned_config):
    source, destination, state = owned_config
    assert detection._try_auto_migrate(source, destination) is False
    assert ''.join(state['reads']) == _TEXT
    assert state['closes'] == 1
