"""Stream-error precedence while reading owned rule-header metadata."""
import io

import pytest

from core.audit import sweep

_TEXT = '// @role: verification\n@@\n'


@pytest.fixture
def owned_rule(tmp_path, monkeypatch):
    source = tmp_path / 'owned.cocci'
    source.write_text(_TEXT, encoding='utf-8')
    state = {'primary': None, 'secondary': None, 'lines': [], 'closes': 0,
             'streams': []}

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
            return stream

    def forbidden(*args, **kwargs):
        raise AssertionError('metadata reader must not execute rules')

    monkeypatch.setattr(sweep, 'Path', OwnedPath)
    monkeypatch.setattr(sweep, 'run_coccinelle_sweep', forbidden)
    monkeypatch.setattr(sweep, 'run_coccinelle_file_sweep', forbidden)
    yield source, state
    assert all(stream.closed for stream in state['streams'])
    assert state['closes'] == 1
    assert source.read_text(encoding='utf-8') == _TEXT


@pytest.mark.parametrize("primary_type", [OSError, ValueError, KeyboardInterrupt])
@pytest.mark.parametrize("close_type", [OSError, ValueError, KeyboardInterrupt])
def test_primary_header_policy_survives_close_error(owned_rule, primary_type, close_type):
    source, state = owned_rule
    primary = primary_type('owned header failure')
    state.update(primary=primary, secondary=close_type('owned close failure'))
    if primary_type is OSError:
        assert sweep.get_rule_role(str(source)) == "detection"
    else:
        with pytest.raises(primary_type) as caught:
            sweep.get_rule_role(str(source))
        assert caught.value is primary
    assert state['lines'] == [_TEXT.splitlines(keepends=True)[0]]


@pytest.mark.parametrize("close_type", [OSError, ValueError, KeyboardInterrupt])
def test_fresh_close_policy_is_unchanged(owned_rule, close_type):
    source, state = owned_rule
    secondary = close_type('fresh close failure')
    state['secondary'] = secondary
    if close_type is OSError:
        assert sweep.get_rule_role(str(source)) == 'detection'
    else:
        with pytest.raises(close_type) as caught:
            sweep.get_rule_role(str(source))
        assert caught.value is secondary
    assert ''.join(state['lines']) == _TEXT


def test_healthy_header_role_is_preserved(owned_rule):
    source, state = owned_rule
    assert sweep.get_rule_role(str(source)) == 'verification'
    assert ''.join(state['lines']) == _TEXT
