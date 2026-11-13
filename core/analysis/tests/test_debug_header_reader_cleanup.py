"""Error precedence at the bounded debug-header file reader."""
import io

import pytest

from core.analysis import binary_provenance


@pytest.fixture
def owned_header(tmp_path, monkeypatch):
    source = tmp_path / 'owned-header.bin'
    header = (20).to_bytes(4, 'little') + (4).to_bytes(2, 'little') + bytes(18)
    source.write_bytes(b'pad!' + header)
    state = {'primary': None, 'secondary': None, 'reads': [], 'seeks': [],
             'closes': 0, 'streams': []}

    class Reader(io.BufferedReader):
        def seek(self, offset, whence=0):
            state['seeks'].append((offset, whence))
            return super().seek(offset, whence)

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
        assert path == source and mode == 'rb'
        stream = Reader(io.FileIO(source, 'rb'))
        state['streams'].append(stream)
        return stream

    def forbidden(*args, **kwargs):
        raise AssertionError('bounded reader must not invoke ELF or native probes')

    monkeypatch.setattr(binary_provenance, 'open', open_owned, raising=False)
    monkeypatch.setattr(binary_provenance, 'probe_binary', forbidden)
    monkeypatch.setattr(binary_provenance, 'is_elf', forbidden)
    yield source, header, state
    assert all(stream.closed for stream in state['streams'])


@pytest.mark.parametrize("primary_type", [OSError, ValueError, KeyboardInterrupt])
@pytest.mark.parametrize("close_type", [OSError, ValueError, KeyboardInterrupt])
def test_primary_read_policy_survives_close_error(owned_header, primary_type, close_type):
    source, header, state = owned_header
    primary = primary_type('owned read failure')
    state.update(primary=primary, secondary=close_type('owned close failure'))
    if primary_type is OSError:
        assert binary_provenance._debug_info_header_sane(source, 4, 24, True) is False
    else:
        with pytest.raises(primary_type) as caught:
            binary_provenance._debug_info_header_sane(source, 4, 24, True)
        assert caught.value is primary
    assert state['reads'] == [(24, header)]
    assert state['seeks'] == [(4, 0)]
    assert state['closes'] == 1


@pytest.mark.parametrize("close_type", [OSError, ValueError, KeyboardInterrupt])
def test_fresh_close_policy_is_unchanged(owned_header, close_type):
    source, header, state = owned_header
    secondary = close_type('fresh close failure')
    state['secondary'] = secondary
    if close_type is OSError:
        assert binary_provenance._debug_info_header_sane(source, 4, 24, True) is False
    else:
        with pytest.raises(close_type) as caught:
            binary_provenance._debug_info_header_sane(source, 4, 24, True)
        assert caught.value is secondary
    assert state['reads'] == [(24, header)]
    assert state['closes'] == 1


def test_healthy_header_reads_only_fixed_span(owned_header):
    source, header, state = owned_header
    assert binary_provenance._debug_info_header_sane(source, 4, 24, True) is True
    assert state['reads'] == [(24, header)]
    assert state['seeks'] == [(4, 0)]
    assert state['closes'] == 1


def test_short_section_refused_before_open(owned_header):
    source, _, state = owned_header
    assert binary_provenance._debug_info_header_sane(source, 4, 7, True) is False
    assert state['streams'] == state['reads'] == state['seeks'] == []
    assert state['closes'] == 0
