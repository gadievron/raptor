"""Rooted finding reads keep containment through the actual open."""

import io
from pathlib import Path

import pytest

from core.analysis import finding_resolver as resolver
from core import paths
from core.source import beneath


def test_directory_swap_after_confinement_refuses(tmp_path, monkeypatch):
    root = tmp_path / 'root'
    outside = tmp_path / 'outside'
    nested = root / 'nested'
    nested.mkdir(parents=True)
    outside.mkdir()
    (nested / 'source.py').write_text('inside marker\n')
    (outside / 'source.py').write_text('outside marker\n')
    original = paths.confine
    checked = []

    def swap(base, candidate):
        confined = original(base, candidate)
        assert confined == nested / 'source.py'
        nested.rename(root / 'original')
        nested.symlink_to(outside, target_is_directory=True)
        checked.append(confined)
        return confined

    monkeypatch.setattr(paths, 'confine', swap)
    result = resolver._read_finding_source('nested/source.py', root)
    assert checked
    assert isinstance(result, resolver.ResolutionFailure)
    assert 'anchored source open refused' in result.reason
    assert (outside / 'source.py').read_text() == 'outside marker\n'


@pytest.mark.parametrize('spelling', ['relative', 'absolute', 'symlink'])
def test_rooted_read_preserves_bytes_and_in_root_links(tmp_path, spelling):
    source = tmp_path / 'source.py'
    source.write_bytes(b'one\r\ntwo\rthree\n')
    candidate = 'source.py'
    if spelling == 'absolute':
        candidate = str(source)
    elif spelling == 'symlink':
        link = tmp_path / 'link.py'
        link.symlink_to(source)
        candidate = 'link.py'
    assert resolver._read_finding_source(candidate, tmp_path) == 'one\r\ntwo\rthree\n'


@pytest.mark.parametrize('payload', [b'\xff', b'healthy\n'])
def test_rooted_decode_contract(tmp_path, payload):
    (tmp_path / 'source.py').write_bytes(payload)
    result = resolver._read_finding_source('source.py', tmp_path)
    if payload == b'\xff':
        assert isinstance(result, resolver.ResolutionFailure)
        assert 'cannot read' in result.reason
    else:
        assert result == 'healthy\n'


@pytest.mark.parametrize('primary', [OSError('primary read'), KeyboardInterrupt('primary read')])
def test_rooted_read_error_precedes_cleanup(tmp_path, monkeypatch, primary):
    source = tmp_path / 'source.py'
    source.write_text('owned\n')

    class Reader(io.BytesIO):
        def read(self, size=-1):
            assert size == 64 * 1024 * 1024 + 1
            raise primary

        def close(self):
            super().close()
            raise OSError('cleanup error')

    stream = Reader(b'owned\n')

    def anchored(root, relative, mode):
        assert root == tmp_path and relative == Path('source.py') and mode == 'rb'
        return stream

    monkeypatch.setattr(beneath, 'open_regular_beneath', anchored)
    if isinstance(primary, OSError):
        result = resolver._read_finding_source('source.py', tmp_path)
        assert isinstance(result, resolver.ResolutionFailure)
        assert 'primary read' in result.reason and 'cleanup error' not in result.reason
    else:
        with pytest.raises(KeyboardInterrupt) as caught:
            resolver._read_finding_source('source.py', tmp_path)
        assert caught.value is primary
    assert stream.closed
