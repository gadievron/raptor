"""Single compressed files share the facade's limits and loss accounting."""
import bz2
import gzip
import io
import lzma
import os
import tarfile
import zipfile

import pytest

from core import atomic_fs
from core.archive import compression, extract as extraction
from core.archive.errors import DecompressionLimitExceeded
from core.testing.module_bindings import patch_module_attribute

FORMATS = ['gz', 'bz2', 'xz', 'zst']


def compressed(root, fmt, payload):
    if fmt == 'zst':
        try:
            from compression import zstd
        except ImportError:
            pytest.skip('native Zstandard requires Python 3.14+')
        encode = zstd.compress
    else:
        encode = {'gz': gzip.compress, 'bz2': bz2.compress, 'xz': lzma.compress}[fmt]
    source = root / ('source.bin.' + fmt)
    source.write_bytes(encode(payload))
    return source


@pytest.mark.parametrize('fmt', FORMATS)
@pytest.mark.parametrize('size', [0, 511, 512, 513], ids=['empty', 'below', 'exact', 'above'])
@pytest.mark.parametrize('existing', [False, True], ids=['new', 'existing'])
def test_single_member_limit_edges_preserve_output_and_skip_accounting(tmp_path, fmt, size, existing):
    payload = b'p' * size
    source = compressed(tmp_path, fmt, payload)
    before = source.read_bytes()
    dest = tmp_path / 'output'
    dest.mkdir()
    target = dest / 'source.bin'
    if existing:
        target.write_bytes(b'previous complete output')
    stats = extraction.extract_to_dir(source, dest, max_files=1, max_member_bytes=512)
    assert source.read_bytes() == before
    assert stats['format'] == fmt
    if size > 512:
        assert stats == {'format': fmt, 'files': 0, 'bytes': 0, 'dropped': 1,
                         'dropped_reasons': {'oversized': 1}}
        if existing:
            assert target.read_bytes() == b'previous complete output'
        else:
            assert not target.exists()
    else:
        assert stats == {'format': fmt, 'files': 1, 'bytes': size, 'dropped': 0,
                         'dropped_reasons': {}}
        assert target.read_bytes() == payload
    assert list(dest.iterdir()) == ([target] if existing or size <= 512 else [])


@pytest.mark.parametrize('fmt', FORMATS)
@pytest.mark.parametrize('payload', [b'', b'payload'], ids=['empty', 'nonempty'])
def test_zero_file_limit_refuses_even_an_empty_single_member(tmp_path, monkeypatch, fmt, payload):
    source = compressed(tmp_path, fmt, payload)
    calls = []
    def forbidden(*args, **kwargs):
        calls.append(True)
        pytest.fail('zero-file extraction reached the output writer')
    monkeypatch.setattr(extraction, 'write_bytes_atomically', forbidden)
    dest = tmp_path / 'output'
    with pytest.raises(DecompressionLimitExceeded) as caught:
        extraction.extract_to_dir(source, dest, max_files=0)
    assert caught.value.cap == 'entry_count'
    assert calls == [] and list(dest.iterdir()) == []


@pytest.mark.parametrize('fmt', FORMATS)
@pytest.mark.parametrize('size', [0, 1])
def test_zero_member_budget_admits_only_empty_files(tmp_path, fmt, size):
    source = compressed(tmp_path, fmt, b'p' * size)
    dest = tmp_path / 'output'
    stats = extraction.extract_to_dir(source, dest, max_member_bytes=0)
    assert stats['files'] == (0 if size else 1)
    assert stats['bytes'] == 0
    assert stats['dropped_reasons'] == ({'oversized': 1} if size else {})
    assert len(list(dest.iterdir())) == (0 if size else 1)


@pytest.mark.parametrize('fmt', FORMATS)
@pytest.mark.parametrize('existing', [False, True])
def test_streamed_oversize_bounds_disk_writes_and_closes_decoder(tmp_path, monkeypatch, fmt, existing):
    source = compressed(tmp_path, fmt, b'p' * 2048)
    dest = tmp_path / 'output'
    dest.mkdir()
    target = dest / 'source.bin'
    if existing:
        target.write_bytes(b'previous complete output')
    monkeypatch.setattr(compression, '_CHUNK_BYTES', 64)
    retained, written = [], []
    original = extraction.iter_decompressed
    real_write = os.write
    def capture(*args, **kwargs):
        result = original(*args, **kwargs)
        retained.append(result)
        return result
    def write(fd, data):
        result = real_write(fd, data)
        written.append(result)
        return result
    monkeypatch.setattr(extraction, 'iter_decompressed', capture)
    patch_module_attribute(monkeypatch, atomic_fs, 'os', 'write', write)
    stats = extraction.extract_to_dir(source, dest, max_member_bytes=512)
    assert stats['files'] == 0 and stats['bytes'] == 0
    assert stats['dropped'] == 1 and stats['dropped_reasons'] == {'oversized': 1}
    assert sum(written) == 512  # Fault reached after real partial staging.
    assert len(retained) == 1 and retained[0].gi_frame is None
    if existing:
        assert target.read_bytes() == b'previous complete output'
    assert list(dest.iterdir()) == ([target] if existing else [])


@pytest.mark.parametrize('fmt', FORMATS)
def test_total_budget_still_refuses_before_oversize_skip(tmp_path, fmt):
    source = compressed(tmp_path, fmt, b'p' * 1024)
    dest = tmp_path / 'output'
    with pytest.raises(DecompressionLimitExceeded) as caught:
        extraction.extract_to_dir(source, dest, max_total_bytes=128, max_member_bytes=64)
    assert caught.value.cap == 'total_bytes'
    assert list(dest.iterdir()) == []


@pytest.mark.parametrize('fmt', ['zip', 'tar', 'tar.gz', 'tar.bz2', 'tar.xz'])
def test_container_oversize_accounting_remains_compatible(tmp_path, fmt):
    source = tmp_path / ('input.' + fmt)
    if fmt == 'zip':
        with zipfile.ZipFile(source, 'w') as writer:
            writer.writestr('source.bin', b'p' * 1024)
    else:
        with tarfile.open(source, 'w' if fmt == 'tar' else 'w:' + fmt.split('.')[1]) as writer:
            member = tarfile.TarInfo('source.bin')
            member.size = 1024
            writer.addfile(member, io.BytesIO(b'p' * 1024))
    dest = tmp_path / 'output'
    stats = extraction.extract_to_dir(source, dest, max_member_bytes=512)
    assert stats['files'] == 0 and stats['bytes'] == 0
    assert stats['dropped'] == 1 and stats['dropped_reasons'] == {'oversized': 1}
    assert list(dest.iterdir()) == []


def test_empty_zip_remains_valid_under_zero_file_budget(tmp_path):
    source = tmp_path / 'empty.zip'
    with zipfile.ZipFile(source, 'w'):
        pass
    stats = extraction.extract_to_dir(source, tmp_path / 'output', max_files=0)
    assert stats['files'] == 0 and stats['dropped'] == 0


@pytest.mark.parametrize('name', ['max_files', 'max_member_bytes', 'max_total_bytes'])
@pytest.mark.parametrize('value', [None, True, False, -1, 1.5, float('nan'), float('inf'), '1'])
def test_invalid_limits_refuse_before_input_or_output_access(tmp_path, monkeypatch, name, value):
    calls = []
    def forbidden(*args, **kwargs):
        calls.append(True)
        pytest.fail('invalid limits reached archive detection')
    monkeypatch.setattr(extraction, 'detect_format', forbidden)
    dest = tmp_path / 'output'
    with pytest.raises(ValueError, match=name):
        extraction.extract_to_dir(tmp_path / 'missing-input', dest, **{name: value})
    assert calls == [] and not dest.exists()
