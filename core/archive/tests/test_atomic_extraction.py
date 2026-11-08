"""Archive output is published whole, with no abandoned staging files."""
import bz2
import errno
import gzip
import io
import lzma
import os
import stat
import tarfile
import zipfile

import pytest

from core import atomic_fs
from core.archive import extract_to_dir
from core.testing.module_bindings import patch_module_attribute

FORMATS = ['zip', 'tar', 'tar.gz', 'tar.bz2', 'tar.xz', 'gz', 'bz2', 'xz']
PAYLOAD = b'complete member contents\n' * 100


def archive(root, fmt, name='member.bin'):
    source = root / ('member.bin.' + fmt)
    if fmt == 'zip':
        with zipfile.ZipFile(source, 'w') as writer:
            writer.writestr(name, PAYLOAD)
    elif fmt.startswith('tar'):
        with tarfile.open(source, 'w' if fmt == 'tar' else 'w:' + fmt.split('.')[1]) as writer:
            info = tarfile.TarInfo(name)
            info.size = len(PAYLOAD)
            writer.addfile(info, io.BytesIO(PAYLOAD))
    else:
        source.write_bytes({'gz': gzip.compress, 'bz2': bz2.compress, 'xz': lzma.compress}[fmt](PAYLOAD))
    return source


@pytest.mark.parametrize('fmt', FORMATS)
@pytest.mark.parametrize('existing', [False, True], ids=['new', 'replace'])
@pytest.mark.parametrize('stage', ['open', 'write', 'fsync', 'close', 'publish'])
@pytest.mark.parametrize('failure_type', [OSError, KeyboardInterrupt, SystemExit])
def test_failed_member_never_publishes_partial_output(tmp_path, monkeypatch, fmt, existing, stage, failure_type):
    source = archive(tmp_path, fmt)
    original_source = source.read_bytes()
    dest = tmp_path / 'output'
    dest.mkdir()
    target = dest / 'member.bin'
    if existing:
        target.write_bytes(b'previous complete output')
        target.chmod(0o640)
    failure = (OSError(errno.EIO, 'injected output failure') if failure_type is OSError
               else failure_type('injected output failure'))
    outputs, reached = set(), []
    real_open, real_write, real_close, real_sync = os.open, os.write, os.close, os.fsync

    def open_output(path, flags, *args, **kwargs):
        if flags & os.O_CREAT and stage == 'open':
            reached.append(stage)
            raise failure
        fd = real_open(path, flags, *args, **kwargs)
        if flags & os.O_CREAT:
            outputs.add(fd)
        return fd

    def write(fd, data):
        if fd in outputs and stage == 'write':
            real_write(fd, data[:1])
            reached.append(stage)
            raise failure
        return real_write(fd, data)

    def sync(fd):
        if fd in outputs and stage == 'fsync':
            reached.append(stage)
            raise failure
        return real_sync(fd)

    def close(fd):
        real_close(fd)
        if fd in outputs:
            outputs.remove(fd)
            if stage == 'close':
                reached.append(stage)
                raise failure

    def publish(*args, **kwargs):
        reached.append(stage)
        raise failure

    patch_module_attribute(monkeypatch, atomic_fs, 'os', 'open', open_output)
    patch_module_attribute(monkeypatch, atomic_fs, 'os', 'write', write)
    patch_module_attribute(monkeypatch, atomic_fs, 'os', 'fsync', sync)
    patch_module_attribute(monkeypatch, atomic_fs, 'os', 'close', close)
    if stage == 'publish':
        patch_module_attribute(monkeypatch, atomic_fs, 'os', 'replace', publish)
    with pytest.raises(failure_type) as caught:
        extract_to_dir(source, dest)
    assert caught.value is failure
    assert reached == [stage]
    assert outputs == set()
    assert source.read_bytes() == original_source
    if existing:
        assert target.read_bytes() == b'previous complete output'
        assert stat.S_IMODE(target.stat().st_mode) == 0o640
        assert list(dest.iterdir()) == [target]
    else:
        assert list(dest.iterdir()) == []


@pytest.mark.parametrize('fmt', FORMATS)
@pytest.mark.parametrize('existing', [False, True])
def test_short_writes_publish_every_byte_and_preserve_modes(tmp_path, monkeypatch, fmt, existing):
    source = archive(tmp_path, fmt)
    dest = tmp_path / 'output'
    dest.mkdir()
    target = dest / 'member.bin'
    if existing:
        target.write_bytes(b'previous')
        target.chmod(0o640)
    real_write = os.write
    sizes = []
    def short_write(fd, data):
        count = real_write(fd, data[:17])
        sizes.append(count)
        return count
    patch_module_attribute(monkeypatch, atomic_fs, 'os', 'write', short_write)
    stats = extract_to_dir(source, dest)
    assert len(sizes) > 1 and sum(sizes) == len(PAYLOAD)
    assert target.read_bytes() == PAYLOAD
    assert stat.S_IMODE(target.stat().st_mode) == (0o640 if existing else 0o644)
    assert list(dest.iterdir()) == [target]
    assert stats['files'] == 1 and stats['bytes'] == len(PAYLOAD)
    assert stats['dropped'] == 0


@pytest.mark.parametrize('fmt', FORMATS)
def test_zero_progress_write_aborts_without_output(tmp_path, monkeypatch, fmt):
    source = archive(tmp_path, fmt)
    calls = []
    def stalled(fd, data):
        calls.append(len(data))
        return 0
    patch_module_attribute(monkeypatch, atomic_fs, 'os', 'write', stalled)
    dest = tmp_path / 'output'
    with pytest.raises(OSError, match='no progress'):
        extract_to_dir(source, dest)
    assert calls and list(dest.iterdir()) == []


@pytest.mark.parametrize('fmt', ['zip', 'tar', 'tar.gz'])
@pytest.mark.parametrize('error', [errno.EINVAL, errno.EILSEQ])
def test_mid_write_path_like_errno_is_not_reported_as_dropped(tmp_path, monkeypatch, fmt, error):
    source = archive(tmp_path, fmt)
    failure = OSError(error, 'write failure after admission')
    calls = []
    def fail(fd, data):
        calls.append(fd)
        raise failure
    patch_module_attribute(monkeypatch, atomic_fs, 'os', 'write', fail)
    dest = tmp_path / 'output'
    with pytest.raises(OSError) as caught:
        extract_to_dir(source, dest)
    assert caught.value is failure
    assert len(calls) == 1 and list(dest.iterdir()) == []


@pytest.mark.parametrize('fmt', ['zip', 'tar', 'tar.gz'])
@pytest.mark.parametrize('kind', ['ascii', 'utf8'])
def test_valid_maximum_length_member_names_are_not_lost(tmp_path, fmt, kind):
    try:
        limit = os.pathconf(tmp_path, 'PC_NAME_MAX')
    except (AttributeError, OSError, ValueError):
        limit = 255
    count = min(limit, 255)
    if count < 80:
        pytest.skip('filesystem component limit is too small for this case')
    name = ('x' * count if kind == 'ascii' else 'é' * (count // 2) + 'x' * (count % 2))
    source = archive(tmp_path, fmt, name)
    dest = tmp_path / 'output'
    stats = extract_to_dir(source, dest)
    assert stats['files'] == 1 and stats['dropped'] == 0
    assert (dest / name).read_bytes() == PAYLOAD
    assert len(list(dest.iterdir())) == 1


@pytest.mark.parametrize('fmt', ['zip', 'tar', 'tar.gz'])
@pytest.mark.parametrize('conflict', ['directory', 'parent-file'])
def test_path_conflicts_preserve_bystanders_and_count_skips(tmp_path, fmt, conflict):
    dest = tmp_path / 'output'
    dest.mkdir()
    blocked = dest / 'blocked'
    if conflict == 'directory':
        blocked.mkdir()
        bystander = blocked / 'keep'
        bystander.write_bytes(b'keep me')
        invalid = 'blocked'
    else:
        blocked.write_bytes(b'keep me')
        bystander = blocked
        invalid = 'blocked/child'
    source = tmp_path / ('input.' + fmt)
    members = [(invalid, b'bad'), ('valid', b'good')]
    if fmt == 'zip':
        with zipfile.ZipFile(source, 'w') as writer:
            for name, data in members:
                writer.writestr(name, data)
    else:
        with tarfile.open(source, 'w' if fmt == 'tar' else 'w:gz') as writer:
            for name, data in members:
                info = tarfile.TarInfo(name)
                info.size = len(data)
                writer.addfile(info, io.BytesIO(data))
    stats = extract_to_dir(source, dest)
    assert stats['files'] == 1 and stats['bytes'] == 7
    assert stats['dropped'] == 1 and stats['dropped_reasons'] == {'unwritable': 1}
    assert bystander.read_bytes() == b'keep me'
    assert (dest / 'valid').read_bytes() == b'good'
    assert sorted(p.name for p in dest.iterdir()) == ['blocked', 'valid']
