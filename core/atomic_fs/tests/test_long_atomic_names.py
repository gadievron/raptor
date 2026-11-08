"""Atomic staging fits valid long filenames and retains descriptor ownership."""
from concurrent.futures import ThreadPoolExecutor
import errno
import os
import threading

import pytest

from core import atomic_fs as fs
from core.testing.module_bindings import patch_module_attribute


def long_name(root, kind):
    try:
        limit = os.pathconf(root, 'PC_NAME_MAX')
    except (AttributeError, OSError, ValueError):
        limit = 255
    if limit <= 0:
        limit = 255
    if limit < 80:
        pytest.skip('test filesystem cannot accommodate conventional staging metadata')
    length = min(limit, 255) - len('.bin')
    return ('x' * length if kind == 'ascii' else 'é' * (length // 2) + 'x' * (length % 2)) + '.bin'


def write(target, kind, *, root, replace=True, prefix='.atomic-'):
    kwargs = {'replace': replace, 'tmp_prefix': prefix}
    if root is not None:
        kwargs['root'] = root
    if kind == 'text':
        fs.write_text_atomically(target, 'new é\n', **kwargs)
        return 'new é\n'.encode()
    payload = b'new payload'
    fs.write_bytes_atomically(target, payload if kind == 'bytes' else iter([b'new ', b'payload']), **kwargs)
    return payload


@pytest.mark.parametrize('anchored', [False, True], ids=['by-name', 'anchored'])
@pytest.mark.parametrize('name_kind', ['ascii', 'utf8'])
@pytest.mark.parametrize('content_kind', ['bytes', 'text', 'chunks'])
@pytest.mark.parametrize('scenario', ['new-replace', 'new-exclusive', 'existing-replace', 'existing-exclusive'])
def test_long_destinations_keep_atomic_replace_and_exclusive_semantics(tmp_path, anchored, name_kind, content_kind, scenario):
    target = tmp_path / long_name(tmp_path, name_kind)
    if scenario.startswith('existing'):
        target.write_bytes(b'original')
        target.chmod(0o640)
    root = tmp_path if anchored else None
    replace = scenario.endswith('replace')
    if scenario == 'existing-exclusive':
        with pytest.raises(FileExistsError):
            write(target, content_kind, root=root, replace=False)
        assert target.read_bytes() == b'original'
    else:
        expected = write(target, content_kind, root=root, replace=replace)
        assert target.read_bytes() == expected
        assert target.stat().st_mode & 0o777 == (0o640 if scenario.startswith('existing') else 0o644)
    assert len(list(tmp_path.iterdir())) == 1


@pytest.mark.parametrize('anchored', [False, True], ids=['by-name', 'anchored'])
@pytest.mark.parametrize('failure_type', [OSError, KeyboardInterrupt, SystemExit])
def test_interrupted_long_name_write_keeps_previous_content_and_reclaims_staging(tmp_path, anchored, failure_type):
    target = tmp_path / long_name(tmp_path, 'utf8')
    target.write_bytes(b'original')
    primary = failure_type('primary write failure')
    def chunks():
        yield b'partial'
        raise primary
    with pytest.raises(failure_type) as caught:
        fs.write_bytes_atomically(target, chunks(), root=tmp_path if anchored else None)
    assert caught.value is primary
    assert target.read_bytes() == b'original'
    assert len(list(tmp_path.iterdir())) == 1


@pytest.mark.parametrize('anchored', [False, True], ids=['by-name', 'anchored'])
def test_occupied_long_name_stage_is_never_removed_or_overwritten(tmp_path, monkeypatch, anchored):
    target = tmp_path / long_name(tmp_path, 'ascii')
    target.write_bytes(b'original')
    patch_module_attribute(monkeypatch, fs, 'secrets', 'token_hex', lambda count: 'fixed')
    name = fs._atomic_temporary_name(target.name, '.atomic-', 'fixed', tmp_path)
    staging = tmp_path / name
    staging.write_bytes(b'bystander')
    with pytest.raises(FileExistsError):
        fs.write_bytes_atomically(target, b'new', root=tmp_path if anchored else None)
    assert staging.read_bytes() == b'bystander'
    assert target.read_bytes() == b'original'
    assert len(list(tmp_path.iterdir())) == 2


@pytest.mark.parametrize('anchored', [False, True], ids=['by-name', 'anchored'])
@pytest.mark.parametrize('limit', [128, 255])
def test_reported_filesystem_limit_controls_staging_components(tmp_path, monkeypatch, anchored, limit):
    target = tmp_path / ('x' * 120)
    original_open = os.open
    created = []
    def opened(path, flags, *args, **kwargs):
        if flags & os.O_CREAT:
            from pathlib import Path
            name = Path(path).name
            assert len(os.fsencode(name)) <= limit
            created.append(name)
        return original_open(path, flags, *args, **kwargs)
    patch_module_attribute(monkeypatch, fs, 'os', 'fpathconf' if anchored else 'pathconf', lambda *args: limit)
    patch_module_attribute(monkeypatch, fs, 'os', 'open', opened)
    fs.write_bytes_atomically(target, b'complete', root=tmp_path if anchored else None)
    assert created and len(created) == 1
    assert target.read_bytes() == b'complete'
    assert len(list(tmp_path.iterdir())) == 1


@pytest.mark.parametrize('anchored', [False, True], ids=['by-name', 'anchored'])
@pytest.mark.parametrize('result', ['missing', 'io', 'invalid', 'unbounded'])
def test_unknown_capacity_uses_a_bounded_portable_fallback(tmp_path, monkeypatch, anchored, result):
    target = tmp_path / long_name(tmp_path, 'ascii')
    def capacity(*args):
        if result == 'missing':
            raise AttributeError('no capacity API')
        if result == 'io':
            raise OSError(errno.EINVAL, 'capacity unavailable')
        if result == 'invalid':
            raise ValueError('capacity unavailable')
        return -1
    patch_module_attribute(monkeypatch, fs, 'os', 'fpathconf' if anchored else 'pathconf', capacity, raising=False)
    fs.write_bytes_atomically(target, b'complete', root=tmp_path if anchored else None)
    assert target.read_bytes() == b'complete'
    assert len(list(tmp_path.iterdir())) == 1


@pytest.mark.parametrize('anchored', [False, True], ids=['by-name', 'anchored'])
def test_short_staging_names_keep_the_existing_layout(tmp_path, monkeypatch, anchored):
    target = tmp_path / 'short.bin'
    patch_module_attribute(monkeypatch, fs, 'secrets', 'token_hex', lambda count: 'fixed')
    expected = f'.owned-{target.name}.{os.getpid()}.{threading.get_ident()}.fixed.tmp'
    assert fs._atomic_temporary_name(target.name, '.owned-', 'fixed', tmp_path) == expected
    write(target, 'bytes', root=tmp_path if anchored else None, prefix='.owned-')
    assert target.read_bytes() == b'new payload'
    assert len(list(tmp_path.iterdir())) == 1


@pytest.mark.parametrize('anchored', [False, True], ids=['by-name', 'anchored'])
@pytest.mark.parametrize('prefix', ['.custom-', '.' + 'p' * 230])
def test_long_custom_prefixes_still_get_bounded_staging(tmp_path, anchored, prefix):
    target = tmp_path / long_name(tmp_path, 'utf8')
    write(target, 'bytes', root=tmp_path if anchored else None, prefix=prefix)
    assert target.read_bytes() == b'new payload'
    assert len(list(tmp_path.iterdir())) == 1


@pytest.mark.parametrize('anchored', [False, True], ids=['by-name', 'anchored'])
@pytest.mark.parametrize('prefix', ['../escape/', '/absolute/', 'bad\x00prefix'], ids=['traversal', 'absolute', 'nul'])
def test_fallback_never_admits_an_invalid_prefix(tmp_path, anchored, prefix):
    target = tmp_path / long_name(tmp_path, 'ascii')
    with pytest.raises(ValueError):
        write(target, 'bytes', root=tmp_path if anchored else None, prefix=prefix)
    assert not target.exists()
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize('phase', ['nonce', 'name'])
@pytest.mark.parametrize('primary_type', [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize('cleanup_type', [OSError, KeyboardInterrupt, SystemExit])
def test_anchored_staging_setup_preserves_primary_and_releases_parent_fd(tmp_path, monkeypatch, phase, primary_type, cleanup_type):
    target = tmp_path / 'data'
    target.write_bytes(b'original')
    primary = primary_type('primary setup failure')
    closed = []
    original_close = os.close
    def fail(*args, **kwargs):
        raise primary
    def close(fd):
        original_close(fd)
        closed.append(fd)
        raise cleanup_type('secondary close failure')
    if phase == 'nonce':
        patch_module_attribute(monkeypatch, fs, 'secrets', 'token_hex', fail)
    else:
        monkeypatch.setattr(fs, '_atomic_temporary_name', fail)
    patch_module_attribute(monkeypatch, fs, 'os', 'close', close)
    with pytest.raises(primary_type) as caught:
        fs.write_bytes_atomically(target, b'new', root=tmp_path)
    assert caught.value is primary
    assert len(closed) == 1
    with pytest.raises(OSError):
        os.fstat(closed[0])
    assert target.read_bytes() == b'original'
    assert len(list(tmp_path.iterdir())) == 1


@pytest.mark.parametrize('anchored', [False, True], ids=['by-name', 'anchored'])
def test_distinct_long_destinations_have_independent_live_staging_names(tmp_path, monkeypatch, anchored):
    base = long_name(tmp_path, 'ascii')
    first, second = tmp_path / base, tmp_path / ('y' + base[1:])
    patch_module_attribute(monkeypatch, fs, 'secrets', 'token_hex', lambda count: 'fixed')
    ready, release = threading.Event(), threading.Event()
    errors = []
    def blocks():
        yield b'first '
        ready.set()
        assert release.wait(10), 'owner did not release the writer'
        yield b'complete'
    def owner():
        try:
            fs.write_bytes_atomically(first, blocks(), root=tmp_path if anchored else None)
        except BaseException as exc:
            errors.append(exc)
    with ThreadPoolExecutor(max_workers=1) as pool:
        try:
            future = pool.submit(owner)
            assert ready.wait(10), f'writer did not reach live staging: {errors!r}'
            fs.write_bytes_atomically(second, b'second complete', root=tmp_path if anchored else None)
        finally:
            release.set()
        future.result(timeout=10)
    assert errors == []
    assert first.read_bytes() == b'first complete'
    assert second.read_bytes() == b'second complete'
    assert len(list(tmp_path.iterdir())) == 2
