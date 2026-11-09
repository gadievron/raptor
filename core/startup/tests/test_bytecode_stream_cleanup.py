"""Bytecode preparation owns descriptors before and after stream handoff."""

import errno
import importlib.util
import os

import pytest

from core.startup import install_guard as guard
from core.testing.module_bindings import patch_module_attribute


@pytest.fixture
def installation(tmp_path, monkeypatch):
    source = tmp_path / "example.py"
    source.write_text("value = 42\n")
    cache = type(source)(importlib.util.cache_from_source(str(source)))
    cache.parent.mkdir()
    cache.write_bytes(b"stale")
    monkeypatch.setattr(guard, "ROOT", tmp_path)
    return source, cache


@pytest.mark.parametrize("site", ["source", "cache", "writer"])
@pytest.mark.parametrize("error_type", [OSError, RuntimeError, KeyboardInterrupt, SystemExit])
def test_failed_stream_handoff_closes_raw_descriptor(
    installation, monkeypatch, site, error_type,
):
    source, cache = installation
    original = cache.read_bytes()
    real_fdopen = os.fdopen
    error = error_type("stream handoff failed")
    descriptors = []
    calls = 0

    def fdopen(fd, mode, **kwargs):
        nonlocal calls
        calls += 1
        if calls == (2 if site == "cache" else 1):
            descriptors.append(fd)
            raise error
        return real_fdopen(fd, mode, **kwargs)

    patch_module_attribute(monkeypatch, guard, "os", "fdopen", fdopen)
    try:
        with pytest.raises(error_type) as caught:
            if site == "writer":
                guard._save_bytecode(cache, b"replacement")
            else:
                list(guard._bytecode_sources())
        assert caught.value is error
        assert len(descriptors) == 1
        with pytest.raises(OSError) as closed:
            os.fstat(descriptors[0])
        assert closed.value.errno == errno.EBADF
        assert cache.read_bytes() == original
        assert not list(cache.parent.glob(".raptor-pyc-*"))
        assert source.read_text() == "value = 42\n"
    finally:
        for fd in descriptors:
            try:
                os.close(fd)
            except OSError:
                pass


@pytest.mark.parametrize("site", ["source", "cache", "writer"])
@pytest.mark.parametrize("error_type", [OSError, KeyboardInterrupt])
def test_body_error_survives_stream_close_failure(
    installation, monkeypatch, site, error_type,
):
    source, cache = installation
    error = error_type("bytecode IO failed")
    real_fdopen = os.fdopen
    opened = []
    calls = 0

    class Stream:
        def __init__(self, raw):
            self.raw = raw
            opened.append(raw)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.close()

        def fileno(self):
            return self.raw.fileno()

        def read(self, *args):
            raise error

        def write(self, *args):
            raise error

        def close(self):
            self.raw.close()
            raise RuntimeError("secondary close failure")

    def fdopen(fd, mode, **kwargs):
        nonlocal calls
        calls += 1
        raw = real_fdopen(fd, mode, **kwargs)
        return Stream(raw) if calls == (2 if site == "cache" else 1) else raw

    patch_module_attribute(monkeypatch, guard, "os", "fdopen", fdopen)
    with pytest.raises(error_type) as caught:
        if site == "writer":
            guard._save_bytecode(cache, b"replacement")
        else:
            list(guard._bytecode_sources())
    assert caught.value is error
    assert opened and all(raw.closed for raw in opened)
    assert cache.read_bytes() == b"stale"
    assert not list(cache.parent.glob(".raptor-pyc-*"))


def test_write_replacement_and_warm_generation(installation):
    source, cache = installation
    expected = guard._compile_bytecode(source.read_bytes(), str(source))
    guard._save_bytecode(cache, expected)
    assert cache.read_bytes() == expected
    before = cache.stat()
    guard._save_bytecode(cache, expected)
    assert cache.stat().st_ino == before.st_ino
    assert list(guard._bytecode_sources()) == []
    assert not list(cache.parent.glob(".raptor-pyc-*"))


def test_invalid_source_does_not_allocate_cache(tmp_path):
    cache = tmp_path / "absent" / "bad.pyc"
    guard._save_bytecode(cache, guard._compile_bytecode(b"def", "bad.py"))
    assert not cache.parent.exists()


def test_failed_handoff_preserves_error_when_raw_close_also_fails(installation, monkeypatch):
    _, cache = installation
    error = KeyboardInterrupt("handoff interrupted")
    real_close = os.close
    closed = []

    def fdopen(fd, mode):
        raise error

    def close(fd):
        real_close(fd)
        closed.append(fd)
        raise OSError("close notification failed")

    patch_module_attribute(monkeypatch, guard, "os", "fdopen", fdopen)
    patch_module_attribute(monkeypatch, guard, "os", "close", close)
    with pytest.raises(KeyboardInterrupt) as caught:
        guard._save_bytecode(cache, b"replacement")
    assert caught.value is error
    assert len(closed) == 1
    assert cache.read_bytes() == b"stale"
    assert not list(cache.parent.glob(".raptor-pyc-*"))


def test_replace_error_survives_staging_unlink_failure(installation, monkeypatch):
    _, cache = installation
    error = OSError("replacement failed")
    leftovers = []

    def replace(*args):
        raise error

    def unlink(path):
        leftovers.append(path)
        raise RuntimeError("unlink failed")

    patch_module_attribute(monkeypatch, guard, "os", "replace", replace)
    patch_module_attribute(monkeypatch, guard, "os", "unlink", unlink)
    try:
        with pytest.raises(OSError) as caught:
            guard._save_bytecode(cache, b"replacement")
        assert caught.value is error
        assert len(leftovers) == 1
        assert cache.read_bytes() == b"stale"
    finally:
        for path in leftovers:
            os.unlink(path)


def test_successful_write_still_requires_successful_close(installation, monkeypatch):
    _, cache = installation
    error = OSError("close failed")
    real_fdopen = os.fdopen
    opened = []

    class Stream:
        def __init__(self, raw):
            self.raw = raw
            opened.append(raw)

        def write(self, data):
            return self.raw.write(data)

        def close(self):
            self.raw.close()
            raise error

    patch_module_attribute(monkeypatch, guard, "os", "fdopen",
                           lambda *args: Stream(real_fdopen(*args)))
    with pytest.raises(OSError) as caught:
        guard._save_bytecode(cache, b"replacement")
    assert caught.value is error
    assert opened and all(raw.closed for raw in opened)
    assert cache.read_bytes() == b"stale"
    assert not list(cache.parent.glob(".raptor-pyc-*"))
