"""Offline blob IO owns all directory and file handles until handoff settles."""

import errno
import hashlib
import os
from types import SimpleNamespace

import pytest

from core.oci import evidence_source
from core.oci.manifest import LayerDescriptor
from core.source import streams
from core.testing.module_bindings import patch_module_attribute


def assert_gone(records):
    for fd, _ in records:
        with pytest.raises(OSError) as caught:
            os.fstat(fd)
        assert caught.value.errno == errno.EBADF


@pytest.fixture
def layer_case(tmp_path, monkeypatch):
    payload = b"owned bytes" * 10000
    digest = hashlib.sha256(payload).hexdigest()
    blobs = tmp_path / "blobs" / "sha256"
    blobs.mkdir(parents=True)
    (blobs / digest).write_bytes(payload)
    layer = LayerDescriptor("sha256:" + digest, len(payload), "application/vnd.oci.image.layer.v1.tar")
    records, directories_closed, raw_streams = [], [], []
    real_open, real_close, real_fdopen, real_fstat = os.open, os.close, os.fdopen, os.fstat

    def install(stage=None, error=None, cleanup=None):
        open_calls = 0

        def opened(*args, **kwargs):
            nonlocal open_calls
            open_calls += 1
            if stage == f"open{open_calls}":
                raise error
            fd = real_open(*args, **kwargs)
            info = real_fstat(fd)
            records.append((fd, (info.st_dev, info.st_ino)))
            return fd

        def close(fd):
            real_close(fd)
            directories_closed.append(fd)
            if cleanup is not None and len(directories_closed) == 1:
                raise cleanup

        class Stream:
            def __init__(self, raw):
                self.raw = raw
                raw_streams.append(raw)

            def __getattr__(self, name):
                return getattr(self.raw, name)

            def read(self, *args):
                if stage == "read":
                    raise error
                return self.raw.read(*args)

            def close(self):
                self.raw.close()

        def wrap(*args, **kwargs):
            if stage == "wrap":
                raise error
            return Stream(real_fdopen(*args, **kwargs))

        def fstat(fd):
            if stage == "fstat":
                raise error
            return real_fstat(fd)

        patch_module_attribute(monkeypatch, evidence_source, "os", "open", opened)
        patch_module_attribute(monkeypatch, evidence_source, "os", "close", close)
        patch_module_attribute(monkeypatch, evidence_source, "os", "fstat", fstat)
        patch_module_attribute(monkeypatch, streams, "os", "fdopen", wrap)
        return SimpleNamespace(
            invoke=lambda: evidence_source.layout_reader(tmp_path)(layer),
            records=records, closed=directories_closed, payload=payload,
        )

    yield install
    for stream in raw_streams:
        stream.close()
    for fd, identity in records:
        try:
            info = real_fstat(fd)
        except OSError:
            continue
        if (info.st_dev, info.st_ino) == identity:
            real_close(fd)


@pytest.mark.parametrize("stage", ["open1", "open2", "open3", "open4", "wrap", "fstat", "read"])
@pytest.mark.parametrize("error_type", [OSError, RuntimeError, KeyboardInterrupt, SystemExit])
def test_layer_setup_and_read_errors_release_all_owned_handles(layer_case, stage, error_type):
    error = error_type("offline layer IO failed")
    owned = layer_case(stage, error)
    with pytest.raises(error_type) as caught:
        list(owned.invoke())
    assert caught.value is error
    assert_gone(owned.records)


@pytest.mark.parametrize("stage", ["wrap", "read"])
@pytest.mark.parametrize("body_type", [RuntimeError, KeyboardInterrupt])
@pytest.mark.parametrize("cleanup_type", [OSError, RuntimeError])
def test_layer_primary_error_survives_directory_cleanup(
    layer_case, stage, body_type, cleanup_type,
):
    error = body_type("primary layer failure")
    owned = layer_case(stage, error, cleanup=cleanup_type("directory cleanup failed"))
    with pytest.raises(body_type) as caught:
        list(owned.invoke())
    assert caught.value is error
    assert len(owned.records) == 4 and len(owned.closed) == 3
    assert len(set(owned.closed)) == 3
    assert_gone(owned.records)


@pytest.mark.parametrize("finish", ["eof", "close", "throw"])
def test_layer_stream_roundtrip_and_early_close_release_all_handles(layer_case, finish):
    owned = layer_case()
    iterator = owned.invoke()
    try:
        if finish == "eof":
            chunks = list(iterator)
            assert b"".join(chunks) == owned.payload
            assert all(len(chunk) <= 65536 for chunk in chunks)
        else:
            assert next(iterator) == owned.payload[:65536]
            if finish == "close":
                iterator.close()
            else:
                error = GeneratorExit("consumer stopped")
                with pytest.raises(GeneratorExit) as caught:
                    iterator.throw(error)
                assert caught.value is error
        assert len(owned.records) == 4 and len(owned.closed) == 3
        assert_gone(owned.records)
    finally:
        iterator.close()


@pytest.mark.parametrize("cleanup_type", [OSError, KeyboardInterrupt])
def test_explicit_iterator_close_reports_cleanup_failure_after_all_attempts(layer_case, cleanup_type):
    error = cleanup_type("directory close failed")
    owned = layer_case(cleanup=error)
    iterator = owned.invoke()
    try:
        assert next(iterator) == owned.payload[:65536]
        with pytest.raises(cleanup_type) as caught:
            iterator.close()
        assert caught.value is error
        assert len(owned.closed) == 3 and len(set(owned.closed)) == 3
        assert_gone(owned.records)
    finally:
        iterator.close()
