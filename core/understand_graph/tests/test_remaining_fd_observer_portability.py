"""Remaining graph observers retain native identity through missing fd paths."""
import errno
import importlib
import os
import sqlite3

import pytest

from core.testing.module_bindings import patch_module_attribute

CASES = ["aggregate_reader", "foreign_fixture"]


def _module(kind):
    return importlib.import_module(
        "core.understand_graph.tests.test_" + kind + "_connection_ownership"
    )


def _observe(module, kind, path, identity):
    if kind == "foreign_fixture":
        return module._owned_fds(path, identity)
    return module._owned_fds(path)


def _fallback(module, monkeypatch):
    original = os.listdir
    seen = []

    def listdir(path):
        seen.append(path)
        if path == "/proc/self/fd":
            raise FileNotFoundError(path)
        return original(path) + ["1000000000", "not-a-descriptor"]

    patch_module_attribute(monkeypatch, module, "os", "listdir", listdir)
    return seen


@pytest.mark.parametrize("kind", CASES)
@pytest.mark.parametrize("fallback", [False, True])
def test_native_open_and_closed_identity(kind, fallback, tmp_path, monkeypatch):
    module = _module(kind)
    seen = _fallback(module, monkeypatch) if fallback else []
    target, other = tmp_path / "owned.sqlite", tmp_path / "other-owner"
    target.write_bytes(b"owned")
    other.write_bytes(b"borrowed")
    status = target.stat()
    identity = status.st_dev, status.st_ino
    with target.open("rb"), other.open("rb") as borrowed:
        assert _observe(module, kind, target, identity) == 1
        assert borrowed.read() == b"borrowed"
    assert _observe(module, kind, target, identity) == 0
    if fallback:
        assert "/proc/self/fd" in seen and "/dev/fd" in seen


@pytest.mark.parametrize("movement", ["unlink", "quarantine"])
def test_saved_identity_observes_old_sqlite_handle_after_path_replacement(
    movement, tmp_path, monkeypatch
):
    module = _module("foreign_fixture")
    _fallback(module, monkeypatch)
    path = tmp_path / "foreign.sqlite"
    connection = sqlite3.connect(path)
    cursor = None
    try:
        connection.execute("CREATE TABLE owned(value INTEGER)").close()
        connection.executemany("INSERT INTO owned VALUES (?)", [(1,), (2,)]).close()
        connection.commit()
        status = path.stat()
        identity = status.st_dev, status.st_ino
        cursor = connection.execute("SELECT value FROM owned")
        assert cursor.fetchone() == (1,)
        if movement == "unlink":
            path.unlink()
        else:
            path.rename(tmp_path / "quarantined.sqlite")
        assert not path.exists()
        connection.close()
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            connection.execute("SELECT 1")
        assert module._owned_fds(path, identity) > 0
        path.write_bytes(b"replacement owner")
        current = path.stat()
        assert (current.st_dev, current.st_ino) != identity
        with path.open("rb") as replacement:
            assert module._owned_fds(path, identity) > 0
            cursor = None
            assert module._owned_fds(path, identity) == 0
            assert replacement.read() == b"replacement owner"
    finally:
        cursor = None
        connection.close()


@pytest.mark.parametrize("kind", CASES)
def test_unavailable_observation_does_not_clear_ownership(kind, tmp_path, monkeypatch):
    module = _module(kind)
    path = tmp_path / "owned.sqlite"
    path.write_bytes(b"owned")
    status = path.stat()
    identity = status.st_dev, status.st_ino
    seen = []

    def missing(directory):
        seen.append(directory)
        raise FileNotFoundError(directory)

    patch_module_attribute(monkeypatch, module, "os", "listdir", missing)
    with path.open("rb"), pytest.raises(RuntimeError, match="observation is unavailable"):
        _observe(module, kind, path, identity)
    assert seen == ["/proc/self/fd", "/dev/fd"]


@pytest.mark.parametrize("kind", CASES)
def test_unexpected_fstat_error_remains_visible(kind, tmp_path, monkeypatch):
    module = _module(kind)
    _fallback(module, monkeypatch)
    path = tmp_path / "owned.sqlite"
    path.write_bytes(b"owned")
    status = path.stat()
    identity = status.st_dev, status.st_ino
    original = os.fstat
    failure = OSError(errno.EIO, "owned observation failure")
    with path.open("rb") as owned:
        def fstat(fd):
            if fd == owned.fileno():
                raise failure
            return original(fd)

        patch_module_attribute(monkeypatch, module, "os", "fstat", fstat)
        with pytest.raises(OSError) as caught:
            _observe(module, kind, path, identity)
        assert caught.value is failure
