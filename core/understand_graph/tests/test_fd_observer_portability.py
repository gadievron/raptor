"""Native descriptor observers retain physical retirement checks without procfs."""
import errno
import importlib
import os
import sqlite3

import pytest

from core.testing.module_bindings import patch_module_attribute

CASES = [
    ("test_budget_fault_cursor_ownership", "_owned_fds"),
    ("test_edge_edit_connection_ownership", "_owned_fds"),
    ("test_fault_cursor_ownership", "_fd_count"),
    ("test_migration_fault_cursor_ownership", "_owned_fds"),
    ("test_rebuild_reader_connection_ownership", "_owned_fds"),
]


def _observer(name, attribute):
    module = importlib.import_module("core.understand_graph.tests." + name)
    return module, getattr(module, attribute)


def _fallback(module, monkeypatch):
    actual = os.listdir
    seen = []

    def listdir(path):
        seen.append(path)
        if path == "/proc/self/fd":
            raise FileNotFoundError(path)
        return actual(path) + ["1000000000", "not-a-descriptor"]

    patch_module_attribute(monkeypatch, module, "os", "listdir", listdir)
    return seen


@pytest.mark.parametrize("name,attribute", CASES)
@pytest.mark.parametrize("fallback", [False, True])
def test_native_descriptor_identity_excludes_unrelated_files(
    name, attribute, fallback, tmp_path, monkeypatch
):
    module, observe = _observer(name, attribute)
    seen = _fallback(module, monkeypatch) if fallback else []
    target, unrelated = tmp_path / "target.sqlite", tmp_path / "other.sqlite"
    assert observe(target) == 0
    target.write_bytes(b"owned target")
    unrelated.write_bytes(b"other owner")
    with target.open("rb"), unrelated.open("rb"):
        assert observe(target) == 1
        assert observe(unrelated) == 1
    assert observe(target) == 0
    assert observe(unrelated) == 0
    if fallback:
        assert "/proc/self/fd" in seen and "/dev/fd" in seen


@pytest.mark.parametrize("name,attribute", CASES)
def test_closed_connection_with_retained_cursor_remains_visible(
    name, attribute, tmp_path, monkeypatch
):
    module, observe = _observer(name, attribute)
    _fallback(module, monkeypatch)
    target = tmp_path / "retained.sqlite"
    connection = sqlite3.connect(target)
    cursor = None
    try:
        connection.execute("CREATE TABLE owned(value INTEGER)").close()
        connection.executemany("INSERT INTO owned VALUES (?)", [(1,), (2,)]).close()
        connection.commit()
        cursor = connection.execute("SELECT value FROM owned")
        assert cursor.fetchone() == (1,)
        connection.close()
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            connection.execute("SELECT 1")
        assert observe(target) > 0
        cursor = None
        assert observe(target) == 0
    finally:
        cursor = None
        connection.close()


@pytest.mark.parametrize("name,attribute", CASES)
def test_unavailable_descriptor_directories_fail_explicitly(
    name, attribute, tmp_path, monkeypatch
):
    module, observe = _observer(name, attribute)
    target = tmp_path / "owned.sqlite"
    target.write_bytes(b"owned")
    seen = []

    def missing(path):
        seen.append(path)
        raise FileNotFoundError(path)

    patch_module_attribute(monkeypatch, module, "os", "listdir", missing)
    with target.open("rb"), pytest.raises(RuntimeError, match="observation is unavailable"):
        observe(target)
    assert seen == ["/proc/self/fd", "/dev/fd"]


@pytest.mark.parametrize("name,attribute", CASES)
def test_unexpected_native_observation_error_is_not_hidden(
    name, attribute, tmp_path, monkeypatch
):
    module, observe = _observer(name, attribute)
    _fallback(module, monkeypatch)
    target = tmp_path / "owned.sqlite"
    target.write_bytes(b"owned")
    original = os.fstat
    failure = OSError(errno.EIO, "owned observation failed")
    with target.open("rb") as stream:
        def fstat(fd):
            if fd == stream.fileno():
                raise failure
            return original(fd)

        patch_module_attribute(monkeypatch, module, "os", "fstat", fstat)
        with pytest.raises(OSError) as caught:
            observe(target)
        assert caught.value is failure
