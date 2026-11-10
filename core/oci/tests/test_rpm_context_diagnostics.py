"""Direct owned SQLite context diagnostics, without RPM/OCI parser workflows."""
from contextlib import contextmanager
from pathlib import Path
import sqlite3
import tempfile
from types import SimpleNamespace

import pytest

from core.oci import sbom as module


@pytest.fixture
def context_io(tmp_path, monkeypatch):
    seed = sqlite3.connect(":memory:")
    try:
        seed.execute("CREATE TABLE owned_probe(value TEXT)")
        seed.execute("INSERT INTO owned_probe VALUES ('plain')")
        seed.commit()
        content = seed.serialize()
    finally:
        seed.close()
    state = {"content": content, "connections": [], "paths": [], "closes": 0,
             "warnings": 0, "cleanup": None, "diagnostic": None, "events": []}
    native_warning = module.logger.warning

    @contextmanager
    def scratch(_prefix):
        with tempfile.TemporaryDirectory(prefix="owned-context-", dir=tmp_path) as directory:
            path = Path(directory)
            state["paths"].append(path)
            state["events"].append("scratch-enter")
            try:
                yield path
            finally:
                state["events"].append("scratch-exit")
        state["events"].append("scratch-retired")

    class Connection(sqlite3.Connection):
        def close(self):
            sqlite3.Connection.close(self)
            state["closes"] += 1
            state["events"].append("close")
            if state["cleanup"] is not None:
                raise state["cleanup"]

    def connected(*args, **kwargs):
        connection = sqlite3.connect(*args, **kwargs, factory=Connection)
        state["connections"].append(connection)
        state["events"].append("connect")
        return connection

    def warning(*args, **kwargs):
        with pytest.raises(sqlite3.ProgrammingError):
            state["connections"][0].execute("SELECT 1")
        native_warning(*args, **kwargs)
        state["warnings"] += 1
        state["events"].append("warning")
        if state["diagnostic"] is not None:
            raise state["diagnostic"]

    monkeypatch.setattr(module, "scratch_dir", scratch)
    monkeypatch.setattr(module, "sqlite3", SimpleNamespace(**{**vars(sqlite3), "connect": connected}))
    monkeypatch.setattr(module, "logger", SimpleNamespace(warning=warning))
    try:
        yield state
    finally:
        for connection in state["connections"]:
            sqlite3.Connection.close(connection)


def _assert_retired(state):
    assert state["closes"] == len(state["connections"]) == 1
    with pytest.raises(sqlite3.ProgrammingError):
        state["connections"][0].execute("SELECT 1")
    assert all(not path.exists() for path in state["paths"])
    assert state["events"].index("close") < state["events"].index("scratch-exit")


def test_secondary_close_warning_keeps_body_interruption(context_io):
    primary = KeyboardInterrupt("inside owned native SQLite context")
    context_io.update(cleanup=sqlite3.OperationalError("after native SQLite close"),
                      diagnostic=MemoryError("after native warning emission"))
    with pytest.raises(KeyboardInterrupt) as raised:
        with module._rpm_connection(context_io["content"]) as connection:
            assert connection.execute("SELECT value FROM owned_probe").fetchone() == ("plain",)
            raise primary
    assert raised.value is primary
    assert context_io["warnings"] == 1
    _assert_retired(context_io)


@pytest.mark.parametrize("primary_type", [RuntimeError, MemoryError, SystemExit])
@pytest.mark.parametrize("close_type", [sqlite3.OperationalError, KeyboardInterrupt])
@pytest.mark.parametrize("diagnostic_type", [OSError, MemoryError, KeyboardInterrupt])
def test_secondary_diagnostic_keeps_original_body_error(context_io, primary_type, close_type, diagnostic_type):
    primary = primary_type("inside owned SQLite context")
    context_io.update(cleanup=close_type("after native close"),
                      diagnostic=diagnostic_type("after native warning emission"))
    with pytest.raises(primary_type) as raised:
        with module._rpm_connection(context_io["content"]) as connection:
            assert connection.execute("SELECT value FROM owned_probe").fetchone() == ("plain",)
            raise primary
    assert raised.value is primary
    assert context_io["warnings"] == 1
    _assert_retired(context_io)


@pytest.mark.parametrize("primary_type", [RuntimeError, KeyboardInterrupt])
def test_normal_secondary_warning_is_still_emitted(context_io, primary_type):
    primary = primary_type("inside owned SQLite context")
    context_io["cleanup"] = sqlite3.OperationalError("after native close")
    with pytest.raises(primary_type) as raised:
        with module._rpm_connection(context_io["content"]):
            raise primary
    assert raised.value is primary
    assert context_io["warnings"] == 1
    _assert_retired(context_io)


@pytest.mark.parametrize("close_type", [sqlite3.OperationalError, KeyboardInterrupt, SystemExit])
def test_fresh_native_close_failure_stays_visible_without_warning(context_io, close_type):
    cleanup = close_type("after native close")
    context_io.update(cleanup=cleanup, diagnostic=MemoryError("must not warn"))
    with pytest.raises(close_type) as raised:
        with module._rpm_connection(context_io["content"]) as connection:
            assert connection.execute("SELECT value FROM owned_probe").fetchone() == ("plain",)
    assert raised.value is cleanup
    assert context_io["warnings"] == 0
    _assert_retired(context_io)


@pytest.mark.parametrize("primary_type", [RuntimeError, KeyboardInterrupt])
def test_body_error_with_healthy_close_never_warns(context_io, primary_type):
    primary = primary_type("inside owned SQLite context")
    context_io["diagnostic"] = MemoryError("must not warn")
    with pytest.raises(primary_type) as raised:
        with module._rpm_connection(context_io["content"]):
            raise primary
    assert raised.value is primary
    assert context_io["warnings"] == 0
    _assert_retired(context_io)


def test_native_context_remains_read_only_and_retires_cursor(context_io):
    with module._rpm_connection(context_io["content"]) as connection:
        cursor = connection.execute("SELECT value FROM owned_probe")
        assert cursor.fetchone() == ("plain",)
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            connection.execute("INSERT INTO owned_probe VALUES ('refused')")
    with pytest.raises(sqlite3.ProgrammingError):
        cursor.fetchone()
    assert context_io["warnings"] == 0
    _assert_retired(context_io)
