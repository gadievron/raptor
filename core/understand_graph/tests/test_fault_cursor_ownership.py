"""Fault observers dispose SELECT cursors before propagating owned errors."""

import errno
import os
import sqlite3
import threading
import traceback
from pathlib import Path
from types import FunctionType, SimpleNamespace

import pytest

from core.understand_graph import store as actual_store
from core.understand_graph.tests import test_backfill_connection_ownership as backfill
from core.understand_graph.tests import test_wal_fixture_connection_ownership as wal

from core.testing.state_isolation import pin_user_state_dirs


@pytest.fixture(autouse=True)
def _user_state_in_tmp(tmp_path):
    with pytest.MonkeyPatch.context() as patch:
        pin_user_state_dirs(patch, tmp_path / "user")
        patch.setenv("HOME", str(tmp_path / "home"))
        patch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg-data"))
        patch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg-config"))
        patch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg-cache"))
        yield



def _fd_count(path):
    try:
        target = Path(path).stat()
    except FileNotFoundError:
        return 0
    for directory in ("/proc/self/fd", "/dev/fd"):
        try:
            names = os.listdir(directory)
            break
        except FileNotFoundError:
            continue
    else:
        raise RuntimeError("native descriptor observation is unavailable")
    count = 0
    for name in names:
        if not name.isdecimal():
            continue
        try:
            status = os.fstat(int(name))
        except OSError as exc:
            if exc.errno != errno.EBADF:
                raise
            continue
        count += (status.st_dev, status.st_ino) == (target.st_dev, target.st_ino)
    return count


def _probe(tmp_path, consumer, base_error):
    errors = []
    connections = []
    events = []
    paths = set()
    main = threading.current_thread()
    main_opens = 0

    class OwnedFault(base_error):
        def __init__(self, *args):
            super().__init__(*args)
            errors.append(self)

    class BackfillConnection(sqlite3.Connection):
        def close(self):
            super().close()
            if self.observe and not self.recorded:
                self.recorded = True
                events.append({"before": self.before, "after": _fd_count(self.path)})

    def connected(path):
        before = _fd_count(path)
        connection = sqlite3.connect(path, factory=BackfillConnection)
        connection.path = Path(path)
        connection.before = before
        connection.observe = not connections
        connection.recorded = False
        connections.append(connection)
        paths.add(Path(path))
        return connection

    class WalConnection:
        def __init__(self, connection, path, before, observe):
            self.connection = connection
            self.path = Path(path)
            self.before = before
            self.observe = observe
            self.recorded = False

        def __getattr__(self, name):
            return getattr(self.connection, name)

        def close(self):
            self.connection.close()
            if self.observe and not self.recorded:
                self.recorded = True
                events.append({"before": self.before, "after": _fd_count(self.path)})

    def opened(path):
        nonlocal main_opens
        if threading.current_thread() is not main:
            return actual_store.open_graph(path)
        before = _fd_count(path)
        connection = actual_store.open_graph(path)
        connections.append(connection)
        paths.add(Path(path))
        proxy = WalConnection(connection, path, before, main_opens == 1)
        main_opens += 1
        return proxy

    subject = backfill if consumer == "backfill" else wal
    namespace = dict(subject._exercise.__globals__)
    if consumer == "backfill":
        namespace["sqlite3"] = SimpleNamespace(**{**vars(sqlite3), "connect": connected})
    else:
        namespace["store"] = SimpleNamespace(**{**vars(actual_store), "open_graph": opened})
    function = subject._exercise
    body = FunctionType(function.__code__, namespace, function.__name__, function.__defaults__, function.__closure__)
    body.__kwdefaults__ = function.__kwdefaults__
    try:
        body(tmp_path, "select" if consumer == "backfill" else "read", OwnedFault, True)
        assert len(errors) == 1
        assert len(events) == 1
        assert events[0]["before"] == 0
        assert events[0]["after"] == 0
    finally:
        # Dispose only tracebacks from this test's owned injected fault.
        # No global GC, module replacement or borrowed exception reset.
        for error in errors:
            if error.__traceback__ is not None:
                traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
        for connection in connections:
            sqlite3.Connection.close(connection)
        assert all(_fd_count(path) == 0 for path in paths)
    return events


@pytest.mark.parametrize("consumer", ["backfill", "wal"])
@pytest.mark.parametrize("base_error", [OSError, KeyboardInterrupt, SystemExit])
def test_discarded_cursor_retires_descriptor_before_error_cleanup(tmp_path, consumer, base_error):
    _probe(tmp_path, consumer, base_error)
