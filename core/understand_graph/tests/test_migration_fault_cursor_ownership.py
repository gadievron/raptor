"""Migration fault observers retire discarded native PRAGMA cursors."""

import errno
import os
import sqlite3
import traceback
from pathlib import Path
from types import FunctionType, SimpleNamespace

import pytest

from core.understand_graph.tests import test_migration_actor_connection_ownership as subject


def _owned_fds(path):
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


def _exercise(tmp_path, name, phase, base_error):
    errors = []
    connections = []
    events = []
    paths = set()

    class OwnedFault(base_error):
        def __init__(self, *args):
            super().__init__(*args)
            errors.append(self)

    def connected(path, *, factory=None, **kwargs):
        if factory is None:
            return sqlite3.connect(path, **kwargs)
        before = _owned_fds(path)

        class ObservedConnection(factory):
            def close(self):
                super().close()
                events.append((before, _owned_fds(path)))

        connection = sqlite3.connect(path, factory=ObservedConnection)
        connections.append(connection)
        paths.add(Path(path))
        return connection

    function = subject._exercise
    namespace = {**function.__globals__, "sqlite3": SimpleNamespace(**{
        **vars(sqlite3), "connect": connected,
    })}
    body = FunctionType(function.__code__, namespace, function.__name__, function.__defaults__, function.__closure__)
    body.__kwdefaults__ = function.__kwdefaults__
    try:
        body(tmp_path, name, phase, OwnedFault, True)
        assert len(errors) == 1
        assert len(events) == 1
        assert events[0][0] == 0
        assert events[0][1] == 0
    finally:
        for error in errors:
            if error.__traceback__ is not None:
                traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
        for connection in connections:
            sqlite3.Connection.close(connection)
        assert all(_owned_fds(path) == 0 for path in paths)


@pytest.mark.parametrize("name,phase", subject.ACTORS)
@pytest.mark.parametrize("base_error", [OSError, KeyboardInterrupt, SystemExit])
def test_discarded_migration_cursor_retires_before_traceback_cleanup(tmp_path, name, phase, base_error):
    _exercise(tmp_path, name, phase, base_error)
