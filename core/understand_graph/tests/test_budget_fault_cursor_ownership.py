"""Budget-reader fault observers retire discarded native SELECT cursors."""

import errno
import os
import sqlite3
import traceback
from pathlib import Path
from types import FunctionType, SimpleNamespace

import pytest

from core.understand_graph.tests import test_budget_reader_connection_ownership as subject

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


def _exercise(tmp_path, name, base_error):
    errors = []
    connections = []
    events = []
    paths = set()

    class OwnedFault(base_error):
        def __init__(self, *args):
            super().__init__(*args)
            errors.append(self)

    def connected(path, *, factory):
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
        body(tmp_path, name, OwnedFault, True)
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


@pytest.mark.parametrize("name", subject.READERS)
@pytest.mark.parametrize("base_error", [OSError, KeyboardInterrupt, SystemExit])
def test_discarded_budget_cursor_retires_before_traceback_cleanup(tmp_path, name, base_error):
    _exercise(tmp_path, name, base_error)
