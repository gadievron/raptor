"""``spawn_worker`` must not leak the token pipe FD when Popen fails.

``allocate_worker`` creates the token pipe before the child is
spawned; the parent's copy of the read FD was only closed after a
successful ``Popen``. A spawn failure (missing worker binary,
exec-permission error) stranded the inheritable read FD in the
parent for the process lifetime.
"""

from __future__ import annotations

import errno
import os
from contextlib import ExitStack, contextmanager
import sys
from unittest.mock import MagicMock

import pytest

from core.llm.dispatcher.spawn import spawn_worker
from core.testing.processes import reap_on_exit
from core.testing.pipes import pipes_for_setup


def _fd_is_open(fd: int) -> bool:
    try:
        os.fstat(fd)
        return True
    except OSError:
        return False


def _close_token_pipe_end(fd, identity):
    try:
        current = os.fstat(fd)
    except OSError as error:
        if error.errno == errno.EBADF:
            return
        raise
    if (current.st_dev, current.st_ino) == identity:
        os.close(fd)


@contextmanager
def _dispatcher_with_real_pipe():
    with ExitStack() as cleanup:
        with pipes_for_setup(1) as pairs:
            for fd in pairs[0]:
                current = os.fstat(fd)
                cleanup.callback(_close_token_pipe_end, fd,
                                 (current.st_dev, current.st_ino))
        read_fd, write_fd = pairs[0]
        os.close(write_fd)
        d = MagicMock()
        d.allocate_worker.return_value = ("./fake.sock", read_fd)
        yield d, read_fd


def test_popen_failure_closes_token_fd():
    with _dispatcher_with_real_pipe() as (dispatcher, token_fd):
        assert _fd_is_open(token_fd)

        with pytest.raises(FileNotFoundError):
            spawn_worker(
                dispatcher,
                ["/nonexistent/worker-binary-for-test"],
                label="test-worker",
                env={"PATH": "/usr/bin"},
            )

        assert not _fd_is_open(token_fd), (
            "token pipe read FD leaked in the parent after Popen failure"
        )


def test_successful_spawn_still_closes_token_fd():
    with _dispatcher_with_real_pipe() as (dispatcher, token_fd):

        proc = spawn_worker(
            dispatcher,
            [sys.executable, "-c", "pass"],
            label="test-worker",
            env={"PATH": "/usr/bin"},
        )
        with reap_on_exit(proc):
            proc.wait()

        assert not _fd_is_open(token_fd)
