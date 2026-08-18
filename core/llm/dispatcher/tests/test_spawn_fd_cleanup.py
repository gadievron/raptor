"""``spawn_worker`` must not leak the token pipe FD when Popen fails.

``allocate_worker`` creates the token pipe before the child is
spawned; the parent's copy of the read FD was only closed after a
successful ``Popen``. A spawn failure (missing worker binary,
exec-permission error) stranded the inheritable read FD in the
parent for the process lifetime.
"""

from __future__ import annotations

import os
from unittest.mock import MagicMock

import pytest

from core.llm.dispatcher.spawn import spawn_worker


def _fd_is_open(fd: int) -> bool:
    try:
        os.fstat(fd)
        return True
    except OSError:
        return False


def _dispatcher_with_real_pipe():
    read_fd, write_fd = os.pipe()
    os.close(write_fd)
    d = MagicMock()
    d.allocate_worker.return_value = ("./fake.sock", read_fd)
    return d, read_fd


def test_popen_failure_closes_token_fd():
    dispatcher, token_fd = _dispatcher_with_real_pipe()
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
    dispatcher, token_fd = _dispatcher_with_real_pipe()

    proc = spawn_worker(
        dispatcher,
        ["/bin/true"],
        label="test-worker",
        env={"PATH": "/usr/bin"},
    )
    proc.wait()

    assert not _fd_is_open(token_fd)
