"""Native non-directory fixture closes its sockets across setup faults."""

import socket

import pytest

from core.atomic_fs.tests import test_cleanup_failures as native
from core.testing.module_bindings import patch_module_attribute


@pytest.mark.parametrize("mode", [0o600, 0o640, 0o444])
@pytest.mark.parametrize("operation,after,error", [
    (operation, after, error)
    for operation in ("bind", "chmod") for after in (False, True)
    for error in (OSError, KeyboardInterrupt, SystemExit)
] + [(None, False, None)])
def test_native_socket_node_retires_after_setup_errors(
    tmp_path, short_socket_dir, monkeypatch, mode, operation, after, error,
):
    sockets, closed = [], []
    failure = error("owned native socket setup failure") if error else None
    borrowed = native.socket

    class Socket(socket.socket):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            sockets.append(self)

        def bind(self, address):
            if operation != "bind" or after:
                super().bind(address)
            if operation == "bind":
                raise failure

        def close(self):
            super().close()
            closed.append(self)

    class Path(type(short_socket_dir)):
        def chmod(self, *a, **k):
            if operation != "chmod" or after:
                super().chmod(*a, **k)
            if operation == "chmod":
                raise failure

    with monkeypatch.context() as patch:
        patch_module_attribute(patch, native, "socket", "socket", Socket)
        try:
            if error:
                with pytest.raises(error) as caught:
                    native.test_non_directory_roots_are_not_removed_or_chmodded(
                        tmp_path, Path(short_socket_dir), "socket", mode,
                    )
                assert caught.value is failure
            else:
                native.test_non_directory_roots_are_not_removed_or_chmodded(
                    tmp_path, Path(short_socket_dir), "socket", mode,
                )
            assert len(sockets) == 1 and sockets[0].fileno() == -1
            assert closed == sockets
            if error is None:
                node = short_socket_dir / "node"
                assert node.is_socket()
                assert node.lstat().st_mode & 0o777 == mode
        finally:
            # Assert native closure first, then close retained objects for
            # safety without touching a stale, potentially recycled FD number.
            for owned in sockets:
                socket.socket.close(owned)
    assert native.socket is borrowed
    assert socket.socket is borrowed.socket
