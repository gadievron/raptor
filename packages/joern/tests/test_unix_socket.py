"""Long runtime bases must not silently become public /tmp directories."""

import socket
import sys

import pytest

from packages.joern.netns_forwarder import create_listener
from packages.joern.unix_socket import socket_address


@pytest.mark.skipif(sys.platform != "linux", reason="procfs directory alias")
def test_long_socket_path_binds_and_connects_in_selected_directory(tmp_path):
    root = tmp_path / ("é" * 60)
    root.mkdir(mode=0o700)
    path = root / "joern.sock"
    with create_listener(str(path)) as listener, socket.socket(socket.AF_UNIX) as client:
        with socket_address(path) as address:
            client.connect(address)
        with listener.accept()[0] as accepted:
            client.sendall(b"probe")
            assert accepted.recv(5) == b"probe"
    assert path.is_socket()


def test_macos_long_path_refuses_without_falling_back(tmp_path, monkeypatch):
    from packages.joern import unix_socket
    root = tmp_path / ("x" * 120)
    root.mkdir(mode=0o700)
    monkeypatch.setattr(unix_socket.sys, "platform", "darwin")
    with pytest.raises(ValueError, match="shorter private runtime"):
        with socket_address(root / "joern.sock"):
            pytest.fail("overlong socket was admitted")
