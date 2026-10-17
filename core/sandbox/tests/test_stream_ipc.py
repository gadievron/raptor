"""An inherited stream works even when network send/recv calls are unavailable."""
import socket
import threading

import pytest

from core.sandbox._stream_ipc import recv_exact, send_all


class DescriptorOnly:
    def __init__(self, stream):
        self.stream = stream

    def fileno(self):
        return self.stream.fileno()

    def gettimeout(self):
        return self.stream.gettimeout()

    def sendall(self, *args):
        pytest.fail('network send syscall must not be used for private IPC')

    def recv(self, *args):
        pytest.fail('network recv syscall must not be used for private IPC')


def test_stream_roundtrip_uses_only_existing_descriptors():
    left, right = socket.socketpair()
    try:
        left.settimeout(1)
        right.settimeout(1)
        send_all(DescriptorOnly(left), b'frame')
        assert recv_exact(DescriptorOnly(right), 5) == b'frame'
        left.close()
        assert recv_exact(DescriptorOnly(right), 1) is None
    finally:
        left.close()
        right.close()


def test_read_deadline_and_partial_eof():
    left, right = socket.socketpair()
    try:
        right.settimeout(0.02)
        with pytest.raises(TimeoutError):
            recv_exact(DescriptorOnly(right), 1)
        send_all(DescriptorOnly(left), b'x')
        left.close()
        assert recv_exact(DescriptorOnly(right), 2) is None
    finally:
        left.close()
        right.close()


def test_partial_writes_preserve_full_payload():
    left, right = socket.socketpair()
    try:
        left.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        left.settimeout(2)
        right.settimeout(2)
        data = b'payload' * 40000
        result = []
        thread = threading.Thread(target=lambda: result.append(recv_exact(DescriptorOnly(right), len(data))))
        thread.start()
        send_all(DescriptorOnly(left), data)
        thread.join(timeout=3)
        assert not thread.is_alive()
        assert result == [data]
    finally:
        left.close()
        right.close()
