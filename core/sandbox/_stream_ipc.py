"""Read/write an existing private stream FD without network send/recv syscalls.

Codex's network-off sandbox denies sendto/recvfrom even for an inherited Unix
socket pair. These helpers do not open sockets or grant any new capabilities;
they retain deadlines and exact-frame/EOF behavior on the existing channel.
"""
import os
import select
import time


def _wait(sock, writing, deadline):
    remaining = None if deadline is None else max(0, deadline - time.monotonic())
    ready = select.select([] if writing else [sock], [sock] if writing else [], [], remaining)
    if not ready[0] and not ready[1]:
        raise TimeoutError('private IPC timed out')


def recv_exact(sock, count):
    timeout = sock.gettimeout()
    deadline = None if timeout is None else time.monotonic() + timeout
    chunks = bytearray()
    while len(chunks) < count:
        _wait(sock, False, deadline)
        try:
            chunk = os.read(sock.fileno(), count - len(chunks))
        except (BlockingIOError, InterruptedError):
            continue
        if not chunk:
            return None
        chunks.extend(chunk)
    return bytes(chunks)


def send_all(sock, data):
    timeout = sock.gettimeout()
    deadline = None if timeout is None else time.monotonic() + timeout
    view = memoryview(data)
    while view:
        _wait(sock, True, deadline)
        try:
            count = os.write(sock.fileno(), view)
        except (BlockingIOError, InterruptedError):
            continue
        if count == 0:
            raise OSError('private IPC stream closed')
        view = view[count:]
