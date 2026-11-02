"""rr's private anonymous pairs must not become host-facing Unix sockets."""
import os
from pathlib import Path
import socket
import subprocess
import sys

import pytest

from core.sandbox import seccomp

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='Linux seccomp')


def test_rr_refuses_a_connection_mediator():
    if not seccomp.check_seccomp_available():
        pytest.skip('seccomp unavailable')
    with pytest.raises(ValueError, match='rr cannot use seccomp connection notification'):
        seccomp._make_seccomp_preexec('rr', unix_scope_export_sock=object())


def test_rr_unix_creation_and_pair_retargeting_are_denied(tmp_path):
    if not seccomp.check_seccomp_available():
        pytest.skip('seccomp unavailable')
    listeners = []
    paths = []
    directory = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for kind in (socket.SOCK_STREAM, socket.SOCK_SEQPACKET):
            listener = socket.socket(socket.AF_UNIX, kind)
            listeners.append(listener)
            # Keep sockaddr_un short even beneath a long selected TMPDIR.
            path = f'/proc/{os.getpid()}/fd/{directory}/{int(kind)}'
            paths.append(path)
            listener.bind(path)
            listener.listen()
            listener.setblocking(False)
        code = '''
import ctypes, socket, sys
for kind in (socket.SOCK_STREAM, socket.SOCK_SEQPACKET, socket.SOCK_DGRAM):
    for flags in (0, socket.SOCK_CLOEXEC | socket.SOCK_NONBLOCK):
        try: socket.socket(socket.AF_UNIX, kind | flags)
        except PermissionError: pass
        else: raise AssertionError('Unix socket creation allowed')
try: socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
except PermissionError: pass
else: raise AssertionError('destination-bearing datagram pair allowed')
lib = ctypes.CDLL(None, use_errno=True)
for kind, path in zip((socket.SOCK_STREAM, socket.SOCK_SEQPACKET), sys.argv[1:]):
    left, right = socket.socketpair(socket.AF_UNIX, kind)
    left.settimeout(1)
    right.settimeout(1)
    try:
        try: left.connect(path)
        except OSError: pass
        else: raise AssertionError('connected pair retargeted to host')
        unspecified = ctypes.c_ushort(socket.AF_UNSPEC)
        lib.connect(left.fileno(), ctypes.byref(unspecified), ctypes.sizeof(unspecified))
        try: left.connect(path)
        except OSError: pass
        else: raise AssertionError('disconnected pair retargeted to host')
        try: count = left.sendto(b'private-pair', path)
        except OSError: pass
        else:
            assert count == 12
            assert right.recv(64) == b'private-pair'
    finally:
        left.close(); right.close()
print('PAIR_SCOPE_OK')
'''
        # Passing True cannot widen the mandatory rr-specific restriction.
        reply = subprocess.run([sys.executable, '-I', '-S', '-c', code, *paths],
            preexec_fn=seccomp._make_seccomp_preexec('rr', allow_unix_sockets=True),
            capture_output=True, timeout=15)
        assert reply.returncode == 0, reply.stderr
        assert b'PAIR_SCOPE_OK' in reply.stdout
        for listener in listeners:
            with pytest.raises(BlockingIOError):
                peer, _ = listener.accept()
                peer.close()
    finally:
        for listener in listeners:
            listener.close()
        for path in paths:
            Path(path).unlink(missing_ok=True)
        os.close(directory)
