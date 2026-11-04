"""One-request, pipe-backed RPC hosts with explicit startup ownership."""

from contextlib import suppress
import json
import os
import struct
import threading

from core.sandbox import host as host_mod
from core.testing.pipes import pipes_for_setup


def _close_fds(*fds):
    for fd in fds:
        with suppress(OSError):
            os.close(fd)


def fake_host(reply):
    """Return a host, its worker, and observed server errors; caller closes host."""
    errors = []
    with pipes_for_setup(2) as ((in_r, in_w), (out_r, out_w)):
        def read_exact(size):
            data = bytearray()
            while len(data) < size:
                chunk = os.read(in_r, size - len(data))
                if not chunk:
                    raise EOFError("parent closed request channel")
                data.extend(chunk)
            return bytes(data)

        def serve():
            try:
                size, = struct.unpack("!I", read_exact(4))
                request = json.loads(read_exact(size))
                body = json.dumps(reply(request)).encode()
                view = memoryview(struct.pack("!I", len(body)) + body)
                while view:
                    written = os.write(out_w, view)
                    view = view[written:]
            except Exception as exc:
                errors.append(exc)
            finally:
                _close_fds(in_r, out_w)

        thread = threading.Thread(target=serve, daemon=True)
        host = host_mod.SandboxHost(
            _thread=thread, _read_fd=out_r, _write_fd=in_w,
            _daemon_fds=None, _lock=threading.Lock(),
        )
    try:
        thread.start()
    except BaseException:
        if thread.ident is None:
            _close_fds(in_r, in_w, out_r, out_w)
        else:
            # The worker owns its endpoints once started. Closing the parent
            # endpoints wakes its read or write without racing a second close
            # of descriptor numbers the worker may already have released.
            _close_fds(in_w, out_r)
            thread.join(timeout=5)
            if thread.is_alive():
                raise RuntimeError("fake pipe host worker did not stop")
        raise
    return host, thread, errors
