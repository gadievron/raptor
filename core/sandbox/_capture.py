"""Bounded capture for the plain subprocess executor's owned pipe streams."""

import codecs
import errno
import os
import subprocess
import time

from ._pipe_poll import ready_fds

_CHUNK_SIZE = 65536


def clipped_output(value, cap: int, label: str, *, truncated: bool = False):
    """Keep a byte-bounded prefix and append one explicit loss marker."""
    if value is None:
        return None
    if isinstance(value, bytes):
        overflow = len(value) > cap
        prefix = value[:cap]
    else:
        raw = value[:cap].encode("utf-8", errors="replace")
        overflow = len(value) > cap or len(raw) > cap
        prefix = raw[:cap].decode("utf-8", errors="ignore") if overflow else value
    if not (truncated or overflow):
        return value
    marker = f"\n[sandbox: {label} capture truncated at {cap} bytes]\n"
    return prefix + (marker.encode("ascii") if isinstance(prefix, bytes) else marker)


def limit_result(result, cap: int) -> None:
    """Clamp once, including results already formatted by an I/O owner."""
    cap = max(0, int(cap))
    snapshot = (cap, result.stdout, result.stderr)
    def within_bound(value, label):
        if value is None:
            return True
        if len(value) <= cap:
            if isinstance(value, bytes) or len(value.encode("utf-8", errors="replace")) <= cap:
                return True
        allowance = cap + len(f"\n[sandbox: {label} capture truncated at {cap} bytes]\n")
        if len(value) > allowance:
            return False
        return isinstance(value, bytes) or len(value.encode("utf-8", errors="replace")) <= allowance
    if (getattr(result, "_capture_limit_snapshot", None) == snapshot
            and within_bound(result.stdout, "stdout") and within_bound(result.stderr, "stderr")):
        return
    for label in ("stdout", "stderr"):
        setattr(result, label, clipped_output(getattr(result, label), cap, label))
    result._capture_limit_snapshot = (cap, result.stdout, result.stderr)


class BoundedCommunicator:
    """Drain owned PIPEs while retaining at most cap bytes per output.

    Only Popen-created streams are touched. Inherited/redirected file objects
    are absent from proc.stdin/stdout/stderr. No BufferedReader.read or
    Popen.communicate accumulator participates in this path. A single instance
    survives timeout cleanup so retries neither reset the prefix nor recapture
    discarded bytes. Text decoding applies only to retained output; discarded
    bytes are intentionally not validated after the caller requests truncation.
    """

    def __init__(self, cap: int) -> None:
        self.cap = cap
        self.proc = None
        self._buffers = {}
        self._truncated = {}
        self._readers = {}
        self._attached = False
        self._input_started = False
        self._input_stopped = False
        self._input = memoryview(b"")
        self._sent = 0

    def attach(self, proc) -> None:
        self.proc = proc
        if self._attached:
            return
        self._readers.clear()
        for label in ("stdout", "stderr"):
            stream = getattr(proc, label)
            if stream is None:
                continue
            self._buffers.setdefault(label, bytearray())
            self._truncated.setdefault(label, False)
            if not stream.closed:
                fd = stream.fileno()
                os.set_blocking(fd, False)
                self._readers[fd] = label
        if proc.stdin is not None and not proc.stdin.closed:
            os.set_blocking(proc.stdin.fileno(), False)
        self._attached = True

    def stop_input(self) -> None:
        self._input_stopped = True
        self._input = memoryview(b"")
        stream = self.proc.stdin if self.proc is not None else None
        if stream is not None and not stream.closed:
            try:
                stream.close()
            except (BrokenPipeError, OSError) as exc:
                if exc.errno not in (errno.EPIPE, errno.EINVAL):
                    raise

    def _accept(self, label: str, chunk: bytes) -> None:
        buf = self._buffers[label]
        room = max(0, self.cap - len(buf))
        buf.extend(chunk[:room])
        self._truncated[label] |= len(chunk) > room

    def outputs(self, *, text: bool = False):
        values = []
        for label in ("stdout", "stderr"):
            if label not in self._buffers:
                values.append(None)
                continue
            raw = bytes(self._buffers[label])
            value = raw
            if text:
                decoder = codecs.getincrementaldecoder(self.proc.encoding)(self.proc.errors)
                # A cap can split a valid encoded character. Keep the complete
                # decoded prefix; an untruncated malformed stream still errors.
                value = decoder.decode(raw, final=not self._truncated[label])
                value = value.replace("\r\n", "\n").replace("\r", "\n")
            values.append(clipped_output(value, self.cap, label,
                                         truncated=self._truncated[label]))
        return tuple(values)

    def _timeout(self, timeout):
        out, err = self.outputs()
        return subprocess.TimeoutExpired(self.proc.args, timeout, output=out, stderr=err)

    def communicate(self, input=None, timeout=None):
        self.attach(self.proc)
        if self._input_started:
            if input is not None:
                raise ValueError("cannot send input after communication started")
        else:
            self._input_started = True
            if input is not None and not self._input_stopped:
                if self.proc.text_mode:
                    input = input.encode(self.proc.stdin.encoding, self.proc.stdin.errors)
                self._input = memoryview(input).cast("B")
        if self._sent >= len(self._input) or self._input_stopped:
            self.stop_input()
        deadline = None if timeout is None else time.monotonic() + timeout
        while self._readers or (self.proc.stdin is not None and not self.proc.stdin.closed):
            remaining = None if deadline is None else deadline - time.monotonic()
            if remaining is not None and remaining <= 0:
                raise self._timeout(timeout)
            writer = (self.proc.stdin.fileno() if self.proc.stdin is not None
                      and not self.proc.stdin.closed else None)
            try:
                readable, writable = ready_fds(self._readers, [writer] if writer is not None else [], remaining)
            except InterruptedError:
                continue
            for fd in readable:
                try:
                    chunk = os.read(fd, _CHUNK_SIZE)
                except (BlockingIOError, InterruptedError):
                    continue
                if not chunk:
                    self._readers.pop(fd, None)
                else:
                    self._accept(self._readers[fd], chunk)
            if writable:
                try:
                    sent = os.write(writer, self._input[self._sent:self._sent + _CHUNK_SIZE])
                except (BlockingIOError, InterruptedError):
                    continue
                except OSError as exc:
                    if exc.errno not in (errno.EPIPE, errno.EINVAL):
                        raise
                    self.stop_input()
                else:
                    if sent <= 0:
                        raise OSError(errno.EIO, "subprocess stdin made no progress")
                    self._sent += sent
                    if self._sent >= len(self._input):
                        self.stop_input()
        remaining = None if deadline is None else max(0, deadline - time.monotonic())
        try:
            self.proc.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            raise self._timeout(timeout) from None
        return self.outputs(text=bool(self.proc.text_mode))
