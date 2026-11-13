"""Newline receives avoid repeatedly scanning an accumulated prefix."""

import os
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from core.sandbox import _daemon as daemon
from core.testing.module_views import module_function_view


@contextmanager
def _receiver(**bindings):
    read_fd, write_fd = os.pipe()
    os.close(write_fd)
    with os.fdopen(read_fd, "rb", buffering=0) as stream:
        def forbidden(*args, **kwargs):
            raise AssertionError("bounded pushback receive reached pipe readiness")

        private = module_function_view(daemon, bindings={
            "_check_request_channel": lambda: None,
            "_step_stderr": lambda proc: SimpleNamespace(fd=None),
            "_target_ready": forbidden, **bindings,
        })
        yield private, SimpleNamespace(stdout=stream)


def test_newline_scan_does_not_revisit_received_prefix():
    scanned = []

    class Counted(bytearray):
        def __contains__(self, value):
            scanned.append(len(self))
            return super().__contains__(value)

        def find(self, value, start=0, end=None):
            limit = len(self) if end is None else min(end, len(self))
            scanned.append(max(limit - start, 0))
            return super().find(value, start, limit)

    source = b"A" * (4096 * 3)
    pushback = bytearray(source)
    with _receiver(bytearray=Counted) as (private, proc):
        assert private._recv_until(proc, "newline", 1, max_bytes=len(source),
                                   pushback=pushback) == source
    assert pushback == b""
    assert sum(scanned) <= len(source)


@pytest.mark.parametrize("source,cap,kept", [
    (b"\nrest", 10, 5),
    (b"A" * 4095 + b"\nTAIL", 5000, 4096),
    (b"A" * 4096 + b"\nTAIL", 5000, 4101),
    (b"A" * 8192, 8192, 8192),
    (b"A" * 8192, 5000, 5000),
    (b"\nrest", 0, 0),
])
def test_newline_retains_existing_chunk_and_cap_semantics(source, cap, kept):
    pushback = bytearray(source)
    with _receiver() as (private, proc):
        result = private._recv_until(proc, "newline", 1, max_bytes=cap, pushback=pushback)
    assert result == source[:kept]
    assert pushback == source[kept:]


def test_newline_pipe_eof_preserves_partial_capture():
    chunks = iter([b"abc", b""])
    with _receiver(_target_ready=lambda *args: ([proc.stdout.fileno()], []),
                   _target_read=lambda *args: next(chunks)) as (private, proc):
        assert private._recv_until(proc, "newline", 1, max_bytes=20) == b"abc"
