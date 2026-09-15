"""Tests for _daemon._recv_until's fd-level reads.

Pins the fix for the select()/BufferedReader mismatch: with Popen's
default buffered stdout, ``read1(n)`` pulled a whole 8 KiB chunk
from the kernel and returned only ``n`` bytes — the remainder sat in
the Python-level buffer, invisible to ``select()`` on the raw fd.
The NEXT bounded recv then stalled for a full ``per_recv_timeout``
and returned nothing, even though the bytes had already arrived.
"""

import subprocess
import sys

from core.sandbox import _daemon
from core.testing.wallclock import wall_deadline


def _spawn_writer(payload: str, hold_open_s: float = 180.0):
    """Child writes *payload* to stdout in one burst, then idles."""
    code = (
        "import sys, time\n"
        f"sys.stdout.write({payload!r})\n"
        "sys.stdout.flush()\n"
        f"time.sleep({hold_open_s})\n"
    )
    return subprocess.Popen(
        [sys.executable, "-c", code],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def test_recv_until_fixed_length_sees_bytes_beyond_first_read():
    """Two back-to-back fixed-length recvs over one 8-byte burst.

    Pre-fix: the first recv's read1(4) pulled all 8 bytes into the
    BufferedReader and returned 4; the second recv select()ed on a
    drained kernel pipe, timed out, and returned b"".
    """
    proc = _spawn_writer("ABCDEFGH")
    try:
        first = _daemon._recv_until(proc, 4, per_recv_timeout=60.0)
        assert first == b"ABCD"
        # The per-recv timeout (and the writer's hold-open) sit far
        # past the assert bound: a stalled second recv either serves
        # the 60s timeout or recovers at pipe EOF (180s) — both are
        # unambiguously beyond the 20s prompt-return window even on a
        # heavily loaded runner.
        with wall_deadline(20.0, code_bound_s=60.0,
                           what="second recv"):
            second = _daemon._recv_until(proc, 4, per_recv_timeout=60.0)
        assert second == b"EFGH", (
            "second recv stalled — bytes stranded in a Python-level "
            "buffer invisible to select()"
        )
    finally:
        proc.kill()
        proc.communicate(timeout=5)


def test_recv_until_newline_then_fixed_length():
    """A newline-terminated recv followed by a fixed-length recv must
    not strand the post-newline bytes."""
    proc = _spawn_writer("header\nBODY")
    try:
        line = _daemon._recv_until(proc, "newline", per_recv_timeout=60.0)
        assert line.startswith(b"header\n")
        already = line[len(b"header\n"):]
        want = 4 - len(already)
        if want > 0:
            # Separation as in the fixed-length test above.
            with wall_deadline(20.0, code_bound_s=60.0,
                               what="post-newline recv"):
                rest = _daemon._recv_until(
                    proc, want, per_recv_timeout=60.0)
            assert already + rest == b"BODY"
    finally:
        proc.kill()
        proc.communicate(timeout=5)
