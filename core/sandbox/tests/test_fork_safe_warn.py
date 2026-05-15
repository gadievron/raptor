"""Tests for the fork-safe post-fork warn/fail helpers."""

import os
import subprocess
import sys

from core.sandbox._fork_safe_warn import warn_post_fork, fail_post_fork


def _read_fd(fd: int) -> bytes:
    chunks: list[bytes] = []
    while True:
        try:
            data = os.read(fd, 4096)
        except OSError:
            break
        if not data:
            break
        chunks.append(data)
    return b"".join(chunks)


def test_warn_post_fork_writes_prefixed_line():
    r, w = os.pipe()
    saved = os.dup(2)
    try:
        os.dup2(w, 2)
        os.close(w)
        warn_post_fork("landlock", "SYS_create returned -1")
    finally:
        os.dup2(saved, 2)
        os.close(saved)

    out = _read_fd(r)
    os.close(r)
    assert out == b"RAPTOR: landlock: SYS_create returned -1\n"


def test_warn_post_fork_does_not_double_prefix():
    r, w = os.pipe()
    saved = os.dup(2)
    try:
        os.dup2(w, 2)
        os.close(w)
        warn_post_fork("RAPTOR: already", "detail")
    finally:
        os.dup2(saved, 2)
        os.close(saved)

    out = _read_fd(r)
    os.close(r)
    assert out.count(b"RAPTOR: ") == 1


def test_warn_post_fork_swallows_closed_stderr():
    # Close fd 2; warn_post_fork must not raise.
    saved = os.dup(2)
    try:
        os.close(2)
        warn_post_fork("test", "no stderr available")
    finally:
        os.dup2(saved, 2)
        os.close(saved)


def test_fail_post_fork_exits_with_code():
    script = (
        "from core.sandbox._fork_safe_warn import fail_post_fork; "
        "fail_post_fork('preexec', 'RLIMIT_CORE failed', 99)"
    )
    proc = subprocess.run(
        [sys.executable, "-c", script],
        env={**os.environ},
        capture_output=True,
        cwd=os.environ["RAPTOR_DIR"],
    )
    assert proc.returncode == 99
    assert proc.stderr == b"RAPTOR: preexec: RLIMIT_CORE failed\n"


def test_fail_post_fork_uses_os_exit_skips_atexit():
    # os._exit must NOT run atexit handlers (which can deadlock post-fork).
    # Register an atexit that writes a sentinel — if it runs, the sentinel
    # appears on stderr; if os._exit is used correctly it does not.
    script = (
        "import atexit, sys; "
        "atexit.register(lambda: sys.stderr.write('ATEXIT_RAN\\n')); "
        "from core.sandbox._fork_safe_warn import fail_post_fork; "
        "fail_post_fork('preexec', 'detail', 7)"
    )
    proc = subprocess.run(
        [sys.executable, "-c", script],
        env={**os.environ},
        capture_output=True,
        cwd=os.environ["RAPTOR_DIR"],
    )
    assert proc.returncode == 7
    assert b"ATEXIT_RAN" not in proc.stderr
    assert proc.stderr == b"RAPTOR: preexec: detail\n"


def test_warn_post_fork_callable_from_preexec_fn():
    # Sanity: callable inside Popen preexec_fn (a real forked child context).
    def preexec():
        warn_post_fork("preexec_test", "from forked child")

    proc = subprocess.run(
        [sys.executable, "-c", "pass"],
        preexec_fn=preexec,
        capture_output=True,
    )
    assert proc.returncode == 0
    # stderr capture is unreliable across subprocess boundaries with
    # custom preexec, so only verify no exception leaked.
