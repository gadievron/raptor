"""Tests for the fork-safe post-fork warn helper.

Single entry point — ``warn_post_fork(message: bytes)`` — matching
the W35.C precedent. Fail-CLOSED sites at landlock / mount_ns /
preexec use direct ``os.write(2, ...) + os._exit(N)`` and are
exercised by the per-site fix tests.
"""

import os
import subprocess
import sys
import textwrap
from pathlib import Path


# Anchor the repo root via the test file's path rather than ``..``
# arithmetic embedded in each subprocess. Refactoring the test layout
# would otherwise silently drift the relative path.
_REPO_ROOT = str(Path(__file__).resolve().parents[3])


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
    from core.sandbox._fork_safe_warn import warn_post_fork

    r, w = os.pipe()
    saved = os.dup(2)
    try:
        os.dup2(w, 2)
        os.close(w)
        warn_post_fork(b"RAPTOR: landlock: SYS_create returned -1\n")
    finally:
        os.dup2(saved, 2)
        os.close(saved)

    out = _read_fd(r)
    os.close(r)
    assert out == b"RAPTOR: landlock: SYS_create returned -1\n"


def test_warn_post_fork_auto_prepends_prefix_when_missing():
    from core.sandbox._fork_safe_warn import warn_post_fork

    r, w = os.pipe()
    saved = os.dup(2)
    try:
        os.dup2(w, 2)
        os.close(w)
        warn_post_fork(b"bare_event\n")
    finally:
        os.dup2(saved, 2)
        os.close(saved)

    out = _read_fd(r)
    os.close(r)
    assert out == b"RAPTOR: bare_event\n"


def test_warn_post_fork_no_double_prefix():
    from core.sandbox._fork_safe_warn import warn_post_fork

    r, w = os.pipe()
    saved = os.dup(2)
    try:
        os.dup2(w, 2)
        os.close(w)
        warn_post_fork(b"RAPTOR: already_prefixed\n")
    finally:
        os.dup2(saved, 2)
        os.close(saved)

    out = _read_fd(r)
    os.close(r)
    assert out.count(b"RAPTOR: ") == 1


def test_warn_post_fork_silent_when_fd2_closed():
    script = (
        "import os, sys; "
        "sys.path.insert(0, os.environ['RAPTOR_DIR']); "
        "from core.sandbox._fork_safe_warn import warn_post_fork; "
        "os.close(2); "
        "warn_post_fork(b'should_not_raise\\n'); "
        "print('OK')"
    )
    proc = subprocess.run(
        [sys.executable, "-c", script],
        env={**os.environ},
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0
    assert "OK" in proc.stdout


def test_warn_post_fork_callable_from_preexec_fn():
    def preexec():
        from core.sandbox._fork_safe_warn import warn_post_fork
        os.close(2)
        warn_post_fork(b"should_not_raise\\n")
        print("OK")
        """
    )
    env = {**os.environ, "RAPTOR_DIR": _REPO_ROOT}
    result = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, env=env,
    )
    assert result.returncode == 0
    assert "OK" in result.stdout

    proc = subprocess.run(
        [sys.executable, "-c", "pass"],
        preexec_fn=preexec,
        capture_output=True,
    )
    env = {**os.environ, "RAPTOR_DIR": _REPO_ROOT}
    result = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, env=env,
    )
    assert result.returncode == 0
    assert "RAPTOR: preexec_test" in result.stderr
