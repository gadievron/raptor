"""Tests for the fork-safe post-fork warn helper.

Single entry point — ``warn_post_fork(message: bytes)`` — matching
the W35.C precedent. Fail-CLOSED sites at landlock / mount_ns /
preexec use direct ``os.write(2, ...) + os._exit(N)`` and are
exercised by the per-site fix tests.
"""

import os
import subprocess
import sys
from pathlib import Path

from core.testing.fds import preserved_fds


# Anchor the subprocess sys.path to the SAME tree these tests run from
# rather than `os.environ["RAPTOR_DIR"]`. The env-var form silently
# misbehaved when RAPTOR_DIR pointed at a different checkout — the
# subprocess imported an unrelated version of core.sandbox._fork_safe_warn,
# and the closed-fd-2 behaviour under test was attributed to the wrong
# module.
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


def _capture_warn(message):
    from core.sandbox._fork_safe_warn import warn_post_fork

    r, w = os.pipe()
    try:
        with preserved_fds(2):
            os.dup2(w, 2)
            os.close(w)
            w = None
            warn_post_fork(message)
        return _read_fd(r)
    finally:
        try:
            os.close(r)
        finally:
            if w is not None:
                os.close(w)


def test_warn_post_fork_writes_prefixed_line():
    out = _capture_warn(b"sandbox: landlock: SYS_create returned -1\n")
    assert out == b"sandbox: landlock: SYS_create returned -1\n"


def test_warn_post_fork_auto_prepends_prefix_when_missing():
    out = _capture_warn(b"bare_event\n")
    assert out == b"sandbox: bare_event\n"


def test_warn_post_fork_no_double_prefix():
    out = _capture_warn(b"RAPTOR: legacy_prefixed\n")
    # A legacy-branded message is rewritten: the framework
    # name must not reach the target-visible stream.
    assert out == b"sandbox: legacy_prefixed\n"
    assert b"RAPTOR" not in out


def test_warn_post_fork_silent_when_fd2_closed():
    script = (
        "import sys; "
        "sys.path.insert(0, sys.argv[1]); "
        "import os; "
        "from core.sandbox._fork_safe_warn import warn_post_fork; "
        "os.close(2); "
        "warn_post_fork(b'should_not_raise\\n'); "
        "print('OK')"
    )
    proc = subprocess.run(
        [sys.executable, "-c", script, _REPO_ROOT],
        env={**os.environ},
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0
    assert "OK" in proc.stdout


def test_warn_post_fork_callable_from_preexec_fn():
    def preexec():
        from core.sandbox._fork_safe_warn import warn_post_fork
        warn_post_fork(b"sandbox: preexec_test: from forked child\n")

    proc = subprocess.run(
        [sys.executable, "-c", "pass"],
        preexec_fn=preexec,
        capture_output=True,
    )
    assert proc.returncode == 0
