"""Tests for fork-safe degraded-mode warning helper."""

import os
import subprocess
import sys
import textwrap


def test_writes_prefixed_message_to_stderr(capfd):
    from core.sandbox._fork_safe_warn import warn_post_fork

    warn_post_fork(b"RAPTOR: unit_test\n")
    captured = capfd.readouterr()
    assert "RAPTOR: unit_test" in captured.err


def test_auto_prepends_prefix_when_missing(capfd):
    from core.sandbox._fork_safe_warn import warn_post_fork

    warn_post_fork(b"bare_event\n")
    captured = capfd.readouterr()
    assert "RAPTOR: bare_event" in captured.err


def test_silent_when_fd2_closed():
    script = textwrap.dedent(
        """
        import os, sys
        sys.path.insert(0, os.environ["RAPTOR_DIR"])
        from core.sandbox._fork_safe_warn import warn_post_fork
        os.close(2)
        warn_post_fork(b"should_not_raise\\n")
        print("OK")
        """
    )
    env = {**os.environ, "RAPTOR_DIR": os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", ".."))}
    result = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, env=env,
    )
    assert result.returncode == 0
    assert "OK" in result.stdout


def test_callable_from_preexec_fn():
    script = textwrap.dedent(
        """
        import os, sys
        sys.path.insert(0, os.environ["RAPTOR_DIR"])
        from core.sandbox._fork_safe_warn import warn_post_fork
        import subprocess
        subprocess.run(
            ["true"],
            preexec_fn=lambda: warn_post_fork(b"RAPTOR: preexec_test\\n"),
            check=True,
        )
        """
    )
    env = {**os.environ, "RAPTOR_DIR": os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", ".."))}
    result = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, env=env,
    )
    assert result.returncode == 0
    assert "RAPTOR: preexec_test" in result.stderr
