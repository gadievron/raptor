"""Tests for cve_env.utils.run — the run_with_timeout helper.

Cleanup-Item-3 (2026-05-05 → 2026-05-07c): consolidate the 13 duplicated
``subprocess.run(...) + except TimeoutExpired`` blocks across tools/ into
a single helper that returns a ``RunOutcome`` dataclass instead of
raising. Phase 1 added the helper; Phase 2 (2026-05-07c) migrated all 13
call sites. Helper now also catches ``OSError`` (transport-layer
spawn failures) for two probe-style sites that previously caught it
(docker_compose_up._compose_invocation, github_fetch.resolve_github_token).
"""

from __future__ import annotations

from unittest.mock import patch

from cve_env.utils.run import RunOutcome, run_with_timeout


def test_run_with_timeout_succeeds_for_fast_command() -> None:
    """A command that finishes in time returns RunOutcome(timed_out=False) with
    the actual returncode, stdout, stderr."""
    outcome = run_with_timeout(["sh", "-c", "echo hello && exit 0"], timeout=5.0)
    assert isinstance(outcome, RunOutcome)
    assert outcome.timed_out is False
    assert outcome.returncode == 0
    assert "hello" in outcome.stdout


def test_run_with_timeout_returns_outcome_on_timeout() -> None:
    """A slow command times out and returns RunOutcome(timed_out=True). Helper
    must NOT raise subprocess.TimeoutExpired — that's the whole point."""
    outcome = run_with_timeout(["sleep", "5"], timeout=0.1)
    assert isinstance(outcome, RunOutcome)
    assert outcome.timed_out is True
    assert outcome.returncode is None


def test_run_with_timeout_captures_nonzero_returncode() -> None:
    """Helper does not raise on nonzero exit; caller decides what to do."""
    outcome = run_with_timeout(["sh", "-c", "echo err >&2; exit 7"], timeout=5.0)
    assert outcome.timed_out is False
    assert outcome.returncode == 7
    assert "err" in outcome.stderr


def test_run_with_timeout_handles_missing_binary() -> None:
    """Adversarial-audit gap (2026-05-05): subprocess.run raises FileNotFoundError
    BEFORE TimeoutExpired when cmd[0] is not on PATH. The helper must catch it
    and return a RunOutcome instead of leaking the exception — that's the whole
    point of a uniform 'never raises' boundary."""
    outcome = run_with_timeout(["definitely_not_a_real_binary_zzzz_12345"], timeout=2.0)
    assert isinstance(outcome, RunOutcome)
    assert outcome.timed_out is False
    assert outcome.returncode is None  # process never started
    # stderr should carry a hint about what went wrong
    assert outcome.stderr  # non-empty
    assert (
        "not found" in outcome.stderr.lower()
        or "no such file" in outcome.stderr.lower()
        or "not_found" in outcome.stderr.lower()
    )


def test_run_with_timeout_returns_when_subprocess_run_itself_hangs(
    monkeypatch: object,
) -> None:
    """Lever #1B (2026-05-28): the ACTUAL ``docker_build → 1440s wall`` mechanism.

    Not a pipe-holding orphan (CPython's ``subprocess.run`` POSIX timeout path
    does ``process.wait()``, which reaps an interruptible child instantly). The
    real hang is ``subprocess.run`` ITSELF blocking past ``timeout``: its
    TimeoutExpired path does an UNBOUNDED ``process.wait()`` after SIGKILL, which
    never returns for a ``docker`` CLI wedged in uninterruptible **D-state** on a
    dead VM socket. The tool handler then never returns → ``finally: tool_end()``
    never runs → the connectivity breaker exempts the in-flight tool to the wall.

    The hardened helper runs ``subprocess.run`` in a daemon thread and joins for
    only ``timeout + _REAP_GRACE_S``; if it is still wedged it ABANDONS it and
    returns ``timed_out=True`` — so the handler returns and clears ``_in_flight``.

    Modelled by a ``subprocess.run`` that blocks far longer than the grace (the
    wedged internal wait). RED on the old direct-call impl (run_with_timeout
    blocks with it, ~60s). GREEN once the impl bounds it via the thread join.
    """
    import threading
    import time as _time

    monkeypatch.setattr("cve_env.utils.run._REAP_GRACE_S", 1.0)
    entered = threading.Event()

    def _hang(*_args: object, **_kwargs: object) -> None:
        entered.set()
        _time.sleep(60.0)  # models subprocess.run's wedged internal post-kill wait()

    monkeypatch.setattr("cve_env.utils.run.subprocess.run", _hang)

    start = _time.monotonic()
    outcome = run_with_timeout(["docker", "build", "."], timeout=1.0)
    elapsed = _time.monotonic() - start

    assert entered.is_set(), "subprocess.run was never invoked"
    assert isinstance(outcome, RunOutcome)
    assert outcome.timed_out is True
    assert outcome.returncode is None
    assert elapsed < 6.0, (
        f"run_with_timeout blocked {elapsed:.1f}s on a wedged subprocess.run "
        f"(timeout=1 + grace=1 ⇒ should abandon at ~2s). This is the docker_build "
        f"→ 1440s-wall hang; the daemon-thread join must bound it."
    )


def test_run_with_timeout_catches_oserror_during_spawn() -> None:
    """Stage 2 migration (2026-05-07c): two pre-migration sites (docker_compose_up.
    _compose_invocation, github_fetch.resolve_github_token) caught bare ``OSError``
    on top of TimeoutExpired/FileNotFoundError to tolerate transport-layer spawn
    failures (EAGAIN, EMFILE, broken pipe). The helper catches OSError too so
    those callers can drop their try/except wrappers without losing tolerance."""
    fake_oserror = OSError(24, "Too many open files")
    with patch("cve_env.utils.run.subprocess.run", side_effect=fake_oserror):
        outcome = run_with_timeout(["echo", "hello"], timeout=2.0)
    assert isinstance(outcome, RunOutcome)
    assert outcome.timed_out is False
    assert outcome.returncode is None  # subprocess never started
    assert outcome.stderr.startswith("os_error:")
    assert "Too many open files" in outcome.stderr


def test_run_with_timeout_tolerates_non_utf8_output() -> None:
    """Container/subprocess stdout can contain non-UTF-8 bytes (e.g. a 0xa9
    copyright byte from latin-1 output). The success path must decode leniently
    and NOT crash the capture thread.

    Regression: the 2026-06-04 bench surfaced a UnicodeDecodeError at run.py:105
    on CVE-2021-26828 (a 0xa9 byte) — ``subprocess.run(..., text=True)`` decodes
    strictly and UnicodeDecodeError (a ValueError) is NOT caught by ``_target``,
    so the daemon capture thread crashed (non-fatal but a real defect)."""
    outcome = run_with_timeout(
        ["python3", "-c", "import sys; sys.stdout.buffer.write(b'pre\\xa9post')"],
        timeout=5.0,
    )
    assert isinstance(outcome, RunOutcome)
    assert outcome.timed_out is False
    assert outcome.returncode == 0
    # 0xa9 is an invalid UTF-8 start byte → lenient decode yields U+FFFD,
    # and the surrounding ASCII survives.
    assert "pre" in outcome.stdout and "post" in outcome.stdout
    assert "�" in outcome.stdout
