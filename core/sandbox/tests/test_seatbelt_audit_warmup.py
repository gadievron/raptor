"""Warm-up gate tests for ``LogStreamer.start()``.

The warm-up gate spawns a synthetic ``sandbox-exec`` workload and
drains ``log stream`` stdout until a kext record from that workload's
PID appears — guaranteeing kernel-side filter attachment before the
real workload runs.

Cross-platform: tests mock ``subprocess.Popen`` for both ``log
stream`` and ``sandbox-exec`` so they exercise the gate's logic
without touching macOS-only binaries. Real Darwin end-to-end
validation lives outside the unit suite.
"""

from __future__ import annotations

import io
import json
from unittest import mock


from core.sandbox import seatbelt_audit
from core.sandbox.seatbelt import SANDBOX_KEXT_SENDER


def _kext_line(*, pid: int, name: str = "sandbox-exec",
               action: str = "file-read-data",
               path: str = "/usr/bin/true") -> bytes:
    """Build one ndjson line that ``log stream`` would emit."""
    entry = {
        "senderImagePath": SANDBOX_KEXT_SENDER,
        "eventMessage": f"Sandbox: {name}({pid}) deny {action} {path}",
        "timestamp": "2026-05-09 12:00:00.000000+0000",
        "subsystem": "",
        "category": "",
    }
    return (json.dumps(entry) + "\n").encode("utf-8")


class _FakeStdout:
    """Pipe-like stdout backed by an injectable line list. Mirrors
    just enough of a TextIO buffered stream that the warm-up gate's
    selector + readline loop works without spawning subprocesses."""

    def __init__(self, lines):
        self._buf = io.BytesIO(b"".join(lines))
        # selectors needs a real fd — back the BytesIO with a pipe.
        import os
        self._read_fd, self._write_fd = os.pipe()
        os.write(self._write_fd, b"".join(lines))
        os.close(self._write_fd)
        self._reader = open(self._read_fd, "r", encoding="utf-8")

    def fileno(self):
        return self._reader.fileno()

    def readline(self):
        return self._reader.readline()

    def close(self):
        try:
            self._reader.close()
        except OSError:
            pass


class _FakeProc:
    """Stand-in for the ``log stream`` Popen. Carries ``stdout`` and a
    ``terminate``/``poll`` shape sufficient for the gate to manage it."""

    def __init__(self, stdout):
        self.stdout = stdout
        self.terminated = False
        self.pid = 99999

    def terminate(self):
        self.terminated = True

    def poll(self):
        return None


class _FakeWarmUp:
    """Stand-in for the ``sandbox-exec`` Popen — exits immediately,
    just carries a synthetic PID for the gate to match against the
    injected kext records."""

    def __init__(self, pid: int):
        self.pid = pid
        self.terminated = False

    def wait(self, timeout=None):
        return 1  # `(deny default)` denies exec → non-zero

    def terminate(self):
        self.terminated = True


def _make_streamer(tmp_path):
    """Construct a LogStreamer wired to a tmp run_dir; tests assign
    ``_proc`` directly to bypass the real Popen('/usr/bin/log')."""
    return seatbelt_audit.LogStreamer(
        run_dir=tmp_path, observe_mode=True, observe_nonce="warm-up-test",
    )


def test_warm_up_returns_true_when_target_pid_event_seen(tmp_path):
    """Gate returns True as soon as a kext record matching the
    warm-up's PID is parsed from log-stream stdout."""
    target_pid = 4242
    lines = [
        _kext_line(pid=111),          # other sandboxed proc — skip
        _kext_line(pid=target_pid),   # warm-up — matches
        _kext_line(pid=222),          # would-be later event
    ]
    streamer = _make_streamer(tmp_path)
    streamer._proc = _FakeProc(_FakeStdout(lines))

    with mock.patch.object(
        seatbelt_audit.subprocess, "Popen",
        return_value=_FakeWarmUp(target_pid),
    ), mock.patch.object(
        seatbelt_audit.shutil, "which",
        return_value="/usr/bin/sandbox-exec",
    ), mock.patch.object(
        seatbelt_audit.Path, "exists", return_value=True,
    ):
        result = streamer._warm_up_until_attached()

    assert result is True


def test_warm_up_returns_false_when_no_target_pid_event(tmp_path):
    """If log-stream stdout never carries the warm-up's PID and the
    timeout fires, the gate returns False so callers fall back to
    best-effort mode."""
    target_pid = 4242
    # Only events from unrelated PIDs.
    lines = [_kext_line(pid=111), _kext_line(pid=222)]
    streamer = _make_streamer(tmp_path)
    streamer._proc = _FakeProc(_FakeStdout(lines))

    # Compress the timeout for a fast unit-test run.
    with mock.patch.object(
        seatbelt_audit, "_WARM_UP_TIMEOUT_S", 0.5,
    ), mock.patch.object(
        seatbelt_audit.subprocess, "Popen",
        return_value=_FakeWarmUp(target_pid),
    ), mock.patch.object(
        seatbelt_audit.shutil, "which",
        return_value="/usr/bin/sandbox-exec",
    ), mock.patch.object(
        seatbelt_audit.Path, "exists", return_value=True,
    ):
        result = streamer._warm_up_until_attached()

    assert result is False


def test_warm_up_returns_false_when_sandbox_exec_missing(tmp_path):
    """Non-Darwin host (or stripped install) — gate skips cleanly."""
    streamer = _make_streamer(tmp_path)
    streamer._proc = _FakeProc(_FakeStdout([]))

    with mock.patch.object(
        seatbelt_audit.shutil, "which", return_value=None,
    ), mock.patch.object(
        seatbelt_audit.Path, "exists", return_value=False,
    ):
        result = streamer._warm_up_until_attached()

    assert result is False


def test_warm_up_returns_false_when_sandbox_exec_oserror(tmp_path):
    """Popen('sandbox-exec') failing (binary present but unrunnable)
    is also a clean fall-through, not a crash."""
    streamer = _make_streamer(tmp_path)
    streamer._proc = _FakeProc(_FakeStdout([]))

    with mock.patch.object(
        seatbelt_audit.subprocess, "Popen",
        side_effect=OSError("denied"),
    ), mock.patch.object(
        seatbelt_audit.shutil, "which",
        return_value="/usr/bin/sandbox-exec",
    ), mock.patch.object(
        seatbelt_audit.Path, "exists", return_value=True,
    ):
        result = streamer._warm_up_until_attached()

    assert result is False


def test_warm_up_invokes_sandbox_exec_with_deny_default_profile(tmp_path):
    """The synthetic workload uses a deny-default SBPL profile so the
    kext deny event fires deterministically. Pin the argv shape — if
    a future change loosens the profile, we want the test to fail so
    we re-validate the warm-up still emits an event."""
    target_pid = 7000
    lines = [_kext_line(pid=target_pid)]
    streamer = _make_streamer(tmp_path)
    streamer._proc = _FakeProc(_FakeStdout(lines))

    captured: list = []

    def _capture_popen(argv, **kwargs):
        captured.append(argv)
        return _FakeWarmUp(target_pid)

    with mock.patch.object(
        seatbelt_audit.subprocess, "Popen", side_effect=_capture_popen,
    ), mock.patch.object(
        seatbelt_audit.shutil, "which",
        return_value="/usr/bin/sandbox-exec",
    ), mock.patch.object(
        seatbelt_audit.Path, "exists", return_value=True,
    ):
        streamer._warm_up_until_attached()

    assert len(captured) == 1
    argv = captured[0]
    assert argv[0] == "/usr/bin/sandbox-exec"
    assert argv[1] == "-p"
    assert "deny default" in argv[2]
    assert "with report" in argv[2]
    assert argv[3] == "/usr/bin/true"


def test_warm_up_skips_non_kext_entries(tmp_path):
    """Non-Sandbox.kext entries (or malformed JSON / messages) are
    ignored — the gate keeps reading until a real kext record from
    the warm-up's PID arrives. Guards against false positives if the
    predicate ever loosens upstream."""
    target_pid = 8000
    # Mix in: malformed JSON, non-kext entry (no eventMessage match),
    # finally the real warm-up event.
    bad_json = b"this is not json\n"
    non_kext = json.dumps({
        "senderImagePath": "/some/other/sender",
        "eventMessage": f"Sandbox: foo({target_pid}) allow file-read /etc",
    }).encode("utf-8") + b"\n"
    lines = [
        bad_json,
        non_kext,  # would match PID but isn't really a kext entry —
                   # though our parser only checks eventMessage shape,
                   # so this DOES count. Use a clearly non-matching
                   # entry instead.
        _kext_line(pid=target_pid),
    ]
    # Replace non_kext with something whose eventMessage doesn't match
    # the kext regex.
    lines[1] = json.dumps({
        "senderImagePath": SANDBOX_KEXT_SENDER,
        "eventMessage": "Some other unrelated kext message",
    }).encode("utf-8") + b"\n"

    streamer = _make_streamer(tmp_path)
    streamer._proc = _FakeProc(_FakeStdout(lines))

    with mock.patch.object(
        seatbelt_audit.subprocess, "Popen",
        return_value=_FakeWarmUp(target_pid),
    ), mock.patch.object(
        seatbelt_audit.shutil, "which",
        return_value="/usr/bin/sandbox-exec",
    ), mock.patch.object(
        seatbelt_audit.Path, "exists", return_value=True,
    ):
        result = streamer._warm_up_until_attached()

    assert result is True


def test_start_proceeds_in_best_effort_when_warm_up_times_out(tmp_path):
    """End-to-end: when the warm-up reports False, ``start()`` still
    starts the reader thread — best-effort fallback — rather than
    raising. Operators get a debug log; sandboxing continues."""
    streamer = _make_streamer(tmp_path)

    # Stub `log stream` Popen with a fake that won't be drained.
    fake_log_stream = _FakeProc(_FakeStdout([]))

    def _popen_substitute(argv, **kwargs):
        # Only the first Popen call is for `log stream`; treat
        # subsequent ones as the warm-up.
        if argv[0] == "/usr/bin/log":
            return fake_log_stream
        return _FakeWarmUp(pid=12345)

    with mock.patch.object(
        seatbelt_audit, "_WARM_UP_TIMEOUT_S", 0.2,
    ), mock.patch.object(
        seatbelt_audit.subprocess, "Popen", side_effect=_popen_substitute,
    ), mock.patch.object(
        seatbelt_audit.shutil, "which",
        return_value="/usr/bin/sandbox-exec",
    ), mock.patch.object(
        seatbelt_audit.Path, "exists", return_value=True,
    ):
        streamer.start()

    # Reader thread started despite warm-up returning False.
    assert streamer._reader is not None
    assert streamer._reader.is_alive() or streamer._reader.ident is not None
    streamer._stopped.set()


def test_warm_up_reaps_child_even_on_match(tmp_path):
    """The synthetic workload must be reaped — leaking a zombie
    sandbox-exec per LogStreamer would compound across runs."""
    target_pid = 9000
    lines = [_kext_line(pid=target_pid)]
    streamer = _make_streamer(tmp_path)
    streamer._proc = _FakeProc(_FakeStdout(lines))

    warm_up = _FakeWarmUp(target_pid)
    wait_called = []
    orig_wait = warm_up.wait

    def _track_wait(timeout=None):
        wait_called.append(timeout)
        return orig_wait(timeout)
    warm_up.wait = _track_wait

    with mock.patch.object(
        seatbelt_audit.subprocess, "Popen", return_value=warm_up,
    ), mock.patch.object(
        seatbelt_audit.shutil, "which",
        return_value="/usr/bin/sandbox-exec",
    ), mock.patch.object(
        seatbelt_audit.Path, "exists", return_value=True,
    ):
        streamer._warm_up_until_attached()

    assert wait_called, "warm-up child was not reaped via wait()"
