"""Regression tests for F070.

`core/sandbox/seatbelt_audit.py` had seven `except OSError/Exception`
sites in the reader thread and the warm-up gate. Per-site triage:

  L284  warm_up.terminate() cleanup after warm-up itself raised
        -> INTENTIONAL cleanup of an already-dead process; KEEP, add
        rationale comment.

  L332  subprocess.Popen of the warm-up `sandbox-exec` binary failed
        -> PROMOTE DEBUG -> WARNING. Without it the warm-up gate
        returns False on a totally-silent OSError and the operator
        never knows why their audit run started without a warm-up.

  L391  warm_up.terminate() inside the gate's selector-loop finally
        -> INTENTIONAL cleanup of a process that may already be dead;
        KEEP, add rationale.

  L447  JSONL append failed inside _read_loop's inner block
        -> PROMOTE DEBUG -> WARNING. Mirrors F069 family-wide rationale
        (operators rarely run with DEBUG, so audit-record loss was
        previously invisible).

  L453  Top-level Exception in _read_loop crashes the reader thread
        -> PROMOTE DEBUG -> WARNING. A dead reader thread means ALL
        subsequent audit records are lost; this must not be invisible.

  L546  Summary record append at stop() failed
        -> PROMOTE DEBUG -> WARNING. Same rationale as L447.

  L557  os.close(self._dirfd) cleanup in stop()
        -> INTENTIONAL cleanup of an fd that may already be invalid;
        KEEP, add rationale.

So: 4 promote (L332, L447, L453, L546) + 3 keep-with-rationale
(L284, L391, L557). The promoted four are the ones that signal a
*loss of audit information*; the kept three signal *cleanup attempts
on best-effort cleanup paths* where additional logging would be
noise.

This test file covers the 4 promoted sites by patching the underlying
operation to raise and asserting WARNING is emitted.
"""

from __future__ import annotations

import logging
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from core.sandbox import seatbelt_audit


def _make_streamer(tmp_path: Path) -> seatbelt_audit.LogStreamer:
    return seatbelt_audit.LogStreamer(tmp_path)


def test_f070_l447_append_failure_logs_warning(tmp_path, caplog):
    """L447: When `_append_record_locked` raises OSError during the
    reader loop's inner block, a WARNING (not DEBUG) must be emitted."""
    streamer = _make_streamer(tmp_path)

    # Fake _proc that yields one parseable line then EOF.
    fake_line = (
        '{"senderImagePath":"/System/Library/Extensions/Sandbox.kext/'
        'Contents/MacOS/Sandbox","eventMessage":"Sandbox: '
        'tgt(1234) deny file-write-create /tmp/x"}\n'
    )
    fake_proc = MagicMock()
    fake_proc.stdout = iter([fake_line])
    streamer._proc = fake_proc

    # parse_log_entry returns a usable record dict.
    with patch.object(
        seatbelt_audit, "parse_log_entry",
        return_value={"syscall": "file-write-create", "target_pid": 1234},
    ):
        # Force the inner _append_record_locked to raise OSError.
        with patch.object(
            seatbelt_audit.LogStreamer, "_append_record_locked",
            side_effect=OSError("disk full"),
        ):
            with caplog.at_level(
                logging.DEBUG, logger="core.sandbox.seatbelt_audit",
            ):
                streamer._read_loop()

    warnings = [
        r for r in caplog.records
        if r.levelname == "WARNING"
        and "append failed" in r.getMessage()
    ]
    assert warnings, (
        "expected WARNING when seatbelt audit append fails; got "
        f"{[(r.levelname, r.getMessage()) for r in caplog.records]}"
    )


def test_f070_l453_reader_crash_logs_warning(tmp_path, caplog):
    """L453: When the reader thread top-level catches an unexpected
    Exception (e.g. an unhandled error from parse_log_entry), a WARNING
    (not DEBUG) must be emitted so operators see the thread death."""
    streamer = _make_streamer(tmp_path)
    fake_line = '{"senderImagePath":"x","eventMessage":"y"}\n'
    fake_proc = MagicMock()
    fake_proc.stdout = iter([fake_line])
    streamer._proc = fake_proc

    # Make parse_log_entry raise a RuntimeError to exercise the L453
    # `except Exception` arm. The OSError-arm (L447) is the other arm
    # and is covered by test_f070_l447 above.
    with patch.object(
        seatbelt_audit, "parse_log_entry",
        side_effect=RuntimeError("unexpected"),
    ):
        with caplog.at_level(
            logging.DEBUG, logger="core.sandbox.seatbelt_audit",
        ):
            streamer._read_loop()

    warnings = [
        r for r in caplog.records
        if r.levelname == "WARNING"
        and "reader thread crashed" in r.getMessage()
    ]
    assert warnings, (
        "expected WARNING when seatbelt reader thread crashes; got "
        f"{[(r.levelname, r.getMessage()) for r in caplog.records]}"
    )


def test_f070_l546_summary_append_failure_logs_warning(tmp_path, caplog):
    """L546: When stop()'s summary-record append raises OSError, a
    WARNING (not DEBUG) must be emitted. Summary loss = silent audit
    integrity gap."""
    streamer = _make_streamer(tmp_path)

    # stop() needs a non-None _proc to enter the summary branch.
    fake_proc = MagicMock()
    fake_proc.poll.return_value = 0  # already terminated
    fake_proc.wait.return_value = 0
    streamer._proc = fake_proc
    # Pretend reader is gone so stop() doesn't try to join a real thread.
    streamer._reader = None

    # Force the summary append to raise OSError.
    with patch.object(
        seatbelt_audit.LogStreamer, "_append_record_locked",
        side_effect=OSError("disk full"),
    ):
        with caplog.at_level(
            logging.DEBUG, logger="core.sandbox.seatbelt_audit",
        ):
            streamer.stop(drain_timeout=0.01)

    warnings = [
        r for r in caplog.records
        if r.levelname == "WARNING"
        and "summary append failed" in r.getMessage()
    ]
    assert warnings, (
        "expected WARNING when seatbelt summary append fails; got "
        f"{[(r.levelname, r.getMessage()) for r in caplog.records]}"
    )


def test_f070_l332_warmup_popen_oserror_logs_warning(tmp_path, caplog):
    """L332: When the warm-up's sandbox-exec subprocess.Popen raises
    OSError (e.g. ENOENT, EACCES), a WARNING (not silent return False)
    must be emitted so operators know the warm-up gate failed."""
    streamer = _make_streamer(tmp_path)

    # _warm_up_until_attached short-circuits early if sandbox-exec is
    # missing. Patch the existence check to make it think the binary
    # is present, then make Popen raise.
    with patch.object(seatbelt_audit.shutil, "which", return_value="/usr/bin/sandbox-exec"), \
         patch.object(seatbelt_audit, "Path") as path_cls, \
         patch.object(seatbelt_audit.subprocess, "Popen",
                      side_effect=OSError("EACCES")):
        path_cls.return_value.exists.return_value = True
        # Also need _proc set so the warm-up function doesn't hit its
        # earlier "self._proc is None" guard.
        streamer._proc = MagicMock()
        streamer._proc.stdout = MagicMock()
        with caplog.at_level(
            logging.DEBUG, logger="core.sandbox.seatbelt_audit",
        ):
            result = streamer._warm_up_until_attached()

    assert result is False
    warnings = [
        r for r in caplog.records
        if r.levelname == "WARNING"
        and "warm-up" in r.getMessage().lower()
        and "popen" in r.getMessage().lower()
    ]
    assert warnings, (
        "expected WARNING when warm-up Popen fails; got "
        f"{[(r.levelname, r.getMessage()) for r in caplog.records]}"
    )
