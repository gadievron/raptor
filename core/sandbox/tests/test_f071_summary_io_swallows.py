"""Regression tests for F071.

`core/sandbox/summary.py` had several `except OSError/Exception` sites
that swallowed I/O failures at DEBUG (or silently). Per-site triage:

  L191  record_denial JSONL append failure
        -> PROMOTE DEBUG -> WARNING. Sandbox-denial record loss must be
        visible to operators; mirrors F069/F070 family.

  L294  record_audit_degraded tmp.unlink cleanup
        -> KEEP-SILENT. Cleanup path; missing_ok=True already used.

  L334  summarize_and_write os.replace(jsonl, tmp) FileNotFoundError
        -> KEEP-SILENT. This is the race-lost branch (sibling already
        renamed and is summarising). Not data loss — the other party
        is producing the summary. Other rename I/O failures warn.
        Returns None correctly for the expected race.

  L349  summarize_and_write open(tmp) read OSError
        -> PROMOTE DEBUG -> WARNING (currently silent return None).
        This drops the entire summary; operator must know.

  L352  L349's tmp.unlink cleanup
        -> KEEP-SILENT. Cleanup path.

  L359  successful-path tmp.unlink
        -> KEEP-SILENT. Cleanup of drained file.

  L403  summarize_and_write summary-write os.replace OSError
        -> PROMOTE DEBUG -> WARNING (currently silent return None).
        Silent loss of the run's final summary; operator must know.
        The default return-None sentinel preserves lifecycle behavior;
        explicit strict callers propagate the operational error.

  L406  L403's tmp.unlink cleanup
        -> KEEP-SILENT. Cleanup path.

So: 3 promote (L191, L349, L403) + 5 keep-with-rationale. The
promoted three are the data-loss-visibility sites; the kept five are
cleanup paths where logging would be noise.
"""

from __future__ import annotations

import errno
import logging
import os
from types import ModuleType

import pytest

from core.sandbox import summary as summary_mod
from core.testing.sandbox_state_scope import isolated_sandbox_state
from core.testing.state_isolation import pin_user_state_dirs


@pytest.fixture(autouse=True)
def owned_state(tmp_path):
    with isolated_sandbox_state(()), pytest.MonkeyPatch.context() as patch:
        pin_user_state_dirs(patch, tmp_path / "state")
        patch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
        yield


@pytest.fixture
def monkeypatch(owned_state):
    with pytest.MonkeyPatch.context() as patch:
        yield patch


def test_f071_l191_record_denial_append_failure_logs_warning(
    tmp_path, caplog, monkeypatch,
):
    """L191: When the JSONL append fails (e.g. EACCES), a WARNING
    (not DEBUG) must be emitted. Mirrors F069 record_denial-side
    visibility rationale."""
    # Set the module-level active run dir so record_denial doesn't
    # no-op early.
    summary_mod.set_active_run_dir(tmp_path)
    # Force the evidence-file open inside record_denial to raise
    # OSError (record_denial appends via a held evidence fd under
    # <run_dir>/.audit/ since the evidence relocation).
    from core.sandbox import evidence as evidence_mod
    real_open = os.open
    target_path = str(
        evidence_mod.evidence_write_path(
            tmp_path, ".sandbox-denials.jsonl",
        )
    )

    private = ModuleType("evidence_warning_os")
    vars(private).update(vars(os))
    failure = PermissionError(errno.EACCES, "owned evidence open refusal")
    failed = []

    def fake_open(path, flags, *args, **kwargs):
        if (str(path) == target_path
                or (str(path) == summary_mod.DENIALS_FILE
                    and kwargs.get("dir_fd") is not None)):
            failed.append(path)
            raise failure
        return real_open(path, flags, *args, **kwargs)

    private.open = fake_open
    monkeypatch.setattr(evidence_mod, "os", private)
    with caplog.at_level(logging.DEBUG, logger="core.sandbox.summary"):
        summary_mod.record_denial(
            "test-cmd", 1, "network",
            host="example.invalid",
        )

    assert len(failed) == 1
    assert os.open is real_open
    assert summary_mod.get_evidence_write_failure(tmp_path) is True
    warnings = [
        r for r in caplog.records
        if r.levelname == "WARNING"
        and "record_denial" in r.getMessage()
    ]
    assert warnings, (
        "expected WARNING when record_denial append fails; got "
        f"{[(r.levelname, r.getMessage()) for r in caplog.records]}"
    )
    assert any(record.exc_info and record.exc_info[1] is failure for record in warnings)


def test_f071_l349_summarize_read_failure_logs_warning(
    tmp_path, caplog, monkeypatch,
):
    """L349: When the renamed-tmp JSONL cannot be opened/read, a
    WARNING (not silent return-None) must be emitted. Otherwise the
    summary disappears with no operator signal."""
    # Seed a JSONL so the rename succeeds.
    jsonl = tmp_path / ".sandbox-denials.jsonl"
    jsonl.write_text('{"type": "network", "host": "x"}\n', encoding="utf-8")

    # Patch os.open (the F071 fd-based read path) to raise OSError
    # when opening the renamed tmp. A generic OSError (not ELOOP) is
    # the host-I/O branch — warn + return None, never tamper-flag.
    private = ModuleType("summary_read_warning_os")
    vars(private).update(vars(os))
    real_os_open = os.open
    failed = []

    def fake_os_open(path, *args, **kwargs):
        spath = str(path)
        if ".sandbox-denials.jsonl.summarising" in spath:
            failed.append(path)
            raise OSError(errno.EIO, "owned read failure")
        return real_os_open(path, *args, **kwargs)

    private.open = fake_os_open
    monkeypatch.setattr(summary_mod, "os", private)

    with caplog.at_level(logging.DEBUG, logger="core.sandbox.summary"):
        result = summary_mod.summarize_and_write(tmp_path)

    assert result is None, "summarize_and_write must return None on read fail"
    assert len(failed) == 1
    assert os.open is real_os_open
    warnings = [
        r for r in caplog.records
        if r.levelname == "WARNING"
        and "summarize_and_write" in r.getMessage()
        and "read" in r.getMessage().lower()
    ]
    assert warnings, (
        "expected WARNING when summarize_and_write read fails; got "
        f"{[(r.levelname, r.getMessage()) for r in caplog.records]}"
    )


def test_f071_l403_summarize_write_failure_logs_warning(
    tmp_path, caplog, monkeypatch,
):
    """L403: When os.replace of the summary-tmp fails (target dir
    vanished, EXDEV, EBUSY), a WARNING (not silent return-None) must
    be emitted. Summary loss = silent audit integrity gap."""
    jsonl = tmp_path / ".sandbox-denials.jsonl"
    jsonl.write_text(
        '{"type": "network", "host": "x"}\n',
        encoding="utf-8",
    )

    # A real destination collision exercises the atomic output failure
    # without replacing process-wide filesystem primitives.
    output = tmp_path / summary_mod.SUMMARY_FILE
    output.mkdir()
    sentinel = output / "owned-sentinel"
    sentinel.write_bytes(b"preserve")

    with caplog.at_level(logging.DEBUG, logger="core.sandbox.summary"):
        result = summary_mod.summarize_and_write(tmp_path)

    assert sentinel.read_bytes() == b"preserve"
    snapshots = list(tmp_path.glob(".sandbox-denials.jsonl.summarising.*"))
    assert len(snapshots) == 1
    assert snapshots[0].read_bytes() == b'{"type": "network", "host": "x"}\n'
    assert result is None, (
        "summarize_and_write must return None on summary-write failure"
    )
    warnings = [
        r for r in caplog.records
        if r.levelname == "WARNING"
        and "summarize_and_write" in r.getMessage()
        and ("write" in r.getMessage().lower()
             or "replace" in r.getMessage().lower())
    ]
    assert warnings, (
        "expected WARNING when summary write fails; got "
        f"{[(r.levelname, r.getMessage()) for r in caplog.records]}"
    )
