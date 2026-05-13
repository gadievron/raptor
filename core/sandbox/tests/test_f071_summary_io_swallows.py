"""Regression tests for F071.

`core/sandbox/summary.py` had several `except OSError/Exception` sites
that swallowed I/O failures at DEBUG (or silently). Per-site triage:

  L191  record_denial JSONL append failure
        -> PROMOTE DEBUG -> WARNING. Sandbox-denial record loss must be
        visible to operators; mirrors F069/F070 family.

  L294  record_audit_degraded tmp.unlink cleanup
        -> KEEP-SILENT. Cleanup path; missing_ok=True already used.

  L334  summarize_and_write os.replace(jsonl, tmp) OSError
        -> KEEP-SILENT. This is the race-lost branch (sibling already
        renamed and is summarising). Not data loss — the other party
        is producing the summary. Returns None correctly.

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
        The sentinel (return None) is correct contract; this just
        adds operator visibility.

  L406  L403's tmp.unlink cleanup
        -> KEEP-SILENT. Cleanup path.

So: 3 promote (L191, L349, L403) + 5 keep-with-rationale. The
promoted three are the data-loss-visibility sites; the kept five are
cleanup paths where logging would be noise.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from core.sandbox import summary as summary_mod


def test_f071_l191_record_denial_append_failure_logs_warning(
    tmp_path, caplog, monkeypatch,
):
    """L191: When the JSONL append fails (e.g. EACCES), a WARNING
    (not DEBUG) must be emitted. Mirrors F069 record_denial-side
    visibility rationale."""
    # Set the module-level active run dir so record_denial doesn't
    # no-op early.
    monkeypatch.setattr(summary_mod, "_active_run_dir", tmp_path)
    # Force os.open inside record_denial to raise OSError.
    real_open = os.open
    target_path = str(tmp_path / ".sandbox-denials.jsonl")

    def fake_open(path, flags, mode=0o666):
        if str(path) == target_path:
            raise OSError("EACCES")
        return real_open(path, flags, mode)

    monkeypatch.setattr(summary_mod.os, "open", fake_open)
    with caplog.at_level(logging.DEBUG, logger="core.sandbox.summary"):
        summary_mod.record_denial(
            "test-cmd", 1, "network",
            host="example.invalid",
        )

    warnings = [
        r for r in caplog.records
        if r.levelname == "WARNING"
        and "record_denial" in r.getMessage()
    ]
    assert warnings, (
        "expected WARNING when record_denial append fails; got "
        f"{[(r.levelname, r.getMessage()) for r in caplog.records]}"
    )


def test_f071_l349_summarize_read_failure_logs_warning(
    tmp_path, caplog, monkeypatch,
):
    """L349: When the renamed-tmp JSONL cannot be opened/read, a
    WARNING (not silent return-None) must be emitted. Otherwise the
    summary disappears with no operator signal."""
    # Seed a JSONL so the rename succeeds.
    jsonl = tmp_path / ".sandbox-denials.jsonl"
    jsonl.write_text('{"type": "network", "host": "x"}\n', encoding="utf-8")

    # Patch builtins.open inside summary_mod to raise OSError when
    # reading the renamed tmp.
    real_open = open

    def fake_open(path, *args, **kwargs):
        spath = str(path)
        if ".sandbox-denials.jsonl.summarising" in spath:
            raise OSError("EIO read failed")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr("builtins.open", fake_open)

    with caplog.at_level(logging.DEBUG, logger="core.sandbox.summary"):
        result = summary_mod.summarize_and_write(tmp_path)

    assert result is None, "summarize_and_write must return None on read fail"
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

    # Patch os.replace so the SUMMARY write (second replace call)
    # fails, while letting the JSONL rename (first replace call)
    # succeed.
    real_replace = os.replace
    state = {"count": 0}

    def fake_replace(src, dst):
        state["count"] += 1
        if "sandbox-summary.json" in str(dst):
            raise OSError("EXDEV")
        return real_replace(src, dst)

    monkeypatch.setattr(summary_mod.os, "replace", fake_replace)

    with caplog.at_level(logging.DEBUG, logger="core.sandbox.summary"):
        result = summary_mod.summarize_and_write(tmp_path)

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
