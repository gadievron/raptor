"""Tests for core/coverage/journal_mac.py — key-loader read discipline.

The mint/verify/tier semantics are exercised end-to-end by the journal
and fold suites; these tests pin the key *loader* mechanics that those
paths depend on.
"""

from __future__ import annotations

import os
from pathlib import Path

from core.coverage import journal_mac


# ---------------------------------------------------------------------------
# Key loader: short-read tolerance
# ---------------------------------------------------------------------------


def test_chunked_key_read_loads_full_key(tmp_path: Path, monkeypatch) -> None:
    """os.read may legally return fewer bytes than requested; chunked
    delivery must not land a healthy key in the wrong-length refusal
    (which would demote every stamped journal row to the unstamped
    tier)."""
    key_file = tmp_path / "journal-mac.key"
    data = os.urandom(32)
    key_file.write_bytes(data)
    key_file.chmod(0o600)
    real_read = os.read
    monkeypatch.setattr(os, "read", lambda fd, n: real_read(fd, min(n, 5)))
    assert journal_mac._read_existing_key(key_file) == data


def test_truncated_key_file_reads_exact_length(
    tmp_path: Path, monkeypatch,
) -> None:
    # Two-direction guard: the loop reads to EOF, never pads — a torn
    # 10-byte key still fails the caller's length check (fail-closed).
    key_file = tmp_path / "journal-mac.key"
    key_file.write_bytes(os.urandom(10))
    key_file.chmod(0o600)
    real_read = os.read
    monkeypatch.setattr(os, "read", lambda fd, n: real_read(fd, min(n, 5)))
    got = journal_mac._read_existing_key(key_file)
    assert isinstance(got, bytes)
    assert len(got) == 10
