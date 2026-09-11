"""Key-creation race: the loser must tolerate the winner's write gap.

The O_EXCL creation loser re-reads the winner's key file. Between the
winner's O_EXCL create and its write, the file exists with 0 bytes — a
transient shape of the same race as the file not existing yet. The
loser must keep polling through short reads inside its bounded loop
and only report a suspect key once the retries are exhausted.
"""

from __future__ import annotations

import itertools
import os

import pytest

from core.llm import cache_integrity


@pytest.fixture(autouse=True)
def _isolated_key(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))


@pytest.fixture()
def warn_calls(monkeypatch):
    calls: list[tuple] = []
    monkeypatch.setattr(
        cache_integrity, "_warn_once_suspect_key",
        lambda *args: calls.append(args),
    )
    return calls


@pytest.fixture()
def _lose_creation_race(monkeypatch):
    """Make the key-create os.open lose the O_EXCL race."""
    real_open = os.open

    def fake_open(path, flags, mode=0o777):
        if flags & os.O_EXCL:
            raise FileExistsError(path)
        return real_open(path, flags, mode)

    monkeypatch.setattr(cache_integrity.os, "open", fake_open)
    monkeypatch.setattr(cache_integrity.time, "sleep", lambda s: None)


def test_race_loser_retries_through_empty_read(
        monkeypatch, warn_calls, _lose_creation_race) -> None:
    """First re-read sees the winner's 0-byte file, second sees the
    full key — hit, no suspect-key warning."""
    full_key = b"k" * 32
    reads = iter([None, b"", full_key])
    monkeypatch.setattr(
        cache_integrity, "_read_existing_key", lambda path: next(reads),
    )

    assert cache_integrity._load_or_create_key() == full_key
    assert warn_calls == []


def test_persistent_wrong_length_warns_after_retries(
        monkeypatch, warn_calls, _lose_creation_race) -> None:
    """A key file that STAYS short is genuinely suspect: the loop runs
    out of retries, warns once, and refuses (None)."""
    reads = itertools.chain([None], itertools.repeat(b"short"))
    monkeypatch.setattr(
        cache_integrity, "_read_existing_key", lambda path: next(reads),
    )

    assert cache_integrity._load_or_create_key() is None
    assert len(warn_calls) == 1
    assert "wrong length" in warn_calls[0][1]
