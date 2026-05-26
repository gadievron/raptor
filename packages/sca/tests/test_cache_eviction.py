"""Tests for ``packages.sca.cache_eviction.evict_stale``."""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from packages.sca.cache_eviction import (
    DEFAULT_MAX_AGE_DAYS,
    EvictionResult,
    evict_stale,
)


def _mktree(root: Path, files: dict[str, int]) -> None:
    """``files`` maps relative-path → age-in-days."""
    now = time.time()
    for rel, age_days in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("x", encoding="utf-8")
        when = now - age_days * 86400
        os.utime(p, (when, when))


def test_returns_zero_when_root_missing(tmp_path: Path) -> None:
    res = evict_stale(tmp_path / "nonexistent")
    assert res == EvictionResult()


def test_removes_files_older_than_max_age(tmp_path: Path) -> None:
    _mktree(tmp_path, {
        "queries/old.json": 60,
        "vulns/older.json": 90,
        "kev.json": 5,            # fresh
    })
    res = evict_stale(tmp_path, max_age_days=30)
    assert res.files_scanned == 3
    assert res.files_removed == 2
    assert (tmp_path / "kev.json").exists()
    assert not (tmp_path / "queries/old.json").exists()
    assert not (tmp_path / "vulns/older.json").exists()


def test_keeps_files_newer_than_max_age(tmp_path: Path) -> None:
    _mktree(tmp_path, {"queries/fresh.json": 1})
    res = evict_stale(tmp_path, max_age_days=30)
    assert res.files_removed == 0
    assert (tmp_path / "queries/fresh.json").exists()


def test_removes_empty_subdirs_after_eviction(tmp_path: Path) -> None:
    _mktree(tmp_path, {"queries/old.json": 60})
    res = evict_stale(tmp_path, max_age_days=30)
    assert res.dirs_removed == 1
    assert not (tmp_path / "queries").exists()


def test_keeps_root_dir_even_when_all_files_evicted(tmp_path: Path) -> None:
    _mktree(tmp_path, {"queries/old.json": 90})
    evict_stale(tmp_path, max_age_days=30)
    assert tmp_path.exists()      # root preserved


def test_default_max_age_is_30_days(tmp_path: Path) -> None:
    """Sanity: the constant is what the design specifies (30 days)."""
    assert DEFAULT_MAX_AGE_DAYS == 30


def test_bytes_freed_is_summed(tmp_path: Path) -> None:
    _mktree(tmp_path, {"q/a.json": 60, "q/b.json": 60})
    # Each file is 1 byte; expect 2 freed.
    res = evict_stale(tmp_path, max_age_days=30)
    assert res.files_removed == 2
    assert res.bytes_freed == 2


def test_now_override_makes_eviction_deterministic(tmp_path: Path) -> None:
    """Pin ``now`` so the cutoff is independent of wall-clock drift —
    same fixture always evicts the same files in CI."""
    _mktree(tmp_path, {"q/old.json": 60, "q/new.json": 1})
    fake_now = time.time()
    res = evict_stale(tmp_path, max_age_days=30, now=fake_now)
    assert res.files_removed == 1
    assert (tmp_path / "q/new.json").exists()


def test_unwritable_file_counted_as_error_not_crash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Permission errors on a single file shouldn't break the sweep."""
    _mktree(tmp_path, {"q/x.json": 60, "q/y.json": 60})

    real_unlink = Path.unlink
    target = tmp_path / "q/x.json"

    def selective_unlink(self, *a, **kw):
        if self == target:
            raise PermissionError("simulated")
        return real_unlink(self, *a, **kw)

    monkeypatch.setattr(Path, "unlink", selective_unlink)
    res = evict_stale(tmp_path, max_age_days=30)
    assert res.errors == 1
    assert res.files_removed == 1     # the other one succeeded
    assert target.exists()            # the failed one stayed
