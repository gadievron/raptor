"""Tests for .github/scripts/test_impact.py — graph cache placement."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import test_impact


class TestCachePath:
    def test_cache_lives_in_per_uid_private_dir(self, tmp_path, monkeypatch):
        monkeypatch.setattr(test_impact.tempfile, "gettempdir",
                            lambda: str(tmp_path))
        p = test_impact._cache_path(Path("/some/repo"))
        assert p is not None
        d = p.parent
        assert d.name == f"raptor-test-impact-{os.getuid()}"
        assert stat.S_IMODE(d.stat().st_mode) == 0o700
        assert d.stat().st_uid == os.getuid()

    def test_same_repo_same_path(self, tmp_path, monkeypatch):
        monkeypatch.setattr(test_impact.tempfile, "gettempdir",
                            lambda: str(tmp_path))
        a = test_impact._cache_path(Path("/some/repo"))
        b = test_impact._cache_path(Path("/some/repo"))
        c = test_impact._cache_path(Path("/other/repo"))
        assert a == b
        assert a != c

    def test_symlinked_dir_disables_cache(self, tmp_path, monkeypatch):
        # A pre-positioned symlink where the cache dir should be is a
        # squat — run uncached rather than follow it.
        monkeypatch.setattr(test_impact.tempfile, "gettempdir",
                            lambda: str(tmp_path))
        target = tmp_path / "elsewhere"
        target.mkdir()
        (tmp_path / f"raptor-test-impact-{os.getuid()}").symlink_to(target)
        assert test_impact._cache_path(Path("/some/repo")) is None
