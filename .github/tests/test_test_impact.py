"""Tests for .github/scripts/test_impact.py — graph cache placement."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

with patch.object(sys, "path", [str(Path(__file__).resolve().parents[1] / "scripts"), *sys.path]):
    import test_impact


class TestCachePath:
    def test_cache_lives_in_per_uid_private_dir(self, tmp_path, monkeypatch):
        monkeypatch.setattr(test_impact, "tempfile", SimpleNamespace(gettempdir=lambda: str(tmp_path)))
        p = test_impact._cache_path(Path("/some/repo"))
        assert p is not None
        d = p.parent
        assert d.name == f"raptor-test-impact-{os.getuid()}"
        assert stat.S_IMODE(d.stat().st_mode) == 0o700
        assert d.stat().st_uid == os.getuid()

    def test_same_repo_same_path(self, tmp_path, monkeypatch):
        monkeypatch.setattr(test_impact, "tempfile", SimpleNamespace(gettempdir=lambda: str(tmp_path)))
        a = test_impact._cache_path(Path("/some/repo"))
        b = test_impact._cache_path(Path("/some/repo"))
        c = test_impact._cache_path(Path("/other/repo"))
        assert a == b
        assert a != c

    def test_symlinked_dir_disables_cache(self, tmp_path, monkeypatch):
        # A pre-positioned symlink where the cache dir should be is a
        # squat — run uncached rather than follow it.
        monkeypatch.setattr(test_impact, "tempfile", SimpleNamespace(gettempdir=lambda: str(tmp_path)))
        target = tmp_path / "elsewhere"
        target.mkdir()
        (tmp_path / f"raptor-test-impact-{os.getuid()}").symlink_to(target)
        assert test_impact._cache_path(Path("/some/repo")) is None


def test_graph_cache_detects_same_mtime_content_changes(tmp_path):
    source = tmp_path / 'owned.py'
    source.write_text('import before\n')
    stamp = source.stat()
    before = test_impact._files_fingerprint([Path('owned.py')], tmp_path)
    source.write_text('import after_\n')
    os.utime(source, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
    assert source.stat().st_mtime_ns == stamp.st_mtime_ns
    assert test_impact._files_fingerprint([Path('owned.py')], tmp_path) != before


def test_graph_builder_changes_invalidate_unmodified_sources(tmp_path):
    source = tmp_path / 'owned.py'
    source.write_text('import owned\n')
    rules = tmp_path / '.github/scripts/codeql_scope.py'
    rules.parent.mkdir(parents=True)
    rules.write_text('BEFORE = 1\n')
    before = test_impact._files_fingerprint([Path('owned.py')], tmp_path)
    rules.write_text('AFTER_ = 1\n')
    assert test_impact._files_fingerprint([Path('owned.py')], tmp_path) != before


@pytest.mark.skipif(sys.platform != 'linux', reason='exercise POSIX undecodable path bytes')
def test_graph_fingerprint_accepts_non_utf8_filenames(tmp_path):
    name = Path(os.fsdecode(b'owned-\xff.py'))
    (tmp_path / name).write_text('import owned\n')
    assert test_impact._files_fingerprint([name], tmp_path)
