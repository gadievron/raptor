"""Tests for packages.joern.prereqs."""

from __future__ import annotations

from unittest.mock import patch

import packages.joern.prereqs as prereqs


class TestIsAvailable:
    def test_returns_bool(self):
        result = prereqs.is_available()
        assert isinstance(result, bool)


class TestCheckPrereqs:
    def test_returns_list(self):
        result = prereqs.check_prereqs()
        assert isinstance(result, list)

    def test_missing_joern_reported(self, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda x: None)
        prereqs.reset_path_cache()
        try:
            result = prereqs.check_prereqs()
            assert any("joern" in m for m in result)
        finally:
            prereqs.reset_path_cache()


class TestVersion:
    def test_returns_none_when_unavailable(self, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda x: None)
        prereqs.reset_path_cache()
        try:
            assert prereqs.version() is None
        finally:
            prereqs.reset_path_cache()

    def test_version_tuple_none_when_unavailable(self, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda x: None)
        prereqs.reset_path_cache()
        try:
            assert prereqs.version_tuple() is None
        finally:
            prereqs.reset_path_cache()

    def test_version_from_dist_jar(self, tmp_path):
        """Version read from lib/ jar names — no JVM boot needed."""
        lib = tmp_path / "lib"
        lib.mkdir()
        (lib / "io.joern.joern-cli-4.0.601.jar").touch()
        (lib / "io.joern.console-4.0.601.jar").touch()
        joern = tmp_path / "joern"
        joern.touch()
        assert prereqs._version_from_dist(str(joern)) == "4.0.601"

    def test_version_from_dist_missing_lib(self, tmp_path):
        joern = tmp_path / "joern"
        joern.touch()
        assert prereqs._version_from_dist(str(joern)) is None

    def test_version_prefers_dist_over_repl(self, monkeypatch, tmp_path):
        """The static jar read wins — the REPL fallback (a full JVM
        boot) must not be reached when lib/ carries the version."""
        lib = tmp_path / "lib"
        lib.mkdir()
        (lib / "io.joern.joern-cli-4.0.599.jar").touch()
        joern = tmp_path / "joern"
        joern.touch()
        monkeypatch.setattr(prereqs, "is_available", lambda: True)
        monkeypatch.setattr(prereqs, "_joern_path", lambda: str(joern))
        with patch.object(prereqs.subprocess, "run") as mock_run:
            assert prereqs.version() == "4.0.599"
            mock_run.assert_not_called()

    def test_version_tuple_parses_patch(self, monkeypatch):
        monkeypatch.setattr(prereqs, "version", lambda: "4.0.458")
        assert prereqs.version_tuple() == (4, 0, 458)

    def test_version_tuple_defaults_missing_patch(self, monkeypatch):
        monkeypatch.setattr(prereqs, "version", lambda: "v4.1")
        assert prereqs.version_tuple() == (4, 1, 0)


class TestMeetsMinVersion:
    def test_floor_is_first_2026_release(self):
        assert prereqs.MIN_JOERN_VERSION == (4, 0, 458)

    def test_at_floor_passes(self, monkeypatch):
        monkeypatch.setattr(prereqs, "version", lambda: "4.0.458")
        assert prereqs.meets_min_version()

    def test_below_floor_fails(self, monkeypatch):
        monkeypatch.setattr(prereqs, "version", lambda: "4.0.457")
        assert not prereqs.meets_min_version()

    def test_v3_fails(self, monkeypatch):
        monkeypatch.setattr(prereqs, "version", lambda: "3.2.100")
        assert not prereqs.meets_min_version()

    def test_false_when_unavailable(self, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda x: None)
        prereqs.reset_path_cache()
        try:
            assert not prereqs.meets_min_version()
        finally:
            prereqs.reset_path_cache()


class TestPathCache:
    def test_reset_clears(self):
        prereqs.reset_path_cache()
        assert prereqs._joern_resolved is False
        assert prereqs._joern_parse_resolved is False
