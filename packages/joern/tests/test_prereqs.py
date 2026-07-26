"""Tests for packages.joern.prereqs."""

from __future__ import annotations

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


class TestMeetsMinVersion:
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
