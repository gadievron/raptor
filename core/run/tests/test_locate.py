"""Tests for core/run/locate.py — shared project/run discovery."""

import re

import pytest

from core.run import locate
from core.run.locate import project_output_dir


@pytest.fixture
def projects_dir(tmp_path, monkeypatch):
    import core.startup

    pdir = tmp_path / "projects"
    pdir.mkdir()
    monkeypatch.setattr(core.startup, "PROJECTS_DIR", pdir)
    return pdir


def _register(projects_dir, name, output_dir):
    output_dir.mkdir(parents=True, exist_ok=True)
    (projects_dir / f"{name}.json").write_text(
        '{"output_dir": "%s"}' % output_dir
    )
    return output_dir


class TestProjectOutputDir:
    def test_valid_name_resolves(self, projects_dir, tmp_path):
        out = _register(projects_dir, "myapp", tmp_path / "out" / "myapp")
        assert project_output_dir("myapp") == out

    def test_missing_project_is_none(self, projects_dir):
        assert project_output_dir("ghost") is None

    def test_traversal_name_is_refused(self, projects_dir, tmp_path):
        # A registry lookup keyed by a raw name is a path join: a
        # name carrying separators escapes PROJECTS_DIR and reads an
        # attacker-placed record. The charset gate refuses it before
        # the join.
        out = tmp_path / "planted-out"
        out.mkdir()
        (tmp_path / "evil.json").write_text(
            '{"output_dir": "%s"}' % out
        )
        assert project_output_dir("../evil") is None

    def test_charset_violations_are_refused(self, projects_dir):
        for name in ("a/b", ".hidden", "-dash-first", "a" * 65, "a\n"):
            assert project_output_dir(name) is None

    def test_name_gate_matches_the_session_registry(self):
        # Twin-equality: the gate here must accept exactly what the
        # session-binding registry accepts, so a project the operator
        # can bind is always locatable and vice versa.
        from core.project.sessions import _NAME_RE

        assert locate._PROJECT_NAME_RE.pattern == _NAME_RE.pattern
        assert isinstance(locate._PROJECT_NAME_RE, re.Pattern)
