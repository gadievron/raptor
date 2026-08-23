"""Tests for core.build.resolve — the build-command precedence chain."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from core.build.resolve import resolve_build_command


def _makefile_target(tmp_path: Path) -> Path:
    (tmp_path / "Makefile").write_text("all:\n\tcc -o app main.c\n")
    (tmp_path / "main.c").write_text("int main(void){return 0;}\n")
    return tmp_path


class TestOperatorSlots:
    def test_lang_slot_wins(self, tmp_path):
        settings = {"build-command": {"default": "make",
                                      "cpp": "cmake --build build"}}
        got = resolve_build_command(tmp_path, "cpp", settings=settings)
        assert got == ("cmake --build build", "project-setting:cpp")

    def test_default_slot_when_lang_slot_absent(self, tmp_path):
        settings = {"build-command": {"default": "make -j4"}}
        got = resolve_build_command(tmp_path, "cpp", settings=settings)
        assert got == ("make -j4", "project-setting:default")

    def test_default_slot_without_lang(self, tmp_path):
        settings = {"build-command": {"default": "make"}}
        got = resolve_build_command(tmp_path, settings=settings)
        assert got == ("make", "project-setting:default")

    def test_operator_setting_beats_detector(self, tmp_path):
        _makefile_target(tmp_path)
        settings = {"build-command": {"default": "./build.sh"}}
        got = resolve_build_command(tmp_path, settings=settings)
        assert got is not None
        assert got[1] == "project-setting:default"


class TestSingleSlotFallback:
    def test_lone_lang_slot_used_without_lang(self, tmp_path):
        settings = {"build-command": {"c": "make smoke"}}
        got = resolve_build_command(tmp_path, settings=settings)
        assert got == ("make smoke", "project-setting:c")

    def test_lone_lang_slot_used_for_other_lang(self, tmp_path):
        settings = {"build-command": {"c": "make smoke"}}
        got = resolve_build_command(tmp_path, "cpp", settings=settings)
        assert got == ("make smoke", "project-setting:c")

    def test_multiple_lang_slots_without_default_ambiguous(self, tmp_path):
        settings = {"build-command": {"c": "make", "java": "mvn package"}}
        # ambiguous: falls through to the detector (empty dir → None)
        assert resolve_build_command(tmp_path, settings=settings) is None


class TestDetectorFallback:
    def test_detector_synthesis_when_no_setting(self, tmp_path):
        _makefile_target(tmp_path)
        got = resolve_build_command(tmp_path, "cpp", settings={})
        assert got is not None
        command, source = got
        assert source.startswith("detected:")
        assert command

    def test_lang_hint_narrows_order_not_coverage(self, tmp_path):
        """A 'c' hint (no detector table entry) must still find the
        Makefile through the cpp chain — regression from the live
        smoke: the hint previously REPLACED the chain."""
        _makefile_target(tmp_path)
        got = resolve_build_command(tmp_path, "c", settings={})
        assert got is not None
        assert got[1].startswith("detected:")

    def test_none_when_nothing_resolves(self, tmp_path):
        # Empty dir: no setting, nothing for the detector.
        assert resolve_build_command(tmp_path, "cpp", settings={}) is None


class TestActiveProjectPath:
    def test_one_target_rule_blocks_foreign_target(self, tmp_path):
        """A project setting must not steer a run against a different
        tree — settings=None resolves the active project only when the
        target matches it."""
        with patch("core.startup.get_active_name", return_value="p"), \
             patch("core.project.trust.run_target_matches_project",
                   return_value=False):
            got = resolve_build_command(tmp_path, "cpp")
        assert got is None  # empty dir → detector finds nothing either

    def test_matching_target_reads_project_slots(self, tmp_path):
        import json
        proj = tmp_path / "p.json"
        proj.write_text(json.dumps({
            "settings": {"build-command": {"default": "make smoke"}}}))
        with patch("core.startup.get_active_name", return_value="p"), \
             patch("core.startup.PROJECTS_DIR", tmp_path), \
             patch("core.project.trust.run_target_matches_project",
                   return_value=True):
            got = resolve_build_command(tmp_path / "src")
        assert got == ("make smoke", "project-setting:default")
