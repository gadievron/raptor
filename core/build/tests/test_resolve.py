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
        with patch("core.project.trust._context_project_name", return_value="p"), \
             patch("core.project.trust.run_target_matches_project",
                   return_value=False):
            got = resolve_build_command(tmp_path, "cpp")
        assert got is None  # empty dir → detector finds nothing either

    def test_matching_target_reads_project_slots(self, tmp_path):
        import json
        proj = tmp_path / "p.json"
        proj.write_text(json.dumps({
            "settings": {"build-command": {"default": "make smoke"}}}))
        with patch("core.project.trust._context_project_name", return_value="p"), \
             patch("core.startup.PROJECTS_DIR", tmp_path), \
             patch("core.project.trust.run_target_matches_project",
                   return_value=True):
            got = resolve_build_command(tmp_path / "src")
        assert got == ("make smoke", "project-setting:default")


class TestLoneSlotVisibility:
    def test_cross_language_serve_warns(self, tmp_path, caplog):
        import logging
        settings = {"build-command": {"java": "mvn package"}}
        with caplog.at_level(logging.WARNING, logger="core.build.resolve"):
            got = resolve_build_command(tmp_path, "cpp", settings=settings)
        # Behavior unchanged (deliberate, pinned above) — but the
        # cross-language serve is operator-visible now.
        assert got == ("mvn package", "project-setting:java")
        assert any("lone populated slot" in r.message for r in caplog.records)

    def test_matching_slot_serve_stays_quiet(self, tmp_path, caplog):
        import logging
        settings = {"build-command": {"c": "make smoke"}}
        with caplog.at_level(logging.WARNING, logger="core.build.resolve"):
            resolve_build_command(tmp_path, "c", settings=settings)
        assert not any("lone populated slot" in r.message
                       for r in caplog.records)


class TestDetectorCandidateList:
    def test_no_dead_language_warning_per_resolution(self, tmp_path, caplog):
        import logging
        # Empty target: nothing detects — the default candidate list
        # must not include a language the table has no key for (the
        # dead "c" candidate warned "No build system detection" on
        # every such resolution).
        with caplog.at_level(logging.WARNING):
            got = resolve_build_command(tmp_path)
        assert got is None
        assert not any("No build system detection" in r.message
                       for r in caplog.records)

    def test_makefile_target_still_detected(self, tmp_path):
        _makefile_target(tmp_path)
        got = resolve_build_command(tmp_path)
        assert got is not None and got[1].startswith("detected:")
