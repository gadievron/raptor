"""Tests for the /audit Joern source gate (target_has_joern_sources).

The gate must only admit languages with a curated joern-parse profile:
an admitted-but-unprofiled language would be classified as the DEFAULT
(Python) by lang_config.detect_language() and pinned to the pythonsrc
frontend — an empty or wrong-language CPG.
"""

from __future__ import annotations

import logging


from core.audit.joern_backend import (
    _C_EXTENSIONS,
    _joern_extensions,
    target_has_joern_sources,
)


class TestJoernExtensions:
    def test_derived_from_lang_config(self):
        from packages.joern.lang_config import supported_source_extensions
        assert _joern_extensions() == (
            supported_source_extensions() - _C_EXTENSIONS
        )

    def test_every_admitted_extension_resolves_to_a_real_profile(self):
        # detect_language on a single file of each admitted extension
        # must land on a language with an explicit profile entry — not
        # the DEFAULT fallback (except Python, whose profile IS the
        # default object).
        from packages.joern.lang_config import (
            _PROFILES,
            detect_language,
        )
        for ext in _joern_extensions():
            lang = detect_language(f"sample{ext}")
            assert lang in _PROFILES, (
                f"{ext} admitted to Joern but detect_language maps it "
                f"to {lang!r}, which has no curated profile"
            )

    def test_unprofiled_languages_not_admitted(self):
        admitted = _joern_extensions()
        for ext in (".rb", ".php", ".scala"):
            assert ext not in admitted

    def test_profiled_frontends_admitted(self):
        admitted = _joern_extensions()
        for ext in (".kt", ".kts", ".cs", ".swift"):
            assert ext in admitted


class TestTargetHasJoernSources:
    def test_supported_source_admits(self, tmp_path):
        (tmp_path / "app.py").write_text("import os\n")
        assert target_has_joern_sources(tmp_path) is True

    def test_unprofiled_only_target_gates_false_with_reason(
        self, tmp_path, caplog,
    ):
        (tmp_path / "app.rb").write_text("puts 'x'\n")
        (tmp_path / "lib.php").write_text("<?php echo 1;\n")
        with caplog.at_level(logging.WARNING, logger="core.audit.joern_backend"):
            assert target_has_joern_sources(tmp_path) is False
        assert any(
            ".php, .rb" in rec.getMessage() for rec in caplog.records
        )

    def test_no_sources_gates_false_silently(self, tmp_path, caplog):
        (tmp_path / "README.md").write_text("docs\n")
        with caplog.at_level(logging.WARNING, logger="core.audit.joern_backend"):
            assert target_has_joern_sources(tmp_path) is False
        assert not caplog.records

    def test_mixed_target_admits_without_warning(self, tmp_path, caplog):
        (tmp_path / "app.rb").write_text("puts 'x'\n")
        (tmp_path / "main.go").write_text("package main\n")
        with caplog.at_level(logging.WARNING, logger="core.audit.joern_backend"):
            assert target_has_joern_sources(tmp_path) is True

    def test_none_and_missing_paths(self, tmp_path):
        assert target_has_joern_sources(None) is False
        assert target_has_joern_sources(tmp_path / "absent") is False


def test_scala_does_not_boot_joern(tmp_path):
    # No Scala frontend; the gate must not admit .scala on the
    # strength of the Java profile. (Kotlin has its own verified
    # frontend and profile now, so it admits.)
    (tmp_path / "Main.scala").write_text("object Main\n")
    assert target_has_joern_sources(tmp_path) is False


def test_kotlin_admits_with_dedicated_frontend(tmp_path):
    (tmp_path / "Main.kt").write_text("fun main() {}\n")
    assert target_has_joern_sources(tmp_path) is True
