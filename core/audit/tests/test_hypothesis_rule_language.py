"""Dynamic per-hypothesis semgrep rules must carry the TARGET's language.

Regression coverage for the wrong-language emission bug: everything
unmapped defaulted to ``languages: [c]``, so for PHP/Ruby/C#/Kotlin/
Swift/Lua/Scala targets the rule could never match its own file —
the audit's only dynamic verification channel was silently dead for
six fully-inventoried languages.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from core.audit.hypothesis_mapping import (
    hypothesis_to_semgrep_rule_keyed,
    semgrep_language_for,
)
from core.audit.sweep import negative_control_fixture

HYP = "sql injection via string concatenation"


def _emitted_lang(file_path: str) -> str:
    keyed = hypothesis_to_semgrep_rule_keyed(HYP, file_path)
    assert keyed is not None
    path, _kw = keyed
    text = Path(path).read_text()
    Path(path).unlink()
    for line in text.splitlines():
        if "languages:" in line:
            return line.split("[", 1)[1].rstrip("]").strip("] ")
    raise AssertionError("no languages key in emitted rule")


@pytest.mark.parametrize("file_path,lang", [
    ("index.php", "php"),
    ("app.rb", "ruby"),
    ("Service.cs", "csharp"),
    ("Main.kt", "kotlin"),
    ("build.kts", "kotlin"),
    ("App.swift", "swift"),
    ("init.lua", "lua"),
    ("Broker.scala", "scala"),
])
def test_previously_wrong_language_targets(file_path, lang):
    assert _emitted_lang(file_path) == lang


@pytest.mark.parametrize("file_path,lang", [
    ("a.py", "python"),
    ("a.js", "javascript"),
    ("a.ts", "typescript"),   # semgrep's javascript lang does not scan .ts
    ("a.tsx", "typescript"),
    ("A.java", "java"),
    ("a.go", "go"),
    ("a.rs", "rust"),
    ("a.c", "c"),
    ("a.h", "c"),
    ("a.cpp", "cpp"),
    ("a.hpp", "cpp"),
])
def test_mapped_languages_stay_correct(file_path, lang):
    assert semgrep_language_for(file_path) == lang


def test_unmapped_extension_falls_back_to_generic():
    # pattern-regex runs fine under generic — never guess `c`.
    assert semgrep_language_for("script.pl") == "generic"
    assert semgrep_language_for("Makefile") == "generic"
    assert _emitted_lang("script.pl") == "generic"


class TestFixtureSelectionFollowsLanguage:
    def test_c_target_gets_c_fixture(self):
        f = negative_control_fixture("sql injection", "db.c")
        assert f is not None and f.suffix == ".c"

    def test_py_target_gets_py_fixture(self):
        f = negative_control_fixture("sql injection", "db.py")
        assert f is not None and f.suffix == ".py"

    def test_generic_target_falls_back_to_existing_fixture(self):
        # A generic-language rule scans any file, so the control can
        # run against whichever fixture exists.
        f = negative_control_fixture("sql injection", "query.pl")
        assert f is not None and f.suffix in (".c", ".py")

    def test_language_without_fixture_skips_control(self):
        # A ruby-language rule would never scan a .c fixture — the
        # control is skipped rather than silently vacuous.
        f = negative_control_fixture("sql injection", "app.rb")
        assert f is None
