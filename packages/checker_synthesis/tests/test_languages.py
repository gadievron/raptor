"""Tests for engine detection."""

from __future__ import annotations

import pytest

from packages.checker_synthesis import detect_engine, supported_engines


class TestDetectEngine:
    @pytest.mark.parametrize("path", [
        "src/foo.c",
        "include/bar.h",
        "drivers/net/dev.c",
        "kernel/sched.c",
    ])
    def test_c_picks_coccinelle(self, path):
        assert detect_engine(path) == "coccinelle"

    @pytest.mark.parametrize("path,expected", [
        ("src/foo.py", "semgrep"),
        ("src/Foo.java", "semgrep"),
        ("cmd/main.go", "semgrep"),
        ("src/app.js", "semgrep"),
        ("src/app.ts", "semgrep"),
        ("src/app.tsx", "semgrep"),
        ("lib/a.rb", "semgrep"),
        ("src/main.rs", "semgrep"),
        ("src/PHPFile.php", "semgrep"),
    ])
    def test_other_languages_pick_semgrep(self, path, expected):
        assert detect_engine(path) == expected

    @pytest.mark.parametrize("path", [
        "Makefile",          # no extension
        "README",
        "docs/notes.txt",    # plain text
        "data.bin",          # binary
        "image.png",
        "",                   # empty
    ])
    def test_unknown_returns_none(self, path):
        assert detect_engine(path) is None

    def test_case_insensitive_extension(self):
        assert detect_engine("src/Foo.PY") == "semgrep"
        assert detect_engine("src/Foo.C") == "coccinelle"


class TestSupportedEngines:
    def test_returns_tuple(self):
        assert supported_engines() == ("semgrep", "coccinelle")
