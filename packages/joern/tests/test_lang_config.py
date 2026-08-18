"""Tests for per-language Joern tuning profiles."""

from packages.joern.lang_config import (
    C_CPP,
    DEFAULT,
    GO,
    JAVA,
    JAVASCRIPT,
    PYTHON,
    detect_language,
    profile_for,
)


class TestProfileFor:
    def test_python_variants(self):
        assert profile_for("python") is PYTHON
        assert profile_for("pythonsrc") is PYTHON
        assert profile_for("Python") is PYTHON

    def test_c_cpp_variants(self):
        assert profile_for("c") is C_CPP
        assert profile_for("cpp") is C_CPP
        assert profile_for("c++") is C_CPP

    def test_java(self):
        assert profile_for("java") is JAVA
        assert profile_for("javasrc") is JAVA

    def test_javascript_variants(self):
        assert profile_for("javascript") is JAVASCRIPT
        assert profile_for("js") is JAVASCRIPT
        assert profile_for("typescript") is JAVASCRIPT
        assert profile_for("ts") is JAVASCRIPT
        assert profile_for("jssrc") is JAVASCRIPT

    def test_go(self):
        assert profile_for("go") is GO
        assert profile_for("gosrc") is GO

    def test_unknown_falls_back_to_default(self):
        assert profile_for("rust") is DEFAULT
        assert profile_for("cobol") is DEFAULT

    def test_default_is_python(self):
        assert DEFAULT is PYTHON


class TestProfileValues:
    def test_python_depth_is_shallow(self):
        assert PYTHON.max_call_depth == 2
        assert PYTHON.max_call_depth_targeted == 2

    def test_c_depth_is_deeper(self):
        assert C_CPP.max_call_depth == 4
        assert C_CPP.max_call_depth_targeted == 3

    def test_python_args_capped(self):
        assert PYTHON.max_args_to_allow == 300
        assert PYTHON.max_output_args_expansion == 300

    def test_c_args_higher(self):
        assert C_CPP.max_args_to_allow == 200

    def test_python_has_sinks(self):
        assert "system" in PYTHON.sinks
        assert "execute" in PYTHON.sinks

    def test_c_has_memory_sinks(self):
        assert "memcpy" in C_CPP.sinks
        assert "strcpy" in C_CPP.sinks
        assert "sprintf" in C_CPP.sinks

    def test_java_has_java_sinks(self):
        assert "executeQuery" in JAVA.sinks
        assert "readObject" in JAVA.sinks

    def test_js_has_dom_sinks(self):
        assert "innerHTML" in JAVASCRIPT.sinks
        assert "dangerouslySetInnerHTML" in JAVASCRIPT.sinks

    def test_go_has_go_sinks(self):
        assert "Command" in GO.sinks
        assert "Unmarshal" in GO.sinks


class TestDetectLanguage:
    def test_python_file(self):
        assert detect_language("foo.py") == "python"

    def test_c_file(self):
        assert detect_language("main.c") == "c"

    def test_java_file(self):
        assert detect_language("App.java") == "java"

    def test_js_file(self):
        assert detect_language("index.js") == "javascript"

    def test_ts_file(self):
        assert detect_language("index.ts") == "typescript"

    def test_go_file(self):
        assert detect_language("main.go") == "go"

    def test_unknown_defaults_to_python(self):
        assert detect_language("data.xml") == "python"

    def test_directory_detection(self, tmp_path):
        (tmp_path / "a.py").write_text("x = 1", encoding="utf-8")
        (tmp_path / "b.py").write_text("y = 2", encoding="utf-8")
        (tmp_path / "c.js").write_text("z = 3", encoding="utf-8")
        assert detect_language(str(tmp_path)) == "python"

    def test_directory_majority_wins(self, tmp_path):
        for i in range(5):
            (tmp_path / f"file{i}.java").write_text(f"class C{i} {{}}", encoding="utf-8")
        (tmp_path / "util.py").write_text("x = 1", encoding="utf-8")
        assert detect_language(str(tmp_path)) == "java"

    def test_empty_directory_defaults(self, tmp_path):
        assert detect_language(str(tmp_path)) == "python"


class TestParseLanguagesFor:
    """parse_languages_for pins the joern-parse frontend from the
    curated per-profile joern_parse_language values."""

    def test_c_target(self, tmp_path):
        from packages.joern.lang_config import parse_languages_for

        (tmp_path / "a.c").write_text("int main() {}", encoding="utf-8")
        assert parse_languages_for(str(tmp_path)) == {"c"}

    def test_python_target(self, tmp_path):
        from packages.joern.lang_config import parse_languages_for

        (tmp_path / "a.py").write_text("x = 1", encoding="utf-8")
        assert parse_languages_for(str(tmp_path)) == {"pythonsrc"}

    def test_majority_language_wins(self, tmp_path):
        from packages.joern.lang_config import parse_languages_for

        for i in range(3):
            (tmp_path / f"f{i}.go").write_text("package main", encoding="utf-8")
        (tmp_path / "u.py").write_text("x = 1", encoding="utf-8")
        assert parse_languages_for(str(tmp_path)) == {"gosrc"}

    def test_every_profile_declares_a_frontend(self):
        from packages.joern.lang_config import _PROFILES

        for name, profile in _PROFILES.items():
            assert profile.joern_parse_language, name
