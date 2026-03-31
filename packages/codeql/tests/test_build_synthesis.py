"""Tests for build synthesis (synthesise_build_command and helpers)."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from packages.codeql.build_detector import BuildDetector


def _find_script(tmp_path):
    """Find the generated .raptor_build_*.py script in tmp_path."""
    scripts = list(tmp_path.glob(".raptor_build_*.py"))
    assert scripts, f"No build script found in {tmp_path}"
    return scripts[0]


class TestValidateFlags:
    """Test _validate_flags — the security boundary for compiler flags."""

    def _bd(self):
        return BuildDetector(Path("/tmp"))

    def test_simple_include(self):
        assert self._bd()._validate_flags(["-Isrc"]) == ["-Isrc"]

    def test_simple_define(self):
        assert self._bd()._validate_flags(["-DFOO"]) == ["-DFOO"]

    def test_define_with_value(self):
        assert self._bd()._validate_flags(["-DBAR=1"]) == ["-DBAR=1"]

    def test_std_flag(self):
        assert self._bd()._validate_flags(["-std=c11"]) == ["-std=c11"]

    def test_include_file_splits(self):
        result = self._bd()._validate_flags(["-include stdlib.h"])
        assert result == ["-include", "stdlib.h"]

    def test_rejects_dollar(self):
        assert self._bd()._validate_flags(["-I$(evil)"]) == []

    def test_rejects_backtick(self):
        assert self._bd()._validate_flags(["-I`whoami`"]) == []

    def test_rejects_semicolon(self):
        assert self._bd()._validate_flags(["-DFOO;rm -rf /"]) == []

    def test_rejects_pipe(self):
        assert self._bd()._validate_flags(["-I/tmp|evil"]) == []

    def test_rejects_ampersand(self):
        assert self._bd()._validate_flags(["-DFOO&evil"]) == []

    def test_rejects_quotes(self):
        assert self._bd()._validate_flags(["-I'/tmp'"]) == []

    def test_rejects_parentheses(self):
        assert self._bd()._validate_flags(["-I$(shell rm -rf /)"]) == []

    def test_rejects_non_string(self):
        assert self._bd()._validate_flags([123, None, True]) == []

    def test_mixed_valid_invalid(self):
        result = self._bd()._validate_flags(["-Isrc", "-I$(evil)", "-DFOO"])
        assert result == ["-Isrc", "-DFOO"]

    def test_empty_list(self):
        assert self._bd()._validate_flags([]) == []

    def test_path_with_dots(self):
        assert self._bd()._validate_flags(["-I../include"]) == ["-I../include"]

    def test_path_with_plus(self):
        assert self._bd()._validate_flags(["-Ic++"]) == ["-Ic++"]


class TestSynthesiseCpp:
    """Test C/C++ build synthesis."""

    def test_synthesises_for_c_files(self, tmp_path):
        (tmp_path / "main.c").write_text("int main() { return 0; }")
        bd = BuildDetector(tmp_path)
        result = bd.synthesise_build_command("cpp")
        assert result is not None
        assert result.type in ("synthesised", "synthesised-cc")
        assert "python" in result.command

    def test_returns_none_for_no_source(self, tmp_path):
        (tmp_path / "readme.txt").write_text("no code here")
        bd = BuildDetector(tmp_path)
        assert bd.synthesise_build_command("cpp") is None

    def test_returns_none_for_interpreted(self, tmp_path):
        (tmp_path / "main.py").write_text("print('hello')")
        bd = BuildDetector(tmp_path)
        assert bd.synthesise_build_command("python") is None

    def test_returns_none_for_unsupported_compiled(self, tmp_path):
        (tmp_path / "main.rs").write_text("fn main() {}")
        bd = BuildDetector(tmp_path)
        assert bd.synthesise_build_command("rust") is None

    def test_detects_headers_for_includes(self, tmp_path):
        (tmp_path / "src").mkdir()
        (tmp_path / "include").mkdir()
        (tmp_path / "src" / "main.c").write_text('#include "foo.h"\nint main() {}')
        (tmp_path / "include" / "foo.h").write_text("// header")
        bd = BuildDetector(tmp_path)
        result = bd.synthesise_build_command("cpp")
        assert result is not None
        script = _find_script(tmp_path).read_text()
        assert "-Iinclude" in script

    def test_uses_gpp_for_cpp_files(self, tmp_path):
        (tmp_path / "main.cpp").write_text("int main() {}")
        bd = BuildDetector(tmp_path)
        result = bd.synthesise_build_command("cpp")
        script = _find_script(tmp_path).read_text()
        assert "g++" in script

    def test_uses_gcc_for_c_files(self, tmp_path):
        (tmp_path / "main.c").write_text("int main() { return 0; }")
        bd = BuildDetector(tmp_path)
        result = bd.synthesise_build_command("cpp")
        script = _find_script(tmp_path).read_text()
        assert "'gcc'" in script

    def test_build_dir_is_temp(self, tmp_path):
        (tmp_path / "main.c").write_text("int main() { return 0; }")
        bd = BuildDetector(tmp_path)
        result = bd.synthesise_build_command("cpp")
        script = _find_script(tmp_path).read_text()
        assert ".raptor_build_" in script

    def test_build_dir_created_for_codeql(self, tmp_path):
        (tmp_path / "main.c").write_text("int main() { return 0; }")
        bd = BuildDetector(tmp_path)
        bd.synthesise_build_command("cpp")
        # Build dir should exist (for CodeQL to use), script should exist
        build_dirs = [p for p in tmp_path.glob(".raptor_build_*") if p.is_dir()]
        scripts = [p for p in tmp_path.glob(".raptor_build_*.py")]
        assert len(build_dirs) == 1
        assert len(scripts) == 1


class TestSynthesiseJava:
    """Test Java build synthesis."""

    def test_synthesises_for_java_files(self, tmp_path):
        (tmp_path / "Main.java").write_text("public class Main {}")
        bd = BuildDetector(tmp_path)
        result = bd.synthesise_build_command("java")
        assert result is not None
        script = _find_script(tmp_path).read_text()
        assert "'javac'" in script
        assert "IS_JAVA = True" in script

    def test_returns_none_for_no_java(self, tmp_path):
        (tmp_path / "main.c").write_text("int main() {}")
        bd = BuildDetector(tmp_path)
        assert bd.synthesise_build_command("java") is None


class TestScriptSafety:
    """Test that generated scripts are injection-safe."""

    def test_filenames_with_spaces(self, tmp_path):
        (tmp_path / "my file.c").write_text("int main() { return 0; }")
        bd = BuildDetector(tmp_path)
        result = bd.synthesise_build_command("cpp")
        assert result is not None
        script = _find_script(tmp_path).read_text()
        # Path should be in a repr'd list — safely quoted
        assert "my file.c" in script

    def test_filenames_with_dollar(self, tmp_path):
        (tmp_path / "evil$var.c").write_text("int main() { return 0; }")
        bd = BuildDetector(tmp_path)
        result = bd.synthesise_build_command("cpp")
        assert result is not None
        script = _find_script(tmp_path).read_text()
        assert "evil$var.c" in script  # repr'd, not shell-expanded

    def test_filenames_with_quotes(self, tmp_path):
        (tmp_path / "evil'quote.c").write_text("int main() { return 0; }")
        bd = BuildDetector(tmp_path)
        result = bd.synthesise_build_command("cpp")
        assert result is not None
        # Script should be valid Python
        import py_compile
        py_compile.compile(str(_find_script(tmp_path)), doraise=True)

    def test_subprocess_uses_list_not_shell(self, tmp_path):
        (tmp_path / "main.c").write_text("int main() { return 0; }")
        bd = BuildDetector(tmp_path)
        bd.synthesise_build_command("cpp")
        script = _find_script(tmp_path).read_text()
        assert "subprocess.run(cmd" in script
        assert "shell=True" not in script
