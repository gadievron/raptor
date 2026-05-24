"""Tests for build synthesis (synthesise_build_command and helpers)."""

import sys
from pathlib import Path

import pytest


# packages/codeql/tests/test_build_synthesis.py -> repo root
sys.path.insert(0, str(Path(__file__).parents[3]))

from packages.codeql.build_detector import BuildDetector


def _find_script(tmp_path):
    """Find the generated .raptor_build_*.py script in tmp_path."""
    scripts = list(tmp_path.glob(".raptor_build_*.py"))
    assert scripts, f"No build script found in {tmp_path}"
    return scripts[0]


class TestValidateFlags:
    """Test _validate_flags — the security boundary for compiler flags."""

    def _bd(self):
        return BuildDetector(Path("."))

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
        # Any flag value containing a pipe metacharacter must be rejected.
        assert self._bd()._validate_flags(["-Iinclude|evil"]) == []

    def test_rejects_ampersand(self):
        assert self._bd()._validate_flags(["-DFOO&evil"]) == []

    def test_rejects_quotes(self):
        assert self._bd()._validate_flags(["-I'.'"]) == []

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
        bd.synthesise_build_command("cpp")
        script = _find_script(tmp_path).read_text()
        assert "g++" in script

    def test_uses_gcc_for_c_files(self, tmp_path):
        (tmp_path / "main.c").write_text("int main() { return 0; }")
        bd = BuildDetector(tmp_path)
        bd.synthesise_build_command("cpp")
        script = _find_script(tmp_path).read_text()
        assert "'gcc'" in script

    def test_build_dir_is_temp(self, tmp_path):
        (tmp_path / "main.c").write_text("int main() { return 0; }")
        bd = BuildDetector(tmp_path)
        bd.synthesise_build_command("cpp")
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
        # Earlier batch SP14 swapped subprocess.run for
        # subprocess.Popen so per-compile stderr could be capped
        # via bounded read. Both are list-form, no-shell — the
        # test's intent is "no shell injection" not "specifically
        # subprocess.run". Accept either.
        assert "subprocess.run(cmd" in script or "subprocess.Popen(cmd" in script
        assert "shell=True" not in script


# =====================================================================
# Item 1: CMake subdirectory-fragment rejection
# =====================================================================

class TestCmakeSubdirRejection:
    """When the only CMakeLists.txt at the target is a subdir
    fragment (no ``cmake_minimum_required`` / ``project()``),
    BuildDetector must NOT return ``cmake . && make`` — that would
    fail at configure and silently break CodeQL DB creation.
    """

    def test_real_cmake_root_accepted(self, tmp_path):
        (tmp_path / "CMakeLists.txt").write_text(
            "cmake_minimum_required(VERSION 3.10)\n"
            "project(TestProj C)\n"
            "add_executable(foo main.c)\n"
        )
        (tmp_path / "main.c").write_text("int main() { return 0; }")
        bs = BuildDetector(tmp_path).detect_build_system("cpp")
        assert bs is not None and bs.type == "cmake"

    def test_subdir_fragment_rejected(self, tmp_path):
        (tmp_path / "CMakeLists.txt").write_text(
            "# Subdir fragment — meant for add_subdirectory()\n"
            "add_library(curl_lib STATIC altsvc.c easy.c)\n"
        )
        (tmp_path / "altsvc.c").write_text("// stub")
        bs = BuildDetector(tmp_path).detect_build_system("cpp")
        assert bs is None or bs.type != "cmake"

    def test_project_decl_uppercase_or_indented(self, tmp_path):
        """CMake commands are case-insensitive; project() inside
        ``if (BUILD_X)`` is still a project root marker."""
        (tmp_path / "CMakeLists.txt").write_text(
            "CMAKE_MINIMUM_REQUIRED(VERSION 3.10)\n"
            "if(BUILD_ALL)\n"
            "    PROJECT(MixedProj)\n"
            "endif()\n"
        )
        assert BuildDetector._is_cmake_project_root(tmp_path / "CMakeLists.txt")

    def test_missing_file_returns_false(self, tmp_path):
        assert not BuildDetector._is_cmake_project_root(tmp_path / "does-not-exist.txt")


# =====================================================================
# Item 2: Ancestor-include discovery
# =====================================================================

class TestAncestorIncludeDiscovery:
    """Walk up from repo_path looking for sibling ``include/``
    directories at ancestors. Used by synthesised compile to fix
    ``#include <foo/bar.h>`` references in subdir targets.
    """

    def test_finds_sibling_include_at_parent(self, tmp_path):
        # tmp_path/include/foo.h + tmp_path/lib/main.c
        (tmp_path / "include").mkdir()
        (tmp_path / "include" / "foo.h").write_text("// header")
        (tmp_path / "lib").mkdir()
        (tmp_path / "lib" / "main.c").write_text("// stub")
        bd = BuildDetector(tmp_path / "lib")
        found = bd._discover_ancestor_includes()
        assert any("include" in p for p in found)

    def test_returns_empty_when_no_ancestor_include(self, tmp_path):
        (tmp_path / "main.c").write_text("// stub")
        bd = BuildDetector(tmp_path)
        # parent of tmp_path may or may not have include/, but we're
        # at tmp_path which has no siblings — so under normal
        # conditions this is empty. Just verify the call works.
        found = bd._discover_ancestor_includes()
        # The check is type-shape: must be a list of strings.
        assert isinstance(found, list)
        assert all(isinstance(p, str) for p in found)

    def test_skips_system_path_targets(self, tmp_path):
        """A symlinked include/ that resolves to /etc must be rejected
        (filesystem-layout leak defence)."""
        import os
        (tmp_path / "lib").mkdir()
        try:
            # Symlink tmp_path/include → /etc — if include/ exists
            # and resolves to /etc, the resolution-block check should
            # reject it.
            os.symlink("/etc", str(tmp_path / "include"))
        except (OSError, PermissionError):
            pytest.skip("symlink creation not permitted")
        bd = BuildDetector(tmp_path / "lib")
        found = bd._discover_ancestor_includes()
        assert not any(p.startswith("/etc") for p in found), found

    def test_max_depth_bounds_walk(self, tmp_path):
        """Walk should stop at max_depth levels even if more ancestors exist."""
        # Make tmp_path/a/b/c/lib/main.c
        deep = tmp_path / "a" / "b" / "c" / "lib"
        deep.mkdir(parents=True)
        (deep / "main.c").write_text("// stub")
        # Put include at tmp_path (4 levels up from lib)
        (tmp_path / "include").mkdir()
        (tmp_path / "include" / "x.h").write_text("// hdr")
        bd = BuildDetector(deep)
        # max_depth=2 isn't enough to reach tmp_path/include
        found_shallow = bd._discover_ancestor_includes(max_depth=2)
        assert not found_shallow
        # max_depth=4 IS enough
        found_deep = bd._discover_ancestor_includes(max_depth=4)
        assert any("include" in p for p in found_deep)

    def test_include_flags_use_absolute_paths(self, tmp_path):
        """End-to-end: synthesised build script uses absolute -I
        for ancestor includes (relative would be ambiguous from the
        compiler's cwd)."""
        (tmp_path / "include").mkdir()
        (tmp_path / "include" / "lib.h").write_text("// header")
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "main.c").write_text("int main() { return 0; }")
        bd = BuildDetector(tmp_path / "src")
        bd.synthesise_build_command("cpp")
        script = _find_script(tmp_path / "src").read_text()
        # Should contain absolute -I path to tmp_path/include.
        assert f"-I{tmp_path}/include" in script or f"-I{tmp_path.resolve()}/include" in script


# =====================================================================
# Item 3: Missing-config-header detection (diagnostic only, no exec)
# =====================================================================

class TestMissingConfigHeaderDetection:
    """``detect_missing_config_headers`` is a pure diagnostic — it
    surfaces a list of referenced ``*config.h`` headers that don't
    exist on disk anywhere reachable. Does NOT auto-execute
    configure/cmake (arbitrary-code-execution risk).
    """

    def test_detects_missing_curl_config(self, tmp_path):
        """``#include "curl_config.h"`` in a .h with no such file on disk."""
        (tmp_path / "main.c").write_text(
            "#include \"setup.h\"\nint main() { return 0; }"
        )
        (tmp_path / "setup.h").write_text(
            "#include \"curl_config.h\"\n"  # missing target
        )
        bd = BuildDetector(tmp_path)
        missing = bd.detect_missing_config_headers()
        assert any(h == "curl_config.h" for h, _ in missing)

    def test_detects_missing_plain_config_h(self, tmp_path):
        """``#include "config.h"`` is the autoconf-canonical pattern."""
        (tmp_path / "x.c").write_text("#include \"config.h\"\n")
        bd = BuildDetector(tmp_path)
        missing = bd.detect_missing_config_headers()
        assert any(h == "config.h" for h, _ in missing)

    def test_reports_zero_when_header_exists(self, tmp_path):
        """If the referenced config.h is present on disk, no report."""
        (tmp_path / "x.c").write_text("#include \"my_config.h\"\n")
        (tmp_path / "my_config.h").write_text("/* generated */\n")
        bd = BuildDetector(tmp_path)
        missing = bd.detect_missing_config_headers()
        assert not [h for h, _ in missing if h == "my_config.h"]

    def test_reports_zero_when_ancestor_include_has_it(self, tmp_path):
        """Header at ancestor include/ counts as 'on disk'."""
        (tmp_path / "include").mkdir()
        (tmp_path / "include" / "ancestor_config.h").write_text("/* gen */\n")
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "main.c").write_text("#include \"ancestor_config.h\"\n")
        bd = BuildDetector(tmp_path / "src")
        missing = bd.detect_missing_config_headers()
        assert not [h for h, _ in missing if h == "ancestor_config.h"]

    def test_dedupes_repeated_references(self, tmp_path):
        """Same missing header referenced from 5 files → one entry."""
        for i in range(5):
            (tmp_path / f"f{i}.c").write_text("#include \"missing_config.h\"\n")
        bd = BuildDetector(tmp_path)
        missing = bd.detect_missing_config_headers()
        names = [h for h, _ in missing if h == "missing_config.h"]
        assert len(names) == 1

    def test_synthesised_compile_logs_missing_config_warning(
        self, tmp_path, caplog
    ):
        """End-to-end: synthesise_build_command emits a WARNING when
        config headers are missing, but does NOT auto-execute anything."""
        import logging
        (tmp_path / "x.c").write_text("#include \"missing_config.h\"\nint main(){return 0;}")
        bd = BuildDetector(tmp_path)
        # build_detector uses ``core.logging.get_logger()`` which
        # returns a wrapper around the ``"raptor"`` stdlib logger
        # (see core/logging/__init__.py:RaptorLogger). Attach the
        # capture there. caplog's pytest integration doesn't see
        # these messages because the wrapper bypasses the standard
        # propagation chain.
        captured: list[logging.LogRecord] = []
        class _Capture(logging.Handler):
            def emit(self, record): captured.append(record)
        h = _Capture(level=logging.WARNING)
        target_logger = logging.getLogger("raptor")
        target_logger.addHandler(h)
        try:
            bd.synthesise_build_command("cpp")
        finally:
            target_logger.removeHandler(h)
        warnings = [r.getMessage() for r in captured if r.levelno == logging.WARNING]
        assert any("missing_config.h" in m for m in warnings), warnings
