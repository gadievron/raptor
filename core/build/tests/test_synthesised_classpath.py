"""Tests for synthesised-Java CLASSPATH construction from repo/lib/*.jar.

Sister file to test_toolchain.py — focuses on build_detector's
synthesised-build path when compiling raw .java files without Maven/
Gradle/Ant. See design/env-handling.md Q6 for scope rationale.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from packages.codeql.build_detector import BuildDetector


class TestJavaSynthesisedClasspath(unittest.TestCase):

    def test_no_lib_dir_returns_empty(self):
        with tempfile.TemporaryDirectory() as d:
            bd = BuildDetector(Path(d))
            self.assertEqual(bd._java_synthesised_classpath(), [])

    def test_empty_lib_dir_returns_empty(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "lib").mkdir()
            bd = BuildDetector(Path(d))
            self.assertEqual(bd._java_synthesised_classpath(), [])

    def test_lib_dir_with_non_jar_files_returns_empty(self):
        # README / docs / whatever — only .jar files count.
        with tempfile.TemporaryDirectory() as d:
            lib = Path(d) / "lib"
            lib.mkdir()
            (lib / "README.md").write_text("")
            (lib / "versions.txt").write_text("")
            bd = BuildDetector(Path(d))
            self.assertEqual(bd._java_synthesised_classpath(), [])

    def test_lib_dir_with_jars_returns_sorted_paths(self):
        with tempfile.TemporaryDirectory() as d:
            lib = Path(d) / "lib"
            lib.mkdir()
            # Unsorted creation order — we expect sorted output for
            # deterministic classpath between runs.
            (lib / "zebra.jar").write_bytes(b"fake jar")
            (lib / "apple.jar").write_bytes(b"fake jar")
            (lib / "mango.jar").write_bytes(b"fake jar")
            bd = BuildDetector(Path(d))
            result = bd._java_synthesised_classpath()
            self.assertEqual(len(result), 3)
            self.assertEqual(
                result,
                sorted(result),
                "classpath should be sorted for reproducibility",
            )
            for p in result:
                self.assertTrue(p.endswith(".jar"))
                self.assertIn("/lib/", p)

    def test_lib_is_file_not_dir_returns_empty(self):
        # Adversarial: repo has a FILE called `lib` (not a dir).
        # is_dir() is False → we return empty, no crash.
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "lib").write_text("not a dir")
            bd = BuildDetector(Path(d))
            self.assertEqual(bd._java_synthesised_classpath(), [])


class TestGeneratedScriptIncludesClasspath(unittest.TestCase):
    """When _write_build_script is called with javac + lib/*.jar
    present, the generated Python script should include the jars in
    its classpath list."""

    def test_script_contains_classpath_when_jars_present(self):
        with tempfile.TemporaryDirectory() as d:
            lib = Path(d) / "lib"
            lib.mkdir()
            (lib / "commons-lang3.jar").write_bytes(b"fake jar")
            # Fake source so _write_build_script has something to iterate
            (Path(d) / "Main.java").write_text("class Main {}")

            bd = BuildDetector(Path(d))
            # Create build dir + script path like synthesise_build_command does
            build_dir = Path(d) / ".build"
            build_dir.mkdir()
            script_path = Path(d) / ".raptor_build_.py"
            script_path.touch()

            bd._write_build_script(
                script_path=script_path,
                build_dir=build_dir,
                source_files=[Path(d) / "Main.java"],
                compiler="javac",
                include_flags=["-sourcepath", str(d)],
                define_flags=[],
            )

            script_text = script_path.read_text()
            # The generated script's JAVA_CLASSPATH_JARS list should
            # contain our stub jar.
            self.assertIn("JAVA_CLASSPATH_JARS", script_text)
            self.assertIn("commons-lang3.jar", script_text)
            # The -cp flag is added only inside the generated script's
            # Java branch. Just assert JAVA_CP composition is present.
            self.assertIn("JAVA_CP", script_text)
            self.assertIn('"-cp"', script_text)

    def test_script_empty_classpath_when_no_jars(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "Main.java").write_text("class Main {}")
            bd = BuildDetector(Path(d))
            build_dir = Path(d) / ".build"
            build_dir.mkdir()
            script_path = Path(d) / ".raptor_build_.py"
            script_path.touch()

            bd._write_build_script(
                script_path=script_path,
                build_dir=build_dir,
                source_files=[Path(d) / "Main.java"],
                compiler="javac",
                include_flags=[],
                define_flags=[],
            )
            script_text = script_path.read_text()
            # JAVA_CLASSPATH_JARS should be an empty list
            self.assertIn("JAVA_CLASSPATH_JARS = []", script_text)

    def test_cpp_script_has_no_classpath(self):
        # Non-Java compilers don't get the classpath logic.
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "lib").mkdir()
            (Path(d) / "lib" / "irrelevant.jar").write_bytes(b"")
            (Path(d) / "main.c").write_text("int main(){return 0;}")
            bd = BuildDetector(Path(d))
            build_dir = Path(d) / ".build"
            build_dir.mkdir()
            script_path = Path(d) / ".raptor_build_.py"
            script_path.touch()
            bd._write_build_script(
                script_path=script_path,
                build_dir=build_dir,
                source_files=[Path(d) / "main.c"],
                compiler="gcc",
                include_flags=[],
                define_flags=[],
            )
            script_text = script_path.read_text()
            # JAVA_CLASSPATH_JARS still emitted (dead for gcc) but
            # the "-cp" flag MUST NOT appear in the generated cmd-
            # building path for gcc. The is_java guard protects this.
            self.assertIn("IS_JAVA = False", script_text)
            # `IS_JAVA = False` means the Java branch never runs.
            # Even though JAVA_CLASSPATH_JARS is in the literals, it
            # isn't used.


if __name__ == "__main__":
    unittest.main()
