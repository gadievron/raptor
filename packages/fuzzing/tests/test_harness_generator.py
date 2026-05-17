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


if __name__ == "__main__":
    unittest.main()
