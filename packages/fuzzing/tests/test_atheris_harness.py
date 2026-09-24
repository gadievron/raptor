"""Tests for the atheris harness template scaffolder."""

import shutil
import tempfile
import unittest
from pathlib import Path

from packages.fuzzing.atheris_harness import (
    AtherisHarnessSpec,
    generate_atheris_harness,
    write_atheris_harness,
)


class TestAtherisHarnessSpec(unittest.TestCase):

    def test_valid_entry_splits_module_and_function(self):
        spec = AtherisHarnessSpec(entry="mypkg.parser:parse_bytes")
        self.assertEqual(spec.module, "mypkg.parser")
        self.assertEqual(spec.function, "parse_bytes")
        self.assertEqual(spec.payload, "bytes")

    def test_dotted_function_chain_is_valid(self):
        spec = AtherisHarnessSpec(entry="json:JSONDecoder.decode")
        self.assertEqual(spec.function, "JSONDecoder.decode")

    def test_rejected_entries(self):
        # The names land verbatim in generated, executed source —
        # anything that is not a plain identifier chain must be
        # rejected at spec construction, never escaped.
        bad = [
            "no_colon",
            "bad-name:func",
            "mod:func()",
            "mod:fu nc",
            "mod:",
            ":func",
            "mod:1func",
            "mod..sub:func",
            "import:x",             # keyword segment
            "mod:__import__('os');x",
            "mod:func\nimport os",
            "a" * 300 + ":func",
            # `$` would match just before a trailing newline — the
            # grammar must anchor at end-of-string (\Z), or these
            # produce a newline-embedded filename and a call line
            # that NameErrors at import.
            "mod:func\n",
            "mod\n:func",
        ]
        for entry in bad:
            with self.subTest(entry=entry), self.assertRaises(ValueError):
                AtherisHarnessSpec(entry=entry)

    def test_rejected_payload_mode(self):
        with self.assertRaises(ValueError):
            AtherisHarnessSpec(entry="mod:func", payload="pickle")


class TestHarnessGeneration(unittest.TestCase):

    def test_bytes_harness_shape(self):
        spec = AtherisHarnessSpec(entry="mypkg.parser:parse")
        source = generate_atheris_harness(spec)
        self.assertIn("GENERATED", source)
        self.assertIn("import mypkg.parser", source)
        self.assertIn("mypkg.parser.parse(payload)", source)
        self.assertIn("def TestOneInput(data: bytes)", source)
        self.assertIn("atheris.Setup(sys.argv, TestOneInput)", source)
        # Generated source must at least be syntactically valid
        # Python (compile() does not import atheris — hermetic).
        compile(source, "<generated-harness>", "exec")

    def test_text_harness_uses_fuzzed_data_provider(self):
        spec = AtherisHarnessSpec(entry="mymod:handle", payload="text")
        source = generate_atheris_harness(spec)
        self.assertIn("FuzzedDataProvider", source)
        self.assertIn("ConsumeUnicodeNoSurrogates", source)
        compile(source, "<generated-harness>", "exec")

    def test_write_emits_identifier_derived_filename(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        spec = AtherisHarnessSpec(entry="mypkg.parser:parse")
        path = write_atheris_harness(spec, tmp / "harness")
        self.assertEqual(path.name, "fuzz_mypkg_parser_parse.py")
        self.assertTrue(path.is_file())
        self.assertIn("GENERATED", path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
