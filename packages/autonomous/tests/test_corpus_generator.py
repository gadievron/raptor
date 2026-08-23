"""Tests for agentic fuzz corpus generation."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from packages.autonomous.corpus_generator import CorpusGenerator


class TestCorpusGenerator(unittest.TestCase):

    def test_discovers_documented_command_grammar_and_generates_seeds(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            binary = root / "target"
            binary.write_bytes(b"dummy")
            (root / "README.md").write_text(
                "Input grammar:\n"
                "STACK:data triggers stack path\n"
                "HEAP:data triggers heap path\n"
                "JSON:{\"key\":\"value\"} triggers JSON parser\n",
                encoding="utf-8",
            )
            corpus = root / "corpus"

            generator = CorpusGenerator(binary, source_dir=root)
            seeds = generator.generate_autonomous_corpus(corpus, max_seeds=16)

            self.assertGreater(seeds, 0)
            self.assertEqual({"HEAP", "JSON", "STACK"}, set(generator.detected_commands))
            seed_data = [path.read_bytes() for path in corpus.iterdir()]
            self.assertTrue(any(data.startswith(b"STACK:") for data in seed_data))
            self.assertTrue(any(data.startswith(b"HEAP:") for data in seed_data))
            self.assertTrue(any(data.startswith(b"JSON:") for data in seed_data))

    def test_discovers_strcmp_command_tokens_from_source(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            binary = root / "target"
            binary.write_bytes(b"dummy")
            (root / "parser.c").write_text(
                'if (strcmp(command, "FMT") == 0) handle_fmt(input);\n',
                encoding="utf-8",
            )

            generator = CorpusGenerator(binary, source_dir=root)
            analysis = generator.analyze_binary()

            self.assertIn("FMT", analysis["commands_detected"])
            self.assertIn("FMT", generator.detected_commands)


class _FakeStrings:
    """Stand-in for the sandboxed ``strings`` invocation."""

    def __init__(self, stdout: str):
        self.returncode = 0
        self.stdout = stdout
        self.stderr = ""


# Strings chosen so dict-literal insertion order (STACK, HEAP, UAF,
# JSON, ...) differs from sorted order (HEAP, JSON, STACK, UAF).
_BINARY_STDOUT = "\n".join(
    ["vuln_stack", "heap: input", "[uaf] handler", "parse_json here"]
)


class TestCommandsDetectedOrdering(unittest.TestCase):
    """``analysis["commands_detected"]`` is emitted in sorted order on
    BOTH the binary-only path and the source-context path, so the report
    field's ordering does not depend on whether ``source_dir`` is set."""

    @staticmethod
    def _make_generator(root: Path, source_dir: Path | None = None) -> CorpusGenerator:
        binary = root / "target"
        binary.write_bytes(b"dummy")
        return CorpusGenerator(binary, source_dir=source_dir)

    def test_commands_detected_sorted_without_source_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            gen = self._make_generator(root)
            with patch(
                "packages.autonomous.corpus_generator._run_trusted",
                return_value=_FakeStrings(_BINARY_STDOUT),
            ):
                analysis = gen.analyze_binary()

            commands = analysis["commands_detected"]
            self.assertEqual(commands, sorted(commands))
            self.assertEqual({"HEAP", "JSON", "STACK", "UAF"}, set(commands))

    def test_commands_detected_ordering_independent_of_source_dir(self):
        """Binary-only vs source-context path must agree on ordering."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            source_dir = root / "src"
            source_dir.mkdir()
            # Source contributes nothing new — set of commands is identical
            # either way, so any ordering difference is purely path-dependent.
            (source_dir / "README.md").write_text("no grammar here\n", encoding="utf-8")

            with patch(
                "packages.autonomous.corpus_generator._run_trusted",
                return_value=_FakeStrings(_BINARY_STDOUT),
            ):
                without_source = self._make_generator(root).analyze_binary()
                with_source = self._make_generator(
                    root, source_dir=source_dir
                ).analyze_binary()

            self.assertEqual(
                without_source["commands_detected"],
                with_source["commands_detected"],
            )


if __name__ == "__main__":
    unittest.main()
