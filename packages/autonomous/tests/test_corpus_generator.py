"""Tests for agentic fuzz corpus generation."""

import tempfile
import unittest
from pathlib import Path

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


if __name__ == "__main__":
    unittest.main()
