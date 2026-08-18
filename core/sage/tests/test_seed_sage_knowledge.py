#!/usr/bin/env python3
"""Tests for core/sage/scripts/seed_sage_knowledge.py.

Pins:
- extract_personas reads each persona file exactly once (a double
  _read_capped call with identical arguments would discard the first
  result and pay the I/O twice).
- _read_capped returns "" on a non-UTF-8 (corrupted) file instead of
  propagating UnicodeDecodeError — the "corrupted .md file" case its
  docstring promises to handle.
- REPO_ROOT resolves to the repo root.
"""

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from core.sage.scripts import seed_sage_knowledge as ssk


class TestExtractPersonasSingleRead(unittest.TestCase):
    """One bounded read per persona file."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.repo_root = Path(self._tmp.name)
        self.personas_dir = self.repo_root / "tiers" / "personas"
        self.personas_dir.mkdir(parents=True)

    def _patch_repo_root(self):
        return mock.patch.object(ssk, "REPO_ROOT", self.repo_root)

    def test_each_persona_file_read_exactly_once(self):
        (self.personas_dir / "alpha-expert.md").write_text(
            "Alpha persona body.", encoding="utf-8"
        )
        (self.personas_dir / "beta_expert.md").write_text(
            "Beta persona body.", encoding="utf-8"
        )

        calls: list[Path] = []
        real_read = ssk._read_capped

        def counting_read(path, *, max_bytes):
            calls.append(path)
            return real_read(path, max_bytes=max_bytes)

        with self._patch_repo_root(), mock.patch.object(
            ssk, "_read_capped", side_effect=counting_read
        ):
            memories = ssk.extract_personas()

        self.assertEqual(len(memories), 2)
        self.assertEqual(len(calls), 2, "each persona file must be read once")
        self.assertEqual(len(set(calls)), 2, "no persona file read twice")

    def test_persona_content_and_label_preserved(self):
        (self.personas_dir / "heap-wizard.md").write_text(
            "  Knows heap grooming.  \n", encoding="utf-8"
        )

        with self._patch_repo_root():
            memories = ssk.extract_personas()

        self.assertEqual(len(memories), 1)
        mem = memories[0]
        self.assertEqual(mem["label"], "persona:heap-wizard")
        self.assertIn("heap wizard", mem["content"])
        self.assertIn("Knows heap grooming.", mem["content"])
        self.assertNotIn("grooming.  ", mem["content"], "content must be stripped")

    def test_unreadable_persona_skipped_others_survive(self):
        # Non-UTF-8 file exercises the guard path end-to-end: the bad
        # file is skipped, the good one still seeds.
        (self.personas_dir / "corrupted.md").write_bytes(b"\xff\xfe\xff garbage")
        (self.personas_dir / "good.md").write_text("Good persona.", encoding="utf-8")

        with self._patch_repo_root():
            memories = ssk.extract_personas()

        self.assertEqual([m["label"] for m in memories], ["persona:good"])

    def test_long_persona_chunked_with_single_read(self):
        (self.personas_dir / "verbose.md").write_text(
            "para one\n\n" + "x" * 2000, encoding="utf-8"
        )

        calls: list[Path] = []
        real_read = ssk._read_capped

        def counting_read(path, *, max_bytes):
            calls.append(path)
            return real_read(path, max_bytes=max_bytes)

        with self._patch_repo_root(), mock.patch.object(
            ssk, "_read_capped", side_effect=counting_read
        ):
            memories = ssk.extract_personas()

        self.assertEqual(len(calls), 1)
        self.assertGreater(len(memories), 1, "long persona must be chunked")
        self.assertTrue(
            all(m["label"].startswith("persona:verbose:part") for m in memories)
        )


class TestReadCapped(unittest.TestCase):
    """_read_capped contract: '' on oversize, missing, or unreadable files."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp_path = Path(self._tmp.name)

    def test_oversize_returns_empty(self):
        f = self.tmp_path / "big.md"
        f.write_text("a" * 100, encoding="utf-8")
        self.assertEqual(ssk._read_capped(f, max_bytes=99), "")

    def test_at_cap_is_read(self):
        f = self.tmp_path / "exact.md"
        f.write_text("a" * 100, encoding="utf-8")
        self.assertEqual(ssk._read_capped(f, max_bytes=100), "a" * 100)

    def test_missing_file_returns_empty(self):
        self.assertEqual(
            ssk._read_capped(self.tmp_path / "nope.md", max_bytes=1024), ""
        )

    def test_non_utf8_returns_empty(self):
        # The docstring promises "" on read failure of corrupted files;
        # a UnicodeDecodeError must not escape.
        f = self.tmp_path / "corrupt.md"
        f.write_bytes(b"\xff\xfe\x00\xff not utf-8")
        self.assertEqual(ssk._read_capped(f, max_bytes=1024), "")


class TestRepoRoot(unittest.TestCase):
    def test_repo_root_resolves_to_repo(self):
        # REPO_ROOT is derived via parents[...] from the script's own
        # location; pin the level so it cannot silently drift.
        self.assertTrue((ssk.REPO_ROOT / "core" / "sage" / "scripts").is_dir())


if __name__ == "__main__":
    unittest.main()
