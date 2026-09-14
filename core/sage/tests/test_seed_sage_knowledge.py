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

import os
import subprocess
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


class TestSeedOneMemoryType(unittest.TestCase):
    """_seed_one routes memory_type through the shared allowlist —
    never getattr on the enum (dunder acceptance / silent-typo
    default)."""

    def _seed(self, memory_type: str):
        import asyncio
        from types import SimpleNamespace
        from unittest.mock import AsyncMock

        mem = {"label": "x", "domain": "d", "content": "c",
               "memory_type": memory_type, "confidence": 0.9}
        client = AsyncMock()
        client.embed.return_value = [0.1]
        enum = SimpleNamespace(fact="fact", observation="observation",
                               inference="inference", task="task")
        with mock.patch.object(ssk, "MemoryType", enum):
            label, status = asyncio.run(ssk._seed_one(
                client, mem, force=True, sem=asyncio.Semaphore(1)))
        self.assertEqual(status, "stored")
        return client.propose.call_args.kwargs["memory_type"]

    def test_fact_maps_to_enum_member(self):
        self.assertEqual(self._seed("fact"), "fact")

    def test_dunder_name_falls_back_to_observation(self):
        # getattr(MemoryType, "__class__", ...) resolved to the class
        # object and shipped it as the memory type.
        self.assertEqual(self._seed("__class__"), "observation")


class TestScriptModePathSetup(unittest.TestCase):
    """Script-mode sys.path setup comes from RAPTOR_DIR (the
    path-safety rule), never from __file__; without RAPTOR_DIR the
    scripts refuse loudly instead of importing a guessed tree."""

    _SCRIPTS = (
        "core/sage/scripts/seed_sage_knowledge.py",
        "core/sage/scripts/register_agents.py",
    )

    def _run(
        self, script: str, with_raptor_dir: bool
    ) -> subprocess.CompletedProcess[str]:
        import sys as _sys
        repo_root = ssk.REPO_ROOT
        env = {k: v for k, v in os.environ.items() if k != "RAPTOR_DIR"}
        if with_raptor_dir:
            env["RAPTOR_DIR"] = str(repo_root)
        return subprocess.run(
            [_sys.executable, str(repo_root / script), "--help"],
            capture_output=True, text=True, env=env, timeout=60,
        )

    def test_refuses_without_raptor_dir(self):
        for script in self._SCRIPTS:
            with self.subTest(script=script):
                r = self._run(script, with_raptor_dir=False)
                self.assertNotEqual(r.returncode, 0)
                self.assertIn("RAPTOR_DIR", r.stderr + r.stdout)

    def test_runs_with_raptor_dir(self):
        for script in self._SCRIPTS:
            with self.subTest(script=script):
                r = self._run(script, with_raptor_dir=True)
                # Both streams, repr'd: a script that dies with its
                # error on stdout (the pre-fix missing-SDK gate did
                # exactly that) otherwise yields an empty-looking
                # diagnostic that hides the actual cause.
                self.assertEqual(
                    r.returncode, 0,
                    f"--help failed: stderr={r.stderr[:500]!r} "
                    f"stdout={r.stdout[:500]!r}",
                )


class TestMissingSdkGating(unittest.TestCase):
    """The deferred sage-agent-sdk import error gates work, not usage:
    `--help` succeeds without the SDK (environments without the
    optional dep still get usage), while a real invocation refuses
    with the install hint on stderr."""

    _SCRIPTS = (
        "core/sage/scripts/seed_sage_knowledge.py",
        "core/sage/scripts/register_agents.py",
    )

    def _run_without_sdk(self, script: str, arg: str) -> subprocess.CompletedProcess[str]:
        import sys as _sys
        repo_root = ssk.REPO_ROOT
        # Shadow sage_sdk with a package that raises ImportError so the
        # test behaves identically whether or not the SDK is installed
        # on the host. The shadow sits on PYTHONPATH, ahead of
        # site-packages but behind RAPTOR_DIR (which has no sage_sdk).
        with tempfile.TemporaryDirectory() as shadow:
            pkg = Path(shadow) / "sage_sdk"
            pkg.mkdir()
            (pkg / "__init__.py").write_text(
                'raise ImportError("sage-agent-sdk absent (test shadow)")\n'
            )
            env = dict(os.environ)
            env["RAPTOR_DIR"] = str(repo_root)
            prior = env.get("PYTHONPATH")
            env["PYTHONPATH"] = shadow + (os.pathsep + prior if prior else "")
            return subprocess.run(
                [_sys.executable, str(repo_root / script), arg],
                capture_output=True, text=True, env=env, timeout=60,
            )

    def test_help_works_without_sdk(self):
        for script in self._SCRIPTS:
            with self.subTest(script=script):
                r = self._run_without_sdk(script, "--help")
                # Both streams, repr'd — same rationale as
                # test_runs_with_raptor_dir.
                self.assertEqual(
                    r.returncode, 0,
                    f"--help failed: stderr={r.stderr[:500]!r} "
                    f"stdout={r.stdout[:500]!r}",
                )
                self.assertIn("usage:", r.stdout)

    def test_work_refuses_without_sdk_on_stderr(self):
        for script in self._SCRIPTS:
            with self.subTest(script=script):
                r = self._run_without_sdk(script, "--dry-run")
                self.assertEqual(r.returncode, 1)
                self.assertIn("sage-agent-sdk", r.stderr)


if __name__ == "__main__":
    unittest.main()
