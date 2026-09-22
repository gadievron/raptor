"""Tests for OpenAnt config path discovery."""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[4]))  # repo root

from packages.openant.config import (
    OpenAntConfig,
    is_available,
    _discover_core,
    OPENANT_CORE_ENV,
)

_MARKER = "core/scanner.py"


def _make_fake_core(tmp: Path) -> Path:
    core_dir = tmp / "libs" / "openant-core"
    marker = core_dir / "core"
    marker.mkdir(parents=True)
    (marker / "scanner.py").touch()
    return core_dir


class TestDiscoverCore(unittest.TestCase):
    def test_openant_core_env_used_when_set(self):
        with tempfile.TemporaryDirectory() as tmp:
            core = _make_fake_core(Path(tmp))
            with patch.dict(os.environ, {OPENANT_CORE_ENV: str(core)}, clear=False):
                result = _discover_core(None)
            self.assertEqual(result, core)

    def test_raptor_dir_heuristic(self):
        with tempfile.TemporaryDirectory() as tmp:
            raptor_dir = Path(tmp) / "raptor"
            raptor_dir.mkdir()
            core = _make_fake_core(Path(tmp))
            env = {k: v for k, v in os.environ.items()
                   if k not in (OPENANT_CORE_ENV,)}
            env["RAPTOR_DIR"] = str(raptor_dir)
            with patch.dict(os.environ, env, clear=True):
                result = _discover_core(None)
            self.assertEqual(result, core)

    def test_raptor_dir_arg_heuristic(self):
        with tempfile.TemporaryDirectory() as tmp:
            raptor_dir = Path(tmp) / "raptor"
            raptor_dir.mkdir()
            core = _make_fake_core(Path(tmp))
            env = {k: v for k, v in os.environ.items()
                   if k not in (OPENANT_CORE_ENV, "RAPTOR_DIR")}
            with patch.dict(os.environ, env, clear=True):
                result = _discover_core(raptor_dir)
            self.assertEqual(result, core)

    def test_neither_raises(self):
        env = {k: v for k, v in os.environ.items()
               if k not in (OPENANT_CORE_ENV, "RAPTOR_DIR")}
        with patch.dict(os.environ, env, clear=True):
            with self.assertRaises(RuntimeError):
                _discover_core(None)


class TestOpenAntConfig(unittest.TestCase):
    def test_validate_raises_if_marker_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = OpenAntConfig(core_path=Path(tmp))
            with self.assertRaises(RuntimeError):
                config.validate()

    def test_validate_passes_when_marker_exists(self):
        with tempfile.TemporaryDirectory() as tmp:
            core = _make_fake_core(Path(tmp))
            config = OpenAntConfig(core_path=core)
            config.validate()  # should not raise

    def test_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            core = _make_fake_core(Path(tmp))
            config = OpenAntConfig(core_path=core)
            self.assertEqual(config.model, "sonnet")
            self.assertEqual(config.level, "reachable")
            self.assertTrue(config.enhance)
            self.assertFalse(config.verify)
            self.assertEqual(config.workers, 4)
            self.assertEqual(config.language, "auto")


class TestIsAvailable(unittest.TestCase):
    def test_returns_false_when_not_configured(self):
        env = {k: v for k, v in os.environ.items()
               if k not in (OPENANT_CORE_ENV, "RAPTOR_DIR")}
        with patch.dict(os.environ, env, clear=True):
            self.assertFalse(is_available())

    def test_returns_true_when_configured(self):
        with tempfile.TemporaryDirectory() as tmp:
            core = _make_fake_core(Path(tmp))
            with patch.dict(os.environ, {OPENANT_CORE_ENV: str(core)}, clear=False):
                self.assertTrue(is_available())


if __name__ == "__main__":
    unittest.main()


class TestSupplyChainPin(unittest.TestCase):
    """openant-core is external, internet-sourced code — the
    integration pins it by immutable commit id."""

    def test_pin_is_a_full_commit_id(self):
        from packages.openant.config import (
            OPENANT_PINNED_COMMIT,
            OPENANT_UPSTREAM_URL,
        )
        self.assertRegex(OPENANT_PINNED_COMMIT, r"^[0-9a-f]{40}$")
        self.assertTrue(OPENANT_UPSTREAM_URL.startswith("https://"))

    @staticmethod
    def _git_repo(repo: Path) -> None:
        import subprocess
        repo.mkdir(parents=True, exist_ok=True)
        env = {**os.environ,
               "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
               "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}
        for cmd in (["git", "init", "-q"],
                    ["git", "commit", "-q", "--allow-empty", "-m", "x"]):
            subprocess.run(cmd, cwd=repo, env=env, check=True,
                           capture_output=True)

    def test_checkout_provenance_reports_mismatch(self):
        from packages.openant import scanner
        from packages.openant.config import OPENANT_PINNED_COMMIT
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td) / "OpenAnt"
            self._git_repo(repo)
            core = repo / "libs" / "openant-core"
            core.mkdir(parents=True)
            with self.assertLogs("raptor", level="WARNING") as cm:
                prov = scanner.checkout_provenance(core)
            self.assertEqual(prov["pinned_commit"], OPENANT_PINNED_COMMIT)
            self.assertIsNotNone(prov["head"])
            self.assertIs(prov["matches"], False)
            self.assertTrue(any("pinned" in m for m in cm.output))

    def test_checkout_provenance_warns_outside_git(self):
        """The non-git shape (tarball extract, deleted .git, an
        attacker-written directory) is the HOSTILE provenance shape —
        it must warn loudly, not degrade silently."""
        from packages.openant import scanner
        with tempfile.TemporaryDirectory() as td:
            with self.assertLogs("raptor", level="WARNING") as cm:
                prov = scanner.checkout_provenance(Path(td))
            self.assertIsNone(prov["head"])
            self.assertIsNone(prov["matches"])
            self.assertTrue(any("UNVERIFIABLE" in m for m in cm.output))

    def test_checkout_provenance_never_reads_an_enclosing_repo(self):
        """A non-git openant-core inside an unrelated repository must
        not record the ENCLOSING repo's HEAD as OpenAnt provenance
        (git -C discovers upward) — and the unverifiable result warns."""
        from packages.openant import scanner
        with tempfile.TemporaryDirectory() as td:
            outer = Path(td) / "unrelated-repo"
            self._git_repo(outer)
            core = outer / "vendor" / "openant-core"
            core.mkdir(parents=True)
            with self.assertLogs("raptor", level="WARNING") as cm:
                prov = scanner.checkout_provenance(core)
            self.assertIsNone(prov["head"])
            self.assertIsNone(prov["matches"])
            self.assertTrue(any("UNVERIFIABLE" in m for m in cm.output))

    def test_agentic_lane_carries_core_provenance(self):
        """/agentic's Phase 1b records the scan's ``core_provenance``
        in its report metrics — the standalone workflow already
        records it, and a lane that drops it leaves no record of which
        OpenAnt core produced the findings."""
        src = (Path(__file__).resolve().parents[3]
               / "raptor_agentic.py").read_text()
        self.assertIn('openant_metrics["core_provenance"]', src)

    def test_checkout_provenance_quiet_at_pin(self):
        """The pinned checkout is the ONLY quiet shape."""
        import subprocess
        from packages.openant import scanner
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td) / "OpenAnt"
            self._git_repo(repo)
            core = repo / "libs" / "openant-core"
            core.mkdir(parents=True)
            head = subprocess.run(
                ["git", "rev-parse", "HEAD"], cwd=repo, check=True,
                capture_output=True, text=True,
            ).stdout.strip().lower()
            with patch.object(scanner, "OPENANT_PINNED_COMMIT", head):
                with self.assertNoLogs("raptor", level="WARNING"):
                    prov = scanner.checkout_provenance(core)
            self.assertIs(prov["matches"], True)
            self.assertEqual(prov["head"], head)
