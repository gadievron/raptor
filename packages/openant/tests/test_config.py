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


class TestEnvKnobsReachArgparse(unittest.TestCase):
    """$OPENANT_MODEL / $OPENANT_LEVEL are documented operator knobs;
    both entry points must seed their argparse defaults from them
    (env respected), while an explicit flag always wins."""

    def _parser(self):
        import raptor_openant
        return raptor_openant._build_parser()

    def test_env_seeds_defaults(self):
        with patch.dict(os.environ, {"OPENANT_MODEL": "opus",
                                     "OPENANT_LEVEL": "all"}, clear=False):
            args = self._parser().parse_args(["--repo", "/x"])
        self.assertEqual(args.model, "opus")
        self.assertEqual(args.level, "all")

    def test_explicit_flag_beats_env(self):
        with patch.dict(os.environ, {"OPENANT_MODEL": "opus",
                                     "OPENANT_LEVEL": "all"}, clear=False):
            args = self._parser().parse_args(
                ["--repo", "/x", "--model", "sonnet", "--level", "codeql"])
        self.assertEqual(args.model, "sonnet")
        self.assertEqual(args.level, "codeql")

    def test_invalid_env_value_falls_back_loudly(self):
        # argparse does NOT validate string defaults against choices —
        # env_choice must reject the value itself.
        with patch.dict(os.environ, {"OPENANT_MODEL": "garbage",
                                     "OPENANT_LEVEL": "bogus"}, clear=False):
            args = self._parser().parse_args(["--repo", "/x"])
        self.assertEqual(args.model, "sonnet")
        self.assertEqual(args.level, "reachable")

    def test_agentic_surface_is_env_aware(self):
        src = (Path(__file__).parents[3] / "raptor_agentic.py").read_text()
        self.assertIn('env_choice("OPENANT_MODEL"', src)
        self.assertIn('env_choice("OPENANT_LEVEL"', src)


class TestCheckoutPinRefForgery(unittest.TestCase):
    """``matches: True`` must rest on a hash-verified object read.
    ``rev-parse HEAD`` resolves whatever id the (attacker-shipped)
    ref carries without checking that the object exists or hashes
    correctly — a ``.git/HEAD`` carrying the raw pin id forged the
    pin bit and silenced the env-surface warning."""

    _FAKE_PIN = "abd1dcf416a1ca329441c4bf8ebb68f70dd0f3cf"

    @staticmethod
    def _hostile_layout(td: Path) -> tuple[Path, Path]:
        """A real git repo at the documented layout with HOSTILE
        content committed; returns (repo, core_path)."""
        import subprocess
        repo = td / "OpenAnt"
        core = repo / "libs" / "openant-core"
        (core / "core").mkdir(parents=True)
        (core / "core" / "scanner.py").write_text("hostile = True\n")
        env = {**os.environ,
               "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
               "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}
        for cmd in (["git", "init", "-q"], ["git", "add", "-A"],
                    ["git", "commit", "-q", "-m", "hostile"]):
            subprocess.run(cmd, cwd=repo, env=env, check=True,
                           capture_output=True)
        return repo, core

    def test_head_carrying_raw_pin_id_is_unverifiable(self):
        """The evilhead shape: .git/HEAD = the raw pin id, no such
        object in the store. Must be the hostile matches=None shape
        with the loud UNVERIFIABLE warning — never matches=True."""
        from packages.openant import scanner
        with tempfile.TemporaryDirectory() as td:
            repo, core = self._hostile_layout(Path(td))
            (repo / ".git" / "HEAD").write_text(self._FAKE_PIN + "\n")
            with patch.object(scanner, "OPENANT_PINNED_COMMIT",
                              self._FAKE_PIN):
                with self.assertLogs("raptor", level="WARNING") as cm:
                    prov = scanner.checkout_provenance(core)
            self.assertIsNot(prov["matches"], True)
            self.assertTrue(any("UNVERIFIABLE" in m for m in cm.output))

    def test_packed_ref_carrying_pin_id_is_unverifiable(self):
        """Adjacent forgery: HEAD stays a symref, the pin id sits in
        .git/packed-refs for the named branch, no such object."""
        from packages.openant import scanner
        with tempfile.TemporaryDirectory() as td:
            repo, core = self._hostile_layout(Path(td))
            (repo / ".git" / "HEAD").write_text("ref: refs/heads/evil\n")
            for loose in (repo / ".git" / "refs" / "heads").glob("*"):
                loose.unlink()
            (repo / ".git" / "packed-refs").write_text(
                "# pack-refs with: peeled fully-peeled sorted \n"
                f"{self._FAKE_PIN} refs/heads/evil\n")
            with patch.object(scanner, "OPENANT_PINNED_COMMIT",
                              self._FAKE_PIN):
                with self.assertLogs("raptor", level="WARNING") as cm:
                    prov = scanner.checkout_provenance(core)
            self.assertIsNot(prov["matches"], True)
            self.assertTrue(any("UNVERIFIABLE" in m for m in cm.output))

    def test_forged_commit_object_at_pin_id_is_unverifiable(self):
        """A forged loose commit object stored UNDER the pin id (its
        content hashes to something else) must not mint matches=True:
        git verifies commits on parse, and the Python self-hash backs
        that up."""
        import shutil
        import subprocess
        from packages.openant import scanner
        with tempfile.TemporaryDirectory() as td:
            repo, core = self._hostile_layout(Path(td))
            real = subprocess.run(
                ["git", "rev-parse", "HEAD"], cwd=repo, check=True,
                capture_output=True, text=True).stdout.strip()
            objects = repo / ".git" / "objects"
            dst = objects / self._FAKE_PIN[:2] / self._FAKE_PIN[2:]
            dst.parent.mkdir(exist_ok=True)
            shutil.copyfile(objects / real[:2] / real[2:], dst)
            (repo / ".git" / "HEAD").write_text(self._FAKE_PIN + "\n")
            with patch.object(scanner, "OPENANT_PINNED_COMMIT",
                              self._FAKE_PIN):
                with self.assertLogs("raptor", level="WARNING") as cm:
                    prov = scanner.checkout_provenance(core)
            self.assertIsNot(prov["matches"], True)
            self.assertTrue(any("UNVERIFIABLE" in m for m in cm.output))

    def test_genuine_pinned_checkout_still_quiet_and_matching(self):
        """Regression direction: a genuine checkout at the pin stays
        the quiet matches=True shape under the verified read."""
        import subprocess
        from packages.openant import scanner
        with tempfile.TemporaryDirectory() as td:
            repo, core = self._hostile_layout(Path(td))
            head = subprocess.run(
                ["git", "rev-parse", "HEAD"], cwd=repo, check=True,
                capture_output=True, text=True).stdout.strip().lower()
            with patch.object(scanner, "OPENANT_PINNED_COMMIT", head):
                with self.assertNoLogs("raptor", level="WARNING"):
                    prov = scanner.checkout_provenance(core)
            self.assertIs(prov["matches"], True)
            self.assertEqual(prov["head"], head)
class TestFromEnvValidatesKnobs(unittest.TestCase):
    """OpenAntConfig.from_env read OPENANT_MODEL / OPENANT_LEVEL raw
    beside the module's own env_choice validator — any get_config()
    consumer that did not overwrite from validated argparse inherited
    the unvalidated lane. The choice tuples are single-sourced."""

    def _from_env(self, env: dict):
        from unittest.mock import patch as _patch
        from packages.openant.config import OpenAntConfig
        with tempfile.TemporaryDirectory() as td:
            core = Path(td) / "core-dir"
            (core / "core").mkdir(parents=True)
            (core / "core" / "scanner.py").touch()
            with _patch.dict(os.environ,
                             {"OPENANT_CORE": str(core), **env}):
                return OpenAntConfig.from_env()

    def test_garbage_env_values_fall_back_with_warning(self):
        import contextlib
        import io
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            cfg = self._from_env({"OPENANT_MODEL": "garbage-model",
                                  "OPENANT_LEVEL": "bogus"})
        self.assertEqual(cfg.model, "sonnet")
        self.assertEqual(cfg.level, "reachable")
        self.assertIn("Ignoring invalid", stderr.getvalue())

    def test_valid_env_values_kept(self):
        cfg = self._from_env({"OPENANT_MODEL": "opus",
                              "OPENANT_LEVEL": "exploitable"})
        self.assertEqual(cfg.model, "opus")
        self.assertEqual(cfg.level, "exploitable")

    def test_choice_tuples_single_sourced(self):
        """The argparse surfaces consume the config module's tuples
        instead of respelling them."""
        from packages.openant.config import (
            OPENANT_LEVEL_CHOICES,
            OPENANT_MODEL_CHOICES,
        )
        self.assertEqual(OPENANT_MODEL_CHOICES, ("opus", "sonnet"))
        self.assertEqual(OPENANT_LEVEL_CHOICES,
                         ("all", "reachable", "codeql", "exploitable"))
        for launcher in ("raptor_openant.py", "raptor_agentic.py"):
            src = (Path(__file__).parents[3] / launcher).read_text()
            self.assertIn("OPENANT_MODEL_CHOICES", src, launcher)
            self.assertIn("OPENANT_LEVEL_CHOICES", src, launcher)
            self.assertNotIn('("opus", "sonnet")', src, launcher)
