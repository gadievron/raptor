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
    get_config,
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
