"""Two-direction contract for the staged llm-config profile.

The pinned OpenAnt CLI selects models via ``--llm-config <profile>``
resolved from ``$XDG_CONFIG_HOME/openant/config.json`` (there is no
``--model`` flag). RAPTOR stages a run-local config carrying a
``raptor-<model>`` profile and points the child's XDG_CONFIG_HOME at
it. Direction 1: RAPTOR's model selection lands on every phase of the
staged profile and on the argv. Direction 2: the operator's own
config.json is merged, never mutated — foreign profiles and providers
survive byte-identical in the staged copy and the source file is
untouched.
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[3]))  # repo root

from packages.openant.config import OpenAntConfig
from packages.openant.scanner import (
    _OPENANT_LLM_PHASES,
    _OPENANT_MODEL_IDS,
    _XDG_STAGE_DIRNAME,
    _build_command,
    _llm_profile_name,
    _stage_llm_config,
)


def _make_fake_core(tmp: Path) -> Path:
    core_dir = tmp / "libs" / "openant-core"
    marker = core_dir / "core"
    marker.mkdir(parents=True)
    (marker / "scanner.py").touch()
    return core_dir


def _staged_config(out_dir: Path) -> dict:
    path = out_dir / _XDG_STAGE_DIRNAME / "openant" / "config.json"
    return json.loads(path.read_text())


class TestModelSelectionReachesEveryPhase(unittest.TestCase):
    """Direction 1: --model X → profile binds X's pinned id on ALL
    phases and the argv names the profile (and never --model)."""

    def test_argv_carries_llm_config_not_model(self):
        with tempfile.TemporaryDirectory() as td:
            core = _make_fake_core(Path(td))
            for model in ("sonnet", "opus"):
                config = OpenAntConfig(core_path=core, model=model)
                cmd = _build_command(Path(td), Path(td) / "out", config)
                self.assertNotIn("--model", cmd)
                idx = cmd.index("--llm-config")
                self.assertEqual(cmd[idx + 1], f"raptor-{model}")

    def test_profile_binds_model_on_every_phase(self):
        for model in ("sonnet", "opus"):
            with tempfile.TemporaryDirectory() as td:
                out_dir = Path(td) / "out"
                out_dir.mkdir()
                # Point the operator-config lookup at an empty dir so
                # the host's real config never leaks into the test.
                with patch.dict(os.environ,
                                {"XDG_CONFIG_HOME": str(Path(td) / "xdg")}):
                    xdg_home = _stage_llm_config(out_dir, model)
                self.assertEqual(xdg_home, out_dir / _XDG_STAGE_DIRNAME)
                staged = _staged_config(out_dir)
                profile = staged["llm_configs"][f"raptor-{model}"]
                self.assertEqual(set(profile), set(_OPENANT_LLM_PHASES))
                for phase in _OPENANT_LLM_PHASES:
                    self.assertEqual(profile[phase], {
                        "provider": "anthropic",
                        "model": _OPENANT_MODEL_IDS[model],
                    })

    def test_no_credential_invented(self):
        """The RAPTOR profile references provider "anthropic" (upstream
        synthesises it from $ANTHROPIC_API_KEY); staging a fresh config
        must never write a key or an llm_providers entry of its own."""
        with tempfile.TemporaryDirectory() as td:
            out_dir = Path(td) / "out"
            out_dir.mkdir()
            with patch.dict(os.environ,
                            {"XDG_CONFIG_HOME": str(Path(td) / "xdg")}):
                _stage_llm_config(out_dir, "sonnet")
            staged = _staged_config(out_dir)
            self.assertNotIn("llm_providers", staged)
            self.assertNotIn("api_key", json.dumps(staged))

    def test_unknown_model_falls_back_to_sonnet(self):
        """$OPENANT_MODEL is the one unvalidated model lane — an
        untranslatable name must warn and fall back, not ship a profile
        upstream would reject mid-scan."""
        self.assertEqual(_llm_profile_name("gpt-99"), "raptor-sonnet")


class TestOperatorConfigMergedNeverMutated(unittest.TestCase):
    """Direction 2: foreign entries survive byte-identical in the
    staged copy; the operator's file is never written."""

    _FOREIGN = {
        "$schema_version": 2,
        "default_llm": "my-config",
        "llm_providers": {
            "my-ollama": {"type": "ollama", "base_url": "http://x:11434"},
            "anthropic": {"type": "anthropic", "api_key": "sk-op-123"},
        },
        "llm_configs": {
            "my-config": {
                phase: {"provider": "my-ollama", "model": "m"}
                for phase in _OPENANT_LLM_PHASES
            },
        },
    }

    def _stage_with_operator_config(self, td: Path) -> tuple[dict, bytes]:
        xdg = td / "xdg"
        cfg = xdg / "openant" / "config.json"
        cfg.parent.mkdir(parents=True)
        cfg.write_text(json.dumps(self._FOREIGN, indent=2))
        before = cfg.read_bytes()
        out_dir = td / "out"
        out_dir.mkdir()
        with patch.dict(os.environ, {"XDG_CONFIG_HOME": str(xdg)}):
            _stage_llm_config(out_dir, "opus")
        self.assertEqual(cfg.read_bytes(), before,
                         "operator config.json was mutated")
        return _staged_config(out_dir), before

    def test_foreign_profile_and_providers_survive(self):
        with tempfile.TemporaryDirectory() as td:
            staged, _ = self._stage_with_operator_config(Path(td))
            self.assertEqual(staged["llm_configs"]["my-config"],
                             self._FOREIGN["llm_configs"]["my-config"])
            self.assertEqual(staged["llm_providers"],
                             self._FOREIGN["llm_providers"])
            self.assertEqual(staged["default_llm"], "my-config")
            self.assertIn("raptor-opus", staged["llm_configs"])

    def test_staged_copy_is_private(self):
        """The staged copy can carry operator api_keys — 0600 file in a
        0700 directory."""
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            self._stage_with_operator_config(base)
            xdg_home = base / "out" / _XDG_STAGE_DIRNAME
            cfg = xdg_home / "openant" / "config.json"
            self.assertEqual(os.stat(xdg_home).st_mode & 0o777, 0o700)
            self.assertEqual(os.stat(cfg).st_mode & 0o777, 0o600)

    def test_malformed_operator_config_staged_fresh(self):
        """A malformed operator file would hard-error the upstream scan;
        staging proceeds with a fresh raptor-only config (warned)."""
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            xdg = base / "xdg"
            cfg = xdg / "openant" / "config.json"
            cfg.parent.mkdir(parents=True)
            cfg.write_text("[not, an, object]")
            out_dir = base / "out"
            out_dir.mkdir()
            with patch.dict(os.environ, {"XDG_CONFIG_HOME": str(xdg)}):
                _stage_llm_config(out_dir, "sonnet")
            staged = _staged_config(out_dir)
            self.assertIn("raptor-sonnet", staged["llm_configs"])

    def test_restaging_is_idempotent(self):
        """A second stage into the same out_dir (retry, agentic re-run)
        overwrites only the RAPTOR profile — atomic replace, no
        accumulation."""
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            out_dir = base / "out"
            out_dir.mkdir()
            with patch.dict(os.environ,
                            {"XDG_CONFIG_HOME": str(base / "xdg")}):
                _stage_llm_config(out_dir, "sonnet")
                _stage_llm_config(out_dir, "sonnet")
            staged = _staged_config(out_dir)
            self.assertEqual(list(staged["llm_configs"]), ["raptor-sonnet"])


class TestSubprocessEnvPointsAtStagedConfig(unittest.TestCase):
    """The sandbox invocation's env carries XDG_CONFIG_HOME → the
    staged directory (otherwise the child resolves the operator's real
    config and the profile named on argv does not exist — a hard
    ConfigError upstream)."""

    def test_run_subprocess_sets_xdg_config_home(self):
        from packages.openant import scanner

        captured = {}

        def fake_sandbox_run(cmd, **kwargs):
            captured["env"] = kwargs.get("env")
            captured["cmd"] = cmd
            raise RuntimeError("stop after capture")

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            core = _make_fake_core(base)
            out_dir = base / "out"
            out_dir.mkdir()
            config = OpenAntConfig(core_path=core, model="sonnet")
            with patch.dict(os.environ,
                            {"XDG_CONFIG_HOME": str(base / "xdg")}), \
                 patch("core.sandbox.context.run", fake_sandbox_run):
                result = scanner._run_subprocess(base, out_dir, config)
            self.assertTrue(result["skipped"])
            self.assertEqual(captured["env"]["XDG_CONFIG_HOME"],
                             str(out_dir / _XDG_STAGE_DIRNAME))
            self.assertIn("--llm-config", captured["cmd"])


if __name__ == "__main__":
    unittest.main()
