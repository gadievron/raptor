"""Pin/flag drift guard: RAPTOR's argv + staged llm-config vs the
REAL pinned OpenAnt CLI.

The /openant lane once shipped ``--model <name>`` to an upstream whose
CLI had replaced it with ``--llm-config`` — an unconditional argparse
error that no operator surface could route around, discovered only at
run time. This test closes the CLASS: it builds the exact argv
``_build_command`` produces and the exact config ``_stage_llm_config``
stages, then validates BOTH against the pinned checkout's own parser
and config machinery (executed with the checkout's venv Python, so the
surface under test is the one the scan subprocess really runs). It
also pins RAPTOR's mirrored constants (model-id map, phase set) to the
checkout's — advancing OPENANT_PINNED_COMMIT with a changed CLI or
model catalog fails here, in CI, before any paid run.

Hermetic: skipped when no clean pinned checkout with a working venv is
discoverable on the host (CI runners), and when the discoverable
checkout is NOT at the pin (a drifted clone cannot witness the pin
contract).
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[3]))  # repo root

from packages.openant.config import OPENANT_PINNED_COMMIT, OpenAntConfig
from packages.openant.scanner import (
    _OPENANT_LLM_PHASES,
    _OPENANT_MODEL_IDS,
    _XDG_STAGE_DIRNAME,
    _build_command,
    _find_venv_python,
    _llm_profile_name,
    _stage_llm_config,
    checkout_provenance,
)

# Executed by the pinned checkout's OWN venv Python with
# PYTHONPATH=<core> and cwd=<core>: parses RAPTOR's argv with the
# pinned build_parser(), validates the staged config through the
# pinned parse_config()/resolve_llm_config(), and reports the pinned
# constants for the mirror comparison.
_DRIVER = """\
import json
import sys

blob = json.load(open(sys.argv[1]))
results = {}

from openant.cli import build_parser
parser = build_parser()
try:
    ns = parser.parse_args(blob["argv"])
    results["argv_ok"] = True
    results["llm_config"] = getattr(ns, "llm_config", None)
except SystemExit:
    results["argv_ok"] = False

from utilities import model_config
from utilities.llm.config import PHASES, parse_config
from utilities.llm.registry import resolve_llm_config

results["phases"] = list(PHASES)
results["model_ids"] = {
    "sonnet": model_config.CLAUDE_SONNET,
    "opus": model_config.CLAUDE_OPUS,
}
raw = json.load(open(blob["staged_config"]))
cf = parse_config(raw)
profile = resolve_llm_config(cf, blob["profile"])
results["profile_models"] = {p: profile.phases[p].model for p in PHASES}
results["profile_providers"] = sorted(
    {profile.phases[p].provider for p in PHASES})
print(json.dumps(results))
"""


def _find_pinned_core() -> Path | None:
    """A clean-enough pinned checkout with a working venv, or None.

    Probes the same surfaces the integration documents: $OPENANT_CORE,
    the sibling auto-detect layout, and ~/libs/openant-core.
    """
    candidates = []
    env_core = os.environ.get("OPENANT_CORE")
    if env_core:
        candidates.append(Path(env_core))
    repo_root = Path(__file__).parents[3]
    candidates.append(repo_root.parent / "libs" / "openant-core")
    candidates.append(Path.home() / "libs" / "openant-core")
    for cand in candidates:
        if not (cand / "core" / "scanner.py").exists():
            continue
        if _find_venv_python(cand) == sys.executable:
            continue  # no venv — the pinned deps are not installed
        if checkout_provenance(cand)["matches"] is not True:
            continue  # drifted clone cannot witness the pin contract
        return cand
    return None


_PINNED_CORE = _find_pinned_core()


@unittest.skipIf(_PINNED_CORE is None,
                 "no pinned openant-core checkout with a venv on this host")
class TestPinnedCliContract(unittest.TestCase):

    def _run_driver(self, model: str) -> dict:
        core = _PINNED_CORE
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            out_dir = base / "out"
            out_dir.mkdir()
            repo = base / "repo"
            repo.mkdir()
            config = OpenAntConfig(core_path=core, model=model)
            cmd = _build_command(repo, out_dir, config)
            # argv exactly as the subprocess receives it, minus the
            # interpreter prelude (python -m openant).
            self.assertEqual(cmd[1:3], ["-m", "openant"])
            with patch.dict(os.environ,
                            {"XDG_CONFIG_HOME": str(base / "xdg")}):
                _stage_llm_config(out_dir, model)
            staged = out_dir / _XDG_STAGE_DIRNAME / "openant" / "config.json"
            blob = base / "blob.json"
            blob.write_text(json.dumps({
                "argv": cmd[3:],
                "staged_config": str(staged),
                "profile": _llm_profile_name(model),
            }))
            driver = base / "driver.py"
            driver.write_text(_DRIVER)
            env = {
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "HOME": os.environ.get("HOME", str(base)),
                "LANG": os.environ.get("LANG", "C.UTF-8"),
                "PYTHONPATH": str(core),
            }
            proc = subprocess.run(
                [_find_venv_python(core), str(driver), str(blob)],
                capture_output=True, text=True, timeout=300,
                cwd=str(core), env=env, check=False,
            )
            self.assertEqual(
                proc.returncode, 0,
                f"driver failed against pinned CLI at "
                f"{OPENANT_PINNED_COMMIT[:12]}:\n{proc.stderr[-2000:]}")
            return json.loads(proc.stdout)

    def test_argv_parses_against_pinned_cli(self):
        for model in ("sonnet", "opus"):
            results = self._run_driver(model)
            self.assertTrue(
                results["argv_ok"],
                "the pinned CLI rejected _build_command's argv — "
                "flag drift (the --model regression class)")
            self.assertEqual(results["llm_config"],
                             _llm_profile_name(model))

    def test_mirrored_constants_match_pinned_tree(self):
        results = self._run_driver("sonnet")
        self.assertEqual(set(results["phases"]), set(_OPENANT_LLM_PHASES),
                         "phase set drifted from the pinned checkout")
        self.assertEqual(results["model_ids"], _OPENANT_MODEL_IDS,
                         "model-id map drifted from the pinned checkout")

    def test_staged_profile_resolves_through_pinned_machinery(self):
        for model in ("sonnet", "opus"):
            results = self._run_driver(model)
            self.assertEqual(results["profile_providers"], ["anthropic"])
            for phase, model_id in results["profile_models"].items():
                self.assertEqual(
                    model_id, _OPENANT_MODEL_IDS[model],
                    f"phase {phase} does not bind the selected model")


if __name__ == "__main__":
    unittest.main()
