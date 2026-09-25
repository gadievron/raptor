"""Contract test: the coverage overlay's error screen mirrors the
pinned core's ``checkpoint.analyze_result_is_error`` EXACTLY.

The overlay must not invent its own "this unit errored" semantics —
the pinned predicate is the upstream truth for which analyze rows are
retried (never adopted as complete), and a divergence either mints
analysed coverage for malformed replies (suppression direction) or
drops genuinely analysed units from the overlay (refusal direction).
This test executes the PINNED checkout's own function (its venv
Python, its PYTHONPATH) over an adversarial row battery and equality-
compares against the mirror, and pins the mirrored Stage-1 verdict
vocabulary to the checkout's constant.

Hermetic: skipped when no clean pinned checkout with a working venv
is discoverable (CI runners), same posture as
test_pinned_cli_contract.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[3]))  # repo root

from packages.openant.coverage import (
    _PINNED_STAGE1_VERDICTS,
    _analyze_result_is_error,
)
from packages.openant.scanner import _find_venv_python, checkout_provenance

_DRIVER = """\
import json
import sys

rows = json.load(open(sys.argv[1]))
from core.checkpoint import analyze_result_is_error
from core.verdict_taxonomy import STAGE1_VERDICTS
print(json.dumps({
    "verdicts": [bool(analyze_result_is_error(r)) for r in rows],
    "stage1_verdicts": sorted(STAGE1_VERDICTS),
}))
"""

#: Adversarial row battery — every arm of the predicate, both
#: directions, plus shapes only the vocabulary arm distinguishes.
_BATTERY: list = [
    None,                                        # non-dict
    "vulnerable",                                # non-dict
    ["VULNERABLE"],                              # non-dict
    {},                                          # neither key
    {"verdict": None},                           # null verdict (#324)
    {"verdict": "", "finding": ""},              # empty strings
    {"verdict": "   "},                          # whitespace-only
    {"verdict": "ERROR"},                        # explicit error
    {"finding": "error"},                        # explicit error
    {"finding": "Error"},                        # case-SENSITIVE arm
    {"verdict": "error"},                        # lowercase verdict
    {"verdict": "SAY WHAT"},                     # unrecognized (#427)
    {"verdict": "vulnerable"},                   # lowercase in-vocab
    {"verdict": "VULNERABLE"},
    {"verdict": "SAFE"},
    {"verdict": "PROTECTED"},
    {"verdict": "BYPASSABLE"},
    {"verdict": "INCONCLUSIVE"},
    {"verdict": "INSUFFICIENT_CONTEXT"},
    {"finding": "safe"},                         # finding-only
    {"finding": "none"},                         # effective finding,
                                                 # NOT vocab-screened
    {"verdict": "ERROR", "finding": "vulnerable"},  # verdict-first
    {"verdict": "VULNERABLE", "finding": "error"},  # finding arm wins
    {"verdict": 7},                              # non-string verdict
    {"verdict": True, "finding": 0},             # non-string both
]


def _find_pinned_core() -> Path | None:
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
            continue
        if checkout_provenance(cand)["matches"] is not True:
            continue
        return cand
    return None


_PINNED_CORE = _find_pinned_core()


@unittest.skipIf(_PINNED_CORE is None,
                 "no pinned openant-core checkout with a venv on this host")
class TestErrorPredicatePinnedContract(unittest.TestCase):

    def test_mirror_matches_pinned_predicate_on_battery(self):
        core = _PINNED_CORE
        with tempfile.TemporaryDirectory() as td:
            rows_path = Path(td) / "rows.json"
            rows_path.write_text(json.dumps(_BATTERY), encoding="utf-8")
            env = dict(os.environ)
            env["PYTHONPATH"] = str(core)
            proc = subprocess.run(
                [_find_venv_python(core), "-c", _DRIVER, str(rows_path)],
                capture_output=True, text=True, timeout=120,
                cwd=str(core), env=env,
            )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        pinned = json.loads(proc.stdout)
        mirror = [bool(_analyze_result_is_error(r)) for r in _BATTERY]
        self.assertEqual(
            mirror, pinned["verdicts"],
            "overlay error screen diverges from the pinned "
            "analyze_result_is_error on: " + ", ".join(
                repr(_BATTERY[i]) for i in range(len(_BATTERY))
                if mirror[i] != pinned["verdicts"][i]))

    def test_mirrored_vocabulary_matches_pinned_constant(self):
        core = _PINNED_CORE
        with tempfile.TemporaryDirectory() as td:
            rows_path = Path(td) / "rows.json"
            rows_path.write_text("[]", encoding="utf-8")
            env = dict(os.environ)
            env["PYTHONPATH"] = str(core)
            proc = subprocess.run(
                [_find_venv_python(core), "-c", _DRIVER, str(rows_path)],
                capture_output=True, text=True, timeout=120,
                cwd=str(core), env=env,
            )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        pinned = json.loads(proc.stdout)
        self.assertEqual(sorted(_PINNED_STAGE1_VERDICTS),
                         pinned["stage1_verdicts"])


if __name__ == "__main__":
    unittest.main()
