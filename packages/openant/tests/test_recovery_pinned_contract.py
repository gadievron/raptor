"""Pin drift guard: checkpoint-verdict recovery vs the REAL pinned core.

Recovery re-derives the pinned reporter's caller/callee dedup and reads
the pinned checkpoint format — both are upstream internals that a pin
bump can change silently, which would make recovery quietly recover
nothing (or the wrong population). Same pattern as
``test_pinned_cli_contract``: a driver executed by the pinned checkout's
own venv Python runs the checkout's REAL ``build_pipeline_output`` /
``StepCheckpoint`` over a synthetic fixture, and the host side asserts
that RAPTOR's re-derivation and field reads agree with what the pinned
code actually produced. Advancing OPENANT_PINNED_COMMIT with a changed
dedup rule, artifact schema, or checkpoint layout fails here, in CI,
before any paid run.

Hermetic: skipped when no clean pinned checkout with a working venv is
discoverable on the host.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[3]))  # repo root

from packages.openant.config import OPENANT_PINNED_COMMIT
from packages.openant.recovery import (
    RECOVERED_TIER,
    _RESERVED_CHECKPOINT_FILES,
    recover_dropped_verdicts,
)

from .test_pinned_cli_contract import _PINNED_CORE
from packages.openant.scanner import _find_venv_python

# Executed by the pinned venv Python (PYTHONPATH=<core>, cwd=<core>).
# Builds pipeline_output.json from the synthetic results/call-graph via
# the pinned reporter, saves one unit through the pinned StepCheckpoint,
# and reports the constants recovery depends on.
_DRIVER = """\
import json
import os
import sys

blob = json.load(open(sys.argv[1]))
scan_dir = blob["scan_dir"]
results = {}

from core.reporter import build_pipeline_output
out_path, count = build_pipeline_output(
    results_path=os.path.join(scan_dir, "results.json"),
    output_path=os.path.join(scan_dir, "pipeline_output.json"),
)
results["findings_count"] = count
results["pipeline_output"] = json.load(open(out_path))

from core.backend_identity import FINGERPRINT_FILE
from core.checkpoint import SUMMARY_FILE, StepCheckpoint, auto_checkpoint_dir
results["reserved_files"] = sorted([SUMMARY_FILE, FINGERPRINT_FILE])
results["auto_dir"] = os.path.basename(
    auto_checkpoint_dir(scan_dir, "analyze"))

ckpt = StepCheckpoint("analyze", scan_dir)
ckpt.save(blob["unit_id"], {
    "result": blob["unit_result"],
    "route_key": blob["unit_id"],
    "code_for_route": "code()",
})
saved = None
for name in os.listdir(ckpt.dir):
    if name.endswith(".json") and name not in results["reserved_files"]:
        saved = json.load(open(os.path.join(ckpt.dir, name)))
results["saved_checkpoint"] = saved

from core.verdict_taxonomy import FINDING_VERDICT_ORDER
results["finding_verdicts"] = list(FINDING_VERDICT_ORDER)

print(json.dumps(results))
"""


def _row(route_key: str, verdict: str = "vulnerable", cwe: int = 89) -> dict:
    return {
        "unit_id": route_key,
        "route_key": route_key,
        "finding": verdict,
        "verdict": verdict.upper(),
        "cwe_id": cwe,
        "cwe_name": "SQL Injection",
        "reasoning": "input reaches the raw query",
        "confidence": 0.9,
    }


# One fixture exercising every arm of the dedup rule: a 3-deep same-CWE
# chain (transitive collapse to the top), a multi-caller callee (kept),
# a different-CWE callee (kept), and a safe unit (never a finding).
TOP = "app/api.py:handle"
MID = "app/db.py:query"
LEAF = "app/db.py:exec_raw"
SHARED = "app/util.py:shared_helper"
OTHER_CWE = "app/fs.py:read_path"

ROWS = [
    _row(TOP), _row(MID), _row(LEAF),
    _row(SHARED),
    _row(OTHER_CWE, cwe=22),
    _row("app/ok.py:fine", verdict="safe"),
]
REVERSE_CG = {
    MID: [TOP],
    LEAF: [MID],
    SHARED: [TOP, MID],       # two callers — never collapsed
    OTHER_CWE: [TOP],         # CWE differs — never collapsed
}
EXPECTED_DROPPED = {MID, LEAF}


@unittest.skipIf(_PINNED_CORE is None,
                 "no pinned openant-core checkout with a venv on this host")
class TestRecoveryPinnedContract(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls._td = tempfile.TemporaryDirectory()
        base = Path(cls._td.name)
        cls.scan_dir = base / "scan"
        cls.scan_dir.mkdir()
        (cls.scan_dir / "results.json").write_text(json.dumps({
            "results": ROWS,
            "code_by_route": {rk: "code()" for rk in (TOP, MID, LEAF)},
            "metrics": {"total": len(ROWS)},
        }), encoding="utf-8")
        (cls.scan_dir / "call_graph.json").write_text(json.dumps({
            "reverse_call_graph": REVERSE_CG,
        }), encoding="utf-8")
        blob = base / "blob.json"
        blob.write_text(json.dumps({
            "scan_dir": str(cls.scan_dir),
            "unit_id": MID,
            "unit_result": _row(MID),
        }), encoding="utf-8")
        driver = base / "driver.py"
        driver.write_text(_DRIVER, encoding="utf-8")
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": os.environ.get("HOME", str(base)),
            "LANG": os.environ.get("LANG", "C.UTF-8"),
            "PYTHONPATH": str(_PINNED_CORE),
        }
        proc = subprocess.run(
            [_find_venv_python(_PINNED_CORE), str(driver), str(blob)],
            capture_output=True, text=True, timeout=300,
            cwd=str(_PINNED_CORE), env=env, check=False,
        )
        if proc.returncode != 0:
            raise AssertionError(
                f"driver failed against pinned core at "
                f"{OPENANT_PINNED_COMMIT[:12]}:\n{proc.stderr[-2000:]}")
        cls.driver_out = json.loads(proc.stdout)

    @classmethod
    def tearDownClass(cls):
        cls._td.cleanup()

    def test_pinned_dedup_drops_exactly_the_rederived_set(self):
        po = self.driver_out["pipeline_output"]
        kept = {
            f"{f['location']['file']}:{f['location']['function']}"
            for f in po["findings"]
        }
        confirmed = {r["route_key"] for r in ROWS
                     if r["finding"] in ("vulnerable", "bypassable")}
        self.assertEqual(confirmed - kept, EXPECTED_DROPPED,
                         "the pinned dedup rule drifted from the "
                         "re-derivation in packages/openant/recovery.py")
        # The aggregate recovery cross-checks against:
        self.assertEqual(po["results"]["deduplicated"],
                         len(EXPECTED_DROPPED))

    def test_recovery_over_pinned_artifacts_recovers_the_dropped_units(self):
        # End-to-end: RAPTOR recovery over the scan dir the PINNED code
        # populated recovers exactly the units the pinned dedup removed,
        # each attributed to the surviving top of its chain.
        recovered = recover_dropped_verdicts(
            self.scan_dir, self.driver_out["pipeline_output"])
        self.assertEqual(
            {r["metadata"]["route_key"] for r in recovered},
            EXPECTED_DROPPED)
        for rec in recovered:
            self.assertEqual(rec["metadata"]["provenance_tier"],
                             RECOVERED_TIER)
            self.assertEqual(rec["metadata"]["deduplicated_into"], TOP)
            self.assertEqual(rec["level"], "note")

    def test_pinned_checkpoint_layout_matches_reader(self):
        # The checkpoint-diff fallback lane's field reads, pinned
        # against what the pinned StepCheckpoint actually writes.
        self.assertEqual(set(self.driver_out["reserved_files"]),
                         _RESERVED_CHECKPOINT_FILES)
        self.assertEqual(self.driver_out["auto_dir"], "analyze_checkpoints")
        saved = self.driver_out["saved_checkpoint"]
        self.assertIsInstance(saved, dict)
        self.assertEqual(saved["id"], MID)
        self.assertEqual(saved["route_key"], MID)
        self.assertEqual(saved["result"]["finding"], "vulnerable")

    def test_pinned_verdict_vocabulary_is_exactly_the_known_set(self):
        # EQUALITY, not subset: an EXTENSION of the pinned vocabulary at
        # a pin bump would silently narrow the checkpoint-diff lane (a
        # new vulnerable-class verdict would never be recovered) — the
        # pin must force re-adjudication of _RECOVERABLE_VERDICTS.
        self.assertEqual(
            tuple(self.driver_out["finding_verdicts"]),
            ("vulnerable", "bypassable", "inconclusive", "protected",
             "safe"),
            "the pinned Stage-1 verdict vocabulary changed — "
            "re-adjudicate recovery._RECOVERABLE_VERDICTS against it")


if __name__ == "__main__":
    unittest.main()
