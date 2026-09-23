"""Every SARIF run's results reach analysis, not just ``runs[0]``.

Single-run files are the CodeQL norm, but a multi-run SARIF's
``runs[1:]`` were silently never analysed.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))


def _import_raptor_codeql():
    import raptor_codeql
    return raptor_codeql


class TestAllRunResults:
    def test_all_runs_contribute_in_order(self):
        raptor_codeql = _import_raptor_codeql()
        run_a = {"results": [{"ruleId": "r1"}, {"ruleId": "r2"}]}
        run_b = {"results": [{"ruleId": "r3"}]}
        pairs = raptor_codeql._all_run_results({"runs": [run_a, run_b]})
        assert [r["ruleId"] for _run, r in pairs] == ["r1", "r2", "r3"]
        # Each result stays paired with ITS run — rule metadata
        # resolves against the owning run's driver.
        assert [run is run_a for run, _r in pairs] == [True, True, False]
        assert pairs[2][0] is run_b

    def test_shape_drift_tolerated(self):
        raptor_codeql = _import_raptor_codeql()
        sarif = {"runs": [
            "not a run",
            {"results": [{"ruleId": "r1"}, "not a result"]},
            {},
        ]}
        pairs = raptor_codeql._all_run_results(sarif)
        assert [r["ruleId"] for _run, r in pairs] == ["r1"]
