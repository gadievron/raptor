"""Suppression audit records must land in the run output dir, never the scanned repo."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from packages.codeql.autonomous_analyzer import AutonomousCodeQLAnalyzer


def _make_analyzer() -> AutonomousCodeQLAnalyzer:
    a = AutonomousCodeQLAnalyzer.__new__(AutonomousCodeQLAnalyzer)
    a.logger = __import__("logging").getLogger("test-suppression")
    a._reachability_inventory = {"functions": []}
    a._allow_unreachable = False
    a.parse_sarif_finding = lambda result, run: SimpleNamespace(
        rule_id="cpp/dead-sink", file_path="src/a.c", start_line=3,
    )
    a._check_reachability = lambda finding, repo: "module_aborts"
    a._locate_finding_function = lambda finding, repo: ("src/a.c", "f", 3)
    return a


def test_suppression_record_written_to_out_dir_not_repo(
    tmp_path: Path, monkeypatch,
) -> None:
    """Pre-fix the record fell back to repo_path (self.out_dir never
    existed on the analyzer): the audit trail vanished from the run dir
    AND the tool mutated the untrusted scanned tree."""
    import core.analysis.reach_chokepoint as chokepoint

    monkeypatch.setattr(
        chokepoint, "check_suppress", lambda **kw: {"suppress": True},
    )

    repo = tmp_path / "repo"
    repo.mkdir()
    out = tmp_path / "out"
    out.mkdir()

    analyzer = _make_analyzer()
    result = analyzer.analyze_finding_autonomous(
        sarif_result={}, sarif_run={}, repo_path=repo, out_dir=out,
    )

    assert result.skipped_reason == "reachability_module_aborts"
    assert not (repo / "suppressions.jsonl").exists()
    record_file = out / "suppressions.jsonl"
    assert record_file.exists()
    record = json.loads(record_file.read_text().splitlines()[0])
    assert record["rule_id"] == "cpp/dead-sink"
    assert record["verdict"] == "module_aborts"
