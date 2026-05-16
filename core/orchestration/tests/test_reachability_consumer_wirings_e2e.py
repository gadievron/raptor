"""End-to-end test for reachability consumer wirings.

Exercises the full integration: a synthetic project tree, the
/agentic prepass building an inventory, then all three consumers
(codeql / /validate / /agentic enrichment) acting on the SAME
inventory + checklist data without rebuilds.

Pure-Python — no LLM calls, no real scanner subprocess. The
expensive scanner stages are mocked; the reachability decisions
that drive consumer behaviour are real.

Architecture exercised:

  1. Project tree: ``src/live.py`` (function called from main),
     ``src/dead.py`` (function never called), ``src/main.py``
     (entry).
  2. ``run_reachability_prepass`` builds inventory, marks the
     dead function priority=low in the checklist on disk.
  3. Codeql analyzer constructed with ``reachability_inventory=``
     pointing at the prepass's inventory. Analyzer's
     ``_check_reachability`` returns "not_called" for findings
     in the dead function and "called" for findings in the live
     one — WITHOUT rebuilding the inventory.
  4. /validate's ``demote_unreachable_paths`` invoked with the
     SAME inventory (via ``inventory=`` kwarg). Attack paths
     anchored to dead-code findings get proximity clamped and
     blockers appended.
  5. The /agentic checklist's priority markers are visible in
     the on-disk JSON (the agentic LLM analysis prompt would
     read these).

Verifies:

  * Prepass builds + persists priority markers to checklist.
  * In-process inventory sharing actually works (no rebuilds in
    sibling consumers when DI'd).
  * Codeql short-circuits before the dataflow validator runs.
  * /validate demotes the right paths.
  * All three consumers' verdicts are CONSISTENT for the same
    function (synthetic project shape verifies the resolver's
    qualified-name construction matches).
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock



_PROJECT = {
    # Live function called from main via cross-file import.
    "src/live.py": (
        "def vulnerable_handler(query):\n"
        "    cursor.execute(query)\n"           # the 'sink' — line 2
    ),
    # Dead function — defined but never called.
    "src/dead.py": (
        "def unused_handler(query):\n"
        "    cursor.execute(query)\n"           # the 'sink' — line 2
    ),
    # main() lives in its own file; calls live via import.
    "src/main.py": (
        "from src.live import vulnerable_handler\n"
        "def main():\n"
        "    vulnerable_handler('SELECT 1')\n"
    ),
    # entry.py imports + calls main(). The resolver tracks
    # cross-file calls via imports, so this anchors main as
    # CALLED. Without this file, main would itself look dead
    # (its only same-file caller is module-level, not via an
    # import binding).
    "src/entry.py": (
        "from src.main import main\n"
        "main()\n"
    ),
}


def _write_project(tmp_path: Path) -> Path:
    for rel, contents in _PROJECT.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(contents)
    return tmp_path


def _write_agentic_checklist(out_dir: Path) -> Path:
    """Build a minimal agentic checklist mirroring what
    ``libexec/raptor-build-checklist`` would emit. Function names
    + paths must match the synthetic project so the resolver can
    bind chains."""
    out_dir.mkdir(parents=True, exist_ok=True)
    data = {
        "files": [
            {
                "path": "src/live.py",
                "items": [{
                    "name": "vulnerable_handler",
                    "kind": "function",
                    "line_start": 1,
                    "line_end": 2,
                }],
            },
            {
                "path": "src/dead.py",
                "items": [{
                    "name": "unused_handler",
                    "kind": "function",
                    "line_start": 1,
                    "line_end": 2,
                }],
            },
            {
                "path": "src/main.py",
                "items": [{
                    "name": "main",
                    "kind": "function",
                    "line_start": 2,
                    "line_end": 3,
                }],
            },
            {
                "path": "src/entry.py",
                "items": [],
            },
        ],
    }
    p = out_dir / "checklist.json"
    p.write_text(json.dumps(data))
    return p


def test_full_pipeline_dead_code_deprioritised(tmp_path):
    """End-to-end: prepass marks dead code → codeql skips dead-
    code findings → /validate demotes dead-code attack paths.
    All three consumers produce consistent verdicts for the same
    underlying functions."""
    target = _write_project(tmp_path)
    agentic_out = tmp_path / "agentic-out"
    _write_agentic_checklist(agentic_out)

    # ----- Stage 1: prepass -----
    from core.orchestration import run_reachability_prepass
    prepass = run_reachability_prepass(target, agentic_out)
    assert prepass.ran is True
    assert prepass.marked_count == 1, (
        "expected the dead function to be marked priority=low; "
        f"got {prepass.marked_count}"
    )
    assert prepass.inventory is not None

    # The on-disk checklist now carries the priority marker.
    saved = json.loads((agentic_out / "checklist.json").read_text())
    funcs_by_path = {
        f["path"]: {it["name"]: it for it in f["items"]}
        for f in saved["files"]
    }
    assert (
        funcs_by_path["src/dead.py"]["unused_handler"]["priority"]
        == "low"
    )
    assert (
        funcs_by_path["src/dead.py"]["unused_handler"]
        ["priority_reason"] == "reachability:not_called"
    )
    assert "priority" not in funcs_by_path["src/live.py"][
        "vulnerable_handler"
    ]

    # ----- Stage 2: codeql consumer with shared inventory -----
    from packages.codeql.autonomous_analyzer import (
        AutonomousCodeQLAnalyzer,
        CodeQLFinding,
    )

    # Construct analyzer with the prepass's inventory — no rebuild.
    analyzer = AutonomousCodeQLAnalyzer(
        llm_client=MagicMock(),
        exploit_validator=MagicMock(),
        reachability_inventory=prepass.inventory,
    )
    # Verify the analyzer is using the shared inventory, not a
    # rebuild.
    assert analyzer._reachability_inventory is prepass.inventory

    dead_finding = CodeQLFinding(
        rule_id="py/sql-injection",
        rule_name="SQL injection",
        message="Tainted data flows to a SQL query",
        level="error",
        file_path="src/dead.py",
        start_line=2,
        end_line=2,
        snippet="cursor.execute(query)",
    )
    live_finding = CodeQLFinding(
        rule_id="py/sql-injection",
        rule_name="SQL injection",
        message="Tainted data flows to a SQL query",
        level="error",
        file_path="src/live.py",
        start_line=2,
        end_line=2,
        snippet="cursor.execute(query)",
    )

    assert analyzer._check_reachability(dead_finding, target) == "not_called"
    assert analyzer._check_reachability(live_finding, target) == "called"

    # Stage-2b: short-circuit observable in analyze_finding_autonomous.
    analyzer.dataflow_validator = MagicMock()
    analyzer.dataflow_validator.validate_finding.side_effect = (
        AssertionError(
            "dataflow validator should not have been invoked for "
            "dead-code finding"
        )
    )
    # Stub parse_sarif_finding so we don't need real SARIF.
    analyzer.parse_sarif_finding = lambda r, run: dead_finding

    result = analyzer.analyze_finding_autonomous(
        sarif_result={}, sarif_run={},
        repo_path=target, out_dir=tmp_path / "codeql-out",
    )
    assert result.skipped_reason == "reachability_not_called"
    assert result.reachability_verdict == "not_called"

    # ----- Stage 3: /validate consumer with shared inventory -----
    from packages.exploitability_validation.reachability import (
        demote_unreachable_paths,
    )

    findings = [
        {
            "id": "f-dead",
            "file_path": "src/dead.py",
            "start_line": 2,
        },
        {
            "id": "f-live",
            "file_path": "src/live.py",
            "start_line": 2,
        },
    ]
    attack_paths = [
        {
            "id": "p-dead",
            "finding_id": "f-dead",
            "proximity": 8,
            "blockers": [],
        },
        {
            "id": "p-live",
            "finding_id": "f-live",
            "proximity": 7,
            "blockers": [],
        },
    ]

    demoted = demote_unreachable_paths(
        attack_paths, findings, target,
        inventory=prepass.inventory,
    )
    assert demoted == 1

    by_id = {p["id"]: p for p in attack_paths}
    # Dead path demoted.
    assert by_id["p-dead"]["proximity"] == 1
    assert any(
        "reachability:not_called" in b
        for b in by_id["p-dead"]["blockers"]
    )
    # Live path untouched.
    assert by_id["p-live"]["proximity"] == 7
    assert by_id["p-live"]["blockers"] == []


def test_inventory_genuinely_shared_across_consumers(tmp_path):
    """The same inventory dict instance threads through all three
    consumers. None of them rebuilds — the test would catch a
    regression that accidentally lazy-builds despite a DI'd
    inventory."""
    target = _write_project(tmp_path)
    agentic_out = tmp_path / "agentic-out"
    _write_agentic_checklist(agentic_out)

    from core.orchestration import run_reachability_prepass
    prepass = run_reachability_prepass(target, agentic_out)
    inv = prepass.inventory
    assert inv is not None

    # Identity check — the SAME dict instance flows through.
    from packages.codeql.autonomous_analyzer import (
        AutonomousCodeQLAnalyzer,
    )
    analyzer = AutonomousCodeQLAnalyzer(
        llm_client=MagicMock(),
        exploit_validator=MagicMock(),
        reachability_inventory=inv,
    )
    assert analyzer._reachability_inventory is inv

    # Mutate the prepass inventory; verify the codeql side sees
    # the mutation (proves identity-sharing, not just
    # equality-sharing).
    sentinel = {"e2e_test": "tracked"}
    inv["__sentinel__"] = sentinel
    assert (
        analyzer._reachability_inventory.get("__sentinel__")
        is sentinel
    )


def test_codeql_loads_checklist_from_disk_when_no_inventory(tmp_path):
    """Cross-process scenario: subprocess analyzer doesn't have
    the parent's in-memory inventory but DOES have the parent's
    on-disk checklist. ``reachability_checklist_path=`` lets it
    skip the rebuild."""
    target = _write_project(tmp_path)

    # The /agentic prepass would have written a checklist with
    # call-graph data via build_inventory. Simulate by running
    # build_inventory ourselves.
    from core.inventory.builder import build_inventory
    shared_dir = tmp_path / "shared"
    build_inventory(str(target), str(shared_dir))
    checklist_path = shared_dir / "checklist.json"
    assert checklist_path.exists()

    from packages.codeql.autonomous_analyzer import (
        AutonomousCodeQLAnalyzer,
        CodeQLFinding,
    )

    analyzer = AutonomousCodeQLAnalyzer(
        llm_client=MagicMock(),
        exploit_validator=MagicMock(),
        reachability_checklist_path=checklist_path,
    )

    dead_finding = CodeQLFinding(
        rule_id="py/sql-injection",
        rule_name="SQL injection",
        message="x", level="error",
        file_path="src/dead.py",
        start_line=2, end_line=2,
        snippet="cursor.execute(query)",
    )
    # Verdict from the loaded checklist.
    assert (
        analyzer._check_reachability(dead_finding, target)
        == "not_called"
    )
    # Inventory cache was populated from the disk read, NOT
    # rebuilt.
    assert isinstance(analyzer._reachability_inventory, dict)
    assert "files" in analyzer._reachability_inventory


def test_uncertain_dispatch_blocks_demotion_consistently(tmp_path):
    """Across all three consumers, an UNCERTAIN verdict (file
    uses dynamic dispatch) does NOT trigger any demotion.
    Conservative: don't trust NOT_CALLED claims when the static
    analysis has gaps."""
    # Project where dead.py's function WOULD be NOT_CALLED, but
    # main.py uses getattr to dispatch — resolver returns
    # UNCERTAIN. main.py still calls vulnerable_handler so live
    # code stays live (and main() at module level so main itself
    # is callable).
    files = dict(_PROJECT)
    files["src/main.py"] = (
        "from src import dead\n"
        "from src.live import vulnerable_handler\n"
        "def main():\n"
        "    fn = getattr(dead, 'unused_handler')\n"
        "    fn('x')\n"
        "    vulnerable_handler('SELECT 1')\n"
        "main()\n"
    )
    target = tmp_path
    for rel, contents in files.items():
        p = target / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(contents)

    agentic_out = tmp_path / "agentic-out"
    _write_agentic_checklist(agentic_out)

    from core.orchestration import run_reachability_prepass
    prepass = run_reachability_prepass(target, agentic_out)
    # Dynamic dispatch → uncertain → no functions marked.
    assert prepass.marked_count == 0

    from packages.codeql.autonomous_analyzer import (
        AutonomousCodeQLAnalyzer, CodeQLFinding,
    )
    analyzer = AutonomousCodeQLAnalyzer(
        llm_client=MagicMock(),
        exploit_validator=MagicMock(),
        reachability_inventory=prepass.inventory,
    )
    dead_finding = CodeQLFinding(
        rule_id="x", rule_name="x", message="x", level="error",
        file_path="src/dead.py", start_line=2, end_line=2,
        snippet="x",
    )
    # Codeql's prefilter returns "uncertain" — analyzer DOES NOT
    # short-circuit.
    assert (
        analyzer._check_reachability(dead_finding, target)
        == "uncertain"
    )

    from packages.exploitability_validation.reachability import (
        demote_unreachable_paths,
    )
    findings = [{
        "id": "f-dead",
        "file_path": "src/dead.py",
        "start_line": 2,
    }]
    attack_paths = [{
        "id": "p-dead",
        "finding_id": "f-dead",
        "proximity": 8,
    }]
    demoted = demote_unreachable_paths(
        attack_paths, findings, target,
        inventory=prepass.inventory,
    )
    assert demoted == 0
    # Path proximity untouched.
    assert attack_paths[0]["proximity"] == 8
