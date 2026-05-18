"""End-to-end test for the cross-process checklist hand-off.

Pure-Python E2E: synthetic project + real ``build_inventory`` for
the parent checklist + real ``ValidationOrchestrator._run_stage_0``
for reuse + real demotion. The agentic launcher's subprocess
dispatch is mocked but the pointer write is exercised directly.

Verifies:

  1. The agentic launcher writes a structurally-valid pointer
     into validate_dir before the subprocess kicks off.
  2. The pointer's fields match what the orchestrator expects
     (path / target / root).
  3. The orchestrator's Stage 0 reuses the pointed-at checklist
     instead of calling ``build_inventory`` (verified by
     ``patch`` raising on any build_inventory call).
  4. Stage B's demotion call uses the reused inventory.
  5. The full chain produces consistent verdicts for live + dead
     functions.

Pre-existing test-isolation flakes in the broader suite reproduce
without these changes — this test runs cleanly on its own.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch


def _write_synthetic_project(tmp_path: Path) -> Path:
    """Project with both live (called from main) and dead
    (defined but unused) functions."""
    files = {
        "src/live.py": (
            "def live_fn(query):\n"
            "    cursor.execute(query)\n"
        ),
        "src/dead.py": (
            "def dead_fn(query):\n"
            "    cursor.execute(query)\n"
        ),
        "src/main.py": (
            "from src.live import live_fn\n"
            "def main():\n"
            "    live_fn('SELECT 1')\n"
        ),
        "src/entry.py": (
            "from src.main import main\n"
            "main()\n"
        ),
    }
    for rel, contents in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(contents)
    return tmp_path


# ---------------------------------------------------------------------------
# Launcher-side: pointer write
# ---------------------------------------------------------------------------


def test_agentic_launcher_writes_pointer_into_validate_dir(tmp_path):
    """``_run_validate_postpass_unsafe`` writes the pointer file
    with the expected fields before kicking off the subprocess.
    Mocks subprocess and lifecycle; exercises the real pointer-
    write path."""
    target = _write_synthetic_project(tmp_path)
    agentic_out = tmp_path / "agentic-out"
    agentic_out.mkdir()
    # Build a checklist at agentic_out/checklist.json so the
    # launcher has something to point at.
    from core.inventory import build_inventory
    build_inventory(str(target), str(agentic_out))
    assert (agentic_out / "checklist.json").is_file()

    # Write a minimal valid analysis report so selection finds
    # something. The selector reads ``results`` (not
    # ``findings``) per the report's canonical schema.
    analysis_report = agentic_out / "analysis-report.json"
    analysis_report.write_text(json.dumps({
        "results": [{
            "id": "f1",
            "vuln_type": "sql-injection",
            "is_exploitable": True,
            "confidence": "high",
            "file": "src/dead.py",
            "line": 2,
        }],
    }))

    # Mock the subprocess so we observe what's in validate_dir
    # at dispatch time. The mock's side_effect inspects the dir
    # and stores the pointer contents for the test to assert on.
    captured = {}

    def _capture_dispatch(*args, **kwargs):
        # The validate_dir is somewhere under raptor's out/. Find
        # it via the captured target/output args. The sandbox_run
        # call has output= pointing at validate_dir.
        output_path = Path(kwargs.get("output", ""))
        pointer_path = output_path / "parent-checklist-pointer.json"
        if pointer_path.is_file():
            captured["pointer"] = json.loads(pointer_path.read_text())
            captured["validate_dir"] = output_path
        # Return a fake successful CompletedProcess.
        rc_mock = MagicMock()
        rc_mock.returncode = 0
        return rc_mock

    # Mock just enough to bypass the LLM dispatch; the rest of
    # the flow stays real. Patch ``shutil.which`` so claude
    # appears to exist.
    from core.orchestration import agentic_passes
    with patch("core.orchestration.agentic_passes.run_untrusted_networked",
               side_effect=_capture_dispatch), \
         patch("core.orchestration.agentic_passes.shutil.which",
               return_value="/usr/bin/fake-claude"), \
         patch("core.security.rule_of_two."
               "require_interactive_for_agentic_pass"):
        result = agentic_passes.run_validate_postpass(
            target=target,
            agentic_out_dir=agentic_out,
            analysis_report=analysis_report,
        )

    if "pointer" not in captured:
        # Test relies on the launcher reaching the dispatch
        # stage. If lifecycle setup or any earlier check
        # short-circuited, surface that for diagnostic.
        raise AssertionError(
            "subprocess was never dispatched — launcher "
            "short-circuited before pointer-write. result="
            f"{result}"
        )

    # Pointer carries all three documented fields.
    pointer = captured["pointer"]
    assert "checklist_path" in pointer
    assert "expected_target_path" in pointer
    assert "expected_root_dir" in pointer
    # And they match what the orchestrator expects.
    assert (
        Path(pointer["checklist_path"])
        == (agentic_out / "checklist.json").resolve()
    )
    assert (
        Path(pointer["expected_target_path"]).resolve()
        == target.resolve()
    )
    assert (
        Path(pointer["expected_root_dir"]).resolve()
        == agentic_out.resolve()
    )


# ---------------------------------------------------------------------------
# E2E: launcher pointer write → orchestrator Stage 0 reuse → Stage B demote
# ---------------------------------------------------------------------------


def test_e2e_pointer_drives_full_reuse_and_demotion(tmp_path):
    """End-to-end: pointer written by the launcher's logic
    drives /validate's Stage 0 to reuse, Stage B's demotion to
    use the reused inventory, and produces the right verdict.

    No subprocess hop — we wire the launcher's pointer-write
    output directly into the orchestrator's input. This
    exercises the data contract between the two halves on the
    same inventory."""
    target = _write_synthetic_project(tmp_path)

    # Stage 1: simulate the launcher's pointer write.
    agentic_out = tmp_path / "agentic-out"
    agentic_out.mkdir()
    from core.inventory import build_inventory
    build_inventory(str(target), str(agentic_out))
    parent_checklist = agentic_out / "checklist.json"

    validate_workdir = tmp_path / "validate-out"
    validate_workdir.mkdir()
    pointer_path = validate_workdir / "parent-checklist-pointer.json"
    pointer_path.write_text(json.dumps({
        "checklist_path": str(parent_checklist.resolve()),
        "expected_target_path": str(target),
        "expected_root_dir": str(agentic_out.resolve()),
    }))

    # Stage 2: orchestrator's Stage 0 — must reuse, not build.
    from packages.exploitability_validation.orchestrator import (
        PipelineConfig,
        ValidationOrchestrator,
    )
    config = PipelineConfig(
        target_path=str(target),
        workdir=str(validate_workdir),
        vuln_type="sql-injection",
    )
    orchestrator = ValidationOrchestrator(config)

    with patch(
        "core.inventory.build_inventory",
        side_effect=AssertionError(
            "build_inventory must not be called — pointer should "
            "have driven reuse"
        ),
    ):
        orchestrator._run_stage_0()

    # The reused checklist persisted to validate's own dir.
    assert (validate_workdir / "checklist.json").is_file()
    assert orchestrator.state.checklist is not None
    file_paths = {
        f["path"] for f in orchestrator.state.checklist["files"]
    }
    assert "src/dead.py" in file_paths
    assert "src/live.py" in file_paths

    # Stage 3: Stage B reuses the loaded inventory for demotion.
    # Set up minimum state for Stage B.
    orchestrator.state.findings = {
        "stage": "A",
        "findings": [
            {
                "id": "f-dead",
                "status": "not_disproven",
                "vuln_type": "sql-injection",
                "file_path": "src/dead.py",
                "start_line": 2,
            },
            {
                "id": "f-live",
                "status": "not_disproven",
                "vuln_type": "sql-injection",
                "file_path": "src/live.py",
                "start_line": 2,
            },
        ],
    }
    orchestrator.state.attack_paths = [
        {
            "id": "p-dead",
            "finding_id": "f-dead",
            "proximity": 8,
            "blockers": [],
        },
        {
            "id": "p-live",
            "finding_id": "f-live",
            "proximity": 8,
            "blockers": [],
        },
    ]
    # Persist Stage B's input artefacts to disk — Stage B
    # reloads them from disk and overwrites state if a file is
    # missing (the orchestrator's resume-from-disk pattern).
    orchestrator.state.save_json(
        "attack-paths.json", orchestrator.state.attack_paths,
    )
    orchestrator.state.attack_surface = {"sources": [], "sinks": []}
    orchestrator.state.save_json(
        "attack-surface.json", orchestrator.state.attack_surface,
    )
    orchestrator.state.hypotheses = []
    orchestrator.state.save_json(
        "hypotheses.json", orchestrator.state.hypotheses,
    )
    orchestrator.state.disproven = []
    orchestrator.state.save_json(
        "disproven.json", orchestrator.state.disproven,
    )
    orchestrator.state.attack_tree = {"root": "x", "nodes": []}
    orchestrator.state.save_json(
        "attack-tree.json", orchestrator.state.attack_tree,
    )

    # The Stage B demotion must use state.checklist (reused) and
    # NOT call build_inventory.
    with patch(
        "core.inventory.build_inventory",
        side_effect=AssertionError(
            "Stage B demotion built a fresh inventory despite "
            "state.checklist being set"
        ),
    ):
        orchestrator._run_stage_b()

    # Demotion fired correctly: dead path has proximity=1 and
    # the reachability blocker.
    paths_by_id = {p["id"]: p for p in orchestrator.state.attack_paths}
    assert paths_by_id["p-dead"]["proximity"] == 1
    assert any(
        "reachability:not_called" in b
        for b in paths_by_id["p-dead"]["blockers"]
    )
    # Live path untouched.
    assert paths_by_id["p-live"]["proximity"] == 8
    assert paths_by_id["p-live"]["blockers"] == []
