"""Audit pipeline runner.

Executes the audit phase-by-phase. Each phase is an atomic unit:

  * Has a stable id (``00_understand``, ``01_inventory``, ...).
  * Writes its output to ``audit/findings/<id>.md`` AND a structured
    JSON sibling at ``audit/findings/<id>.json``.
  * Records its completion + exit signature in ``audit/state.json`` so
    a re-run can verify "did anything change?" and so the final report
    can prove every step ran.

A phase is treated as "completed" only when:
  1. Its module's ``run(ctx)`` returns without raising.
  2. Both the .md and .json files exist on disk.
  3. The state.json entry has ``status == 'ok'`` and a non-empty
     ``signature`` (a hash of the findings file).

Anything else → ``status='failed'``. Failed phases block downstream
phases that declare a dependency on them. No silent skip. No guessing.

USAGE:

    python -m audit.runner all            # run every phase in order
    python -m audit.runner 00_understand  # run a single phase
    python -m audit.runner status         # print state without running
"""
from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import sys
import time
import traceback
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
FINDINGS = ROOT / "findings"
STATE_PATH = ROOT / "state.json"
PROJECT_ROOT = ROOT.parent  # ship/


# Phase order is significant. Each entry is the module name in
# ``audit.phases`` (without the ``.py`` extension) and a description.
# Adding a new phase: append it here, drop a module under phases/.
PHASES: tuple[tuple[str, str], ...] = (
    ("00_understand", "Architectural map + data flow"),
    ("01_inventory", "Per-file inventory: LOC, exports, imports"),
    ("02_functions", "Per-function audit on critical paths"),
    ("03_quality", "Style, naming, docstrings, type hints"),
    ("04_security", "Threat model + injection / SSRF / path-traversal"),
    ("05_optimization", "Perf hot spots + redundant work"),
    ("06_user_stories", "README claims vs actual behavior"),
    ("99_report", "Final synthesis"),
)


@dataclass
class PhaseResult:
    phase_id: str
    status: str  # "ok" | "failed"
    started_at: float
    elapsed_s: float
    signature: str  # sha256 of the .md output, or "" on failure
    error: str = ""  # traceback on failure
    counts: dict = field(default_factory=dict)  # phase-specific


@dataclass
class State:
    project_root: str
    last_run_at: float
    phases: dict[str, PhaseResult] = field(default_factory=dict)


@dataclass
class PhaseContext:
    """Passed into every phase's ``run`` function.

    Phases write their output via ``ctx.write_md`` / ``ctx.write_json``;
    the runner then verifies the files exist before marking the phase
    completed. Phases NEVER write directly to ``state.json`` — that's
    the runner's job, after the phase returns cleanly.
    """
    phase_id: str
    project_root: Path
    findings_dir: Path
    state: State

    def write_md(self, body: str) -> Path:
        path = self.findings_dir / f"{self.phase_id}.md"
        path.write_text(body)
        return path

    def write_json(self, payload: dict | list) -> Path:
        path = self.findings_dir / f"{self.phase_id}.json"
        path.write_text(json.dumps(payload, indent=2, default=str) + "\n")
        return path

    def previous(self, phase_id: str) -> dict | list | None:
        """Read a previously-completed phase's JSON output."""
        path = self.findings_dir / f"{phase_id}.json"
        if not path.exists():
            return None
        return json.loads(path.read_text())


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def _load_state() -> State:
    if not STATE_PATH.exists():
        return State(project_root=str(PROJECT_ROOT), last_run_at=0.0)
    raw = json.loads(STATE_PATH.read_text())
    phases = {
        pid: PhaseResult(**v) for pid, v in (raw.get("phases") or {}).items()
    }
    return State(
        project_root=raw.get("project_root", str(PROJECT_ROOT)),
        last_run_at=raw.get("last_run_at", 0.0),
        phases=phases,
    )


def _save_state(state: State) -> None:
    state.last_run_at = time.time()
    raw = {
        "project_root": state.project_root,
        "last_run_at": state.last_run_at,
        "phases": {pid: asdict(pr) for pid, pr in state.phases.items()},
    }
    STATE_PATH.write_text(json.dumps(raw, indent=2) + "\n")


def _run_one(phase_id: str, state: State) -> PhaseResult:
    """Import + execute one phase. Records start/elapsed/signature."""
    started = time.time()
    md_path = FINDINGS / f"{phase_id}.md"
    json_path = FINDINGS / f"{phase_id}.json"

    # Wipe the previous outputs so a re-run starts clean. State will
    # record "failed" if the phase doesn't write fresh ones.
    for p in (md_path, json_path):
        if p.exists():
            p.unlink()

    try:
        module = importlib.import_module(f"audit.phases.{phase_id}")
    except ImportError as exc:
        return PhaseResult(
            phase_id=phase_id, status="failed",
            started_at=started, elapsed_s=time.time() - started,
            signature="",
            error=f"phase module not found: {exc}",
        )

    ctx = PhaseContext(
        phase_id=phase_id,
        project_root=PROJECT_ROOT,
        findings_dir=FINDINGS,
        state=state,
    )

    try:
        counts = module.run(ctx) or {}
    except Exception:  # noqa: BLE001 — runner must catalog every failure
        return PhaseResult(
            phase_id=phase_id, status="failed",
            started_at=started, elapsed_s=time.time() - started,
            signature="",
            error=traceback.format_exc(),
        )

    if not md_path.exists() or not json_path.exists():
        return PhaseResult(
            phase_id=phase_id, status="failed",
            started_at=started, elapsed_s=time.time() - started,
            signature="",
            error=(f"phase did not produce both findings files; "
                   f"md={md_path.exists()} json={json_path.exists()}"),
        )

    return PhaseResult(
        phase_id=phase_id, status="ok",
        started_at=started, elapsed_s=time.time() - started,
        signature=_sha256(md_path.read_text()),
        counts=counts,
    )


def cmd_run_all(state: State) -> int:
    """Run every phase in order. Stop on first failure (caller can fix
    + re-run; partial state is preserved)."""
    for phase_id, desc in PHASES:
        print(f"=== {phase_id} — {desc} ===", flush=True)
        result = _run_one(phase_id, state)
        state.phases[phase_id] = result
        _save_state(state)
        if result.status != "ok":
            print(f"  FAILED: {result.error.splitlines()[0] if result.error else '?'}",
                  flush=True)
            print(f"  See ``audit/state.json`` for the full error.")
            return 1
        print(f"  OK · {result.elapsed_s:.1f}s · {result.signature}",
              flush=True)
    return 0


def cmd_run_one(phase_id: str, state: State) -> int:
    if phase_id not in {pid for pid, _ in PHASES}:
        print(f"unknown phase: {phase_id}", file=sys.stderr)
        print(f"known: {[pid for pid, _ in PHASES]}", file=sys.stderr)
        return 2
    print(f"=== {phase_id} ===", flush=True)
    result = _run_one(phase_id, state)
    state.phases[phase_id] = result
    _save_state(state)
    if result.status != "ok":
        print(f"  FAILED: {result.error}", flush=True)
        return 1
    print(f"  OK · {result.elapsed_s:.1f}s · {result.signature}", flush=True)
    return 0


def cmd_status(state: State) -> int:
    """Print phase status without running anything."""
    print(f"project_root: {state.project_root}")
    print(f"last_run_at:  {time.ctime(state.last_run_at) if state.last_run_at else '(never)'}")
    print()
    print(f"{'PHASE':<20} {'STATUS':<8} {'ELAPSED':>10}  SIGNATURE        DESC")
    for phase_id, desc in PHASES:
        r = state.phases.get(phase_id)
        if r is None:
            print(f"{phase_id:<20} {'-':<8} {'-':>10}  {'-':<16} {desc}")
        else:
            print(f"{phase_id:<20} {r.status:<8} {r.elapsed_s:>9.1f}s "
                  f" {r.signature:<16} {desc}")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="audit", description="cve-diff audit pipeline"
    )
    parser.add_argument(
        "command",
        help="`all` to run every phase, `status` to inspect, or a "
        "phase id (e.g. `00_understand`).",
    )
    args = parser.parse_args(argv)

    FINDINGS.mkdir(exist_ok=True)
    state = _load_state()

    if args.command == "all":
        return cmd_run_all(state)
    if args.command == "status":
        return cmd_status(state)
    return cmd_run_one(args.command, state)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
