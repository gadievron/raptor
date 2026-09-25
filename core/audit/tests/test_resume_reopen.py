"""Resume of a contradicted 'completed' audit run (``--reopen``).

A genuinely completed audit always carries audit-report.json (the
pipeline tail writes it before the lifecycle completes). 'completed'
WITHOUT a report means a step that did not own the run stamped the
status (observed: a mapping-phase lifecycle complete on the audit dir
— the run then refused both its real completion and resume until the
status was hand-edited). ``resume_ineligibility(reopen=True)`` flips
exactly that contradiction back to 'interrupted'; a completed run
WITH a report stays final regardless of the flag.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.audit.resume import resume_ineligibility
from core.run.metadata import RUN_METADATA_FILE, reopen_run


def _mk_run(tmp_path: Path, status: str = "completed",
            with_report: bool = False) -> Path:
    out = tmp_path / "audit_run"
    out.mkdir()
    (out / RUN_METADATA_FILE).write_text(json.dumps({
        "command": "audit",
        "status": status,
        "timestamp": "2026-08-20T21:16:16+00:00",
    }))
    if with_report:
        (out / "audit-report.json").write_text("{}")
    return out


def test_contradicted_completion_refused_with_reopen_hint(tmp_path):
    out = _mk_run(tmp_path)
    err = resume_ineligibility(out)
    assert err is not None
    assert "--reopen" in err
    assert "audit-report.json" in err


def test_reopen_flips_contradicted_completion(tmp_path):
    out = _mk_run(tmp_path)
    assert resume_ineligibility(out, reopen=True) is None
    meta = json.loads((out / RUN_METADATA_FILE).read_text())
    assert meta["status"] == "interrupted"
    reopens = meta["extra"]["reopens"]
    assert len(reopens) == 1
    assert reopens[0]["prior_status"] == "completed"
    assert "audit-report.json" in reopens[0]["note"]


def test_reopen_with_live_worker_refused_through_audit_binding(
        tmp_path):
    """A contradicted completion whose recorded worker is still alive
    (a non-owning lifecycle complete never clears the worker stamp)
    must refuse --reopen through the audit binding too — flipping it
    would double-drive the in-flight run. Nothing is mutated."""
    import os

    from core.project.sessions import proc_starttime

    out = _mk_run(tmp_path)
    meta_path = out / RUN_METADATA_FILE
    meta = json.loads(meta_path.read_text())
    meta["tool_pid"] = os.getpid()  # demonstrably alive
    start = proc_starttime(os.getpid())
    if start is not None:
        meta["tool_pid_start"] = start
    meta_path.write_text(json.dumps(meta))
    err = resume_ineligibility(out, reopen=True)
    assert err is not None
    assert "still alive" in err
    assert str(os.getpid()) in err
    meta = json.loads(meta_path.read_text())
    assert meta["status"] == "completed"
    assert "reopens" not in (meta.get("extra") or {})


def test_genuine_completion_stays_final_even_with_reopen(tmp_path):
    out = _mk_run(tmp_path, with_report=True)
    err = resume_ineligibility(out, reopen=True)
    assert err is not None
    assert "never resumed" in err
    meta = json.loads((out / RUN_METADATA_FILE).read_text())
    assert meta["status"] == "completed"


def test_reopen_run_rejects_non_completed(tmp_path):
    out = _mk_run(tmp_path, status="running")
    with pytest.raises(ValueError, match="expected status 'completed'"):
        reopen_run(out)
