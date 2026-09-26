"""/audit → /validate post-pass lifecycle seam — hermetic end-to-end.

The post-pass is a CHILD phase of a live parent run: its lifecycle
start must land in the PARENT RUN's pinned project. Pre-fix the child
``raptor-run-lifecycle start`` re-resolved the project ambiently
(session binding, then the last-activated ``.active`` default); when
another session bumped the machine-wide default mid-run, the child
resolved a DIFFERENT project whose target-match gate refused the
start ("target ... is outside project ...") — the post-pass then
skipped with ``skipped_reason="lifecycle start failed"`` and every
emitted finding stayed unvalidated.

Real ``raptor-run-lifecycle`` subprocesses run against a temp HOME +
RAPTOR_OUT_DIR (registry, ``.active`` symlink, sessions dir all under
the temp home); only the sandboxed ``claude -p`` dispatch is faked —
the pipeline plumbing is under test, not the LLM.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]

# The dispatch transport is faked (run_untrusted_networked patched) —
# clear the kill switch the root conftest sets.
pytestmark = pytest.mark.usefixtures("cc_spawn_machinery_enabled")


def _write_run_marker(run_dir: Path, *, command: str, target: Path,
                      project: str | None = ..., status: str = "running",
                      ) -> None:
    """Write a ``.raptor-run.json`` run marker.

    ``project=...`` (the default) writes a pinned marker; passing the
    sentinel ``None`` writes an authoritative-projectless pin; omitting
    the key entirely (``project`` left as the module sentinel) is
    expressed by ``project="__legacy__"``.
    """
    meta: dict = {
        "version": 2,
        "command": command,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": status,
        "target_path": str(target),
    }
    if project != "__legacy__":
        meta["project"] = None if project is ... else project
        meta["project_source"] = "argv"
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / ".raptor-run.json").write_text(
        json.dumps(meta), encoding="utf-8")


@pytest.fixture
def seam(tmp_path, monkeypatch):
    """Two registered projects, ``.active`` pointing at the WRONG one,
    and a live parent audit run pinned to the right one."""
    home = tmp_path / "home"
    home.mkdir()
    out_base = tmp_path / "out"
    code = tmp_path / "code"
    code.mkdir()
    (code / "a.c").write_text("int f(void);\n", encoding="utf-8")
    other_target = tmp_path / "other"
    other_target.mkdir()

    # Environment the child lifecycle subprocess resolves through.
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("RAPTOR_OUT_DIR", str(out_base))
    monkeypatch.setenv("_RAPTOR_TRUSTED", "1")
    monkeypatch.setenv("RAPTOR_DIR", str(_REPO_ROOT))
    # A live session's credential must not leak into the child — the
    # seam under test is exactly the sessionless/detached shape.
    monkeypatch.delenv("RAPTOR_SESSION_PID", raising=False)
    monkeypatch.delenv("RAPTOR_SESSION_TOKEN", raising=False)
    # Env-credential dispatch mode: the proxy mode would try to stand
    # up a real credential dispatcher.
    monkeypatch.delenv("RAPTOR_CC_CREDENTIAL_MODE", raising=False)

    # In-process module constants frozen at import time.
    projects_dir = home / ".raptor" / "projects"
    monkeypatch.setattr("core.project.project.PROJECTS_DIR", projects_dir)
    monkeypatch.setattr("core.project.project.DEFAULT_OUTPUT_BASE",
                        out_base / "projects")
    monkeypatch.setattr("core.project.sessions.SESSIONS_DIR",
                        home / ".local" / "share" / "raptor" / "sessions.d")
    # No process-scoped --project override in this process.
    monkeypatch.setattr("core.run.pin._process_project", None)
    monkeypatch.setattr("core.run.pin._process_project_set", False)

    from core.project.project import ProjectManager
    mgr = ProjectManager(projects_dir=projects_dir)
    proj_out = out_base / "projects" / "projalpha"
    mgr.create("projalpha", str(code), output_dir=str(proj_out))
    mgr.create("projbeta", str(other_target),
               output_dir=str(out_base / "projects" / "projbeta"))
    # The mid-run default switch: another session's activity re-points
    # the machine-wide last-activated default at a different project.
    mgr.set_active("projbeta")

    parent = proj_out / "audit-parent-run"
    _write_run_marker(parent, command="audit", target=code,
                      project="projalpha")

    # Gate legs that need a human/sandbox or a claude binary.
    monkeypatch.setattr(
        "core.security.rule_of_two._session_has_human_terminal",
        lambda: True)
    monkeypatch.setattr("core.llm.cc_adapter.resolve_claude_cli",
                        lambda explicit=None: "/bin/true")

    def _fake_cc_dispatch(cmd, *args, **kwargs):
        # The faked LLM: write the terminal artifact the output probe
        # requires into the child run dir the dispatch names.
        run_dir = Path(kwargs["output"])
        (run_dir / "validation-report.md").write_text(
            "# Validation Report\n\n1 finding validated.\n",
            encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="done", stderr="")

    monkeypatch.setattr(
        "core.orchestration.skill_dispatch.run_untrusted_networked",
        _fake_cc_dispatch)

    return SimpleNamespace(code=code, proj_out=proj_out, parent=parent,
                           out_base=out_base)


def _finding_result():
    from core.audit.orchestrator import OrchestratorResult, ReviewOutcome
    r = OrchestratorResult()
    r.outcomes = [ReviewOutcome(
        file="a.c", function="f", status="finding", body="bug",
        hypothesis="", review_result=None, line=1,
    )]
    r.findings = 1
    r.reviewed = 1
    return r


def _postpass_record(out_dir: Path) -> dict:
    return json.loads(
        (out_dir / "validate-postpass.json").read_text(encoding="utf-8"))


class TestPostpassReachesRunningValidate:
    def test_postpass_starts_and_completes_in_the_parents_project(
            self, seam):
        # The field defect's exact shape: parent audit run live in its
        # pinned project, machine default pointing elsewhere. The
        # post-pass must still start — in the PARENT's project.
        from core.audit.validate import validate_findings
        validate_findings(_finding_result(), target_path=seam.code,
                          out_dir=seam.parent)

        record = _postpass_record(seam.parent)
        assert record["ran"] is True, record.get("skipped_reason")
        assert record["skipped_reason"] == ""
        validate_dir = Path(record["validate_dir"])
        # Landed as a sibling run in the parent run's pinned project —
        # never in the project the stale machine default names.
        assert validate_dir.parent == seam.proj_out
        meta = json.loads(
            (validate_dir / ".raptor-run.json").read_text(
                encoding="utf-8"))
        assert meta["command"] == "validate"
        assert meta["status"] == "completed"
        assert meta["project"] == "projalpha"
        assert (validate_dir / "validation-report.md").is_file()

    def test_legacy_parent_cannot_start_and_skips_cleanly(self, seam):
        # A pin-less (pre-series) parent marker gives the child nothing
        # to thread: it re-resolves ambiently, lands on the mismatching
        # machine default, and the start is genuinely refused. The
        # post-pass must skip cleanly with the recorded reason — this
        # is also the pre-fix behaviour, pinned as the legacy shape.
        _write_run_marker(seam.parent, command="audit", target=seam.code,
                          project="__legacy__")
        from core.audit.validate import validate_findings
        validate_findings(_finding_result(), target_path=seam.code,
                          out_dir=seam.parent)

        record = _postpass_record(seam.parent)
        assert record["ran"] is False
        assert record["skipped_reason"] == "lifecycle start failed"
        assert record["validate_dir"] is None
        # The follow-up command still reaches the operator.
        assert str(record["followup_command"]).startswith("/validate ")

    def test_projectless_parent_threads_the_explicit_none(self, seam):
        # A parent pinned authoritatively projectless must not let the
        # child fall through to the machine default either: the child
        # runs standalone (bound-to-none is authoritative).
        _write_run_marker(seam.parent, command="audit", target=seam.code,
                          project=None)
        from core.audit.validate import validate_findings
        validate_findings(_finding_result(), target_path=seam.code,
                          out_dir=seam.parent)

        record = _postpass_record(seam.parent)
        assert record["ran"] is True, record.get("skipped_reason")
        validate_dir = Path(record["validate_dir"])
        # Standalone run: under the out base, not in either project.
        assert validate_dir.parent == seam.out_base
