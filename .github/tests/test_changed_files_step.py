"""Simulation tests for the ``changed_files`` workflow step in
tests.yml / codeql.yml.

The step's push branch reads the GitHub compare API, which caps the
``files`` array at 300 entries and silently returns the FIRST 300 for
a bigger diff (the key stays present — it is not omitted). A truncated
list is indistinguishable from a real one downstream, so the step
itself must detect the cap and discard the list (→ full dispatch).
These tests extract the step's ``run:`` script from the workflow YAML
and execute it under bash against a stubbed ``gh``, so the guard is
exercised as the shell code that actually ships.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

WORKFLOWS = {
    "tests.yml": REPO_ROOT / ".github/workflows/tests.yml",
    "codeql.yml": REPO_ROOT / ".github/workflows/codeql.yml",
}

pytestmark = pytest.mark.skipif(
    shutil.which("bash") is None or shutil.which("jq") is None,
    reason="needs bash and jq",
)


def _extract_changed_files_run(workflow: Path) -> str:
    """Pull the ``run: |`` body of the ``changed_files`` step out of a
    workflow file, without a YAML dependency (the ci_lint job installs
    only pytest)."""
    lines = workflow.read_text(encoding="utf-8").splitlines()
    step_start = None
    for i, ln in enumerate(lines):
        if ln.strip() == "- id: changed_files":
            step_start = i
            break
    assert step_start is not None, f"no changed_files step in {workflow.name}"

    run_line = None
    for i in range(step_start + 1, len(lines)):
        stripped = lines[i].strip()
        if stripped == "run: |":
            run_line = i
            break
        # A new step began before any run: block — malformed for us.
        assert not stripped.startswith("- "), (
            f"changed_files step in {workflow.name} has no run: | block"
        )
    assert run_line is not None

    run_indent = len(lines[run_line]) - len(lines[run_line].lstrip())
    body: list[str] = []
    for ln in lines[run_line + 1:]:
        if ln.strip() == "":
            body.append("")
            continue
        indent = len(ln) - len(ln.lstrip())
        if indent <= run_indent:
            break
        body.append(ln)
    script = textwrap.dedent("\n".join(body))
    assert "compare" in script, "extracted script lost the push branch"
    # The harness runs plain ``bash -c``; GHA injects ``-e``. Parity
    # holds only while the shipped script sets its own strictness —
    # if this line is ever dropped, the sim would keep passing while
    # GHA error semantics silently change.
    assert script.startswith("set -euo pipefail"), (
        "changed_files step no longer opens with set -euo pipefail — "
        "the bash simulation would diverge from GHA semantics"
    )
    return script


def _run_step(
    tmp_path: Path, workflow: Path, compare_response: dict,
) -> tuple[Path, str]:
    """Execute the extracted step script for a push event against a
    stubbed ``gh`` emitting *compare_response*.

    Returns (changed-files list path, GITHUB_OUTPUT content). The
    script hardcodes ``/tmp/...`` scratch paths; they are relocated
    into the test's tmp dir (pure path substitution) so parallel runs
    cannot collide.
    """
    script = _extract_changed_files_run(workflow)
    script = script.replace("/tmp/", f"{tmp_path}/scratch/")
    (tmp_path / "scratch").mkdir()

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    response_file = tmp_path / "response.json"
    response_file.write_text(json.dumps(compare_response), encoding="utf-8")
    gh_stub = bin_dir / "gh"
    gh_stub.write_text(
        "#!/usr/bin/env bash\n"
        'cat "$GH_STUB_RESPONSE"\n',
        encoding="utf-8",
    )
    gh_stub.chmod(gh_stub.stat().st_mode | stat.S_IXUSR)

    gh_output = tmp_path / "github_output"
    gh_output.write_text("", encoding="utf-8")
    env = {
        **os.environ,
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "GH_STUB_RESPONSE": str(response_file),
        "EVENT": "push",
        "REPO": "owner/repo",
        "PR_NUMBER": "",
        "BEFORE": "a" * 40,
        "AFTER": "b" * 40,
        "GITHUB_OUTPUT": str(gh_output),
    }
    proc = subprocess.run(
        ["bash", "-c", script],
        env=env, capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, (
        f"step script failed:\n{proc.stdout}\n{proc.stderr}"
    )
    out_list = tmp_path / "scratch" / "changed_files.txt"
    return out_list, gh_output.read_text(encoding="utf-8")


def _compare_response(n_files: int, renames: bool = False) -> dict:
    files = []
    for i in range(n_files):
        entry: dict = {"filename": f"core/pkg/file_{i:04d}.py"}
        if renames:
            entry["previous_filename"] = f"core/pkg/old_{i:04d}.py"
        files.append(entry)
    return {"total_commits": 5, "files": files}


@pytest.mark.parametrize("workflow_name", sorted(WORKFLOWS))
class TestCompareCapTruncation:
    def test_below_cap_keeps_scoped_list(self, tmp_path, workflow_name):
        out_list, gh_output = _run_step(
            tmp_path, WORKFLOWS[workflow_name], _compare_response(299),
        )
        assert out_list.is_file()
        lines = out_list.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 299
        assert "list=" in gh_output

    def test_at_cap_discards_list_for_full_dispatch(
        self, tmp_path, workflow_name,
    ):
        # 300 entries IS what a >300-file diff looks like — the API
        # returns the first 300 with no truncation marker. The step
        # must discard the list (no ``list=`` output), which the
        # scope scripts treat as "no changed-file list" → full
        # dispatch. An exactly-300-file push pays a full run too:
        # fail toward full, never toward silently untested files.
        out_list, gh_output = _run_step(
            tmp_path, WORKFLOWS[workflow_name], _compare_response(300),
        )
        assert not out_list.exists(), (
            "300-entry (cap-sized) list was kept — big landings would "
            "under-dispatch"
        )
        assert "list=" not in gh_output

    def test_error_object_response_stays_fail_open(
        self, tmp_path, workflow_name,
    ):
        # An error-object response (no .files array) yields an EMPTY
        # list that IS handed downstream (``list=`` emitted) — both
        # consumers treat an empty changed-file list as full dispatch
        # (test_scope.main "empty changed-file list";
        # compute_filters._read_changed_files → None → all true).
        out_list, gh_output = _run_step(
            tmp_path, WORKFLOWS[workflow_name],
            {"message": "Server Error"},
        )
        assert out_list.is_file()
        assert out_list.read_text(encoding="utf-8").strip() == ""
        assert "list=" in gh_output


class TestRenameCompanionsDontCountTowardCap:
    def test_renames_kept_and_not_miscounted(self, tmp_path):
        # tests.yml also emits previous_filename lines (rename
        # companions). 200 renamed files produce 400 list lines but
        # only 200 API file entries — nowhere near the cap, so the
        # list must be kept, and both path spellings must be in it.
        out_list, gh_output = _run_step(
            tmp_path, WORKFLOWS["tests.yml"],
            _compare_response(200, renames=True),
        )
        assert out_list.is_file()
        lines = out_list.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 400
        assert "core/pkg/old_0000.py" in lines
        assert "list=" in gh_output
