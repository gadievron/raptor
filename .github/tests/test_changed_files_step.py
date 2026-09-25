"""Simulation tests for the ``changed_files`` workflow step in
tests.yml / codeql.yml / preflight.yml.

The step's push branch (tests.yml / codeql.yml) reads the GitHub
compare API, which caps the ``files`` array at 300 entries and
silently returns the FIRST 300 for a bigger diff (the key stays
present — it is not omitted). A truncated list is indistinguishable
from a real one downstream, so the step itself must detect the cap
and discard the list (→ full dispatch). preflight.yml's variant has
no full-dispatch fallback; instead it retries a hard ``gh api``
failure and then fails LOUDLY — an empty file would silently skip
every simulation leg and let the skipped-is-pass aggregate go green.
These tests extract each step's ``run:`` script from the workflow
YAML and execute it under bash against a stubbed ``gh``, so the
guards are exercised as the shell code that actually ships.
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


def _extract_changed_files_run(
    workflow: Path, must_contain: str = "compare",
) -> str:
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
    assert must_contain in script, (
        f"extracted script lost its {must_contain!r} branch"
    )
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


PREFLIGHT = REPO_ROOT / ".github/workflows/preflight.yml"


def _run_preflight_step(
    tmp_path: Path, fail_times: int, filenames: list[str],
) -> tuple[subprocess.CompletedProcess, Path, int]:
    """Execute preflight.yml's changed_files step against a stubbed
    ``gh`` that fails its first *fail_times* invocations.

    The step passes ``--jq`` to gh (jq runs inside gh, unlike the
    push-branch steps that pipe raw JSON through local jq), so the
    stub's success output is the post-filter line list. ``sleep`` is
    stubbed to a no-op so the retry backoff doesn't cost the test
    real seconds. Returns (process, changed-files path, gh call
    count).
    """
    script = _extract_changed_files_run(PREFLIGHT, must_contain="attempt")
    script = script.replace("/tmp/", f"{tmp_path}/scratch/")
    (tmp_path / "scratch").mkdir()

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    response_file = tmp_path / "response.txt"
    response_file.write_text("\n".join(filenames) + "\n", encoding="utf-8")
    count_file = tmp_path / "gh_calls"
    count_file.write_text("0", encoding="utf-8")
    gh_stub = bin_dir / "gh"
    gh_stub.write_text(
        "#!/usr/bin/env bash\n"
        'n=$(cat "$GH_STUB_COUNT")\n'
        'n=$((n + 1))\n'
        'echo "$n" > "$GH_STUB_COUNT"\n'
        'if [ "$n" -le "$GH_STUB_FAILS" ]; then\n'
        '  echo "stub outage" >&2\n'
        "  exit 1\n"
        "fi\n"
        'cat "$GH_STUB_RESPONSE"\n',
        encoding="utf-8",
    )
    gh_stub.chmod(gh_stub.stat().st_mode | stat.S_IXUSR)
    sleep_stub = bin_dir / "sleep"
    sleep_stub.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
    sleep_stub.chmod(sleep_stub.stat().st_mode | stat.S_IXUSR)

    env = {
        **os.environ,
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "GH_STUB_RESPONSE": str(response_file),
        "GH_STUB_COUNT": str(count_file),
        "GH_STUB_FAILS": str(fail_times),
        "GH_TOKEN": "stub-token",
        "REPO": "owner/repo",
        "PR_NUMBER": "7",
    }
    proc = subprocess.run(
        ["bash", "-c", script],
        env=env, capture_output=True, text=True, timeout=60,
    )
    out_list = tmp_path / "scratch" / "changed_files.txt"
    calls = int(count_file.read_text(encoding="utf-8"))
    return proc, out_list, calls


class TestPreflightRetryLoop:
    def test_first_attempt_success(self, tmp_path):
        proc, out_list, calls = _run_preflight_step(
            tmp_path, fail_times=0,
            filenames=["core/pkg/tests/test_a.py"],
        )
        assert proc.returncode == 0, proc.stderr
        assert calls == 1
        assert out_list.read_text(encoding="utf-8").splitlines() == [
            "core/pkg/tests/test_a.py",
        ]

    def test_transient_failures_are_retried(self, tmp_path):
        proc, out_list, calls = _run_preflight_step(
            tmp_path, fail_times=2,
            filenames=["core/pkg/tests/test_a.py"],
        )
        assert proc.returncode == 0, proc.stderr
        assert calls == 3
        assert "retrying" in proc.stdout
        assert out_list.read_text(encoding="utf-8").splitlines() == [
            "core/pkg/tests/test_a.py",
        ]

    def test_total_failure_refuses_loudly(self, tmp_path):
        # An exhausted retry loop must FAIL the step — an empty
        # changed-file list would make preflight_scope skip every
        # simulation leg and the skipped-is-pass aggregate go green
        # on no data.
        proc, _out_list, calls = _run_preflight_step(
            tmp_path, fail_times=3,
            filenames=["core/pkg/tests/test_a.py"],
        )
        assert proc.returncode != 0
        assert calls == 3
        assert "::error::" in proc.stdout
        assert "refusing to skip" in proc.stdout


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
