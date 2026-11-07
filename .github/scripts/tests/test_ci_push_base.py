"""Only completed, same-workflow cumulative checkpoints can narrow a push."""

from copy import deepcopy
import importlib.util
from pathlib import Path
import subprocess

import pytest

from core.testing.module_views import module_function_view

SCRIPT = Path(__file__).resolve().parents[1] / "ci_push_base.py"
spec = importlib.util.spec_from_file_location("owned_ci_push_base", SCRIPT)
base_scope = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base_scope)
BASE, HEAD = "a" * 40, "c" * 40


def payloads(workflow="tests.yml"):
    run = dict(id=12, run_attempt=2, head_sha=BASE, status="completed", conclusion="success",
               event="push", head_branch="main", path=f".github/workflows/{workflow}",
               repository={"full_name": "owner/repo"}, head_repository={"full_name": "owner/repo"})
    job = dict(name=base_scope.CHECKPOINT_JOBS[workflow], run_id=12, run_attempt=2,
               head_sha=BASE, status="completed", conclusion="success", steps=[{
                   "name": base_scope.CHECKPOINT_STEP, "status": "completed", "conclusion": "success",
               }])
    comparison = dict(status="ahead", base_commit={"sha": BASE}, merge_base_commit={"sha": BASE},
                      files=[{"filename": "core/earlier.py"}, {"filename": "core/latest.py"}])
    return {"run": run, "job": job, "comparison": comparison}


def api_for(data, calls):
    def api(endpoint):
        calls.append(endpoint)
        if "/workflows/" in endpoint:
            return {"workflow_runs": [data["run"]]}
        if "/jobs?" in endpoint:
            return {"total_count": 1, "jobs": [data["job"]]}
        if "/compare/" in endpoint:
            return data["comparison"]
        pytest.fail("unexpected API endpoint: " + endpoint)
    return api


@pytest.mark.parametrize("workflow", base_scope.CHECKPOINT_JOBS)
def test_verified_checkpoint_keeps_cancelled_push_changes(workflow):
    data, calls = payloads(workflow), []
    before = deepcopy(data)
    base, comparison = base_scope.checkpoint("owner/repo", "main", HEAD, "99", workflow,
                                            api=api_for(data, calls))
    assert base == BASE and comparison["files"] == before["comparison"]["files"]
    assert calls[-1] == f"repos/owner/repo/compare/{BASE}...{HEAD}"
    assert len(calls) == 3
    assert "/jobs?filter=all&per_page=100" in calls[1]
    assert data == before


@pytest.mark.parametrize("section,field,value", [
    ("run", "id", 99), ("run", "id", True), ("run", "run_attempt", 0),
    ("run", "head_sha", "0" * 40), ("run", "head_sha", "not-a-sha"),
    ("run", "status", "in_progress"), ("run", "conclusion", "cancelled"),
    ("run", "conclusion", "failure"), ("run", "event", "pull_request"),
    ("run", "head_branch", "other"), ("run", "path", ".github/workflows/other.yml"),
    ("run", "repository", {"full_name": "other/repo"}),
    ("run", "head_repository", {"full_name": "fork/repo"}),
    ("job", "run_id", 13), ("job", "run_attempt", 3),
    ("job", "head_sha", "b" * 40), ("job", "status", "queued"),
    ("job", "conclusion", "failure"), ("job", "name", "other-job"),
    ("job", "steps", []), ("job", "steps", [{"name": "old-policy", "status": "completed", "conclusion": "success"}]),
    ("comparison", "status", "diverged"), ("comparison", "status", "behind"),
    ("comparison", "status", "identical"),
    ("comparison", "merge_base_commit", {"sha": "b" * 40}),
    ("comparison", "base_commit", {"sha": "b" * 40}),
    ("comparison", "files", None),
], ids=["current-run", "boolean-run-id", "bad-attempt", "zero-sha", "bad-sha",
        "unfinished-run", "cancelled-run", "failed-run", "pr-run", "other-branch", "other-workflow",
        "other-repo", "fork-head", "other-job-run", "future-attempt", "other-job-sha", "unfinished-job",
        "failed-job", "other-job", "missing-marker", "old-policy", "diverged", "behind", "false-identical",
        "wrong-merge-base", "wrong-base", "missing-files"])
def test_invalid_or_pre_policy_checkpoint_cannot_narrow(section, field, value):
    data = payloads()
    data[section][field] = value
    with pytest.raises((ValueError, KeyError, TypeError)):
        base_scope.checkpoint("owner/repo", "main", HEAD, "99", "tests.yml", api=api_for(data, []))


@pytest.mark.parametrize("field,value", [("status", "in_progress"), ("conclusion", "failure"),
                                         ("conclusion", "skipped")])
def test_marker_must_have_completed_successfully(field, value):
    data = payloads()
    data["job"]["steps"][0][field] = value
    with pytest.raises(ValueError):
        base_scope.checkpoint("owner/repo", "main", HEAD, "99", "tests.yml", api=api_for(data, []))


@pytest.mark.parametrize("kind", ["no-runs", "truncated-jobs", "duplicate-job"])
def test_missing_or_ambiguous_api_results_are_not_checkpoints(kind):
    data = payloads()
    original = api_for(data, [])

    def api(endpoint):
        result = original(endpoint)
        if kind == "no-runs" and "workflow_runs" in result:
            result["workflow_runs"] = []
        if "/jobs?" in endpoint:
            if kind == "truncated-jobs":
                result["total_count"] = 101
            elif kind == "duplicate-job":
                result["total_count"] = 2
                result["jobs"].append(deepcopy(data["job"]))
        return result

    with pytest.raises(ValueError):
        base_scope.checkpoint("owner/repo", "main", HEAD, "99", "tests.yml", api=api)


@pytest.mark.parametrize("field", ["filename", "previous_filename"])
@pytest.mark.parametrize("value", ["core/line\nbreak.py", "core/return\rbreak.py", "core/nul\0.py", None])
def test_unrepresentable_paths_require_full_coverage(field, value):
    data = payloads()
    data["comparison"]["files"][0][field] = value
    with pytest.raises(ValueError):
        base_scope.checkpoint("owner/repo", "main", HEAD, "99", "tests.yml", api=api_for(data, []))


def test_identical_verified_tree_can_reuse_coverage():
    data = payloads()
    data["comparison"]["status"] = "identical"
    data["comparison"]["files"] = []
    assert base_scope.checkpoint("owner/repo", "main", BASE, "99", "tests.yml",
                                 api=api_for(data, []))[0] == BASE


def test_checkpoint_advances_only_after_green_push():
    data = payloads()
    assert base_scope.checkpoint("owner/repo", "main", HEAD, "99", "tests.yml",
                                 api=api_for(data, []))[0] == BASE
    # Simulate that surviving push becoming the completed policy checkpoint.
    data["run"]["head_sha"] = data["job"]["head_sha"] = HEAD
    data["run"]["id"] = data["job"]["run_id"] = 99
    data["comparison"] = dict(status="ahead", base_commit={"sha": HEAD},
                              merge_base_commit={"sha": HEAD}, files=[{"filename": "core/next.py"}])
    base, comparison = base_scope.checkpoint("owner/repo", "main", "d" * 40, "100", "tests.yml",
                                            api=api_for(data, []))
    assert base == HEAD and comparison["files"] == [{"filename": "core/next.py"}]


@pytest.mark.parametrize("error", [OSError("unavailable"), subprocess.TimeoutExpired("gh", 20),
                                  subprocess.CalledProcessError(1, "gh", stderr="private error"),
                                  ValueError("bad response")], ids=["os-error", "timeout", "api-failure", "bad-json"])
def test_lookup_failures_emit_explicit_full_scope(monkeypatch, tmp_path, capsys, error):
    output = tmp_path / "output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    monkeypatch.setenv("GITHUB_EVENT_NAME", "push")
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    monkeypatch.setenv("GITHUB_REF_NAME", "main")
    monkeypatch.setenv("GITHUB_SHA", HEAD)
    monkeypatch.setenv("GITHUB_RUN_ID", "99")
    monkeypatch.setenv("BEFORE", "b" * 40)

    def api(endpoint):
        raise error

    consumer = module_function_view(base_scope, bindings={"_api": api})
    compare = tmp_path / "compare.json"
    assert consumer.main(["--workflow", "tests.yml", "--compare-out", str(compare)]) == 0
    assert output.read_text() == f"base={base_scope.FULL_BASE}\ncompare=\n"
    assert not compare.exists()
    assert "private error" not in capsys.readouterr().out


@pytest.mark.parametrize("workflow", ["tests.yml", "sandbox-wrappers.yml"])
def test_targeted_recovery_retains_successful_scope_from_earlier_attempt(workflow):
    data = payloads(workflow)
    recovered = deepcopy(data["job"])
    recovered.update(name=("python-unit-tests-sandbox-macos" if workflow == "tests.yml"
                           else "wrappers-macos-latest"), steps=[{
                               "name": "Native tests", "status": "completed", "conclusion": "success",
                           }])
    data["job"]["run_attempt"] = 1
    original = api_for(data, [])

    def api(endpoint):
        if "/jobs?" in endpoint:
            return {"total_count": 2, "jobs": [recovered, data["job"]]}
        return original(endpoint)

    assert base_scope.checkpoint("owner/repo", "main", HEAD, "99", workflow,
                                 api=api)[0] == BASE


@pytest.mark.parametrize("newer_failed", [False, True], ids=["unmarked", "failed"])
def test_new_scope_execution_cannot_fall_back_to_an_older_marker(newer_failed):
    data = payloads()
    old = deepcopy(data["job"])
    old["run_attempt"] = 1
    if newer_failed:
        data["job"]["conclusion"] = "failure"
    else:
        data["job"]["steps"] = []
    original = api_for(data, [])

    def api(endpoint):
        if "/jobs?" in endpoint:
            return {"total_count": 2, "jobs": [data["job"], old]}
        return original(endpoint)

    with pytest.raises(ValueError):
        base_scope.checkpoint("owner/repo", "main", HEAD, "99", "tests.yml", api=api)


def test_new_successful_scope_supersedes_earlier_failed_execution():
    data = payloads()
    old = deepcopy(data["job"])
    old.update(run_attempt=1, conclusion="failure", steps=[])
    original = api_for(data, [])

    def api(endpoint):
        if "/jobs?" in endpoint:
            return {"total_count": 2, "jobs": [old, data["job"]]}
        return original(endpoint)

    assert base_scope.checkpoint("owner/repo", "main", HEAD, "99", "tests.yml", api=api)[0] == BASE
