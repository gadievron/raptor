"""Exercise the shipped push resolver and changed-file shell together."""

import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import textwrap
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
BASE, BEFORE, HEAD = "a" * 40, "b" * 40, "c" * 40
WORKFLOWS = {"tests.yml": "changes", "codeql.yml": "changes",
             "lint.yml": "command-metadata", "sandbox-wrappers.yml": "scope"}


@pytest.fixture
def resolver():
    path = ROOT / ".github/scripts/ci_push_base.py"
    spec = importlib.util.spec_from_file_location("owned_push_timing", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("phase,endpoint", [
    ("checkpoint-run", "repos/private/sentinel/actions/workflows/tests.yml/runs?branch=secret"),
    ("jobs", "repos/private/sentinel/actions/runs/123/jobs?filter=all"),
    ("compare", "repos/private/sentinel/compare/secret-base...secret-head"),
], ids=["runs", "jobs", "compare"])
def test_api_timing_discloses_only_phase(resolver, monkeypatch, phase, endpoint):
    calls = []
    ticks = iter([10.0, 10.375])
    output = io.StringIO()

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(stdout='{"ok": true}')

    monkeypatch.setattr(resolver, "subprocess", SimpleNamespace(run=run))
    monkeypatch.setattr(resolver, "time", SimpleNamespace(monotonic=lambda: next(ticks)))
    monkeypatch.setattr(resolver, "sys", SimpleNamespace(stderr=output))
    assert resolver._api(endpoint) == {"ok": True}
    assert calls == [(["gh", "api", endpoint], {
        "capture_output": True, "text": True, "timeout": 20, "check": True,
    })]
    assert output.getvalue() == f"Push checkpoint {phase}: 0.375s\n"


@pytest.mark.parametrize("stage", ["clock-start", "clock-end", "format", "stderr"])
@pytest.mark.parametrize("observer_error", [RuntimeError, KeyboardInterrupt], ids=["error", "interrupt"])
@pytest.mark.parametrize("primary", ["success", "json-error", "api-error"])
def test_api_outcome_survives_observer_failure(resolver, monkeypatch, stage, observer_error, primary):
    endpoint = "repos/private/sentinel/compare/base...head"
    calls = []
    primary_error = subprocess.CalledProcessError(7, ["gh", "api", endpoint])
    clock_calls = 0

    class BadFormat(float):
        def __format__(self, spec):
            raise observer_error("format observer")

    class EndTick:
        def __sub__(self, other):
            return BadFormat(0.375)

    class Sink(io.StringIO):
        def write(self, text):
            if stage == "stderr":
                raise observer_error("stderr observer")
            return super().write(text)

    def clock():
        nonlocal clock_calls
        clock_calls += 1
        if stage == ("clock-start" if clock_calls == 1 else "clock-end"):
            raise observer_error("clock observer")
        return 10.0 if clock_calls == 1 else EndTick() if stage == "format" else 10.375

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        if primary == "api-error":
            raise primary_error
        return SimpleNamespace(stdout="invalid JSON" if primary == "json-error" else '{"ok": true}')

    monkeypatch.setattr(resolver, "subprocess", SimpleNamespace(run=run))
    monkeypatch.setattr(resolver, "time", SimpleNamespace(monotonic=clock))
    monkeypatch.setattr(resolver, "sys", SimpleNamespace(stderr=Sink()))
    if primary == "success":
        assert resolver._api(endpoint) == {"ok": True}
    elif primary == "json-error":
        with pytest.raises(json.JSONDecodeError) as error:
            resolver._api(endpoint)
        assert error.value.doc == "invalid JSON"
    else:
        with pytest.raises(subprocess.CalledProcessError) as error:
            resolver._api(endpoint)
        assert error.value is primary_error
    assert calls == [(["gh", "api", endpoint], {
        "capture_output": True, "text": True, "timeout": 20, "check": True,
    })]


@pytest.mark.parametrize("primary_error", [KeyboardInterrupt("primary"), SystemExit(9)],
                         ids=["keyboard-interrupt", "system-exit"])
def test_primary_interrupt_survives_diagnostic_failure(resolver, monkeypatch, primary_error):
    ticks = iter([10.0, 10.375])

    def run(*args, **kwargs):
        raise primary_error

    class Sink:
        def write(self, text):
            raise RuntimeError("diagnostic failed")

    monkeypatch.setattr(resolver, "subprocess", SimpleNamespace(run=run))
    monkeypatch.setattr(resolver, "time", SimpleNamespace(monotonic=lambda: next(ticks)))
    monkeypatch.setattr(resolver, "sys", SimpleNamespace(stderr=Sink()))
    with pytest.raises(type(primary_error)) as error:
        resolver._api("repos/private/sentinel/compare/base...head")
    assert error.value is primary_error


def job_block(source, name):
    match = re.search(r"^  " + re.escape(name) + r":\n(.*?)(?=^  [A-Za-z][A-Za-z0-9_-]*:|\Z)",
                      source.split("\njobs:\n", 1)[1], re.M | re.S)
    assert match is not None
    return match[1]


@pytest.mark.parametrize("workflow,job", WORKFLOWS.items())
def test_push_policy_is_wired_without_event_before_fallback(workflow, job):
    source = (ROOT / ".github/workflows" / workflow).read_text()
    concurrency = source.split("\nconcurrency:\n", 1)[1].split("\n", 3)[:3]
    expected = "== 'pull_request'" if workflow == "codeql.yml" else "!= 'push'"
    assert "cancel-in-progress: ${{ github.event_name " + expected + " }}" in "\n".join(concurrency)
    block = job_block(source, job)
    assert "id: push_base" in block
    assert "if: github.event_name == 'push'" in block
    assert f"ci_push_base.py --workflow {workflow}" in block
    assert "name: Record verified push scope v1" in block
    assert "github.event.before" not in block
    assert "actions: read" in block or "actions: read" in source.split("\njobs:\n")[0]
    if workflow in {"tests.yml", "codeql.yml"}:
        assert "BEFORE: ${{ steps.push_base.outputs.base }}" in block
        assert "VERIFIED_COMPARE: ${{ steps.push_base.outputs.compare }}" in block
    else:
        assert "github.event_name != 'push'" in block
        assert "steps.push_base.outputs.base" in block


def test_lint_invariant_rider_also_uses_verified_base():
    source = (ROOT / ".github/workflows/lint.yml").read_text()
    block = job_block(source, "repo-invariants")
    assert "ci_push_base.py --workflow lint.yml" in block
    assert "steps.push_base.outputs.base" in block and "github.event.before" not in block
    assert "actions: read" in block


@pytest.mark.skipif(not shutil.which("bash") or not shutil.which("jq"), reason="native shell and jq")
@pytest.mark.parametrize("workflow", ["tests.yml", "codeql.yml"])
@pytest.mark.parametrize("scenario", ["cancelled-predecessor", "pre-policy", "compare-cap"])
def test_real_resolver_and_shell_keep_unverified_paths(tmp_path, workflow, scenario):
    path = ROOT / ".github/tests/test_changed_files_step.py"
    spec = importlib.util.spec_from_file_location("owned_changed_step", path)
    harness = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(harness)
    run = dict(id=12, run_attempt=1, head_sha=BASE, status="completed", conclusion="success",
               event="push", head_branch="main", path=f".github/workflows/{workflow}",
               repository={"full_name": "owner/repo"}, head_repository={"full_name": "owner/repo"})
    job = dict(name=WORKFLOWS[workflow], run_id=12, run_attempt=1, head_sha=BASE,
               status="completed", conclusion="success", steps=[] if scenario == "pre-policy" else [{
                   "name": "Record verified push scope v1", "status": "completed", "conclusion": "success",
               }])
    files = [{"filename": "core/inventory/dead_scope.py"}, {"filename": ".github/tests/latest.py"}]
    if scenario == "compare-cap":
        files = [{"filename": f"core/changed_{i}.py"} for i in range(300)]
    compare = dict(status="ahead", base_commit={"sha": BASE}, merge_base_commit={"sha": BASE}, files=files)
    payload = tmp_path / "api.json"
    payload.write_text(json.dumps(dict(run=run, job=job, compare=compare)))
    bindir = tmp_path / "bin"
    bindir.mkdir()
    stub = bindir / "gh"
    stub.write_text(f"#!{sys.executable}\n" + textwrap.dedent('''
        import json,os,sys
        from pathlib import Path
        endpoint=sys.argv[-1]
        with Path(os.environ['API_CALLS']).open('a') as out:out.write(endpoint+'\\n')
        data=json.loads(Path(os.environ['API_DATA']).read_text())
        if '/workflows/' in endpoint: result={'workflow_runs':[data['run']]}
        elif '/jobs?' in endpoint: result={'total_count':1,'jobs':[data['job']]}
        elif '/compare/' in endpoint:
            assert endpoint.endswith(data['run']['head_sha']+'...'+os.environ['GITHUB_SHA'])
            result=data['compare']
        else: raise AssertionError(endpoint)
        print(json.dumps(result))
    '''))
    stub.chmod(0o700)
    output, compare_path, calls = (tmp_path / name for name in ["resolver.out", "compare.json", "calls"])
    env = dict(os.environ, PATH=str(bindir) + os.pathsep + os.environ.get("PATH", ""),
               API_DATA=str(payload), API_CALLS=str(calls), GITHUB_OUTPUT=str(output),
               GITHUB_EVENT_NAME="push", GITHUB_REPOSITORY="owner/repo", GITHUB_REF_NAME="main",
               GITHUB_SHA=HEAD, GITHUB_RUN_ID="99", EVENT="push", REPO="owner/repo", AFTER=HEAD,
               BEFORE=BEFORE)
    resolved = subprocess.run([sys.executable, str(ROOT / ".github/scripts/ci_push_base.py"),
                               "--workflow", workflow, "--compare-out", str(compare_path)],
                              cwd=ROOT, env=env, capture_output=True, text=True, timeout=30)
    assert resolved.returncode == 0, resolved.stdout + resolved.stderr
    values = dict(line.split("=", 1) for line in output.read_text().splitlines())
    env.update(BEFORE=values["base"], VERIFIED_COMPARE=values["compare"])
    script = harness._extract_changed_files_run(ROOT / ".github/workflows" / workflow)
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    script = script.replace("/tmp/changed_files.txt", str(scratch / "changed_files.txt"))
    script = script.replace("/tmp/compare_response.json", str(scratch / "response.json"))
    output.write_text("")
    result = subprocess.run(["bash", "-c", script], cwd=ROOT, env=env,
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    listed = scratch / "changed_files.txt"
    if scenario == "cancelled-predecessor":
        assert values["base"] == BASE
        assert listed.read_text().splitlines() == [row["filename"] for row in files]
        assert len(calls.read_text().splitlines()) == 3  # cached compare is not fetched again
    else:
        assert not listed.exists() and "list=" not in output.read_text()
        if scenario == "pre-policy":
            assert values["base"] == "0" * 40 and values["compare"] == ""
