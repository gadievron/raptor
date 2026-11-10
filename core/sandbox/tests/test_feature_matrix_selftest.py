"""Wiring check for the sandbox feature-matrix harness.

`run-matrix.sh --self-test` is the docker-free lane: it generates the
derived seccomp profiles, runs the capability probe on this host, and
exercises the report aggregator on synthetic clean/diverged fixtures
(asserting the divergence gate actually gates). Running it here keeps
the weekly workflow's substrate from bit-rotting between Saturdays —
a broken profile generator or report schema surfaces in the PR tier.
"""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from core.testing.gitrepo import git_run, init_scratch_repo
from core.testing.processes import run_in_process_group
from core.testing.standalone_cli import run_standalone_cli

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="harness targets the Linux sandbox",
)

_REPO_ROOT = os.path.realpath(
    os.path.join(os.path.dirname(__file__), "..", "..", ".."))
_SCRIPT = os.path.join(_REPO_ROOT, "core", "sandbox", "scripts",
                       "feature-matrix", "run-matrix.sh")


@pytest.mark.parametrize("stale_launch", [False, True], ids=["clean", "retired-parent"])
def test_self_test_passes(tmp_path, stale_launch):
    before = dict(os.environ)
    with pytest.MonkeyPatch.context() as parent:
        if stale_launch:
            retired = tmp_path / "retired-parent"
            retired.mkdir()
            retired.rmdir()
            parent.setenv("TMPDIR", str(retired))
            parent.setenv("_RAPTOR_SCRATCH_AUTH", "retired-self-test-authorization")
            parent.setenv("RAPTOR_SESSION_PID", "99999999")
            parent.setenv("RAPTOR_SESSION_TOKEN", "retired-self-test-session")
        else:
            for name in ("_RAPTOR_SCRATCH_AUTH", "RAPTOR_SESSION_PID", "RAPTOR_SESSION_TOKEN"):
                parent.delenv(name, raising=False)
        borrowed = dict(os.environ)
        r = run_standalone_cli([_SCRIPT, "--self-test"], capture_output=True,
                               text=True, timeout=120, check=False,
                               cwd=_REPO_ROOT)
        unchanged = dict(os.environ) == borrowed
        assert unchanged, "self-test changed its parent's launch state"
    restored = dict(os.environ) == before
    assert restored, "launch-state regression did not restore its caller"
    assert r.returncode == 0, (
        f"feature-matrix self-test failed:\n{r.stdout[-800:]}"
        f"\n{r.stderr[-800:]}")
    assert "self-test OK" in r.stdout


@pytest.mark.parametrize(("selected", "missing", "expected"), [
    ("24", "Dockerfile.26", ["Dockerfile"]),
    ("26", "Dockerfile", ["Dockerfile.26"]),
    ("both", None, ["Dockerfile", "Dockerfile.26"]),
    (None, None, ["Dockerfile", "Dockerfile.26"]),
    ("24", "Dockerfile", None),
    ("both", "Dockerfile.26", None),
])
def test_build_only_stages_selected_recipes(tmp_path, selected, missing, expected):
    """Run the real driver; replace only external image/network transports."""
    harness = tmp_path / "harness"
    shutil.copytree(Path(_SCRIPT).parent, harness)
    if missing:
        (harness / "images" / missing).unlink()
    repo = init_scratch_repo(tmp_path)
    for name in ("pyproject.toml", "uv.lock"):
        (repo / name).write_text(name + " fixture\n")
    git_run(repo, "add", ".")
    git_run(repo, "commit", "-qm", "fixture")
    tools = tmp_path / "tools"
    tools.mkdir()
    (tools / "python3").symlink_to(sys.executable)
    calls = tmp_path / "docker-calls.jsonl"
    docker = tools / "docker"
    docker.write_text(f"#!{sys.executable}\n" + r'''
import hashlib, json, os, pathlib, sys
args = sys.argv[1:]
if args == ["info"]:
    raise SystemExit(0)
assert args[0] == "build", args
context = pathlib.Path(args[-1])
recipe = pathlib.Path(args[args.index("-f") + 1])
assert recipe.is_file()
row = {"args": args, "recipe": recipe.name,
       "files": {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                 for p in context.iterdir()}}
with open(os.environ["DOCKER_CALLS"], "a") as stream:
    stream.write(json.dumps(row) + "\n")
''')
    docker.chmod(0o755)
    curl = tools / "curl"
    curl.write_text(f"#!{sys.executable}\n" + r'''
import json, sys
assert sys.argv[1:] == ["-fsSL", "https://raw.githubusercontent.com/actions/python-versions/main/versions-manifest.json"]
print(json.dumps([{"version": "3.14.7", "files": [{"platform": "linux",
    "platform_version": "24.04", "arch": "x64", "download_url": "https://fixture.invalid/python.tar.gz"}]}]))
''')
    curl.chmod(0o755)
    env = {"PATH": str(tools) + os.pathsep + os.defpath, "HOME": str(tmp_path),
           "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull,
           "DOCKER_CALLS": str(calls)}
    results = tmp_path / "results"
    command = ["bash", str(harness / "run-matrix.sh"), "--repo", str(repo),
               "--build-only", "--results", str(results)]
    if selected is not None:
        command += ["--image", selected]
    result = run_in_process_group(
        command,
        timeout=20, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    rows = [json.loads(line) for line in calls.read_text().splitlines()] if calls.exists() else []
    if expected is None:
        assert result.returncode != 0, result.stdout + result.stderr
        assert not rows, rows
        return
    assert result.returncode == 0, result.stdout + result.stderr
    assert [row["recipe"] for row in rows] == expected
    manifests = {name: hashlib.sha256((repo / name).read_bytes()).hexdigest()
                 for name in ("pyproject.toml", "uv.lock")}
    recipes = {name: hashlib.sha256((harness / "images" / name).read_bytes()).hexdigest()
               for name in expected}
    proxy = hashlib.sha256((harness / "images" / "rustup-proxy.c").read_bytes()).hexdigest()
    reqhash = hashlib.sha256(b"".join((repo / name).read_bytes()
                                   for name in ("pyproject.toml", "uv.lock"))).hexdigest()
    for row in rows:
        assert row["files"] == {**manifests, **recipes, "rustup-proxy.c": proxy}
        args = row["args"]
        assert args[args.index("--label") + 1] == "sxv.reqhash=" + reqhash
        assert "PY_VERSION=3.14.7" in args
        assert "PY_URL=https://fixture.invalid/python.tar.gz" in args
    assert "build-only: stopping before lane runs" in result.stdout
    run, = results.iterdir()
    assert not (run / "build-ctx").exists()
    assert not (run / "repo").exists()
    assert not (run / "repo.tar").exists()
    assert not (run / "profiles").exists()
