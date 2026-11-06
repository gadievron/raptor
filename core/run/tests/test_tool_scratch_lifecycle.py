"""Real tool adapters own scratch while incidental startup is stubbed locally."""

import json
import logging
import subprocess
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from core import sandbox
from core.atomic_fs import rmtree_hardened
from core.binary import elf_worker, inspect
from core.coverage import collect
from core.dataflow import ghsa_harvester
from core.git import clone
from core.recall import runner
from core.run import scratch
from core.testing.scratch_state import isolated_scratch_keepalive


OWNERS = ["git-refs", "advisory-parent", "gcov", "sarif", "binutils", "elf-worker"]


@pytest.fixture
def owned(tmp_path, monkeypatch):
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    binary = inputs / "fixture"
    binary.write_bytes(b"owned binary input")
    (inputs / "fixture.gcda").write_bytes(b"owned gcov input")
    sarif = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "fixture"}},
             "results": [{"ruleId": "fixture-rule", "message": {"text": "fixture"},
                          "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app.py"},
                                         "region": {"startLine": 1}}}]}]}]}
    (inputs / "fixture.sarif").write_text(json.dumps(sarif))
    before = {p.name: p.read_bytes() for p in inputs.iterdir()}
    roots = []
    original = tempfile.mkdtemp

    def allocate(*args, **kwargs):
        path = Path(original(*args, **{**kwargs, "dir": runtime}))
        roots.append(path)
        return str(path)

    monkeypatch.setattr(scratch, "tempfile", SimpleNamespace(**{**vars(tempfile), "mkdtemp": allocate}))
    monkeypatch.setattr(scratch, "logger", logging.Logger("tool-scratch-test"))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    monkeypatch.setenv("RAPTOR_REGISTRY_HOME", str(tmp_path / "registry"))
    from core.security import env_sanitisation
    monkeypatch.setattr(env_sanitisation, "subprocess_tmpdir", lambda: str(runtime))
    monkeypatch.setattr(elf_worker, "site", SimpleNamespace(getusersitepackages=lambda: ""))
    try:
        with isolated_scratch_keepalive() as pins:
            yield SimpleNamespace(roots=roots, pins=pins, inputs=inputs, binary=binary)
            assert all(not root.exists() for root in roots), roots
            assert {p.name: p.read_bytes() for p in inputs.iterdir()} == before
    finally:
        assert rmtree_hardened(runtime)


def dirty(owned):
    root = owned.roots[-1]
    assert root.is_dir() and str(root) in owned.pins
    child = root / "restricted" / "cache"
    if child.exists():
        child.chmod(0o700)
    child.mkdir(parents=True, exist_ok=True)
    (child / "payload").write_bytes(b"cache" * 1024)
    child.chmod(0)
    return root


def outcome(kind, stdout=""):
    if kind == "timeout":
        raise subprocess.TimeoutExpired("fixture-tool", 1)
    if kind in ("error", "interrupt", "exit"):
        raise {"error": RuntimeError, "interrupt": KeyboardInterrupt, "exit": SystemExit}[kind]("primary work failure")
    return subprocess.CompletedProcess([], int(kind == "nonzero"), stdout, "")


def invocation(owned, monkeypatch, owner, kind):
    def run(*args, **kwargs):
        root = dirty(owned)
        if owner == "gcov":
            Path(kwargs["env"]["RAPTOR_GCOV_OUT"]).write_text("        -:    0:Source:app.c\n        1:    1:int main(){}\n")
        elif owner in ("git-refs", "binutils", "elf-worker"):
            assert kwargs["output"] == str(root)
        if owner == "elf-worker":
            value = dict(arch="amd64", bits=64, endian="little", os_abi="SYSV", relro="Full",
                         pie=True, nx=True, canary=True, fortify=True, has_gnu_stack=True, checksec="NX enabled")
            result = outcome(kind, json.dumps(value).encode())
            result.stderr = b""
            return result
        if owner == "advisory-parent":
            return outcome(kind, "a" * 40 + " " + "b" * 40 + "\n")
        return outcome(kind, "a" * 40 + "\trefs/heads/main\n")

    if owner == "git-refs":
        monkeypatch.setattr(sandbox, "run_untrusted_networked", run)
        return lambda: clone.ls_remote("https://example.invalid/repo", proxy_hosts=["example.invalid"])
    if owner == "advisory-parent":
        monkeypatch.setattr(ghsa_harvester, "subprocess", SimpleNamespace(**{**vars(subprocess), "run": run}))
        return lambda: ghsa_harvester._resolve_parent("https://example.invalid/repo", "a" * 40)
    if owner == "gcov":
        monkeypatch.setattr(collect, "_sandboxed_run", run)
        return lambda: collect.collect_gcov(owned.inputs)
    if owner == "sarif":
        monkeypatch.setattr(runner, "_SARIF_CHUNK_THRESHOLD", 1)
        original = runner.parse_sarif_findings
        def parse(path, **kwargs):
            dirty(owned)
            outcome(kind)
            return original(path, **kwargs)
        monkeypatch.setattr(runner, "parse_sarif_findings", parse)
        return lambda: runner.collect_findings(owned.inputs)
    monkeypatch.setattr(sandbox, "run", run)
    if owner == "binutils":
        return lambda: inspect.readelf(owned.binary, "-h")
    return lambda: elf_worker.inspect_elf(owned.binary)


@pytest.mark.parametrize("owner", OWNERS)
@pytest.mark.parametrize("kind", ["success", "nonzero", "timeout", "error", "interrupt", "exit"])
def test_adapter_scratch_covers_work(owned, monkeypatch, owner, kind):
    call = invocation(owned, monkeypatch, owner, kind)
    expected = None
    if kind in ("error", "interrupt", "exit"):
        expected = {"error": RuntimeError, "interrupt": KeyboardInterrupt, "exit": SystemExit}[kind]
    elif kind == "timeout" and owner not in ("advisory-parent", "binutils", "elf-worker"):
        expected = subprocess.TimeoutExpired
    elif kind == "nonzero" and owner == "git-refs":
        expected = RuntimeError
    if expected:
        with pytest.raises(expected):
            call()
    else:
        call()
    assert len(owned.roots) == 1


@pytest.mark.parametrize("owner", OWNERS)
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
def test_secondary_cleanup_failure_preserves_primary(owned, monkeypatch, owner, error):
    call = invocation(owned, monkeypatch, owner, "interrupt")
    def remove(*args, **kwargs):
        raise error("secondary removal failure")
    with pytest.MonkeyPatch.context() as fault:
        fault.setattr(scratch, "rmtree_hardened", remove)
        with pytest.raises(KeyboardInterrupt, match="primary work failure"):
            call()
    assert not owned.pins
    for root in owned.roots:
        assert root.is_dir()
        assert rmtree_hardened(root)


@pytest.mark.parametrize("owner", OWNERS)
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_registration_failure_cleans_reservation(owned, monkeypatch, owner, error):
    call = invocation(owned, monkeypatch, owner, "success")
    register = scratch.keepalive_register
    def fail(path):
        register(path)
        raise error("registration failure")
    monkeypatch.setattr(scratch, "keepalive_register", fail)
    with pytest.raises(error, match="registration failure"):
        call()
    assert len(owned.roots) == 1


@pytest.mark.parametrize("has_report", [False, True])
def test_small_sarif_does_not_allocate_chunk_scratch(owned, monkeypatch, has_report):
    if not has_report:
        # Keep the owned input fixture unchanged; select an empty sibling.
        reports = owned.inputs / "empty-reports"
        reports.mkdir()
    else:
        reports = owned.inputs
    monkeypatch.setattr(runner, "scratch_dir", lambda *a, **k: pytest.fail("unneeded chunk scratch"))
    try:
        findings = runner.collect_findings(reports)
        assert bool(findings) == has_report
    finally:
        if not has_report:
            reports.rmdir()
    assert not owned.roots
