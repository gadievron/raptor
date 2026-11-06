"""Headless JVM scratch and incomplete imports cannot accumulate on failures."""

import logging
from pathlib import Path
import subprocess

import pytest

from core.atomic_fs import rmtree_hardened
from core.build import artifacts
from core.run import scratch
from packages.ghidra import headless


@pytest.fixture
def invocation(request, tmp_path, monkeypatch, caplog, _owned_ghidra_keepalive):
    kind = request.param
    source = tmp_path / "source"
    source.mkdir()
    gpr = source / "owned.gpr"
    gpr.write_text('<PROJECT NAME="owned"/>')
    (source / "owned.rep").mkdir()
    binary = tmp_path / "binary"
    binary.write_bytes(b"owned binary fixture")
    out = tmp_path / "out"
    out.mkdir()
    marker = out / "operator.txt"
    marker.write_text("operator data")
    outside = tmp_path / "operator.gpr"
    outside.write_text("operator project")
    enrichments = tmp_path / "enrichments.json"
    enrichments.write_text("{}")
    monkeypatch.setenv("RAPTOR_REGISTRY_HOME", str(tmp_path / "state"))
    monkeypatch.setattr(headless, "_find_headless", lambda: "/owned/ghidra/support/analyzeHeadless")
    monkeypatch.setattr(headless, "_install_read_paths", lambda path: [])
    logger = logging.getLogger("test.headless-scratch-owned")
    monkeypatch.setattr(logger, "handlers", [caplog.handler])
    monkeypatch.setattr(logger, "propagate", False)
    for module in (headless, scratch, artifacts):
        monkeypatch.setattr(module, "logger", logger)
    roots = []
    state = {"error": None, "returncode": 0, "gpr": "file"}
    def execute(command, **kwargs):
        root = Path(kwargs["env"]["HOME"])
        roots.append(root)
        assert str(root) in _owned_ghidra_keepalive
        locked = root / "locked"
        locked.mkdir()
        (locked / "temporary-database").write_bytes(b"JVM scratch")
        locked.chmod(0)
        (root / "heap.hprof").write_bytes(b"JVM dump")
        if kind == "create":
            project = out / "raptor.gpr"
            if state["gpr"] == "file":
                project.write_text("project header")
            elif state["gpr"] == "directory":
                project.mkdir()
            elif state["gpr"] == "symlink":
                project.symlink_to(outside)
            rep = out / "raptor.rep/locked"
            rep.mkdir(parents=True)
            (rep / "database").write_bytes(b"partial database")
            rep.chmod(0)
            for name in ("raptor.lock", "raptor.lock~"):
                (out / name).write_text("lock")
        elif kind == "export":
            (out / "export.json").write_text("{}")
        if state["error"] is not None:
            raise state["error"]
        return subprocess.CompletedProcess(command, state["returncode"], "", "worker failed")
    monkeypatch.setattr("core.sandbox.run", execute)
    def run():
        if kind == "create":
            return headless.create_project_from_binary(binary, out)
        if kind == "export":
            return headless.export_project(gpr, out / "export.json")
        return headless.import_enrichments(gpr, enrichments, out / "owned.gpr")
    try:
        yield kind, run, out, roots, state, _owned_ghidra_keepalive
    finally:
        assert marker.read_text() == "operator data"
        assert outside.read_text() == "operator project"
        assert gpr.read_text() == '<PROJECT NAME="owned"/>'
        assert rmtree_hardened(out)


@pytest.mark.parametrize("invocation", ["create", "export", "import"], indirect=True)
@pytest.mark.parametrize("failure", ["success", "nonzero", "timeout", "io", "runtime", "interrupt", "exit"])
def test_every_jvm_exit_reclaims_private_scratch(invocation, failure):
    kind, run, out, roots, state, pins = invocation
    errors = {"timeout": subprocess.TimeoutExpired("owned-ghidra", 1), "io": OSError("spawn stopped"),
              "runtime": RuntimeError("worker stopped"), "interrupt": KeyboardInterrupt("worker interrupted"),
              "exit": SystemExit("worker exited")}
    if failure == "nonzero":
        state["returncode"] = 1
    elif failure in errors:
        state["error"] = errors[failure]
    if failure == "success":
        assert run().is_file()
    else:
        expected = (headless.GhidraError if failure in {"nonzero", "timeout", "io"}
                    else type(errors[failure]))
        with pytest.raises(expected) as caught:
            run()
        if failure in {"runtime", "interrupt", "exit"}:
            assert caught.value is errors[failure]
        if kind == "create":
            assert not any((out / name).exists() for name in ("raptor.gpr", "raptor.rep", "raptor.lock", "raptor.lock~"))
    assert roots and all(not path.exists() for path in roots)
    assert not pins


@pytest.mark.parametrize("invocation", ["create", "export", "import"], indirect=True)
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_jvm_environment_setup_failure_reclaims_its_allocation(invocation, monkeypatch, error):
    kind, run, out, roots, state, pins = invocation
    failure = error("JVM environment setup failed")
    allocated = []
    def fail(path):
        allocated.append(path)
        (path / "partial-home").mkdir()
        raise failure
    monkeypatch.setattr(headless, "_jvm_scoped_env", fail)
    with pytest.raises(error) as caught:
        run()
    assert caught.value is failure
    assert allocated and all(not path.exists() for path in allocated)
    assert not roots
    assert not pins


@pytest.mark.parametrize("invocation", ["create", "export", "import"], indirect=True)
def test_registration_failure_releases_explicit_parent_scratch(invocation, monkeypatch):
    kind, run, out, roots, state, pins = invocation
    register = scratch.keepalive_register
    allocated = []
    failure = KeyboardInterrupt("registration interrupted")
    def fail(path):
        allocated.append(path)
        register(path)
        raise failure
    monkeypatch.setattr(scratch, "keepalive_register", fail)
    with pytest.raises(KeyboardInterrupt) as caught:
        run()
    assert caught.value is failure
    assert allocated and all(not path.exists() for path in allocated)
    assert not roots and not pins


@pytest.mark.parametrize("invocation", ["create"], indirect=True)
@pytest.mark.parametrize("name", ["raptor.gpr", "raptor.rep", "raptor.lock", "raptor.lock~"])
def test_preexisting_dangling_project_artifact_is_preserved(invocation, name):
    kind, run, out, roots, state, pins = invocation
    preexisting = out / name
    preexisting.symlink_to(out / "missing-target")
    with pytest.raises(headless.GhidraProjectExistsError, match="already exists"):
        run()
    assert preexisting.is_symlink()
    assert not roots and not pins


@pytest.mark.parametrize("invocation", ["create"], indirect=True)
@pytest.mark.parametrize("shape", ["directory", "symlink", "missing"])
def test_invalid_success_marker_does_not_publish_a_project(invocation, shape):
    kind, run, out, roots, state, pins = invocation
    state["gpr"] = shape
    with pytest.raises(headless.GhidraError, match="no project"):
        run()
    assert not (out / "raptor.gpr").exists()
    assert not (out / "raptor.gpr").is_symlink()
    assert not (out / "raptor.rep").exists()
    assert not roots[0].exists() and not pins


@pytest.mark.parametrize("invocation", ["create"], indirect=True)
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_failed_database_removal_still_releases_other_artifacts(invocation, monkeypatch, error):
    kind, run, out, roots, state, pins = invocation
    primary = RuntimeError("worker failed")
    state["error"] = primary
    remove = artifacts.rmtree_hardened
    def fail(path):
        if Path(path) == out / "raptor.rep":
            raise error("secondary database cleanup failure")
        return remove(path)
    with monkeypatch.context() as fault:
        fault.setattr(artifacts, "rmtree_hardened", fail)
        with pytest.raises(RuntimeError) as caught:
            run()
        assert caught.value is primary
    assert (out / "raptor.rep").exists()
    assert not any((out / name).exists() for name in ("raptor.gpr", "raptor.lock", "raptor.lock~"))
    headless._remove_created_project(out)
    assert not (out / "raptor.rep").exists()
    assert not pins



@pytest.mark.parametrize("invocation", ["create"], indirect=True)
def test_failed_create_cleanup_preserves_operator_registry(invocation, monkeypatch):
    kind, run, out, roots, state, pins = invocation
    registry = out / "raptor.rep"
    registry.mkdir()
    keep = registry / "keep"
    keep.write_text("operator registry")
    monkeypatch.setenv("RAPTOR_REGISTRY_HOME", str(registry))
    (out / "raptor.gpr").write_text("partial project")
    (out / "raptor.lock").write_text("partial lock")
    headless._remove_created_project(out)
    assert keep.read_text() == "operator registry"
    assert not (out / "raptor.gpr").exists()
    assert not (out / "raptor.lock").exists()
