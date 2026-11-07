"""Matrix storage has explicit ownership and bounded failure cleanup."""

import importlib.util
import os
import sys
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from core.atomic_fs import rmtree_hardened
from core.run import scratch, tmp_reaper
from core.testing.module_state import isolated_module_state
from core.testing.restricted_tree import restricted_tree
from core.testing.scratch_state import isolated_scratch_keepalive
from packages.joern import JoernServer, models, prereqs, runner
import packages.joern as joern


@pytest.fixture
def cm(tmp_path, monkeypatch):
    script = Path(__file__).resolve().parents[1] / "scripts" / "compat_matrix.py"
    monkeypatch.setenv("RAPTOR_DIR", str(script.parents[3]))
    with patch.object(sys, "path", sys.path.copy()), isolated_module_state(tmp_reaper, {
        "_RUNTIME_DIR_PREFIXES": set(tmp_reaper._RUNTIME_DIR_PREFIXES),
    }), isolated_scratch_keepalive():
        spec = importlib.util.spec_from_file_location("matrix_storage_tests", script)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        yield module


@pytest.fixture
def matrix_case(cm, tmp_path, monkeypatch):
    work = tmp_path / "operator"
    work.mkdir()
    (work / "v1.zip").write_bytes(b"operator archive")
    borrowed = work / "v1"
    borrowed.mkdir()
    (borrowed / "data").write_bytes(b"operator tree")
    roots, downloads = [], []
    state = SimpleNamespace(keep=False, mode="success", primary=None)
    actual = scratch.scratch_dir

    @contextmanager
    def workspace(prefix, **kwargs):
        with actual(prefix, **kwargs) as root:
            roots.append(root)
            assert str(root) in scratch._keepalive_paths
            yield root

    def download(tag, path):
        previous_download = bool(downloads)
        downloads.append(tag)
        if previous_download and not state.keep:
            assert not (roots[0] / "v1.zip").exists()
            assert not (roots[0] / "v1").exists()
        assert path.parent == roots[0]
        assert str(path.parent) in scratch._keepalive_paths
        path.write_bytes(b"release archive")
        if state.mode == "download":
            raise state.primary
        return "joern-cli.zip", "a" * 64

    def extract(archive, tree):
        tree.mkdir()
        nested = tree / "restricted"
        nested.mkdir()
        (nested / "graph").write_bytes(b"partial graph")
        nested.chmod(0)
        if state.mode == "extract":
            raise state.primary
        return tree

    def run(tree):
        assert str(tree.parent) in scratch._keepalive_paths
        if state.mode == "scan":
            raise state.primary
        return {"pass": True}

    monkeypatch.setattr(cm, "scratch_dir", workspace)
    monkeypatch.setattr(cm, "_download", download)
    monkeypatch.setattr(cm, "_extract", extract)
    monkeypatch.setattr(cm, "_run_e2e_subprocess", run)
    monkeypatch.setattr(cm, "_load_pins", lambda: {f"{tag}/joern-cli.zip": "a" * 64 for tag in ("v1", "v2")})
    try:
        yield state, work, roots, downloads
    finally:
        # --keep transfers successful or partial output to this caller.
        for root in roots:
            rmtree_hardened(root)


@pytest.mark.parametrize("keep", [False, True])
@pytest.mark.parametrize("explicit", [False, True], ids=["system-parent", "operator-parent"])
@pytest.mark.parametrize("scenario", ["success", "download", "extract", "scan", "cancel-download", "cancel-scan"])
def test_matrix_owns_only_private_run_artifacts(cm, matrix_case, monkeypatch, capsys, keep, explicit, scenario):
    state, work, roots, downloads = matrix_case
    state.keep = keep
    state.mode = scenario.removeprefix("cancel-")
    state.primary = KeyboardInterrupt("download cancelled") if scenario == "cancel-download" else SystemExit(7) if scenario == "cancel-scan" else OSError("release failed")
    args = ["matrix", "--tags", "v1,v2"]
    if explicit:
        args += ["--workdir", str(work)]
    if keep:
        args += ["--keep"]
    monkeypatch.setattr(sys, "argv", args)
    if scenario.startswith("cancel-"):
        with pytest.raises(type(state.primary)) as caught:
            cm.main()
        assert caught.value is state.primary
    else:
        assert cm.main() == (0 if scenario == "success" else 1)
        assert downloads == ["v1", "v2"]
    assert len(roots) == 1
    assert roots[0].exists() is keep
    if explicit:
        assert roots[0].parent == work
    if keep:
        assert str(roots[0]) in capsys.readouterr().out
    assert str(roots[0]) not in scratch._keepalive_paths
    assert (work / "v1.zip").read_bytes() == b"operator archive"
    assert (work / "v1" / "data").read_bytes() == b"operator tree"


@pytest.mark.parametrize("error_type", [OSError, ValueError, KeyboardInterrupt, SystemExit])
def test_pin_loading_failure_removes_owned_run(cm, matrix_case, monkeypatch, error_type):
    state, work, roots, downloads = matrix_case
    primary = error_type("pin setup failed")

    def fail():
        raise primary

    monkeypatch.setattr(cm, "_load_pins", fail)
    monkeypatch.setattr(sys, "argv", ["matrix", "--tags", "v1", "--workdir", str(work)])
    with pytest.raises(error_type) as caught:
        cm.main()
    assert caught.value is primary
    assert not downloads
    assert not roots[0].exists()
    assert not scratch._keepalive_paths


@pytest.mark.parametrize("artifact", ["archive", "tree"])
def test_failed_release_cleanup_stops_next_download(cm, matrix_case, monkeypatch, capsys, artifact):
    state, work, roots, downloads = matrix_case
    unlink = Path.unlink
    remove = cm.rmtree_hardened
    checked = []

    def fail_archive(path, *args, **kwargs):
        if roots and path == roots[0] / "v1.zip":
            checked.append("archive")
            raise OSError("cannot unlink archive")
        return unlink(path, *args, **kwargs)

    def fail_tree(path):
        checked.append("tree")
        assert not (Path(path).parent / "v1.zip").exists()
        return False

    monkeypatch.setattr(Path, "unlink", fail_archive if artifact == "archive" else unlink)
    monkeypatch.setattr(cm, "rmtree_hardened", fail_tree if artifact == "tree" else remove)
    monkeypatch.setattr(sys, "argv", ["matrix", "--tags", "v1,v2", "--workdir", str(work)])
    assert cm.main() == 1
    assert downloads == ["v1"]
    assert checked == [artifact]
    assert "stopping downloads" in capsys.readouterr().out
    assert not roots[0].exists()  # outer scope independently retries tree cleanup
    assert not scratch._keepalive_paths


@pytest.mark.parametrize("artifact", ["archive", "tree"])
@pytest.mark.parametrize("outside", [False, True], ids=["inside", "outside"])
@pytest.mark.parametrize("directory", [False, True], ids=["file", "directory"])
def test_cleanup_unlinks_alias_without_deleting_target(cm, tmp_path, artifact, outside, directory):
    root = tmp_path / "work"
    root.mkdir()
    victim = (tmp_path if outside else root) / "operator-data"
    if directory:
        victim.mkdir()
        data = victim / "data"
    else:
        data = victim
    data.write_bytes(b"preserve")
    archive, tree = root / "v1.zip", root / "v1"
    alias = archive if artifact == "archive" else tree
    other = tree if artifact == "archive" else archive
    alias.symlink_to(victim)
    other.write_bytes(b"owned")
    assert cm._contained_cleanup(root, archive, tree)
    assert not alias.is_symlink()
    assert not other.exists()
    assert data.read_bytes() == b"preserve"


@pytest.mark.parametrize("mode", [0, 0o500, 0o555])
def test_cleanup_reclaims_restricted_release_tree(cm, tmp_path, mode):
    archive = tmp_path / "v1.zip"
    archive.write_bytes(b"archive")
    with restricted_tree(tmp_path / "v1", mode) as tree:
        assert cm._contained_cleanup(tmp_path, archive, tree)
        assert not tree.exists()
        assert not archive.exists()


@pytest.mark.parametrize("nested", [False, True])
def test_cleanup_refuses_non_child_paths_but_cleans_other_artifact(cm, tmp_path, nested):
    root = tmp_path / "work"
    root.mkdir()
    parent = root / "nested" if nested else tmp_path
    parent.mkdir(exist_ok=True)
    victim = parent / "operator"
    victim.write_bytes(b"preserve")
    archive = root / "v1.zip"
    archive.write_bytes(b"owned")
    assert not cm._contained_cleanup(root, archive, victim)
    assert not archive.exists()
    assert victim.read_bytes() == b"preserve"


@pytest.fixture
def e2e_case(cm, tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", os.environ.get("PATH", os.defpath))
    server = JoernServer()
    state = SimpleNamespace(primary=None, stop_error=None, second_error=None, killed=False)
    roots, stops = [], []
    actual = scratch.scratch_dir

    @contextmanager
    def workspace(prefix, **kwargs):
        if roots and state.second_error is not None:
            raise state.second_error
        with actual(prefix, dir=tmp_path, keepalive=True) as root:
            roots.append(root)
            yield root

    def build(target, *, output_dir):
        path = output_dir / "cpg.bin"
        path.write_bytes(b"graph")
        return models.JoernCPG(path=path, target=target)

    def query(*args, **kwargs):
        if state.primary is not None:
            raise state.primary
        return models.JoernResult("probe", raw_output="process main")

    def stop():
        stops.append(True)
        assert all(root.exists() for root in roots)
        if state.stop_error is not None:
            raise state.stop_error

    flow = models.TaintFlow("main", "arg", "strcpy", 1, is_inter_procedural=True)
    monkeypatch.setattr(cm, "scratch_dir", workspace)
    monkeypatch.setattr(prereqs, "version", lambda: "fixture")
    monkeypatch.setattr(runner, "build_cpg", build)
    monkeypatch.setattr(joern, "JoernServer", lambda: server)
    monkeypatch.setattr(server, "bind_graph", lambda graph: True)
    monkeypatch.setattr(server, "query", query)
    monkeypatch.setattr(server, "run_taint_query", lambda *args: [flow])
    monkeypatch.setattr(server, "run_tiered_sweep", lambda **kwargs: models.JoernResult("sweep", flows=[flow]))
    monkeypatch.setattr(server, "run_taint_queries_batch", lambda queries: [] if state.killed else [flow])
    monkeypatch.setattr(server, "set_flow_semantics", lambda names: setattr(state, "killed", bool(names)))
    monkeypatch.setattr(server, "stop", stop)
    return state, roots, stops


@pytest.mark.parametrize("error_type", [OSError, KeyboardInterrupt, SystemExit])
def test_second_e2e_allocation_failure_reclaims_first(cm, e2e_case, error_type):
    state, roots, stops = e2e_case
    state.second_error = error_type("second allocation failed")
    with pytest.raises(error_type) as caught:
        cm.run_e2e("/fixture")
    assert caught.value is state.second_error
    assert len(roots) == 1 and not roots[0].exists()
    assert not stops
    assert not scratch._keepalive_paths


@pytest.mark.parametrize("error_type", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("cleanup_type", [OSError, KeyboardInterrupt, SystemExit])
def test_e2e_cancellation_survives_server_teardown_failure(cm, e2e_case, error_type, cleanup_type):
    state, roots, stops = e2e_case
    state.primary = error_type("query interrupted")
    state.stop_error = cleanup_type("stop failed")
    with pytest.raises(error_type) as caught:
        cm.run_e2e("/fixture")
    assert caught.value is state.primary
    assert len(stops) == 1
    assert len(roots) == 2 and all(not root.exists() for root in roots)
    assert not scratch._keepalive_paths


@pytest.mark.parametrize("error_type", [None, OSError, ValueError, KeyboardInterrupt, SystemExit])
def test_e2e_teardown_always_releases_scratch(cm, e2e_case, error_type):
    state, roots, stops = e2e_case
    state.stop_error = error_type("stop failed") if error_type else None
    if error_type in {ValueError, KeyboardInterrupt, SystemExit}:
        with pytest.raises(error_type) as caught:
            cm.run_e2e("/fixture")
        assert caught.value is state.stop_error
    else:
        result = cm.run_e2e("/fixture")
        assert result["pass"] is (error_type is None)
    assert len(stops) == 1
    assert len(roots) == 2 and all(not root.exists() for root in roots)
    assert not scratch._keepalive_paths
