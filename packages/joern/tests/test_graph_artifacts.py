"""Graph identity must survive mutation and eviction of the cache index."""

import json
from unittest.mock import Mock

import pytest

from packages.joern import artifacts, runner


def test_worker_copy_survives_cache_replacement_and_deletion(tmp_path):
    source = tmp_path / "cache" / "cpg.bin"
    source.parent.mkdir()
    source.write_bytes(b"original graph")
    expected = artifacts.graph_digest(source)
    frozen = artifacts.FrozenGraph.copy(source, directory=tmp_path / "worker", expected=expected)
    replacement = source.with_name("replacement")
    replacement.write_bytes(b"different graph")
    replacement.replace(source)
    source.unlink()
    assert frozen.path.read_bytes() == b"original graph"
    assert artifacts.graph_digest(frozen.path) == expected
    frozen.close()
    assert not frozen.path.exists()


def test_wrong_receipt_never_produces_an_importable_artifact(tmp_path):
    source = tmp_path / "cpg.bin"
    source.write_bytes(b"wrong graph")
    directory = tmp_path / "worker"
    with pytest.raises(ValueError, match="build receipt"):
        artifacts.FrozenGraph.copy(source, directory=directory, expected="0" * 64)
    assert list(directory.iterdir()) == []


def test_graph_symlink_is_never_adopted(tmp_path):
    source = tmp_path / "cpg.bin"
    source.symlink_to(tmp_path / "victim")
    (tmp_path / "victim").write_bytes(b"private")
    with pytest.raises(OSError):
        artifacts.FrozenGraph.copy(source, directory=tmp_path / "worker")
    assert (tmp_path / "victim").read_bytes() == b"private"


def _seed(tmp_path):
    target = tmp_path / "source"
    target.mkdir()
    (target / "a.py").write_text("def fixture(): return 1\n")
    cache = tmp_path / "cache"
    slot = cache / runner.cpg_cache_slot_name(target=target)
    slot.mkdir(parents=True)
    (slot / "cpg.bin").write_bytes(b'FLATGRAPH{"version":1,"nodes":[{"nodeLabel":"METHOD","nnodes":1}]}')
    runner._write_cpg_manifest(slot, target, runner._target_content_hash(target), {"c"}, requested_languages={"c"})
    return target, cache, slot


def test_requested_language_cannot_reuse_another_frontend_graph(tmp_path, monkeypatch):
    target, cache, _ = _seed(tmp_path)
    build = Mock(side_effect=RuntimeError("new build requested"))
    monkeypatch.setattr(runner, "build_cpg", build)
    with pytest.raises(RuntimeError, match="new build requested"):
        runner.build_cpg_cached(target, cache, languages={"pythonsrc"})
    build.assert_called_once()


def test_tool_upgrade_invalidates_graph(tmp_path, monkeypatch):
    target, cache, _ = _seed(tmp_path)
    monkeypatch.setattr(artifacts, "toolchain_identity", lambda: "upgraded runtime")
    assert runner.load_cached_cpg(target, cache) is None


def test_schema_without_build_receipt_is_a_miss(tmp_path):
    target, cache, slot = _seed(tmp_path)
    data = json.loads((slot / "manifest.json").read_text())
    data.pop("graph_digest")
    (slot / "manifest.json").write_text(json.dumps(data))
    assert runner.load_cached_cpg(target, cache) is None


def test_scope_identity_also_names_target(tmp_path):
    excluded = tmp_path / "outside"
    assert runner.cpg_cache_slot_name([excluded], target=tmp_path / "first") != runner.cpg_cache_slot_name([excluded], target=tmp_path / "second")


def test_service_base_marker_survives_helpers_but_never_target_environment(monkeypatch):
    from core.config import RaptorConfig
    name = "_RAPTOR_JOERN_TMP_BASE"
    monkeypatch.setenv(name, "/operator-private-temp")
    environment = RaptorConfig.get_safe_env()
    assert environment[name] == "/operator-private-temp"
    assert name not in RaptorConfig.strip_target_exec_markers(environment)
    shim = (__import__('pathlib').Path(__file__).resolve().parents[3] / "libexec" / "raptor-seatbelt-shim").read_text()
    assert name in shim


def test_runtime_base_never_falls_back_from_explicit_invalid_directory(tmp_path, monkeypatch):
    from packages.joern import client
    monkeypatch.setattr(client, "_INITIAL_BASE", str(tmp_path / "missing"))
    with pytest.raises(FileNotFoundError):
        client.runtime_base()


def test_unset_macos_temp_uses_private_os_directory(tmp_path, monkeypatch):
    from packages.joern import client
    monkeypatch.setattr(client, "_INITIAL_BASE", None)
    monkeypatch.setattr(client.os.sys, "platform", "darwin")
    monkeypatch.setattr(client.os, "confstr", lambda name: str(tmp_path))
    assert client.runtime_base() == tmp_path


def test_cli_query_pins_graph_before_cache_eviction(tmp_path):
    from types import SimpleNamespace
    from packages.joern.models import JoernCPG
    source = tmp_path / "cache.bin"
    source.write_bytes(b"pinned graph")
    graph = JoernCPG(source, tmp_path, content_digest=artifacts.graph_digest(source))
    def execute(command, **kwargs):
        source.unlink()
        copies = list(__import__('pathlib').Path(kwargs["cwd"]).glob("graph-*/cpg.bin"))
        assert len(copies) == 1 and copies[0].read_bytes() == b"pinned graph"
        script = (__import__('pathlib').Path(kwargs["cwd"]) / "query.sc").read_text()
        assert str(copies[0]) in script and str(source) not in script
        return SimpleNamespace(returncode=0, stdout="", stderr="")
    assert runner.run_query(graph, "cpg.method.l", subprocess_runner=execute).ok


def test_cache_refreshes_inputs_after_waiting_for_exclusive_admission(tmp_path, monkeypatch):
    import contextlib
    import threading
    from concurrent.futures import ThreadPoolExecutor
    from packages.joern.models import JoernCPG
    from core.atomic_fs.fs_lock import artifact_lock
    target = tmp_path / "source"
    target.mkdir()
    source = target / "main.c"
    source.write_text("int old_name(void) { return 1; }")
    cache = tmp_path / "cache"
    slot = cache / runner.cpg_cache_slot_name(target=target)
    attempted = threading.Event()

    @contextlib.contextmanager
    def waiting_lock(*args, **kwargs):
        attempted.set()
        with artifact_lock(*args, **kwargs):
            yield

    def build(target, *, output_dir, **kwargs):
        assert "new_name" in source.read_text()
        graph = output_dir / "cpg.bin"
        graph.write_bytes(b"completed graph")
        return JoernCPG(graph, target)

    monkeypatch.setattr(runner, "artifact_lock", waiting_lock)
    monkeypatch.setattr(runner, "build_cpg", build)
    monkeypatch.setattr(runner, "cpg_method_count", lambda path: 1)
    with ThreadPoolExecutor(max_workers=1) as executor:
        with artifact_lock(slot / "cpg.bin", required=True):
            job = executor.submit(runner.build_cpg_cached, target, cache)
            assert attempted.wait(2)
            source.write_text("int new_name(void) { return 2; }")
        graph = job.result(timeout=5)
    assert graph.exists() and not graph.build_failed
    manifest = json.loads((slot / "manifest.json").read_text())
    assert manifest["content_hash"] == runner._target_content_hash(target)


def test_runtime_image_change_invalidates_identity_with_unchanged_java_launcher(tmp_path, monkeypatch):
    from packages.joern import prereqs
    root = tmp_path / "jdk"
    (root / "bin").mkdir(parents=True)
    (root / "lib").mkdir()
    executable = root / "bin" / "java"
    executable.write_bytes(b"launcher")
    image = root / "lib" / "modules"
    image.write_bytes(b"old runtime")
    monkeypatch.setattr(prereqs, "_java_path", lambda: str(executable))
    previous = artifacts.toolchain_identity()
    image.write_bytes(b"new runtime with different contents")
    assert artifacts.toolchain_identity() != previous


def test_toolchain_settings_and_frontend_launchers_invalidate_identity(tmp_path, monkeypatch):
    from packages.joern import prereqs
    install = tmp_path / "joern"
    (install / "bin").mkdir(parents=True)
    (install / "lib").mkdir()
    (install / "conf").mkdir()
    launcher = install / "bin/joern"
    launcher.write_text("launcher")
    monkeypatch.setattr(prereqs, "_joern_path", lambda: str(launcher))
    monkeypatch.setattr(prereqs, "_joern_parse_path", lambda: None)
    monkeypatch.setattr(prereqs, "_java_path", lambda: None)
    previous = artifacts.toolchain_identity()
    (install / "conf/application.ini").write_text("-Dsetting=changed")
    assert artifacts.toolchain_identity() != previous
    previous = artifacts.toolchain_identity()
    (install / "c2cpg.sh").write_text("new frontend")
    assert artifacts.toolchain_identity() != previous
