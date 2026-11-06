"""Container scratch survives active work and is freed before daemon teardown."""

import io
import json
import stat
import tarfile
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.container import compose, export
from core.container.proc import RunOutcome
from core.run import scratch


@pytest.fixture
def resolver_case(tmp_path, monkeypatch):
    stage = tmp_path / "stage"
    stage.mkdir()
    config = stage / "compose.yml"
    config.write_text("services: {}")
    roots = []

    @contextmanager
    def home(prefix):
        with scratch.scratch_dir(prefix, dir=tmp_path / "homes", keepalive=True) as root:
            roots.append(root)
            yield root

    def resolve(argv, staging, env, *, scratch_home):
        assert staging == stage
        assert scratch_home.parent != stage
        assert str(scratch_home) in scratch._keepalive_paths
        assert stat.S_IMODE(scratch_home.stat().st_mode) == 0o700
        assert stat.S_IMODE((scratch_home / ".docker").stat().st_mode) == 0o700
        assert list((scratch_home / ".docker").iterdir()) == []
        assert env == compose._resolver_env(scratch_home)
        assert env["HOME"] == str(scratch_home)
        nested = scratch_home / "nested"
        nested.mkdir()
        (nested / "partial").write_bytes(b"partial")
        nested.chmod(0)
        return "services: {}"

    monkeypatch.setattr(compose, "scratch_dir", home)
    monkeypatch.setattr(compose, "_compose_invocation", lambda: ("docker", "compose"))
    monkeypatch.setattr(compose, "_run_resolver", resolve)
    return config, roots


@pytest.mark.parametrize("stage", ["register", "mkdir", "environment", "run"])
@pytest.mark.parametrize("error_type", [OSError, ValueError, KeyboardInterrupt, SystemExit])
def test_resolver_failure_reclaims_home(resolver_case, tmp_path, monkeypatch, stage, error_type):
    config, roots = resolver_case
    primary = error_type("resolver failure")
    register = scratch.keepalive_register
    mkdir = Path.mkdir

    def fail(*args, **kwargs):
        raise primary

    def register_then_fail(path):
        register(path)
        raise primary

    def fail_docker_directory(path, *args, **kwargs):
        if path.name == ".docker":
            raise primary
        return mkdir(path, *args, **kwargs)

    if stage == "register":
        monkeypatch.setattr(scratch, "keepalive_register", register_then_fail)
    elif stage == "mkdir":
        monkeypatch.setattr(Path, "mkdir", fail_docker_directory)
    else:
        monkeypatch.setattr(compose, "_resolver_env" if stage == "environment" else "_run_resolver", fail)
    with pytest.raises(error_type) as caught:
        compose._resolve_effective_model(config)
    assert caught.value is primary
    assert list((tmp_path / "homes").iterdir()) == []
    assert not scratch._keepalive_paths
    assert all(not root.exists() for root in roots)


@pytest.mark.parametrize("error_type", [OSError, ValueError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("cleanup_type", [OSError, KeyboardInterrupt, SystemExit])
def test_resolver_cleanup_preserves_original_failure(resolver_case, monkeypatch, error_type, cleanup_type):
    config, roots = resolver_case
    primary = error_type("resolver failed")
    remove = scratch.rmtree_hardened

    def fail(*args, **kwargs):
        raise primary

    def cleanup(path):
        assert remove(path)
        raise cleanup_type("cleanup failed")

    monkeypatch.setattr(compose, "_run_resolver", fail)
    monkeypatch.setattr(scratch, "rmtree_hardened", cleanup)
    with pytest.raises(error_type) as caught:
        compose._resolve_effective_model(config)
    assert caught.value is primary
    assert all(not root.exists() for root in roots)
    assert not scratch._keepalive_paths


@pytest.mark.parametrize("raw", ["services: {}", "[", "- list"])
def test_resolver_home_is_freed_before_parsing(resolver_case, monkeypatch, raw):
    config, roots = resolver_case
    real_load = compose.yaml.safe_load

    def parse(text):
        assert roots and all(not root.exists() for root in roots)
        assert not scratch._keepalive_paths
        return real_load(text)

    monkeypatch.setattr(compose, "_run_resolver", lambda *args, **kwargs: raw)
    monkeypatch.setattr(compose, "yaml", SimpleNamespace(safe_load=parse, YAMLError=compose.yaml.YAMLError))
    if raw == "services: {}":
        assert compose._resolve_effective_model(config) == {"services": {}}
    else:
        with pytest.raises(compose.ComposeError):
            compose._resolve_effective_model(config)


@pytest.fixture
def exporter_case(tmp_path, monkeypatch):
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w") as tar:
        for name in ("first", "second"):
            info = tarfile.TarInfo(name)
            info.size = 3
            tar.addfile(info, io.BytesIO(b"bin"))
    roots = []
    removals = []
    state = SimpleNamespace(mode="success", primary=None, removal_error=None)
    dest = tmp_path / "run" / "rootfs"
    dest.parent.mkdir()
    original = export.scratch_dir

    @contextmanager
    def workspace(prefix, **kwargs):
        assert kwargs["keepalive"] is True
        assert Path(kwargs["dir"]) == dest.parent
        with original(prefix, **kwargs) as root:
            roots.append(root)
            yield root

    def run(argv, **kwargs):
        if argv[:2] == ["docker", "create"]:
            return RunOutcome(0, "owned-container", "", False)
        if argv[:3] == ["docker", "image", "inspect"]:
            return RunOutcome(0, json.dumps([{"Config": {}, "Size": 6}]), "", False)
        if argv[:2] == ["docker", "export"]:
            target = Path(argv[argv.index("-o") + 1])
            assert target.parent == roots[0]
            assert str(target.parent) in scratch._keepalive_paths
            assert stat.S_IMODE(target.parent.stat().st_mode) == 0o700
            target.write_bytes(b"partial" if state.primary else payload.getvalue())
            if state.primary is not None:
                raise state.primary
            if state.mode == "export-failed":
                return RunOutcome(1, "", "export failed", False)
            if state.mode == "corrupt":
                target.write_bytes(b"not a tar")
            if state.mode == "empty":
                with tarfile.open(target, "w"):
                    pass
            return RunOutcome(0, "", "", False)
        assert argv == ["docker", "rm", "-f", "-v", "owned-container"]
        # Large host files must be gone BEFORE daemon cleanup starts.
        assert roots and all(not root.exists() for root in roots)
        assert not scratch._keepalive_paths
        removals.append(argv)
        if state.removal_error is not None:
            raise state.removal_error
        return RunOutcome(0, "", "", False)

    monkeypatch.setattr(export, "scratch_dir", workspace)
    monkeypatch.setattr(export, "run_cli", run)
    return state, dest, roots, removals


@pytest.mark.parametrize("error_type", [OSError, ValueError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("cleanup_type", [OSError, KeyboardInterrupt, SystemExit])
def test_export_error_survives_daemon_cleanup_failure(exporter_case, error_type, cleanup_type):
    state, dest, roots, removals = exporter_case
    state.primary = error_type("export interrupted")
    state.removal_error = cleanup_type("daemon cleanup failed")
    with pytest.raises(error_type) as caught:
        export.export_rootfs("image", dest)
    assert caught.value is state.primary
    assert len(removals) == 1
    assert not dest.exists()
    assert all(not root.exists() for root in roots)


@pytest.mark.parametrize("mode", ["success", "export-failed", "empty", "corrupt", "bytes", "entries"])
@pytest.mark.parametrize("cleanup_type", [None, OSError, KeyboardInterrupt])
def test_export_scratch_is_gone_before_daemon_teardown(exporter_case, mode, cleanup_type):
    state, dest, roots, removals = exporter_case
    state.mode = mode
    state.removal_error = cleanup_type("daemon cleanup failed") if cleanup_type else None
    limits = {"max_rootfs_bytes": 3} if mode == "bytes" else {"max_rootfs_entries": 1} if mode == "entries" else {}
    if cleanup_type:
        with pytest.raises(cleanup_type) as caught:
            export.export_rootfs("image", dest, **limits)
        assert caught.value is state.removal_error
    else:
        outcome = export.export_rootfs("image", dest, **limits)
        assert outcome.ok is (mode == "success")
        reasons = {"export-failed": "export_failed", "empty": "extract_failed", "corrupt": "extract_failed", "bytes": "quota_exceeded", "entries": "quota_exceeded"}
        assert outcome.reason == reasons.get(mode, "")
    assert len(removals) == 1
    assert all(not root.exists() for root in roots)
    assert not scratch._keepalive_paths
    if mode == "success":
        assert (dest / "first").read_bytes() == b"bin"
        assert (dest / "second").read_bytes() == b"bin"
    else:
        assert not dest.exists()


@pytest.mark.parametrize("first_type", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("second_type", [OSError, KeyboardInterrupt, SystemExit])
def test_compose_teardown_preserves_first_cancellation(tmp_path, monkeypatch, first_type, second_type):
    root = tmp_path / "staging"
    root.mkdir()
    (root / "partial").write_bytes(b"data")
    first = first_type("unregister interrupted")
    unregister = compose.keepalive_unregister
    remove = compose.rmtree_hardened
    calls = []
    scratch.keepalive_register(root)

    def unregister_then_fail(path):
        calls.append("unregister")
        unregister(path)
        raise first

    def remove_then_fail(path):
        calls.append("remove")
        assert remove(path)
        raise second_type("remove interrupted")

    monkeypatch.setattr(compose, "keepalive_unregister", unregister_then_fail)
    monkeypatch.setattr(compose, "rmtree_hardened", remove_then_fail)
    try:
        with pytest.raises(first_type) as caught:
            compose.cleanup_staging(root)
        assert caught.value is first
        assert calls == ["unregister", "remove"]
        assert not root.exists()
        assert str(root) not in scratch._keepalive_paths
    finally:
        scratch.keepalive_unregister(root)
        remove(root)
