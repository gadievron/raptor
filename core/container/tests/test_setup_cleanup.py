"""Failed staging never transfers ownership of partial trees."""

import json
from pathlib import Path
from types import SimpleNamespace
import pytest
from core.container import compose, export


@pytest.mark.parametrize("stage", ["keepalive", "copy", "prune", "rewrite"])
@pytest.mark.parametrize("error", [OSError("disk full"), KeyboardInterrupt()])
def test_compose_setup_failure_cleans_tree(tmp_path, monkeypatch, stage, error):
    source = tmp_path / "source"
    source.mkdir()
    config = source / "compose.yml"
    config.write_text("services: {}")
    staging = tmp_path / "staging"
    staging.mkdir()
    (staging / "partial").write_text("partial copied data")
    live = set()
    monkeypatch.setattr(compose.tempfile, "mkdtemp", lambda **kw: str(staging))

    def register(path):
        live.add(path)
        if stage == "keepalive":
            raise error

    def fail(*args, **kw):
        raise error

    monkeypatch.setattr(compose, "keepalive_register", register)
    monkeypatch.setattr(compose, "keepalive_unregister", live.discard)
    target = {
        "copy": "copytree",
        "prune": "_prune_escaping_symlinks",
        "rewrite": "_rewrite_ports_in_place",
    }.get(stage)
    if target:
        monkeypatch.setattr(
            compose.shutil if stage == "copy" else compose, target, fail
        )
    with pytest.raises(type(error)):
        compose.rewrite_for_localhost(config)
    assert not staging.exists()
    assert not live


def test_resolver_home_mkdir_failure_cleans_tree(tmp_path, monkeypatch):
    scratch = tmp_path / "resolver"
    scratch.mkdir()
    monkeypatch.setattr(compose.tempfile, "mkdtemp", lambda **kw: str(scratch))
    original = Path.mkdir

    def mkdir(path, *args, **kw):
        if path == scratch / ".docker":
            raise OSError("disk full")
        return original(path, *args, **kw)

    monkeypatch.setattr(Path, "mkdir", mkdir)
    with pytest.raises(OSError, match="disk full"):
        with compose._resolver_scratch_home():
            pytest.fail("failed setup must not enter the resolver scope")
    assert not scratch.exists()


def test_export_tar_removed_even_when_container_removal_raises(tmp_path, monkeypatch):
    tars = []

    def run(cmd, **kw):
        if cmd[:2] == ["docker", "create"]:
            return SimpleNamespace(
                returncode=0, stdout="container", stderr="", timed_out=False
            )
        if cmd[:3] == ["docker", "image", "inspect"]:
            return SimpleNamespace(returncode=0, stdout=json.dumps([{"Config": {}}]))
        if cmd[:2] == ["docker", "export"]:
            tar = Path(cmd[cmd.index("-o") + 1])
            tar.write_bytes(b"partial tar")
            tars.append(tar)
            return SimpleNamespace(
                returncode=1, stderr="export failed", timed_out=False
            )
        if cmd[:2] == ["docker", "rm"]:
            raise OSError("docker unavailable")
        raise AssertionError(cmd)

    monkeypatch.setattr(export, "run_cli", run)
    with pytest.raises(OSError, match="docker unavailable"):
        export.export_rootfs("image", tmp_path / "rootfs")
    assert tars and all(not path.exists() for path in tars)
