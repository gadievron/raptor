"""Contract tests for core.container.export (docker intercepted /
pure parts exercised directly)."""

from __future__ import annotations

import io
import tarfile
from pathlib import Path
from typing import Any
from unittest.mock import patch

from core.container import export as ex
from core.container.proc import RunOutcome

_INSPECT = """[
  {"Config": {
    "Env": ["PATH=/usr/bin", "APP_KEY=x"],
    "Entrypoint": ["/docker-entrypoint.sh"],
    "Cmd": ["nginx", "-g", "daemon off;"],
    "WorkingDir": "/app",
    "User": "www-data",
    "ExposedPorts": {"80/tcp": {}, "443/tcp": {}, "bogus/tcp": {}}
  }}
]"""


def test_parse_image_config_full_shape() -> None:
    cfg = ex.parse_image_config(_INSPECT)
    assert cfg is not None
    assert cfg.env == ("PATH=/usr/bin", "APP_KEY=x")
    assert cfg.argv() == ["/docker-entrypoint.sh", "nginx", "-g",
                          "daemon off;"]
    assert cfg.workdir == "/app" and cfg.user == "www-data"
    assert cfg.exposed_ports == (80, 443)


def test_parse_image_config_tolerates_garbage() -> None:
    assert ex.parse_image_config("not json") is None
    assert ex.parse_image_config("[]") is None
    assert ex.parse_image_config('[{"Config": null}]') is None
    minimal = ex.parse_image_config('[{"Config": {}}]')
    assert minimal is not None and minimal.argv() == []


def _tar_with(members: list[tuple[tarfile.TarInfo, bytes | None]],
              path: Path) -> Path:
    with tarfile.open(path, "w") as tf:
        for info, data in members:
            tf.addfile(info, io.BytesIO(data) if data is not None else None)
    return path


def test_extract_skips_hostile_members(tmp_path: Path) -> None:
    """Traversal and device members are skipped, not trusted; benign
    files and in-tree symlinks extract."""
    good = tarfile.TarInfo("etc/os-release")
    payload = b"ID=test\n"
    good.size = len(payload)
    dirm = tarfile.TarInfo("etc")
    dirm.type = tarfile.DIRTYPE
    link = tarfile.TarInfo("etc/alias")
    link.type = tarfile.SYMTYPE
    link.linkname = "os-release"
    evil_traversal = tarfile.TarInfo("../../outside")
    evil_traversal.size = 1
    dev = tarfile.TarInfo("dev/sda")
    dev.type = tarfile.BLKTYPE

    tar = _tar_with([(dirm, None), (good, payload), (link, None),
                     (evil_traversal, b"x"), (dev, None)],
                    tmp_path / "img.tar")
    dest = tmp_path / "rootfs"
    extracted, skipped = ex.extract_rootfs_tar(tar, dest)
    assert (dest / "etc" / "os-release").read_bytes() == payload
    assert (dest / "etc" / "alias").is_symlink()
    assert not (tmp_path / "outside").exists()
    assert not (dest / "dev" / "sda").exists()
    assert extracted == 3 and skipped == 2


def test_export_rootfs_happy_path_and_cleanup(tmp_path: Path) -> None:
    tar = tmp_path / "canned.tar"
    info = tarfile.TarInfo("bin/init")
    info.size = 2
    _tar_with([(info, b"#!")], tar)
    captured: list[list[str]] = []

    def fake(cmd: list[str], **_kw: Any) -> RunOutcome:
        captured.append(list(cmd))
        if cmd[:2] == ["docker", "create"]:
            return RunOutcome(returncode=0, stdout="cid123\n", stderr="",
                              timed_out=False)
        if cmd[:2] == ["docker", "export"]:
            out_path = Path(cmd[cmd.index("-o") + 1])
            out_path.write_bytes(tar.read_bytes())
            return RunOutcome(returncode=0, stdout="", stderr="",
                              timed_out=False)
        if cmd[:3] == ["docker", "image", "inspect"]:
            return RunOutcome(returncode=0, stdout=_INSPECT, stderr="",
                              timed_out=False)
        return RunOutcome(returncode=0, stdout="", stderr="",
                          timed_out=False)

    dest = tmp_path / "rootfs"
    with patch.object(ex, "run_cli", side_effect=fake):
        outcome = ex.export_rootfs("nginx@sha256:" + "a" * 64, dest)
    assert outcome.ok, outcome.reason
    assert (dest / "bin" / "init").is_file()
    assert outcome.config is not None and outcome.config.workdir == "/app"
    assert ["docker", "rm", "-f", "cid123"] in captured  # throwaway removed


def test_export_rootfs_create_failure_classified(tmp_path: Path) -> None:
    def fake(cmd: list[str], **_kw: Any) -> RunOutcome:
        if cmd[:2] == ["docker", "create"]:
            return RunOutcome(returncode=1, stdout="",
                              stderr="manifest unknown", timed_out=False)
        return RunOutcome(returncode=0, stdout="", stderr="",
                          timed_out=False)

    with patch.object(ex, "run_cli", side_effect=fake):
        outcome = ex.export_rootfs("gone:1", tmp_path / "r")
    assert not outcome.ok
    assert outcome.reason == "create_failed"
    assert outcome.reason_class == "manifest_unknown"
