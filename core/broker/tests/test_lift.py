"""Tests for binary lifting and cross-fleet routing."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from core.broker.capabilities import (
    Architecture,
    OperatingSystem,
    SystemCapabilities,
)
from core.broker.inventory import Inventory
from core.broker.lift import (
    LiftError,
    LiftSpec,
    LiftedBinary,
    _detect_file_type,
    _staging_dir,
    choose_fuzz_target,
    lift,
    list_native_libs,
)
from core.broker.transport import CommandResult, RemoteSystemEntry, TransportKind


def _entry(alias: str, host: str = "10.0.0.1", transport: TransportKind = TransportKind.SSH) -> RemoteSystemEntry:
    return RemoteSystemEntry(
        alias=alias, host=host, port=22, user="root", transport=transport,
    )


def _caps(alias: str, os: OperatingSystem = OperatingSystem.LINUX) -> SystemCapabilities:
    return SystemCapabilities(
        alias=alias, os=os, arch=Architecture.X86_64,
        tools=frozenset(), ram_mb=8192, cores=4, free_disk_mb=50000,
    )


class TestLiftSpec:
    def test_frozen(self):
        spec = LiftSpec(source_alias="pixel", remote_path="/data/app/x.apk")
        with pytest.raises(AttributeError):
            spec.source_alias = "other"

    def test_defaults(self):
        spec = LiftSpec(source_alias="pixel", remote_path="/data/app/x.apk")
        assert spec.unpack is True


class TestLiftedBinary:
    def test_frozen(self):
        lb = LiftedBinary(
            source_alias="pixel",
            remote_path="/data/app/x.apk",
            local_path="/tmp/x.apk",
            original_name="x.apk",
        )
        with pytest.raises(AttributeError):
            lb.local_path = "/other"

    def test_defaults(self):
        lb = LiftedBinary(
            source_alias="pixel",
            remote_path="/data/app/x.apk",
            local_path="/tmp/x.apk",
            original_name="x.apk",
        )
        assert lb.unpacked_dir is None
        assert lb.file_type is None
        assert lb.size_bytes == 0


class TestStagingDir:
    def test_uses_raptor_dir(self, monkeypatch):
        monkeypatch.setenv("RAPTOR_DIR", "/opt/raptor")
        assert str(_staging_dir()) == "/opt/raptor/out/lifted"

    def test_uses_cwd_fallback(self, monkeypatch):
        monkeypatch.delenv("RAPTOR_DIR", raising=False)
        result = _staging_dir()
        assert result.name == "lifted"
        assert result.parent.name == "out"


class TestListNativeLibs:
    def test_no_unpacked_dir(self):
        lb = LiftedBinary(
            source_alias="pixel", remote_path="/x.apk",
            local_path="/tmp/x.apk", original_name="x.apk",
        )
        assert list_native_libs(lb) == []

    def test_finds_so_files(self, tmp_path):
        lib_dir = tmp_path / "arm64-v8a"
        lib_dir.mkdir(parents=True)
        (lib_dir / "libnative.so").write_text("ELF")
        (lib_dir / "libutils.so").write_text("ELF")
        (tmp_path / "classes.dex").write_text("dex")

        lb = LiftedBinary(
            source_alias="pixel", remote_path="/x.apk",
            local_path="/tmp/x.apk", original_name="x.apk",
            unpacked_dir=str(tmp_path),
        )
        libs = list_native_libs(lb)
        assert len(libs) == 2
        assert all(l.endswith(".so") for l in libs)


class TestChooseFuzzTarget:
    def test_no_natives_returns_original(self):
        lb = LiftedBinary(
            source_alias="pixel", remote_path="/x.apk",
            local_path="/tmp/x.apk", original_name="x.apk",
        )
        assert choose_fuzz_target(lb) == "/tmp/x.apk"

    def test_prefers_arm64_largest(self, tmp_path):
        arm64_dir = tmp_path / "lib" / "arm64-v8a"
        arm_dir = tmp_path / "lib" / "armeabi-v7a"
        arm64_dir.mkdir(parents=True)
        arm_dir.mkdir(parents=True)

        (arm64_dir / "libbig.so").write_bytes(b"A" * 1000)
        (arm64_dir / "libsmall.so").write_bytes(b"B" * 100)
        (arm_dir / "libarm.so").write_bytes(b"C" * 500)

        lb = LiftedBinary(
            source_alias="pixel", remote_path="/x.apk",
            local_path="/tmp/x.apk", original_name="x.apk",
            unpacked_dir=str(tmp_path),
        )
        target = choose_fuzz_target(lb)
        assert "arm64-v8a" in target
        assert "libbig.so" in target


class TestLift:
    def test_unknown_alias_raises(self, tmp_path):
        inv = Inventory(path=tmp_path / "inv.json")
        spec = LiftSpec(source_alias="ghost", remote_path="/x")
        with pytest.raises(LiftError, match="not in inventory"):
            lift(spec, inv)

    def test_missing_remote_path_raises(self, tmp_path):
        inv = Inventory(path=tmp_path / "inv.json")
        inv.add(_entry("box"), capabilities=_caps("box"))

        spec = LiftSpec(source_alias="box", remote_path="/nonexistent")

        mock_transport = MagicMock()
        mock_transport.path_exists.return_value = False

        with patch("core.broker.lift._build_transport", return_value=mock_transport):
            with pytest.raises(LiftError, match="does not exist"):
                lift(spec, inv, staging_dir=str(tmp_path / "stage"))

    def test_successful_lift(self, tmp_path):
        inv = Inventory(path=tmp_path / "inv.json")
        inv.add(_entry("box"), capabilities=_caps("box"))

        stage = tmp_path / "stage"
        stage.mkdir()
        (stage / "target.elf").write_bytes(b"\x7fELF" + b"\x00" * 100)

        spec = LiftSpec(source_alias="box", remote_path="/opt/target.elf", unpack=False)

        mock_transport = MagicMock()
        mock_transport.path_exists.return_value = True

        def fake_download(remote, local):
            Path(local).write_bytes(b"\x7fELF" + b"\x00" * 100)

        mock_transport.download.side_effect = fake_download

        with patch("core.broker.lift._build_transport", return_value=mock_transport):
            lifted = lift(spec, inv, staging_dir=str(stage))

        assert lifted.source_alias == "box"
        assert lifted.original_name == "target.elf"
        assert lifted.size_bytes > 0
        assert os.path.exists(lifted.local_path)


class TestParseSourceSpec:
    def test_valid_parse(self):
        from core.broker.cli import _parse_source_spec

        alias, path = _parse_source_spec("pixel-7:/data/app/x.apk")
        assert alias == "pixel-7"
        assert path == "/data/app/x.apk"

    def test_windows_path(self):
        from core.broker.cli import _parse_source_spec

        alias, path = _parse_source_spec("win:C:\\Users\\x\\app.exe")
        assert alias == "win"
        assert path == "C:\\Users\\x\\app.exe"

    def test_missing_colon_raises(self):
        from core.broker.cli import _parse_source_spec

        with pytest.raises(ValueError, match="invalid source"):
            _parse_source_spec("just-an-alias")

    def test_empty_path_raises(self):
        from core.broker.cli import _parse_source_spec

        with pytest.raises(ValueError, match="invalid source"):
            _parse_source_spec("alias:")
