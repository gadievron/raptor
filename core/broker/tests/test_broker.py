"""Tests for the top-level broker dispatcher."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from core.broker.broker import (
    Broker,
    BrokerError,
    LocalExecution,
    RemoteExecution,
)
from core.broker.capabilities import (
    Architecture,
    ModeRequirements,
    OperatingSystem,
    SystemCapabilities,
)
from core.broker.inventory import Inventory
from core.broker.transport import RemoteSystemEntry, TransportKind


@pytest.fixture
def linux_caps() -> SystemCapabilities:
    return SystemCapabilities(
        alias="localhost",
        os=OperatingSystem.LINUX,
        arch=Architecture.X86_64,
        tools=frozenset({"semgrep", "codeql", "gdb", "afl++"}),
        ram_mb=16384,
        cores=8,
        free_disk_mb=50000,
    )


@pytest.fixture
def macos_caps() -> SystemCapabilities:
    return SystemCapabilities(
        alias="localhost",
        os=OperatingSystem.DARWIN,
        arch=Architecture.AARCH64,
        tools=frozenset({"semgrep", "codeql"}),
        ram_mb=32768,
        cores=10,
        free_disk_mb=100000,
    )


@pytest.fixture
def remote_linux_entry() -> RemoteSystemEntry:
    return RemoteSystemEntry(
        alias="ci-linux",
        host="10.0.0.5",
        port=22,
        user="raptor",
        transport=TransportKind.SSH,
    )


@pytest.fixture
def remote_linux_caps() -> SystemCapabilities:
    return SystemCapabilities(
        alias="ci-linux",
        os=OperatingSystem.LINUX,
        arch=Architecture.X86_64,
        tools=frozenset({"afl++", "gdb", "semgrep", "codeql"}),
        ram_mb=32768,
        cores=16,
        free_disk_mb=200000,
    )


class TestBrokerResolveLocal:
    def test_scan_runs_anywhere(self, linux_caps, tmp_path):
        inv = Inventory(path=tmp_path / "inv.json")
        broker = Broker(inventory=inv)
        broker._local_caps = linux_caps

        result = broker.resolve("scan")
        assert isinstance(result, LocalExecution)
        assert result.verdict.met

    def test_fuzz_runs_on_linux(self, linux_caps, tmp_path):
        inv = Inventory(path=tmp_path / "inv.json")
        broker = Broker(inventory=inv)
        broker._local_caps = linux_caps

        result = broker.resolve("fuzz")
        assert isinstance(result, LocalExecution)

    def test_fuzz_fails_on_macos_no_remote(self, macos_caps, tmp_path):
        inv = Inventory(path=tmp_path / "inv.json")
        broker = Broker(inventory=inv)
        broker._local_caps = macos_caps

        with pytest.raises(BrokerError, match="no system capable"):
            broker.resolve("fuzz")


class TestBrokerResolveRemote:
    @patch("core.broker.broker._build_transport")
    def test_routes_to_remote_when_local_fails(
        self,
        mock_transport_factory,
        macos_caps,
        remote_linux_entry,
        remote_linux_caps,
        tmp_path,
    ):
        mock_transport = MagicMock()
        mock_transport_factory.return_value = mock_transport

        inv = Inventory(path=tmp_path / "inv.json")
        inv.add(remote_linux_entry, remote_linux_caps)

        broker = Broker(inventory=inv)
        broker._local_caps = macos_caps

        result = broker.resolve("fuzz")
        assert isinstance(result, RemoteExecution)
        assert result.entry.alias == "ci-linux"
        mock_transport.connect.assert_called_once()
        mock_transport.mkdir.assert_called_once()

    def test_prefers_local_when_capable(self, linux_caps, tmp_path):
        inv = Inventory(path=tmp_path / "inv.json")
        broker = Broker(inventory=inv)
        broker._local_caps = linux_caps

        result = broker.resolve("fuzz")
        assert isinstance(result, LocalExecution)


class TestBrokerLocalCapabilities:
    @patch("core.broker.capabilities.SystemCapabilities.detect_local")
    def test_caches_local_caps(self, mock_detect, tmp_path):
        mock_detect.return_value = SystemCapabilities(
            alias="localhost",
            os=OperatingSystem.LINUX,
            arch=Architecture.X86_64,
        )
        inv = Inventory(path=tmp_path / "inv.json")
        broker = Broker(inventory=inv)

        _ = broker.local_capabilities
        _ = broker.local_capabilities
        mock_detect.assert_called_once()
