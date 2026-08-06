"""Tests for the top-level broker dispatcher.

The broker scores every system (local + fleet) and routes to the best
one.  Local has no automatic preference — it wins only when its score
is highest (with a small tiebreak to avoid unnecessary transport).
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from core.broker.broker import (
    Broker,
    BrokerError,
    LocalExecution,
    RemoteExecution,
    _LOCAL_TIEBREAK,
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
    """Modest local Linux box — 8 cores, 16 GB."""
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
    """macOS laptop — good RAM but no AFL/fuzz tools."""
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
    """Beefy CI box — 2x cores, 2x RAM vs the local fixture."""
    return SystemCapabilities(
        alias="ci-linux",
        os=OperatingSystem.LINUX,
        arch=Architecture.X86_64,
        tools=frozenset({"afl++", "gdb", "semgrep", "codeql"}),
        ram_mb=32768,
        cores=16,
        free_disk_mb=200000,
    )


class TestBrokerScoreBasedRouting:
    """Verify the broker routes to the highest-scoring system."""

    def test_local_wins_when_no_fleet(self, linux_caps, tmp_path):
        inv = Inventory(path=tmp_path / "inv.json")
        broker = Broker(inventory=inv)
        broker._local_caps = linux_caps

        result = broker.resolve("scan")
        assert isinstance(result, LocalExecution)
        assert result.verdict.met

    def test_local_wins_when_no_fleet_fuzz(self, linux_caps, tmp_path):
        inv = Inventory(path=tmp_path / "inv.json")
        broker = Broker(inventory=inv)
        broker._local_caps = linux_caps

        result = broker.resolve("fuzz")
        assert isinstance(result, LocalExecution)

    def test_fuzz_fails_when_nothing_capable(self, macos_caps, tmp_path):
        inv = Inventory(path=tmp_path / "inv.json")
        broker = Broker(inventory=inv)
        broker._local_caps = macos_caps

        with pytest.raises(BrokerError, match="no system capable"):
            broker.resolve("fuzz")

    @patch("core.broker.broker._build_transport")
    def test_beefy_remote_beats_modest_local(
        self,
        mock_transport_factory,
        linux_caps,
        remote_linux_entry,
        remote_linux_caps,
        tmp_path,
    ):
        """A 16-core remote should beat an 8-core local for fuzzing."""
        mock_transport = MagicMock()
        mock_transport_factory.return_value = mock_transport

        inv = Inventory(path=tmp_path / "inv.json")
        inv.add(remote_linux_entry, remote_linux_caps)

        broker = Broker(inventory=inv)
        broker._local_caps = linux_caps

        result = broker.resolve("fuzz")
        assert isinstance(result, RemoteExecution)
        assert result.entry.alias == "ci-linux"

    def test_local_wins_tiebreak_equal_specs(self, tmp_path):
        """When local and remote are identical, local wins (avoids transport)."""
        identical = SystemCapabilities(
            alias="localhost",
            os=OperatingSystem.LINUX,
            arch=Architecture.X86_64,
            tools=frozenset({"semgrep"}),
            ram_mb=8192,
            cores=4,
            free_disk_mb=20000,
        )
        remote_entry = RemoteSystemEntry(
            alias="twin",
            host="10.0.0.9",
            port=22,
            user="raptor",
            transport=TransportKind.SSH,
        )
        remote_caps = SystemCapabilities(
            alias="twin",
            os=OperatingSystem.LINUX,
            arch=Architecture.X86_64,
            tools=frozenset({"semgrep"}),
            ram_mb=8192,
            cores=4,
            free_disk_mb=20000,
        )
        inv = Inventory(path=tmp_path / "inv.json")
        inv.add(remote_entry, remote_caps)

        broker = Broker(inventory=inv)
        broker._local_caps = identical

        result = broker.resolve("scan")
        assert isinstance(result, LocalExecution)

    @patch("core.broker.broker._build_transport")
    def test_scan_routes_to_better_remote(
        self,
        mock_transport_factory,
        tmp_path,
    ):
        """Even for scan (no OS requirement), a much better remote wins."""
        mock_transport = MagicMock()
        mock_transport_factory.return_value = mock_transport

        weak_local = SystemCapabilities(
            alias="localhost",
            os=OperatingSystem.DARWIN,
            arch=Architecture.AARCH64,
            tools=frozenset({"semgrep"}),
            ram_mb=8192,
            cores=4,
            free_disk_mb=10000,
        )
        strong_entry = RemoteSystemEntry(
            alias="beast",
            host="10.0.0.20",
            port=22,
            user="raptor",
            transport=TransportKind.SSH,
        )
        strong_caps = SystemCapabilities(
            alias="beast",
            os=OperatingSystem.LINUX,
            arch=Architecture.X86_64,
            tools=frozenset({"semgrep", "codeql"}),
            ram_mb=131072,
            cores=64,
            free_disk_mb=500000,
        )
        inv = Inventory(path=tmp_path / "inv.json")
        inv.add(strong_entry, strong_caps)

        broker = Broker(inventory=inv)
        broker._local_caps = weak_local

        result = broker.resolve("scan")
        assert isinstance(result, RemoteExecution)
        assert result.entry.alias == "beast"


class TestBrokerResolveIncapableLocal:
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
