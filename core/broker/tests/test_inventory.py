"""Tests for the broker inventory (persistence layer)."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from core.broker.capabilities import (
    Architecture,
    ModeRequirements,
    OperatingSystem,
    SystemCapabilities,
)
from core.broker.inventory import Inventory
from core.broker.transport import RemoteSystemEntry, TransportKind


@pytest.fixture
def tmp_inventory(tmp_path: Path) -> Inventory:
    return Inventory(path=tmp_path / "inventory.json")


@pytest.fixture
def sample_entry() -> RemoteSystemEntry:
    return RemoteSystemEntry(
        alias="linux-box",
        host="10.0.0.5",
        port=22,
        user="raptor",
        transport=TransportKind.SSH,
        key_path="/home/raptor/.ssh/id_ed25519",
        labels=frozenset({"ci-runner"}),
    )


@pytest.fixture
def sample_caps() -> SystemCapabilities:
    return SystemCapabilities(
        alias="linux-box",
        os=OperatingSystem.LINUX,
        arch=Architecture.X86_64,
        tools=frozenset({"semgrep", "codeql", "afl++", "gdb"}),
        ram_mb=32768,
        cores=16,
        free_disk_mb=100000,
    )


class TestInventoryCRUD:
    def test_add_and_get(self, tmp_inventory, sample_entry, sample_caps):
        tmp_inventory.add(sample_entry, sample_caps)
        got = tmp_inventory.get("linux-box")
        assert got is not None
        assert got.host == "10.0.0.5"
        assert got.user == "raptor"

    def test_list_all(self, tmp_inventory, sample_entry):
        tmp_inventory.add(sample_entry)
        systems = tmp_inventory.list_all()
        assert len(systems) == 1
        assert systems[0].alias == "linux-box"

    def test_remove(self, tmp_inventory, sample_entry):
        tmp_inventory.add(sample_entry)
        assert tmp_inventory.remove("linux-box")
        assert tmp_inventory.get("linux-box") is None

    def test_remove_nonexistent(self, tmp_inventory):
        assert not tmp_inventory.remove("ghost")

    def test_capabilities_stored(self, tmp_inventory, sample_entry, sample_caps):
        tmp_inventory.add(sample_entry, sample_caps)
        caps = tmp_inventory.get_capabilities("linux-box")
        assert caps is not None
        assert caps.os == OperatingSystem.LINUX
        assert "afl++" in caps.tools
        assert caps.ram_mb == 32768


class TestInventoryPersistence:
    def test_roundtrip(self, tmp_path, sample_entry, sample_caps):
        path = tmp_path / "inventory.json"
        inv1 = Inventory(path=path)
        inv1.add(sample_entry, sample_caps)

        inv2 = Inventory(path=path)
        got = inv2.get("linux-box")
        assert got is not None
        assert got.host == "10.0.0.5"
        caps = inv2.get_capabilities("linux-box")
        assert caps is not None
        assert caps.cores == 16

    def test_empty_load(self, tmp_path):
        inv = Inventory(path=tmp_path / "does-not-exist.json")
        assert inv.list_all() == []

    def test_corrupt_json(self, tmp_path):
        path = tmp_path / "bad.json"
        path.write_text("not json!!!")
        inv = Inventory(path=path)
        assert inv.list_all() == []


class TestFindCapable:
    def test_finds_matching_system(self, tmp_inventory, sample_entry, sample_caps):
        tmp_inventory.add(sample_entry, sample_caps)
        reqs = ModeRequirements(
            mode="fuzz",
            os=OperatingSystem.LINUX,
            tools=frozenset({"afl++"}),
        )
        matches = tmp_inventory.find_capable(reqs)
        assert len(matches) == 1
        assert matches[0][0].alias == "linux-box"

    def test_no_match_wrong_os(self, tmp_inventory, sample_entry, sample_caps):
        tmp_inventory.add(sample_entry, sample_caps)
        reqs = ModeRequirements(
            mode="wintest",
            os=OperatingSystem.WINDOWS,
        )
        matches = tmp_inventory.find_capable(reqs)
        assert len(matches) == 0

    def test_label_merge(self, tmp_inventory, sample_entry, sample_caps):
        tmp_inventory.add(sample_entry, sample_caps)
        reqs = ModeRequirements(
            mode="ci",
            labels=frozenset({"ci-runner"}),
        )
        matches = tmp_inventory.find_capable(reqs)
        assert len(matches) == 1


class TestRemoteSystemEntrySerde:
    def test_roundtrip(self, sample_entry):
        d = sample_entry.to_dict()
        restored = RemoteSystemEntry.from_dict(d)
        assert restored == sample_entry

    def test_defaults(self):
        entry = RemoteSystemEntry.from_dict({"alias": "x", "host": "1.2.3.4"})
        assert entry.port == 22
        assert entry.user == "root"
        assert entry.transport == TransportKind.SSH
