"""Tests for task routing and assignment."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.broker.capabilities import (
    Architecture,
    OperatingSystem,
    SystemCapabilities,
)
from core.broker.inventory import Inventory
from core.broker.tasks import (
    TaskAssignment,
    TaskHandle,
    TaskResult,
    TaskRouter,
    TaskRoutingError,
    TaskSpec,
    TaskState,
    _generate_task_id,
    _load_task_handle,
    _remove_task_handle,
    _save_task_handle,
    _TASK_STATE_DIR,
)
from core.broker.transport import RemoteSystemEntry, TransportKind


def _entry(alias: str, host: str = "10.0.0.1") -> RemoteSystemEntry:
    return RemoteSystemEntry(
        alias=alias, host=host, port=22, user="root",
        transport=TransportKind.SSH,
    )


def _caps(
    alias: str,
    *,
    cores: int = 8,
    ram_mb: int = 16384,
    os: OperatingSystem = OperatingSystem.LINUX,
    tools: frozenset[str] = frozenset({"semgrep", "git", "python3"}),
) -> SystemCapabilities:
    return SystemCapabilities(
        alias=alias, os=os, arch=Architecture.X86_64,
        tools=tools, ram_mb=ram_mb, cores=cores,
        free_disk_mb=50000,
    )


class TestTaskSpec:
    def test_frozen(self):
        spec = TaskSpec(mode="fuzz", target_path="/src")
        with pytest.raises(AttributeError):
            spec.mode = "scan"

    def test_url_target(self):
        spec = TaskSpec(mode="web", target_path="https://target.com")
        assert spec.is_url_target is True

    def test_local_target(self):
        spec = TaskSpec(mode="fuzz", target_path="/home/user/src")
        assert spec.is_url_target is False


class TestGenerateTaskId:
    def test_length(self):
        spec = TaskSpec(mode="fuzz", target_path="/src")
        tid = _generate_task_id(spec)
        assert len(tid) == 12

    def test_hex(self):
        spec = TaskSpec(mode="scan", target_path="/src")
        tid = _generate_task_id(spec)
        int(tid, 16)  # raises if not hex


class TestTaskRouter:
    def _inventory(self, tmp_path: Path, systems: list) -> Inventory:
        inv = Inventory(path=tmp_path / "inv.json")
        for entry, caps in systems:
            inv.add(entry, capabilities=caps)
        return inv

    def test_routes_to_best_scorer(self, tmp_path):
        weak = (_entry("weak"), _caps("weak", cores=2, ram_mb=4096))
        strong = (_entry("strong", "10.0.0.2"), _caps("strong", cores=32, ram_mb=65536))
        inv = self._inventory(tmp_path, [weak, strong])

        router = TaskRouter(inv)
        assignment = router.route(TaskSpec(mode="scan", target_path="/src"))

        assert assignment.system.entry.alias == "strong"
        assert len(assignment.alternatives) == 1
        assert assignment.alternatives[0].entry.alias == "weak"

    def test_respects_prefer_alias(self, tmp_path):
        a = (_entry("alpha"), _caps("alpha", cores=4))
        b = (_entry("beta", "10.0.0.2"), _caps("beta", cores=32))
        inv = self._inventory(tmp_path, [a, b])

        router = TaskRouter(inv)
        assignment = router.route(
            TaskSpec(mode="scan", target_path="/src", prefer_alias="alpha"),
        )
        assert assignment.system.entry.alias == "alpha"
        assert "preference" in assignment.reason

    def test_prefer_alias_fallback_when_incapable(self, tmp_path):
        linux = (
            _entry("linux"),
            _caps("linux", os=OperatingSystem.LINUX, tools=frozenset({"afl++", "gdb"})),
        )
        mac = (
            _entry("mac", "10.0.0.2"),
            _caps("mac", os=OperatingSystem.DARWIN),
        )
        inv = self._inventory(tmp_path, [linux, mac])

        router = TaskRouter(inv)
        assignment = router.route(
            TaskSpec(mode="fuzz", target_path="/src", prefer_alias="mac"),
        )
        assert assignment.system.entry.alias == "linux"
        assert "not capable" in assignment.reason

    def test_raises_on_empty_fleet(self, tmp_path):
        inv = Inventory(path=tmp_path / "inv.json")
        router = TaskRouter(inv)

        with pytest.raises(TaskRoutingError, match="no systems registered"):
            router.route(TaskSpec(mode="scan", target_path="/src"))

    def test_raises_when_none_capable(self, tmp_path):
        mac = (
            _entry("mac"),
            _caps("mac", os=OperatingSystem.DARWIN),
        )
        inv = self._inventory(tmp_path, [mac])
        router = TaskRouter(inv)

        with pytest.raises(TaskRoutingError, match="no fleet member"):
            router.route(TaskSpec(mode="fuzz", target_path="/src"))

    def test_assignment_has_task_id(self, tmp_path):
        sys = (_entry("box"), _caps("box"))
        inv = self._inventory(tmp_path, [sys])
        router = TaskRouter(inv)
        assignment = router.route(TaskSpec(mode="scan", target_path="/src"))
        assert len(assignment.task_id) == 12


class TestTaskResult:
    def test_frozen(self):
        result = TaskResult(
            task_id="abc123", state=TaskState.COMPLETED,
            system_alias="box",
        )
        with pytest.raises(AttributeError):
            result.state = TaskState.FAILED

    def test_default_fields(self):
        result = TaskResult(
            task_id="abc123", state=TaskState.PENDING,
            system_alias="box",
        )
        assert result.exit_code is None
        assert result.stdout == ""
        assert result.output_dir is None


class TestTaskHandlePersistence:
    def test_save_and_load(self, tmp_path, monkeypatch):
        monkeypatch.setattr("core.broker.tasks._TASK_STATE_DIR", tmp_path)
        handle = TaskHandle(
            task_id="abc123",
            system_alias="linux-box",
            workspace="/tmp/raptor-task-abc123",
            backend="tmux",
            started_at=1700000000.0,
            spec_mode="fuzz",
            spec_target="/src",
        )
        _save_task_handle(handle)
        loaded = _load_task_handle("abc123")
        assert loaded is not None
        assert loaded.task_id == "abc123"
        assert loaded.system_alias == "linux-box"
        assert loaded.backend == "tmux"
        assert loaded.spec_mode == "fuzz"

    def test_load_nonexistent(self, tmp_path, monkeypatch):
        monkeypatch.setattr("core.broker.tasks._TASK_STATE_DIR", tmp_path)
        assert _load_task_handle("nonexistent") is None

    def test_remove(self, tmp_path, monkeypatch):
        monkeypatch.setattr("core.broker.tasks._TASK_STATE_DIR", tmp_path)
        handle = TaskHandle(
            task_id="del123",
            system_alias="box",
            workspace="/tmp/x",
            backend="tmux",
            started_at=1700000000.0,
            spec_mode="scan",
            spec_target="/src",
        )
        _save_task_handle(handle)
        assert _load_task_handle("del123") is not None
        _remove_task_handle("del123")
        assert _load_task_handle("del123") is None


class TestTaskSpec:
    def test_detach_flag(self):
        spec = TaskSpec(mode="fuzz", target_path="/src", detach=True)
        assert spec.detach is True
