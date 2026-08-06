"""Tests for resource-aware fleet scoring."""

from __future__ import annotations

import pytest

from core.broker.capabilities import (
    Architecture,
    ModeRequirements,
    OperatingSystem,
    SystemCapabilities,
)
from core.broker.scoring import (
    MODE_RESOURCE_WEIGHTS,
    ResourceWeights,
    ScoredSystem,
    TaskConstraints,
    TOOL_PLATFORM_MATRIX,
    rank_fleet,
    score_system,
    tool_available_on,
)
from core.broker.transport import RemoteSystemEntry, TransportKind


def _caps(
    *,
    cores: int = 4,
    ram_mb: int = 8192,
    disk_mb: int = 50000,
    tools: frozenset[str] = frozenset(),
    os: OperatingSystem = OperatingSystem.LINUX,
    arch: Architecture = Architecture.X86_64,
    labels: frozenset[str] = frozenset(),
) -> SystemCapabilities:
    return SystemCapabilities(
        alias="test",
        os=os,
        arch=arch,
        tools=tools,
        ram_mb=ram_mb,
        cores=cores,
        free_disk_mb=disk_mb,
        labels=labels,
    )


def _entry(alias: str = "test", **kwargs) -> RemoteSystemEntry:
    defaults = dict(
        alias=alias, host="10.0.0.1", port=22, user="root",
        transport=TransportKind.SSH,
    )
    defaults.update(kwargs)
    return RemoteSystemEntry(**defaults)


class TestScoreSystem:
    def test_more_cores_scores_higher_for_fuzz(self):
        few = _caps(cores=4)
        many = _caps(cores=32)
        assert score_system(many, "fuzz") > score_system(few, "fuzz")

    def test_more_ram_scores_higher_for_codeql(self):
        low = _caps(ram_mb=4096)
        high = _caps(ram_mb=65536)
        assert score_system(high, "codeql") > score_system(low, "codeql")

    def test_fuzz_weights_cores_over_ram(self):
        core_heavy = _caps(cores=32, ram_mb=4096)
        ram_heavy = _caps(cores=4, ram_mb=65536)
        assert score_system(core_heavy, "fuzz") > score_system(ram_heavy, "fuzz")

    def test_codeql_weights_ram_over_cores(self):
        core_heavy = _caps(cores=32, ram_mb=4096)
        ram_heavy = _caps(cores=4, ram_mb=65536)
        assert score_system(ram_heavy, "codeql") > score_system(core_heavy, "codeql")

    def test_tool_bonus_significant(self):
        no_tools = _caps(cores=8, tools=frozenset())
        with_tools = _caps(cores=8, tools=frozenset({"afl++", "gdb"}))
        assert score_system(with_tools, "fuzz") > score_system(no_tools, "fuzz")

    def test_unknown_mode_uses_default_weights(self):
        caps = _caps(cores=8, ram_mb=16384)
        score = score_system(caps, "nonexistent-mode")
        assert score > 0

    def test_zero_resources_score_zero_component(self):
        caps = _caps(cores=0, ram_mb=0, disk_mb=0)
        assert score_system(caps, "scan") == 0.0

    def test_score_is_float(self):
        caps = _caps()
        assert isinstance(score_system(caps, "fuzz"), float)


_FUZZ_TOOLS = frozenset({"afl++"})


class TestRankFleet:
    def test_best_first(self):
        a = (_entry("weak"), _caps(cores=2, ram_mb=4096, os=OperatingSystem.LINUX, tools=_FUZZ_TOOLS))
        b = (_entry("strong"), _caps(cores=32, ram_mb=65536, os=OperatingSystem.LINUX, tools=_FUZZ_TOOLS))
        ranked = rank_fleet([a, b], "fuzz")
        assert ranked[0].entry.alias == "strong"
        assert ranked[1].entry.alias == "weak"

    def test_filters_incapable(self):
        linux = (_entry("linux"), _caps(os=OperatingSystem.LINUX, tools=_FUZZ_TOOLS))
        macos = (_entry("mac"), _caps(os=OperatingSystem.DARWIN))
        ranked = rank_fleet([linux, macos], "fuzz", require_capable=True)
        aliases = [s.entry.alias for s in ranked]
        assert "linux" in aliases
        assert "mac" not in aliases

    def test_include_incapable_when_requested(self):
        linux = (_entry("linux"), _caps(os=OperatingSystem.LINUX, tools=_FUZZ_TOOLS))
        macos = (_entry("mac"), _caps(os=OperatingSystem.DARWIN))
        ranked = rank_fleet([linux, macos], "fuzz", require_capable=False)
        assert len(ranked) == 2

    def test_label_filter(self):
        gpu = (_entry("gpu"), _caps(labels=frozenset({"gpu"}), os=OperatingSystem.LINUX, tools=_FUZZ_TOOLS))
        plain = (_entry("plain"), _caps(os=OperatingSystem.LINUX, tools=_FUZZ_TOOLS))
        ranked = rank_fleet(
            [gpu, plain], "fuzz", labels=frozenset({"gpu"}),
        )
        assert len(ranked) == 1
        assert ranked[0].entry.alias == "gpu"

    def test_empty_fleet(self):
        ranked = rank_fleet([], "fuzz")
        assert ranked == []

    def test_entry_labels_merged(self):
        entry = _entry("tagged", labels=frozenset({"gpu"}))
        caps = _caps(labels=frozenset())
        ranked = rank_fleet(
            [(entry, caps)], "scan", labels=frozenset({"gpu"}),
        )
        assert len(ranked) == 1


class TestToolAvailableOn:
    def test_afl_on_linux_x86(self):
        assert tool_available_on("afl++", OperatingSystem.LINUX, Architecture.X86_64)

    def test_afl_not_on_windows(self):
        assert not tool_available_on("afl++", OperatingSystem.WINDOWS, Architecture.X86_64)

    def test_rr_only_linux_x86(self):
        assert tool_available_on("rr", OperatingSystem.LINUX, Architecture.X86_64)
        assert not tool_available_on("rr", OperatingSystem.LINUX, Architecture.AARCH64)

    def test_codeql_cross_platform(self):
        assert tool_available_on("codeql", OperatingSystem.LINUX, Architecture.X86_64)
        assert tool_available_on("codeql", OperatingSystem.DARWIN, Architecture.AARCH64)
        assert tool_available_on("codeql", OperatingSystem.WINDOWS, Architecture.X86_64)

    def test_unknown_tool_assumed_portable(self):
        assert tool_available_on("mytool", OperatingSystem.WINDOWS, Architecture.AARCH64)

    def test_windbg_only_windows(self):
        assert tool_available_on("windbg", OperatingSystem.WINDOWS, Architecture.X86_64)
        assert not tool_available_on("windbg", OperatingSystem.LINUX, Architecture.X86_64)


class TestTaskConstraints:
    def test_frozen(self):
        c = TaskConstraints(require_os=OperatingSystem.LINUX)
        with pytest.raises(AttributeError):
            c.require_os = OperatingSystem.WINDOWS

    def test_defaults_are_none(self):
        c = TaskConstraints()
        assert c.require_os is None
        assert c.require_arch is None
        assert c.require_transport is None
        assert c.require_tools == frozenset()


class TestHardGates:
    def test_require_os_excludes_mismatch(self):
        linux = (_entry("lin"), _caps(os=OperatingSystem.LINUX))
        windows = (
            _entry("win", host="10.0.0.2", transport=TransportKind.WINRM),
            _caps(os=OperatingSystem.WINDOWS),
        )
        constraints = TaskConstraints(require_os=OperatingSystem.LINUX)
        ranked = rank_fleet(
            [linux, windows], "scan", constraints=constraints,
        )
        assert len(ranked) == 1
        assert ranked[0].entry.alias == "lin"

    def test_require_arch_excludes_mismatch(self):
        x86 = (_entry("x86"), _caps(arch=Architecture.X86_64))
        arm = (_entry("arm", host="10.0.0.2"), _caps(arch=Architecture.AARCH64))
        constraints = TaskConstraints(require_arch=Architecture.X86_64)
        ranked = rank_fleet(
            [x86, arm], "scan", constraints=constraints,
        )
        assert len(ranked) == 1
        assert ranked[0].entry.alias == "x86"

    def test_require_transport_excludes_mismatch(self):
        ssh_sys = (_entry("ssh"), _caps())
        winrm_sys = (
            _entry("winrm", host="10.0.0.2", transport=TransportKind.WINRM),
            _caps(os=OperatingSystem.WINDOWS),
        )
        constraints = TaskConstraints(require_transport=TransportKind.SSH)
        ranked = rank_fleet(
            [ssh_sys, winrm_sys], "scan", constraints=constraints,
        )
        assert len(ranked) == 1
        assert ranked[0].entry.alias == "ssh"

    def test_require_tools_excludes_missing(self):
        has = (_entry("has"), _caps(tools=frozenset({"gdb", "afl++"})))
        lacks = (_entry("lacks", host="10.0.0.2"), _caps(tools=frozenset({"gdb"})))
        constraints = TaskConstraints(require_tools=frozenset({"afl++"}))
        ranked = rank_fleet(
            [has, lacks], "scan", constraints=constraints,
        )
        assert len(ranked) == 1
        assert ranked[0].entry.alias == "has"


class TestSoftBonuses:
    def test_prefer_os_boosts_score(self):
        caps = _caps(os=OperatingSystem.LINUX, cores=8)
        entry = _entry()
        constraints = TaskConstraints(prefer_os=OperatingSystem.LINUX)
        boosted = score_system(caps, "scan", constraints=constraints, entry=entry)
        unboosted = score_system(caps, "scan")
        assert boosted > unboosted

    def test_prefer_transport_boosts_score(self):
        caps = _caps()
        entry = _entry(transport=TransportKind.SSH)
        constraints = TaskConstraints(prefer_transport=TransportKind.SSH)
        boosted = score_system(caps, "scan", constraints=constraints, entry=entry)
        unboosted = score_system(caps, "scan")
        assert boosted > unboosted

    def test_prefer_arch_boosts_score(self):
        caps = _caps(arch=Architecture.X86_64)
        entry = _entry()
        constraints = TaskConstraints(prefer_arch=Architecture.X86_64)
        boosted = score_system(caps, "scan", constraints=constraints, entry=entry)
        unboosted = score_system(caps, "scan")
        assert boosted > unboosted
