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
    rank_fleet,
    score_system,
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
