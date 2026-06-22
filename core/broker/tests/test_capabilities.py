"""Tests for the capability model."""

from __future__ import annotations

from core.broker.capabilities import (
    Architecture,
    CapabilityVerdict,
    ModeRequirements,
    OperatingSystem,
    SystemCapabilities,
)


def _make_system(**overrides) -> SystemCapabilities:
    defaults = {
        "alias": "test",
        "os": OperatingSystem.LINUX,
        "arch": Architecture.X86_64,
        "tools": frozenset({"semgrep", "codeql", "gdb"}),
        "ram_mb": 16384,
        "cores": 8,
        "free_disk_mb": 50000,
        "labels": frozenset(),
    }
    defaults.update(overrides)
    return SystemCapabilities(**defaults)


class TestSystemCapabilitiesSatisfies:
    def test_empty_requirements_always_met(self):
        sys = _make_system()
        reqs = ModeRequirements(mode="scan")
        verdict = sys.satisfies(reqs)
        assert verdict.met
        assert verdict.summary() == "all requirements satisfied"

    def test_os_mismatch(self):
        sys = _make_system(os=OperatingSystem.DARWIN)
        reqs = ModeRequirements(mode="fuzz", os=OperatingSystem.LINUX)
        verdict = sys.satisfies(reqs)
        assert not verdict.met
        assert verdict.missing_os == OperatingSystem.LINUX

    def test_arch_mismatch(self):
        sys = _make_system(arch=Architecture.AARCH64)
        reqs = ModeRequirements(mode="test", arch=Architecture.X86_64)
        verdict = sys.satisfies(reqs)
        assert not verdict.met
        assert verdict.missing_arch == Architecture.X86_64

    def test_missing_tools(self):
        sys = _make_system(tools=frozenset({"semgrep"}))
        reqs = ModeRequirements(
            mode="codeql", tools=frozenset({"semgrep", "codeql"})
        )
        verdict = sys.satisfies(reqs)
        assert not verdict.met
        assert "codeql" in verdict.missing_tools

    def test_all_tools_present(self):
        sys = _make_system(tools=frozenset({"afl++", "gdb"}))
        reqs = ModeRequirements(
            mode="fuzz",
            os=OperatingSystem.LINUX,
            tools=frozenset({"afl++"}),
        )
        verdict = sys.satisfies(reqs)
        assert verdict.met

    def test_ram_shortfall(self):
        sys = _make_system(ram_mb=1024)
        reqs = ModeRequirements(mode="codeql", min_ram_mb=4096)
        verdict = sys.satisfies(reqs)
        assert not verdict.met
        assert verdict.ram_shortfall_mb == 3072

    def test_labels_check(self):
        sys = _make_system(labels=frozenset({"gpu"}))
        reqs = ModeRequirements(
            mode="ml", labels=frozenset({"gpu", "cuda"})
        )
        verdict = sys.satisfies(reqs)
        assert not verdict.met
        assert "cuda" in verdict.missing_labels

    def test_full_match(self):
        sys = _make_system(
            os=OperatingSystem.LINUX,
            arch=Architecture.X86_64,
            tools=frozenset({"afl++", "gdb"}),
            ram_mb=8192,
            cores=4,
        )
        reqs = ModeRequirements(
            mode="fuzz",
            os=OperatingSystem.LINUX,
            tools=frozenset({"afl++"}),
            min_ram_mb=2048,
            min_cores=2,
        )
        verdict = sys.satisfies(reqs)
        assert verdict.met


class TestOperatingSystem:
    def test_known_values(self):
        assert OperatingSystem("linux") == OperatingSystem.LINUX
        assert OperatingSystem("darwin") == OperatingSystem.DARWIN
        assert OperatingSystem("windows") == OperatingSystem.WINDOWS


class TestArchitecture:
    def test_arm_detection(self):
        assert Architecture.AARCH64.is_arm()
        assert Architecture.ARM64.is_arm()
        assert not Architecture.X86_64.is_arm()


class TestCapabilityVerdictSummary:
    def test_met_summary(self):
        v = CapabilityVerdict(met=True)
        assert v.summary() == "all requirements satisfied"

    def test_compound_failures(self):
        v = CapabilityVerdict(
            met=False,
            missing_os=OperatingSystem.LINUX,
            missing_tools=frozenset({"afl++"}),
            ram_shortfall_mb=1024,
        )
        s = v.summary()
        assert "linux" in s
        assert "afl++" in s
        assert "1024" in s
