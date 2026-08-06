"""Tests for engagement planning and fleet negotiation."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.broker.capabilities import (
    Architecture,
    OperatingSystem,
    SystemCapabilities,
)
from core.broker.engage import (
    ENGAGEMENT_SCOPES,
    EngagementPlan,
    EngagementProposal,
    ModeAssignment,
    RoleAssignment,
    clear_engagement,
    confirm_engagement,
    format_plan,
    format_proposal,
    load_engagement,
    propose_engagement,
    save_engagement,
)
from core.broker.inventory import Inventory
from core.broker.transport import RemoteSystemEntry, TransportKind


def _entry(alias: str, host: str = "10.0.0.1", transport: TransportKind = TransportKind.SSH) -> RemoteSystemEntry:
    return RemoteSystemEntry(alias=alias, host=host, port=22, user="root", transport=transport)


def _caps(
    alias: str,
    *,
    os: OperatingSystem = OperatingSystem.LINUX,
    arch: Architecture = Architecture.X86_64,
    cores: int = 8,
    ram_mb: int = 16384,
    tools: frozenset[str] = frozenset({"semgrep", "git", "python3"}),
) -> SystemCapabilities:
    return SystemCapabilities(
        alias=alias, os=os, arch=arch, tools=tools,
        ram_mb=ram_mb, cores=cores, free_disk_mb=50000,
    )


def _build_fleet(tmp_path: Path) -> Inventory:
    inv = Inventory(path=tmp_path / "inv.json")

    inv.add(
        _entry("linux-arm", "10.0.0.1"),
        capabilities=_caps(
            "linux-arm", os=OperatingSystem.LINUX, arch=Architecture.AARCH64,
            tools=frozenset({"afl++", "gdb", "semgrep", "git", "python3"}),
        ),
    )
    inv.add(
        _entry("win-desktop", "10.0.0.2", TransportKind.WINRM),
        capabilities=_caps(
            "win-desktop", os=OperatingSystem.WINDOWS, cores=16, ram_mb=32768,
            tools=frozenset({"codeql", "windbg", "frida", "git", "python3"}),
        ),
    )
    inv.add(
        _entry("pixel-7", "localhost", TransportKind.ADB),
        capabilities=_caps(
            "pixel-7", os=OperatingSystem.ANDROID, arch=Architecture.AARCH64,
            cores=8, ram_mb=8192,
            tools=frozenset({"frida-server", "objection"}),
        ),
    )
    return inv


class TestEngagementScopes:
    def test_full_scope_has_all_key_modes(self):
        assert "scan" in ENGAGEMENT_SCOPES["full"]
        assert "fuzz" in ENGAGEMENT_SCOPES["full"]
        assert "codeql" in ENGAGEMENT_SCOPES["full"]

    def test_mobile_scope(self):
        assert "frida" in ENGAGEMENT_SCOPES["mobile"]

    def test_binary_scope(self):
        assert "fuzz" in ENGAGEMENT_SCOPES["binary"]


class TestProposeEngagement:
    def test_proposes_for_all_modes(self, tmp_path):
        inv = _build_fleet(tmp_path)
        modes = frozenset({"scan", "fuzz"})
        proposal = propose_engagement(inv, modes, "test target")

        assert proposal.target_description == "test target"
        assert proposal.modes == modes
        assert len(proposal.mode_assignments) == 2

    def test_fuzz_routes_to_linux(self, tmp_path):
        inv = _build_fleet(tmp_path)
        proposal = propose_engagement(inv, frozenset({"fuzz"}))

        fuzz_ma = [ma for ma in proposal.mode_assignments if ma.mode == "fuzz"]
        assert len(fuzz_ma) == 1
        assert fuzz_ma[0].primary_alias == "linux-arm"
        assert not fuzz_ma[0].unassignable

    def test_unassignable_mode_marked(self, tmp_path):
        inv = Inventory(path=tmp_path / "inv.json")
        inv.add(
            _entry("weak"),
            capabilities=_caps("weak", os=OperatingSystem.DARWIN),
        )
        proposal = propose_engagement(inv, frozenset({"fuzz"}))

        fuzz_ma = proposal.mode_assignments[0]
        assert fuzz_ma.unassignable is True

    def test_role_assignments_populated(self, tmp_path):
        inv = _build_fleet(tmp_path)
        proposal = propose_engagement(inv, frozenset({"scan", "fuzz"}))

        aliases = {ra.alias for ra in proposal.role_assignments}
        assert "linux-arm" in aliases
        assert "localhost" in aliases

    def test_fleet_summary_present(self, tmp_path):
        inv = _build_fleet(tmp_path)
        proposal = propose_engagement(inv, frozenset({"scan"}))
        assert "systems evaluated" in proposal.fleet_summary


class TestConfirmEngagement:
    def test_confirm_without_overrides(self, tmp_path):
        inv = _build_fleet(tmp_path)
        proposal = propose_engagement(inv, frozenset({"scan", "fuzz"}))
        plan = confirm_engagement(proposal)

        assert plan.modes == frozenset({"scan", "fuzz"})
        assert plan.confirmed_at > 0
        assert len(plan.overrides_applied) == 0

    def test_override_reassigns_mode(self, tmp_path):
        inv = _build_fleet(tmp_path)
        proposal = propose_engagement(inv, frozenset({"scan"}))
        plan = confirm_engagement(proposal, overrides={"scan": "win-desktop"})

        scan_ma = [ma for ma in plan.mode_assignments if ma.mode == "scan"]
        assert scan_ma[0].primary_alias == "win-desktop"
        assert len(plan.overrides_applied) == 1

    def test_exclude_promotes_fallback(self, tmp_path):
        inv = _build_fleet(tmp_path)
        proposal = propose_engagement(inv, frozenset({"scan"}))

        original = [ma for ma in proposal.mode_assignments if ma.mode == "scan"][0]
        primary = original.primary_alias

        plan = confirm_engagement(proposal, exclude=frozenset({primary}))
        scan_ma = [ma for ma in plan.mode_assignments if ma.mode == "scan"][0]
        assert scan_ma.primary_alias != primary
        assert primary in plan.excluded_aliases

    def test_exclude_all_makes_unassignable(self, tmp_path):
        inv = Inventory(path=tmp_path / "inv.json")
        inv.add(_entry("solo"), capabilities=_caps("solo"))
        proposal = propose_engagement(inv, frozenset({"scan"}))

        plan = confirm_engagement(
            proposal, exclude=frozenset({"solo", "localhost"}),
        )
        scan_ma = [ma for ma in plan.mode_assignments if ma.mode == "scan"][0]
        assert scan_ma.unassignable is True


class TestEngagementPlanLookup:
    def test_system_for_mode(self):
        plan = EngagementPlan(
            target_description="test",
            modes=frozenset({"scan", "fuzz"}),
            mode_assignments=(
                ModeAssignment(mode="scan", primary_alias="box-a", primary_score=10.0),
                ModeAssignment(mode="fuzz", primary_alias="box-b", primary_score=20.0),
            ),
            excluded_aliases=frozenset(),
        )
        assert plan.system_for_mode("scan") == "box-a"
        assert plan.system_for_mode("fuzz") == "box-b"
        assert plan.system_for_mode("web") is None

    def test_is_excluded(self):
        plan = EngagementPlan(
            target_description="test",
            modes=frozenset(),
            mode_assignments=(),
            excluded_aliases=frozenset({"bad-box"}),
        )
        assert plan.is_excluded("bad-box") is True
        assert plan.is_excluded("good-box") is False

    def test_fallback_for_mode(self):
        plan = EngagementPlan(
            target_description="test",
            modes=frozenset({"scan"}),
            mode_assignments=(
                ModeAssignment(
                    mode="scan", primary_alias="a", primary_score=10.0,
                    fallback_alias="b", fallback_score=8.0,
                ),
            ),
            excluded_aliases=frozenset(),
        )
        assert plan.fallback_for_mode("scan") == "b"


class TestEngagementPersistence:
    def test_save_and_load(self, tmp_path, monkeypatch):
        monkeypatch.setattr("core.broker.engage._ENGAGE_DIR", tmp_path)

        plan = EngagementPlan(
            target_description="persist test",
            modes=frozenset({"scan", "fuzz"}),
            mode_assignments=(
                ModeAssignment(mode="scan", primary_alias="box-a", primary_score=10.0),
                ModeAssignment(mode="fuzz", primary_alias="box-b", primary_score=20.0),
            ),
            excluded_aliases=frozenset({"bad"}),
            confirmed_at=1700000000.0,
            overrides_applied=("scan: box-c → box-a",),
        )
        save_engagement(plan)
        loaded = load_engagement()

        assert loaded is not None
        assert loaded.target_description == "persist test"
        assert loaded.modes == frozenset({"scan", "fuzz"})
        assert loaded.system_for_mode("scan") == "box-a"
        assert loaded.is_excluded("bad")
        assert len(loaded.overrides_applied) == 1

    def test_load_nonexistent(self, tmp_path, monkeypatch):
        monkeypatch.setattr("core.broker.engage._ENGAGE_DIR", tmp_path)
        assert load_engagement() is None

    def test_clear(self, tmp_path, monkeypatch):
        monkeypatch.setattr("core.broker.engage._ENGAGE_DIR", tmp_path)
        plan = EngagementPlan(
            target_description="x",
            modes=frozenset(),
            mode_assignments=(),
            excluded_aliases=frozenset(),
        )
        save_engagement(plan)
        assert load_engagement() is not None
        assert clear_engagement() is True
        assert load_engagement() is None
        assert clear_engagement() is False


class TestFormatProposal:
    def test_produces_output(self, tmp_path):
        inv = _build_fleet(tmp_path)
        proposal = propose_engagement(inv, frozenset({"scan", "fuzz"}), "test app")
        output = format_proposal(proposal)
        assert "test app" in output
        assert "Mode Assignments:" in output
        assert "System Roles:" in output


class TestFormatPlan:
    def test_produces_output(self):
        plan = EngagementPlan(
            target_description="test",
            modes=frozenset({"scan"}),
            mode_assignments=(
                ModeAssignment(mode="scan", primary_alias="box", primary_score=10.0),
            ),
            excluded_aliases=frozenset(),
            confirmed_at=1700000000.0,
        )
        output = format_plan(plan)
        assert "test" in output
        assert "scan" in output
        assert "box" in output
