"""The host-consent leg of the untrusted-floor consent chain.

Precedence matrix (flag > project > env > host-consent > default),
the ns-only-single-value guard, conditional-inertness transitions
through the real marker store, and the visibility contract (one
banner per process; the per-call consented-degrade warning collapses
to one notice per process under the host source).
"""

from __future__ import annotations

import logging
import subprocess
import sys
import types

import pytest

from core.sandbox import context as _ctx
from core.sandbox import host_consent as hc
from core.sandbox import state
from core.sandbox import tiers as _tiers
from core.sandbox.errors import SandboxFloorError
from core.sandbox.tiers import ContainmentTier

WSL2_RELEASE = "5.15.167.4-microsoft-standard-WSL2"
MACHINE_ID = "0123456789abcdef0123456789abcdef"


def _ok_spawn(cmd, **kwargs):
    return subprocess.CompletedProcess(cmd, returncode=0,
                                       stdout="", stderr="")


@pytest.fixture()
def host_consent_active(monkeypatch):
    """Mock the marker store's verdict: the host consent APPLIES."""
    monkeypatch.setattr(
        "core.sandbox.host_consent.host_consented_floor",
        lambda: "ns-only")
    monkeypatch.setattr(
        "core.sandbox.host_consent.applied_consent",
        lambda: hc.HostConsent(floor="ns-only",
                               granted_at="2026-09-24T10:00:00+00:00",
                               kernel_identity=WSL2_RELEASE))


@pytest.fixture()
def no_env_waiver(monkeypatch):
    monkeypatch.delenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", raising=False)


# ─── unit: tiers.resolve_call_floor host leg ─────────────────────────

class TestResolveCallFloorHostLeg:
    def test_host_supplies_ns_only_on_the_default_refusal_arms(self):
        """Both fail-closed default arms — the derived/literal
        fresh-procfs contract and the underived untrusted-workload
        mark — resolve to (ns-only, host-consent) under the marker."""
        for shape in (
            {"require_fresh_procfs": True, "untrusted_workload": True},
            {"require_fresh_procfs": True, "untrusted_workload": False},
            {"require_fresh_procfs": None, "untrusted_workload": True},
        ):
            got = _tiers.resolve_call_floor(
                operator_disabled=False, waiver_active=False,
                host_floor=ContainmentTier.NS_NOMOUNT, **shape)
            assert got == (ContainmentTier.NS_NOMOUNT,
                           "host-consent"), (shape, got)

    def test_host_never_floors_trusted_calls(self):
        got = _tiers.resolve_call_floor(
            operator_disabled=False, require_fresh_procfs=None,
            untrusted_workload=False,
            host_floor=ContainmentTier.NS_NOMOUNT)
        assert got == (ContainmentTier.BARE, "default")

    def test_explicit_surfaces_beat_host_both_directions(self):
        """A project/flag floor is never MOVED by the marker: a higher
        explicit floor stays (never lowered), and a lower explicit
        floor stays too (the marker replaces only the default
        refusal, never a chosen floor)."""
        for tier in (ContainmentTier.MOUNT_NS,
                     ContainmentTier.MOUNTLESS_NS,
                     ContainmentTier.NS_NOMOUNT):
            for source in ("flag", "project"):
                got = _tiers.resolve_call_floor(
                    operator_disabled=False, require_fresh_procfs=True,
                    untrusted_workload=True, waiver_active=False,
                    explicit_floor=tier, explicit_source=source,
                    host_floor=ContainmentTier.NS_NOMOUNT)
                assert got == (tier, source), (tier, source, got)
        # Lowering direction: explicit landlock with a derived-False
        # contract keeps the explicit floor; host is not consulted.
        got = _tiers.resolve_call_floor(
            operator_disabled=False, require_fresh_procfs=False,
            untrusted_workload=True, waiver_active=False,
            explicit_floor=ContainmentTier.LANDLOCK_ONLY,
            explicit_source="project",
            host_floor=ContainmentTier.NS_NOMOUNT)
        assert got == (ContainmentTier.LANDLOCK_ONLY, "project")

    def test_host_never_touches_the_waived_arm(self):
        """require_fresh_procfs=False (the derivation under a lowered
        floor, or a caller-literal relaxation) resolves exactly as
        without the marker — the env waiver keeps its frozen mapping
        and attribution."""
        assert _tiers.resolve_call_floor(
            operator_disabled=False, require_fresh_procfs=False,
            untrusted_workload=True, waiver_active=True,
            host_floor=ContainmentTier.NS_NOMOUNT,
        ) == (_tiers.waived_untrusted_floor(), "env")
        assert _tiers.resolve_call_floor(
            operator_disabled=False, require_fresh_procfs=False,
            untrusted_workload=True, waiver_active=False,
            host_floor=ContainmentTier.NS_NOMOUNT,
        ) == (_tiers.waived_untrusted_floor(), "default")

    def test_operator_disable_beats_host(self):
        got = _tiers.resolve_call_floor(
            operator_disabled=True, require_fresh_procfs=True,
            untrusted_workload=True,
            host_floor=ContainmentTier.NS_NOMOUNT)
        assert got == (ContainmentTier.BARE, "operator-disable")

    def test_explicit_bare_still_refuses_with_host_present(self):
        """Never-BARE-by-consent is unchanged: the marker cannot
        rescue an explicit 'none' into a permitted run."""
        with pytest.raises(SandboxFloorError):
            _tiers.resolve_call_floor(
                operator_disabled=False, require_fresh_procfs=True,
                untrusted_workload=True,
                explicit_floor=ContainmentTier.BARE,
                explicit_source="flag",
                host_floor=ContainmentTier.NS_NOMOUNT)

    def test_literal_ask_with_explicit_landlock_keeps_the_default(self):
        """The literal-contract honesty arm is untouched by the
        marker: a literal require_fresh_procfs=True alongside an
        explicit landlock floor keeps the CONTRACT floor with the
        default source — the marker never re-attributes a refusal of
        an explicit surface (the resulting floor is also strictly
        higher than the marker's tier: fail-safe)."""
        got = _tiers.resolve_call_floor(
            operator_disabled=False, require_fresh_procfs=True,
            untrusted_workload=True, waiver_active=False,
            explicit_floor=ContainmentTier.LANDLOCK_ONLY,
            explicit_source="flag",
            host_floor=ContainmentTier.NS_NOMOUNT)
        assert got == (_tiers.untrusted_default_floor(), "default")

    @pytest.mark.parametrize("bad", [
        ContainmentTier.BARE, ContainmentTier.LANDLOCK_ONLY,
        ContainmentTier.MOUNTLESS_NS, ContainmentTier.MOUNT_NS,
        ContainmentTier.SEATBELT,
    ])
    def test_host_floor_admits_exactly_ns_only(self, bad):
        """The single-consentable-value guard: any other tier in the
        host slot is a caller bug, refused loudly for every shape —
        including trusted ones (a coding-error guard never depends on
        reaching a consumption arm)."""
        with pytest.raises(ValueError, match="host_floor"):
            _tiers.resolve_call_floor(
                operator_disabled=False, require_fresh_procfs=None,
                untrusted_workload=False, host_floor=bad)

    @pytest.mark.parametrize("junk", [7, "ns-only", object()])
    def test_host_floor_junk_gets_the_naming_message(self, junk):
        """Non-enum junk gets the same host_floor-naming ValueError,
        not the bare enum conversion error."""
        with pytest.raises(ValueError, match="host_floor"):
            _tiers.resolve_call_floor(
                operator_disabled=False, require_fresh_procfs=None,
                untrusted_workload=False, host_floor=junk)

    def test_absent_host_floor_changes_nothing(self):
        """Default-argument composition: without the marker every
        legacy cell resolves identically."""
        assert _tiers.resolve_call_floor(
            operator_disabled=False, require_fresh_procfs=True,
            untrusted_workload=True, waiver_active=False,
        ) == (_tiers.untrusted_default_floor(), "default")
        assert _tiers.resolve_call_floor(
            operator_disabled=False, require_fresh_procfs=None,
            untrusted_workload=True, waiver_active=False,
        ) == (_tiers.untrusted_default_floor(), "default")


# ─── unit: the chain reader ──────────────────────────────────────────

class TestChainReaderHostLeg:
    """context.resolve_untrusted_floor: flag > project > env >
    host-consent > default."""

    @pytest.mark.skipif(
        sys.platform != "linux",
        reason="the marker is a WSL(Linux) consent surface — "
               "context._host_consented_floor platform-gates it off "
               "elsewhere, so the chain correctly falls to the class "
               "default there",
    )
    def test_host_only(self, no_env_waiver, host_consent_active):
        assert _ctx.resolve_untrusted_floor() == (
            ContainmentTier.NS_NOMOUNT, "host-consent")
        # ns-only still demands the fresh pid-ns procfs — the derived
        # contract stays armed under the marker.
        assert _ctx.untrusted_fresh_procfs_required() is True

    def test_env_beats_host(self, monkeypatch, host_consent_active):
        monkeypatch.setenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", "1")
        assert _ctx.resolve_untrusted_floor() == (
            _tiers.waived_untrusted_floor(), "env")

    def test_project_beats_host_both_directions(
            self, no_env_waiver, host_consent_active):
        state._project_sandbox_floor = "mount-ns"
        assert _ctx.resolve_untrusted_floor() == (
            ContainmentTier.MOUNT_NS, "project")
        state._project_sandbox_floor = "landlock"
        assert _ctx.resolve_untrusted_floor() == (
            ContainmentTier.LANDLOCK_ONLY, "project")

    def test_flag_beats_everything(self, monkeypatch,
                                   host_consent_active):
        monkeypatch.setenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", "1")
        state._project_sandbox_floor = "landlock"
        state._cli_sandbox_floor = "mount-ns"
        assert _ctx.resolve_untrusted_floor() == (
            ContainmentTier.MOUNT_NS, "flag")

    def test_inert_host_falls_to_default(self, no_env_waiver,
                                         monkeypatch):
        monkeypatch.setattr(
            "core.sandbox.host_consent.host_consented_floor",
            lambda: None)
        assert _ctx.resolve_untrusted_floor() == (
            _tiers.untrusted_default_floor(), "default")

    def test_probe_error_falls_to_default(self, no_env_waiver,
                                          monkeypatch):
        def _boom() -> None:
            raise RuntimeError("marker store exploded")
        monkeypatch.setattr(
            "core.sandbox.host_consent.host_consented_floor", _boom)
        assert _ctx.resolve_untrusted_floor() == (
            _tiers.untrusted_default_floor(), "default")


# ─── inertness transitions through the real marker store ─────────────

@pytest.mark.skipif(
    sys.platform != "linux",
    reason="transitions through the real marker store — a WSL(Linux) "
           "surface; off-Linux the context chain never consults the "
           "marker (context._host_consented_floor platform gate), so "
           "every arm here would collapse to the platform default and "
           "prove nothing",
)
class TestInertnessTransitions:
    @pytest.fixture()
    def granted_wsl_host(self, tmp_path, monkeypatch, no_env_waiver):
        """A real marker written through the store on a mocked WSL2
        Landlock-less host (identity sources hermetic)."""
        hc._reset_warning_latches()
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
        (tmp_path / "osrelease").write_text(WSL2_RELEASE + "\n",
                                            encoding="ascii")
        (tmp_path / "machine-id").write_text(MACHINE_ID + "\n",
                                             encoding="ascii")
        monkeypatch.setattr(hc, "_OSRELEASE_PATH",
                            str(tmp_path / "osrelease"))
        monkeypatch.setattr(hc, "_MACHINE_ID_PATH",
                            str(tmp_path / "machine-id"))
        monkeypatch.setattr(hc, "sys",
                            types.SimpleNamespace(platform="linux"))
        monkeypatch.setattr("core.startup.wsl.is_wsl",
                            lambda kernel_id=None: True)
        monkeypatch.setattr(
            "core.sandbox.landlock.check_landlock_available",
            lambda: False)
        hc.write_marker()
        yield tmp_path
        hc._reset_warning_latches()

    def test_marker_drives_the_resolved_floor(self, granted_wsl_host):
        assert _ctx.resolve_untrusted_floor() == (
            ContainmentTier.NS_NOMOUNT, "host-consent")

    def test_landlock_appearing_raises_the_floor(self, granted_wsl_host,
                                                 monkeypatch):
        monkeypatch.setattr(
            "core.sandbox.landlock.check_landlock_available",
            lambda: True)
        assert _ctx.resolve_untrusted_floor() == (
            _tiers.untrusted_default_floor(), "default")

    def test_non_wsl_keeps_the_default(self, granted_wsl_host,
                                       monkeypatch):
        monkeypatch.setattr("core.startup.wsl.is_wsl",
                            lambda kernel_id=None: False)
        assert _ctx.resolve_untrusted_floor() == (
            _tiers.untrusted_default_floor(), "default")

    def test_corrupt_marker_keeps_the_default_and_warns(
            self, granted_wsl_host, caplog):
        hc.marker_path().write_bytes(b"{corrupt")
        with caplog.at_level(logging.WARNING):
            assert _ctx.resolve_untrusted_floor() == (
                _tiers.untrusted_default_floor(), "default")
        assert any("invalid-json" in r.getMessage()
                   for r in caplog.records)

    def test_revoke_restores_the_default(self, granted_wsl_host):
        assert hc.remove_marker() is True
        assert _ctx.resolve_untrusted_floor() == (
            _tiers.untrusted_default_floor(), "default")


# ─── run-level visibility ────────────────────────────────────────────

@pytest.mark.skipif(sys.platform != "linux",
                    reason="Linux consent surfaces")
class TestRunLevelVisibility:
    @pytest.fixture(autouse=True)
    def _stub_spawn(self, monkeypatch):
        from core.sandbox import _spawn as _spawn_mod
        monkeypatch.setattr(_spawn_mod, "run_sandboxed", _ok_spawn)
        monkeypatch.delenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED",
                           raising=False)

    def _run_untrusted_class(self, tmp_path):
        return _ctx.run(
            ["true"], target=str(tmp_path), output=str(tmp_path),
            timeout=60,
            require_fresh_procfs=_ctx.untrusted_fresh_procfs_required())

    def test_host_floor_stamped_in_posture(self, tmp_path,
                                           host_consent_active):
        try:
            r = self._run_untrusted_class(tmp_path)
        except BaseException as e:  # noqa: BLE001 — host capability gate
            pytest.skip(f"sandbox lane unavailable: {e}")
        assert r.sandbox_info["containment_floor"] == "ns-only"
        assert r.sandbox_info["floor_source"] == "host-consent"

    def test_host_banner_once_names_grant_and_revoke(
            self, tmp_path, caplog, host_consent_active):
        state.reset_warn_once("_floor_host_banner_warned")
        with caplog.at_level(logging.WARNING,
                             logger="core.sandbox.context"):
            try:
                self._run_untrusted_class(tmp_path)
                self._run_untrusted_class(tmp_path)
            except BaseException as e:  # noqa: BLE001 — host capability gate
                pytest.skip(f"sandbox lane unavailable: {e}")
        banners = [r for r in caplog.records
                   if "by host consent" in r.getMessage()]
        assert len(banners) == 1, caplog.text
        msg = banners[0].getMessage()
        assert "'ns-only'" in msg
        assert "granted 2026-09-24" in msg
        assert "Landlock unavailable on this kernel" in msg
        assert "wsl-consent revoke" in msg
        assert "--sandbox-floor" in msg

    def test_no_banner_without_the_marker(self, tmp_path, caplog):
        state.reset_warn_once("_floor_host_banner_warned")
        with caplog.at_level(logging.WARNING,
                             logger="core.sandbox.context"):
            try:
                self._run_untrusted_class(tmp_path)
            except BaseException as e:  # noqa: BLE001 — host capability gate
                pytest.skip(f"sandbox lane unavailable: {e}")
        assert not [r for r in caplog.records
                    if "by host consent" in r.getMessage()], caplog.text


def _seccomp_ok() -> bool:
    from core.sandbox.seccomp import check_seccomp_available
    return check_seccomp_available()


def _fresh_proc_ok() -> bool:
    from core.sandbox.probes import check_pidns_fresh_proc_available
    return check_pidns_fresh_proc_available()


@pytest.mark.integration
@pytest.mark.skipif(sys.platform != "linux",
                    reason="Linux namespace lanes")
def test_host_consented_run_lands_ns_only_with_one_degrade_notice(
        tmp_path, monkeypatch, caplog, host_consent_active):
    """Live WSL-shape E2E: Landlock-less host emulation + the marker
    → untrusted work runs on the ported ns-only lane, stamped with
    the host-consent source, and the consented-degrade warning fires
    ONCE for the whole process (the collapse), not per call."""
    if not (_seccomp_ok() and _fresh_proc_ok()):
        pytest.skip("ported lane needs libseccomp + the procfs remount")
    from core.sandbox import landlock as _landlock_mod
    monkeypatch.delenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", raising=False)
    monkeypatch.setattr(_ctx, "check_landlock_available", lambda: False)
    monkeypatch.setattr(_landlock_mod, "check_landlock_available",
                        lambda: False)
    monkeypatch.setattr(_ctx, "check_mount_available", lambda: False)
    state.reset_warn_once("_floor_host_degrade_notice_warned")
    state.reset_warn_once("_floor_host_banner_warned")
    with caplog.at_level(logging.WARNING, logger="core.sandbox.context"):
        try:
            r = _ctx.run_untrusted(
                ["true"], target=str(tmp_path), output=str(tmp_path),
                timeout=60)
            _ctx.run_untrusted(
                ["true"], target=str(tmp_path), output=str(tmp_path),
                timeout=60)
        except (SandboxFloorError, Exception) as e:  # noqa: BLE001 — host capability gate
            pytest.skip(f"namespace lane unavailable live: {e}")
    assert r.returncode == 0, getattr(r, "stderr", "")
    info = r.sandbox_info
    assert info["containment_tier"] == "ns-only"
    assert info["floor_source"] == "host-consent"
    notices = [rec.getMessage() for rec in caplog.records
               if "proceeding on" in rec.getMessage()]
    assert len(notices) == 1, caplog.text
    assert "WSL host consent" in notices[0]
    assert "WITHOUT Landlock" in notices[0]
    assert "shown once per process" in notices[0]
