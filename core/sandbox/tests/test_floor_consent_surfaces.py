"""Consent surfaces for the untrusted containment floor.

Phase-3 of the floor contract: the per-run ``--sandbox-floor`` flag
and the project ``sandbox-floor`` setting join the legacy env var as
consent surfaces, resolved by one chain:

    per-run flag  >  project setting  >  legacy env var  >  default

Properties pinned here, per surface and across compositions:

1. Each surface consents EXACTLY its named tier and nothing lower —
   a lane below the consented floor still refuses.
2. Precedence holds in BOTH directions (an explicit surface can raise
   the floor back over the env waiver), and a disagreement banners
   once, naming both surfaces.
3. The env-var-only configuration behaves byte-identically to
   phase 2 (floor value, source attribution, banner text).
4. Untrusted work can never be consented to BARE through ANY surface
   — the flag's ``none`` refuses loudly, the project registry refuses
   to store ``none``, and the env var's Linux mapping stops at
   landlock. Only the operator-explicit ``--sandbox none`` /
   ``--no-sandbox`` runs untrusted work bare, exactly as before.
5. Propagation: the flag rides nested-worker COMMAND LINES (no env
   expression exists for a target to observe); the project setting is
   on disk and re-read by each worker's run-pin bootstrap.
"""

import argparse
import logging
import subprocess
import sys
import types
from pathlib import Path

import pytest

from core.sandbox import cli as _cli
from core.sandbox import state
from core.sandbox import tiers as _tiers
from core.sandbox.errors import SandboxFloorError
from core.sandbox.tiers import ContainmentTier

_REPO_ROOT = Path(__file__).resolve().parents[3]

_CONSENT_TIERS = (
    ContainmentTier.LANDLOCK_ONLY, ContainmentTier.NS_NOMOUNT,
    ContainmentTier.MOUNTLESS_NS, ContainmentTier.MOUNT_NS,
)


def _ok_spawn(cmd, **kwargs):
    return subprocess.CompletedProcess(cmd, returncode=0,
                                       stdout="", stderr="")


# ------------------------------------------------------- unit: tiers

def test_explicit_floor_wins_for_every_untrusted_shape():
    """resolve_call_floor returns exactly the explicit tier + source
    for every untrusted-class shape (contract kwarg derived-False,
    untrusted-marked without kwarg — and the kwarg-True shapes for
    raising/equal floors), for both explicit sources."""
    shapes = [
        {"require_fresh_procfs": False, "untrusted_workload": True},
        {"require_fresh_procfs": False, "untrusted_workload": False},
        {"require_fresh_procfs": None, "untrusted_workload": True},
    ]
    for tier in _CONSENT_TIERS:
        for source in ("flag", "project"):
            for shape in shapes:
                got = _tiers.resolve_call_floor(
                    operator_disabled=False, waiver_active=True,
                    explicit_floor=tier, explicit_source=source,
                    **shape)
                assert got == (tier, source), (tier, source, shape, got)
    # kwarg-True at the platform default (equal floor): the explicit
    # attribution is kept — banner and posture name the surface.
    got = _tiers.resolve_call_floor(
        operator_disabled=False, require_fresh_procfs=True,
        untrusted_workload=True, waiver_active=True,
        explicit_floor=_tiers.untrusted_default_floor(),
        explicit_source="flag")
    assert got == (_tiers.untrusted_default_floor(), "flag")


def test_literal_contract_ask_resists_explicit_lowering():
    """A LITERAL require_fresh_procfs=True is an explicit caller ask
    no consent surface relaxes — the same honesty rule the env waiver
    has always followed. The derivation arrives False for every floor
    at or below the landlock tier, so a True alongside such a floor
    can only be a direct caller's literal ask: the contract floor
    stays in force, with the default source (no consent banner in the
    surface's name). Floors that still deliver a fresh pid-ns procfs
    (ns-only and above) HONOUR the ask and apply."""
    for tier in _CONSENT_TIERS:
        for source in ("flag", "project"):
            got = _tiers.resolve_call_floor(
                operator_disabled=False, require_fresh_procfs=True,
                untrusted_workload=True, waiver_active=False,
                explicit_floor=tier, explicit_source=source)
            if tier <= ContainmentTier.LANDLOCK_ONLY:
                assert got == (_tiers.untrusted_default_floor(),
                               "default"), (tier, source, got)
            else:
                assert got == (tier, source)


def test_explicit_floor_is_scoped_to_untrusted_classes():
    """A plain trusted call ignores the explicit surfaces entirely:
    the flag/project setting set the UNTRUSTED floor, never a
    process-wide minimum for trusted work."""
    for tier in (*_CONSENT_TIERS, ContainmentTier.BARE):
        got = _tiers.resolve_call_floor(
            operator_disabled=False, require_fresh_procfs=None,
            untrusted_workload=False, explicit_floor=tier,
            explicit_source="flag")
        assert got == (ContainmentTier.BARE, "default")


def test_operator_disable_beats_explicit_floor():
    """--sandbox none / --no-sandbox stays globally authoritative:
    the explicit consent surfaces never override the operator's
    sandbox-off, in either direction."""
    got = _tiers.resolve_call_floor(
        operator_disabled=True, require_fresh_procfs=True,
        untrusted_workload=True,
        explicit_floor=ContainmentTier.MOUNT_NS,
        explicit_source="flag")
    assert got == (ContainmentTier.BARE, "operator-disable")


def test_explicit_bare_refuses_for_untrusted_work():
    """Never-BARE-by-consent: an explicit floor of BARE on an
    untrusted-class call raises, naming the real sandbox-off surface;
    the same value on a trusted call resolves to the trusted default
    (no consent was needed)."""
    for source, surface in (("flag", "--sandbox-floor none"),
                            ("project", "sandbox-floor=none")):
        with pytest.raises(SandboxFloorError) as excinfo:
            _tiers.resolve_call_floor(
                operator_disabled=False, require_fresh_procfs=True,
                untrusted_workload=True,
                explicit_floor=ContainmentTier.BARE,
                explicit_source=source)
        msg = str(excinfo.value) + (excinfo.value.instructions or "")
        assert surface in msg
        assert "--sandbox none" in msg
        assert excinfo.value.achievable is ContainmentTier.BARE
    got = _tiers.resolve_call_floor(
        operator_disabled=False, require_fresh_procfs=None,
        untrusted_workload=False,
        explicit_floor=ContainmentTier.BARE, explicit_source="flag")
    assert got == (ContainmentTier.BARE, "default")


def test_explicit_floor_requires_a_consent_source():
    """explicit_floor without a recognised explicit_source is a
    caller bug — fail loud, never attribute consent to nothing."""
    for bogus in (None, "default", "env", "operator-disable", "x"):
        with pytest.raises(ValueError):
            _tiers.resolve_call_floor(
                operator_disabled=False, require_fresh_procfs=True,
                untrusted_workload=True,
                explicit_floor=ContainmentTier.LANDLOCK_ONLY,
                explicit_source=bogus)


def test_env_only_cells_unchanged_by_the_new_parameters():
    """The phase-2 consent matrix is untouched when no explicit
    surface is set: the new parameters default to None and every
    legacy cell resolves identically (test_consent_chain_matrix in
    test_floor_contract.py is the full pin; this asserts the default
    arguments compose)."""
    assert _tiers.resolve_call_floor(
        operator_disabled=False, require_fresh_procfs=False,
        untrusted_workload=True, waiver_active=True,
    ) == (_tiers.waived_untrusted_floor(), "env")
    assert _tiers.resolve_call_floor(
        operator_disabled=False, require_fresh_procfs=True,
        untrusted_workload=True, waiver_active=True,
    ) == (_tiers.untrusted_default_floor(), "default")


# --------------------------------------------- unit: the chain reader

class TestResolveUntrustedFloor:
    """context.resolve_untrusted_floor: flag > project > env > default,
    in both directions."""

    def test_default_refuse(self, monkeypatch):
        from core.sandbox import context as _ctx
        monkeypatch.delenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED",
                           raising=False)
        assert _ctx.resolve_untrusted_floor() == (
            _tiers.untrusted_default_floor(), "default")
        assert _ctx.untrusted_fresh_procfs_required() is True

    def test_env_only_frozen_mapping(self, monkeypatch):
        from core.sandbox import context as _ctx
        monkeypatch.setenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", "1")
        assert _ctx.resolve_untrusted_floor() == (
            _tiers.waived_untrusted_floor(), "env")
        assert _ctx.untrusted_fresh_procfs_required() is False

    def test_project_beats_env_both_directions(self, monkeypatch):
        from core.sandbox import context as _ctx
        monkeypatch.setenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", "1")
        state._project_sandbox_floor = "mount-ns"
        assert _ctx.resolve_untrusted_floor() == (
            ContainmentTier.MOUNT_NS, "project")
        # Raised back over the waiver: the contract flag re-arms.
        if sys.platform == "linux":
            assert _ctx.untrusted_fresh_procfs_required() is True
        monkeypatch.delenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED",
                           raising=False)
        state._project_sandbox_floor = "landlock"
        assert _ctx.resolve_untrusted_floor() == (
            ContainmentTier.LANDLOCK_ONLY, "project")
        assert _ctx.untrusted_fresh_procfs_required() is False

    def test_flag_beats_project_and_env(self, monkeypatch):
        from core.sandbox import context as _ctx
        monkeypatch.setenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", "1")
        state._project_sandbox_floor = "mountless-ns"
        state._cli_sandbox_floor = "ns-only"
        assert _ctx.resolve_untrusted_floor() == (
            ContainmentTier.NS_NOMOUNT, "flag")

    def test_ns_only_floor_keeps_the_fresh_procfs_contract(
            self, monkeypatch):
        """ns-only consents to Landlock ABSENCE, not to host procfs:
        every tier it admits delivers a fresh pid-ns procfs, so the
        fail-closed contract flag stays armed."""
        if sys.platform != "linux":
            pytest.skip("linux tier vocabulary")
        from core.sandbox import context as _ctx
        monkeypatch.delenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED",
                           raising=False)
        for label in ("ns-only", "mountless-ns", "mount-ns"):
            state._cli_sandbox_floor = label
            assert _ctx.untrusted_fresh_procfs_required() is True, label
        state._cli_sandbox_floor = "landlock"
        assert _ctx.untrusted_fresh_procfs_required() is False


# --------------------------------------------------- unit: CLI plumbing

class TestCliSurface:
    def _parse(self, argv):
        ap = argparse.ArgumentParser()
        _cli.add_cli_args(ap)
        return ap, ap.parse_args(argv)

    def test_flag_sets_state_for_every_tier(self):
        for label in _tiers.CONSENTABLE_FLOOR_LABELS:
            state._cli_sandbox_floor = None
            ap, args = self._parse(["--sandbox-floor", label])
            _cli.apply_cli_args(args, parser=ap)
            assert state._cli_sandbox_floor == label

    def test_flag_absent_is_a_noop(self):
        ap, args = self._parse([])
        _cli.apply_cli_args(args, parser=ap)
        assert state._cli_sandbox_floor is None

    def test_unknown_tier_rejected_at_parse(self):
        ap, _ = self._parse([])
        with pytest.raises(SystemExit):
            ap.parse_args(["--sandbox-floor", "seatbelt"])

    def test_incoherent_with_operator_disable(self):
        for disable in (["--no-sandbox"], ["--sandbox", "none"]):
            ap, args = self._parse(
                [*disable, "--sandbox-floor", "landlock"])
            with pytest.raises(ValueError):
                _cli.apply_cli_args(args)
            assert state._cli_sandbox_floor is None

    def test_darwin_rejects_linux_tier_labels(self, monkeypatch):
        monkeypatch.setattr(_cli, "sys",
                            types.SimpleNamespace(platform="darwin"))
        ap, args = self._parse(["--sandbox-floor", "landlock"])
        with pytest.raises(ValueError, match="macOS"):
            _cli.apply_cli_args(args)
        with pytest.raises(ValueError, match="macOS"):
            _cli.set_cli_sandbox_floor("mount-ns")
        assert state._cli_sandbox_floor is None

    def test_project_setter_validates_and_rejects_none(self):
        with pytest.raises(ValueError):
            _cli.set_project_sandbox_floor("none")
        with pytest.raises(ValueError):
            _cli.set_project_sandbox_floor("junk")
        assert state._project_sandbox_floor is None
        _cli.set_project_sandbox_floor("landlock")
        assert state._project_sandbox_floor == "landlock"

    def test_flag_none_parses_and_reaches_resolution(self):
        """'none' PARSES (the refusal must be loud and situational,
        not an argparse error) and lands in state; the untrusted
        resolution refuses it (test_explicit_bare_refuses_...)."""
        ap, args = self._parse(["--sandbox-floor", "none"])
        _cli.apply_cli_args(args, parser=ap)
        assert state._cli_sandbox_floor == "none"


# ------------------------------------------------ run()-level behaviour

pytestmark_linux = pytest.mark.skipif(
    sys.platform != "linux", reason="linux tier vocabulary")


@pytestmark_linux
class TestRunLevelConsent:
    @pytest.fixture(autouse=True)
    def _stub_spawn(self, monkeypatch):
        from core.sandbox import _spawn as _spawn_mod
        monkeypatch.setattr(_spawn_mod, "run_sandboxed", _ok_spawn)
        monkeypatch.delenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED",
                           raising=False)

    def _run_untrusted_class(self, tmp_path):
        from core.sandbox import context as _ctx
        return _ctx.run(
            ["true"], target=str(tmp_path), output=str(tmp_path),
            timeout=60,
            require_fresh_procfs=_ctx.untrusted_fresh_procfs_required())

    def test_flag_floor_stamped_in_posture(self, tmp_path):
        state._cli_sandbox_floor = "landlock"
        try:
            r = self._run_untrusted_class(tmp_path)
        except BaseException as e:  # noqa: BLE001 — host capability gate
            pytest.skip(f"sandbox lane unavailable: {e}")
        assert r.sandbox_info["containment_floor"] == "landlock"
        assert r.sandbox_info["floor_source"] == "flag"

    def test_project_floor_stamped_in_posture(self, tmp_path):
        state._project_sandbox_floor = "landlock"
        try:
            r = self._run_untrusted_class(tmp_path)
        except BaseException as e:  # noqa: BLE001 — host capability gate
            pytest.skip(f"sandbox lane unavailable: {e}")
        assert r.sandbox_info["containment_floor"] == "landlock"
        assert r.sandbox_info["floor_source"] == "project"

    def test_flag_banner_once_names_the_flag(self, tmp_path, caplog):
        state._cli_sandbox_floor = "landlock"
        state.reset_warn_once("_floor_flag_banner_warned")
        with caplog.at_level(logging.WARNING,
                             logger="core.sandbox.context"):
            try:
                self._run_untrusted_class(tmp_path)
                self._run_untrusted_class(tmp_path)
            except BaseException as e:  # noqa: BLE001 — host capability gate
                pytest.skip(f"sandbox lane unavailable: {e}")
        banners = [r for r in caplog.records
                   if "containment floor set to" in r.getMessage()
                   and "--sandbox-floor" in r.getMessage()]
        assert len(banners) == 1, caplog.text
        assert "'landlock'" in banners[0].getMessage()

    def test_project_banner_once_names_the_setting(self, tmp_path,
                                                   caplog):
        state._project_sandbox_floor = "landlock"
        state.reset_warn_once("_floor_project_banner_warned")
        with caplog.at_level(logging.WARNING,
                             logger="core.sandbox.context"):
            try:
                self._run_untrusted_class(tmp_path)
                self._run_untrusted_class(tmp_path)
            except BaseException as e:  # noqa: BLE001 — host capability gate
                pytest.skip(f"sandbox lane unavailable: {e}")
        banners = [r for r in caplog.records
                   if "project setting sandbox-floor" in r.getMessage()]
        assert len(banners) == 1, caplog.text
        assert "'landlock'" in banners[0].getMessage()

    def test_env_only_banner_byte_identical(self, tmp_path, caplog,
                                            monkeypatch):
        """The frozen surface: with ONLY the env var set, the banner
        renders the exact phase-2 string — the explicit surfaces must
        not perturb the legacy path."""
        monkeypatch.setenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", "1")
        state.reset_warn_once("_floor_lowered_banner_warned")
        with caplog.at_level(logging.WARNING,
                             logger="core.sandbox.context"):
            try:
                self._run_untrusted_class(tmp_path)
            except BaseException as e:  # noqa: BLE001 — host capability gate
                pytest.skip(f"sandbox lane unavailable: {e}")
        banners = [r for r in caplog.records
                   if "containment floor lowered" in r.getMessage()]
        assert len(banners) == 1, caplog.text
        assert banners[0].getMessage() == (
            "sandbox: untrusted containment floor lowered to "
            "'landlock' (source: RAPTOR_ALLOW_DEGRADED_UNTRUSTED)."
        )

    def test_disagreement_banner_names_both_surfaces(
            self, tmp_path, caplog, monkeypatch):
        monkeypatch.setenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", "1")
        state._cli_sandbox_floor = "mount-ns"
        state.reset_warn_once("_floor_surface_disagreement_warned")
        with caplog.at_level(logging.WARNING,
                             logger="core.sandbox.context"):
            try:
                self._run_untrusted_class(tmp_path)
            except BaseException as e:  # noqa: BLE001 — host capability gate
                pytest.skip(f"sandbox lane unavailable: {e}")
        banners = [r for r in caplog.records
                   if "consent surfaces disagree" in r.getMessage()]
        assert len(banners) == 1, caplog.text
        msg = banners[0].getMessage()
        assert "--sandbox-floor" in msg
        assert "'mount-ns'" in msg
        assert "RAPTOR_ALLOW_DEGRADED_UNTRUSTED" in msg

    def test_flag_project_disagreement_names_the_project(
            self, tmp_path, caplog):
        state._cli_sandbox_floor = "ns-only"
        state._project_sandbox_floor = "mountless-ns"
        state.reset_warn_once("_floor_surface_disagreement_warned")
        with caplog.at_level(logging.WARNING,
                             logger="core.sandbox.context"):
            try:
                self._run_untrusted_class(tmp_path)
            except BaseException as e:  # noqa: BLE001 — host capability gate
                pytest.skip(f"sandbox lane unavailable: {e}")
        banners = [r for r in caplog.records
                   if "consent surfaces disagree" in r.getMessage()]
        assert len(banners) == 1, caplog.text
        msg = banners[0].getMessage()
        assert "sandbox-floor='mountless-ns'" in msg
        assert "'ns-only'" in msg

    def test_agreement_produces_no_disagreement_banner(
            self, tmp_path, caplog, monkeypatch):
        """flag=landlock while the env waiver maps to landlock: the
        surfaces AGREE — no disagreement banner may fire."""
        monkeypatch.setenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", "1")
        state._cli_sandbox_floor = "landlock"
        state.reset_warn_once("_floor_surface_disagreement_warned")
        with caplog.at_level(logging.WARNING,
                             logger="core.sandbox.context"):
            try:
                self._run_untrusted_class(tmp_path)
            except BaseException as e:  # noqa: BLE001 — host capability gate
                pytest.skip(f"sandbox lane unavailable: {e}")
        assert not [r for r in caplog.records
                    if "consent surfaces disagree" in r.getMessage()], \
            caplog.text

    def test_flag_none_refuses_untrusted_class_work(self, tmp_path):
        """Never-BARE via the flag: an untrusted-class call under
        --sandbox-floor none refuses before any spawn, naming the
        authoritative sandbox-off surface."""
        state._cli_sandbox_floor = "none"
        from core.sandbox import context as _ctx
        spawn_calls: list = []

        def counting_spawn(cmd, **kwargs):
            spawn_calls.append(cmd)
            return _ok_spawn(cmd, **kwargs)

        from core.sandbox import _spawn as _spawn_mod
        import unittest.mock as _mock
        with _mock.patch.object(_spawn_mod, "run_sandboxed",
                                counting_spawn):
            with pytest.raises(SandboxFloorError) as excinfo:
                _ctx.run(["true"], target=str(tmp_path),
                         output=str(tmp_path), timeout=60,
                         require_fresh_procfs=(
                             _ctx.untrusted_fresh_procfs_required()),
                         _untrusted_workload=True)
        assert "--sandbox none" in (str(excinfo.value)
                                    + (excinfo.value.instructions or ""))
        assert spawn_calls == []

    def test_lowered_floor_is_a_minimum_not_a_ceiling(self, tmp_path):
        """--sandbox-floor landlock does not STEER the run onto the
        landlock lane — lane selection is unchanged; the floor only
        moves the refusal threshold. The delivered tier with the flag
        equals the delivered tier without it on the same host."""
        try:
            baseline = self._run_untrusted_class(tmp_path)
        except BaseException as e:  # noqa: BLE001 — host capability gate
            pytest.skip(f"sandbox lane unavailable: {e}")
        state._cli_sandbox_floor = "landlock"
        flagged = self._run_untrusted_class(tmp_path)
        assert (flagged.sandbox_info["containment_tier"]
                == baseline.sandbox_info["containment_tier"])
        assert (_tiers.label_tier(flagged.sandbox_info["containment_tier"])
                >= ContainmentTier.LANDLOCK_ONLY)

    def test_flag_none_leaves_trusted_calls_alone(self, tmp_path):
        state._cli_sandbox_floor = "none"
        from core.sandbox import context as _ctx
        try:
            r = _ctx.run(["true"], target=str(tmp_path),
                         output=str(tmp_path), timeout=60)
        except BaseException as e:  # noqa: BLE001 — host capability gate
            pytest.skip(f"sandbox lane unavailable: {e}")
        assert r.sandbox_info["floor_source"] == "default"
        assert r.sandbox_info["containment_floor"] == "none"


# --------------------------- constrained hosts: exactly-the-tier proofs

@pytestmark_linux
class TestConsentIsExactlyTheTier:
    """On a host that can only deliver the plain (Landlock-only) lane,
    a consent for 'landlock' runs there and any HIGHER consented floor
    still refuses — each surface buys exactly its named tier, nothing
    below it."""

    @pytest.fixture(autouse=True)
    def _userns_denied_host(self, monkeypatch):
        from core.sandbox import context as _ctx
        from core.sandbox import seccomp as _seccomp_mod
        if not _seccomp_mod.check_seccomp_available():
            pytest.skip("libseccomp required for the simulated hosts")
        monkeypatch.setattr(_ctx, "check_net_available", lambda: False)
        monkeypatch.setattr(_ctx, "check_mount_available",
                            lambda: False)
        monkeypatch.setattr(_ctx, "check_landlock_available",
                            lambda: True)
        monkeypatch.setattr(_ctx, "_get_landlock_abi", lambda: 4)
        monkeypatch.delenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED",
                           raising=False)

    def _untrusted_call(self, tmp_path):
        from core.sandbox import context as _ctx
        return _ctx.run(
            ["true"], target=str(tmp_path), output=str(tmp_path),
            timeout=60,
            require_fresh_procfs=_ctx.untrusted_fresh_procfs_required(),
            _untrusted_workload=True)

    @pytest.mark.parametrize("surface", ["flag", "project"])
    def test_landlock_consent_admits_the_plain_lane(self, tmp_path,
                                                    surface):
        if surface == "flag":
            state._cli_sandbox_floor = "landlock"
        else:
            state._project_sandbox_floor = "landlock"
        r = self._untrusted_call(tmp_path)
        assert r.returncode == 0
        assert r.sandbox_info["containment_floor"] == "landlock"
        assert r.sandbox_info["floor_source"] == surface
        assert (_tiers.label_tier(r.sandbox_info["containment_tier"])
                >= ContainmentTier.LANDLOCK_ONLY)

    @pytest.mark.parametrize("label", ["ns-only", "mountless-ns",
                                       "mount-ns"])
    @pytest.mark.parametrize("surface", ["flag", "project"])
    def test_higher_consents_still_refuse_below_their_tier(
            self, tmp_path, label, surface):
        """A floor above landlock refuses this host's plain lane —
        consenting 'ns-only' (etc.) does NOT quietly admit anything
        weaker, and the refusal remedy names the exact re-run flag."""
        if surface == "flag":
            state._cli_sandbox_floor = label
        else:
            state._project_sandbox_floor = label
        with pytest.raises(SandboxFloorError) as excinfo:
            self._untrusted_call(tmp_path)
        e = excinfo.value
        assert e.floor is _tiers.label_tier(label)
        assert "--sandbox-floor" in (str(e) + (e.instructions or ""))

    def test_explicit_raise_beats_the_env_waiver(self, tmp_path,
                                                 monkeypatch):
        """The behavioural core of the precedence contract: with the
        env waiver set (which alone would run this host's plain
        lane), an explicitly RAISED flag floor refuses instead —
        explicit wins in both directions."""
        monkeypatch.setenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", "1")
        # Baseline: env-only runs (the waived floor admits the lane).
        r = self._untrusted_call(tmp_path)
        assert r.sandbox_info["floor_source"] == "env"
        # Raised flag: same host, same call — refuses.
        state._cli_sandbox_floor = "mount-ns"
        with pytest.raises(SandboxFloorError) as excinfo:
            self._untrusted_call(tmp_path)
        assert excinfo.value.floor is ContainmentTier.MOUNT_NS
        # The remedy is honest: the env var does not relax an
        # explicitly pinned floor.
        remedy = excinfo.value.instructions or ""
        assert "--sandbox-floor" in remedy

    def test_default_refusal_remedy_names_all_three_surfaces(
            self, tmp_path):
        """Mechanical half of the interactive refusal-boundary choice:
        the unconsented refusal carries the exact re-run flag, the
        project spelling, and the env var."""
        with pytest.raises(SandboxFloorError) as excinfo:
            self._untrusted_call(tmp_path)
        remedy = excinfo.value.instructions or ""
        assert "--sandbox-floor landlock" in remedy
        assert "/project set sandbox-floor landlock" in remedy
        assert "RAPTOR_ALLOW_DEGRADED_UNTRUSTED" in remedy


# ------------------------- capability axes: the chain's exact reach

@pytestmark_linux
class TestSeccompAxis:
    """No tier waives a missing libseccomp (every tier's contract
    includes the filter), and an explicit surface WITHDRAWS the env
    waiver's filterless acceptance — the explicit surface names a
    tier whose contract includes the filter, so it wins over the env
    var on this axis exactly as it does on the tier chain."""

    @pytest.fixture(autouse=True)
    def _no_seccomp(self, monkeypatch):
        from core.sandbox import context as _ctx
        monkeypatch.setattr(_ctx._seccomp, "check_seccomp_available",
                            lambda: False)
        monkeypatch.setattr(_ctx, "check_net_available", lambda: True)
        monkeypatch.delenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED",
                           raising=False)

    def _gate(self):
        from core.sandbox import context as _ctx
        return _ctx._require_userns_or_optin("probe")

    def test_env_only_acceptance_unchanged(self, monkeypatch, caplog):
        from core.sandbox.errors import SandboxSetupError
        monkeypatch.setenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", "1")
        with caplog.at_level(logging.WARNING,
                             logger="core.sandbox.context"):
            self._gate()
        msgs = [r.getMessage() for r in caplog.records
                if "libseccomp unavailable" in r.getMessage()]
        assert msgs and "operator override "\
            "RAPTOR_ALLOW_DEGRADED_UNTRUSTED" in msgs[0]
        # And without the waiver: refusal (unchanged), whose remedy
        # says the tier surfaces do not apply here.
        monkeypatch.delenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED")
        with pytest.raises(SandboxSetupError) as excinfo:
            self._gate()
        assert "no --sandbox-floor tier waives" in (
            str(excinfo.value) + (excinfo.value.instructions or ""))

    @pytest.mark.parametrize("label", ["landlock", "ns-only",
                                       "mountless-ns", "mount-ns"])
    def test_explicit_surface_withdraws_the_filterless_acceptance(
            self, monkeypatch, label):
        """Even WITH the env waiver set, a pinned floor refuses a
        filterless untrusted run — running without the filter would
        be below every tier's documented meaning."""
        from core.sandbox.errors import SandboxSetupError
        monkeypatch.setenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", "1")
        state._cli_sandbox_floor = label
        with pytest.raises(SandboxSetupError) as excinfo:
            self._gate()
        text = str(excinfo.value) + (excinfo.value.instructions or "")
        assert "--sandbox-floor" in text
        assert f"'{label}'" in text
        assert "does not override" in text


@pytestmark_linux
class TestConstructionAcceptancePinNote:
    """The construction-time Landlock-enforceability refusal follows
    the honesty rule: when an explicit surface pins the floor above
    the acceptance range, the remedy says the env var and lower
    surfaces will not help, instead of steering the operator at
    overrides that would lose."""

    def test_pinned_raise_refuses_and_notes_the_pin(self, monkeypatch,
                                                    tmp_path):
        from core.sandbox import context as _ctx
        from core.sandbox.errors import SandboxSetupError
        monkeypatch.setattr(_ctx, "check_landlock_available",
                            lambda: False)
        # The acceptance arm is reachable only without a mount tier
        # (the bind tree is the mount tier's own fs enforcement).
        monkeypatch.setattr(_ctx, "check_mount_available",
                            lambda: False)
        monkeypatch.setenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", "1")
        state._cli_sandbox_floor = "mount-ns"
        with pytest.raises(SandboxSetupError) as excinfo:
            with _ctx.sandbox(target=str(tmp_path),
                              output=str(tmp_path)):
                pass  # pragma: no cover — construction must refuse
        text = str(excinfo.value) + (excinfo.value.instructions or "")
        assert "pins the floor at 'mount-ns'" in text
        assert "do not override" in text


@pytestmark_linux
class TestRefusalHintHonesty:
    """_fresh_procfs_override_hint's literal_contract split: under a
    lowered floor, a refusal that did NOT carry a literal contract
    ask must not claim the caller passed require_fresh_procfs=True —
    it names the bare-delivery truth instead."""

    def test_bare_delivery_wording_under_each_source(self, monkeypatch):
        from core.sandbox import context as _ctx
        cases = [
            ("flag", lambda: setattr(state, "_cli_sandbox_floor",
                                     "landlock")),
            ("project", lambda: setattr(state, "_project_sandbox_floor",
                                        "landlock")),
            ("env", lambda: monkeypatch.setenv(
                "RAPTOR_ALLOW_DEGRADED_UNTRUSTED", "1")),
        ]
        for _name, arm in cases:
            state._cli_sandbox_floor = None
            state._project_sandbox_floor = None
            monkeypatch.delenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED",
                               raising=False)
            arm()
            hint = _ctx._fresh_procfs_override_hint(
                literal_contract=False)
            assert "require_fresh_procfs=True" not in hint, _name
            assert "cannot deliver even" in hint, _name
            literal = _ctx._fresh_procfs_override_hint(
                literal_contract=True)
            assert "require_fresh_procfs=True" in literal, _name
