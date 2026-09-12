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
import types

import pytest

from core.sandbox import cli as _cli
from core.sandbox import state
from core.sandbox import tiers as _tiers
from core.sandbox.errors import SandboxFloorError
from core.sandbox.tiers import ContainmentTier

_CONSENT_TIERS = (
    ContainmentTier.LANDLOCK_ONLY, ContainmentTier.NS_NOMOUNT,
    ContainmentTier.MOUNTLESS_NS, ContainmentTier.MOUNT_NS,
)


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
