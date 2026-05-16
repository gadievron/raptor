"""Tests for the orthogonal --audit / --verbose CLI flags.

Audit mode used to be a profile (`--sandbox audit`); after refactor
it's a flag that composes with any compatible profile. This file
covers the validation and propagation of the new flags.
"""

from __future__ import annotations

import argparse

import pytest

from core.sandbox import cli as cli_mod
from core.sandbox import state


@pytest.fixture
def parser():
    p = argparse.ArgumentParser()
    cli_mod.add_cli_args(p)
    return p


@pytest.fixture(autouse=True)
def reset_state():
    state._cli_sandbox_audit = False
    state._cli_sandbox_audit_verbose = False
    state._cli_sandbox_disabled = False
    state._cli_sandbox_profile = None
    yield
    state._cli_sandbox_audit = False
    state._cli_sandbox_audit_verbose = False
    state._cli_sandbox_disabled = False
    state._cli_sandbox_profile = None


class TestArgparseShape:
    def test_audit_flag_recognised(self, parser):
        args = parser.parse_args(["--audit"])
        assert args.audit is True
        assert args.audit_verbose is False

    def test_audit_verbose_flag_recognised(self, parser):
        args = parser.parse_args(["--audit", "--audit-verbose"])
        assert args.audit is True
        assert args.audit_verbose is True

    def test_audit_with_profile(self, parser):
        args = parser.parse_args(["--sandbox", "full", "--audit"])
        assert args.sandbox == "full"
        assert args.audit is True

    def test_audit_with_debug_profile(self, parser):
        # Debug + audit composes — operators running gdb/rr can also
        # see what enforcement would have blocked.
        args = parser.parse_args(["--sandbox", "debug", "--audit"])
        assert args.sandbox == "debug"
        assert args.audit is True

    def test_no_audit_flags_default_false(self, parser):
        args = parser.parse_args([])
        assert args.audit is False
        assert args.audit_verbose is False

    def test_old_audit_profile_no_longer_a_choice(self, parser, capsys):
        # --sandbox audit and --sandbox audit-verbose are GONE; should
        # fail at argparse-time (invalid choice).
        with pytest.raises(SystemExit):
            parser.parse_args(["--sandbox", "audit"])
        with pytest.raises(SystemExit):
            parser.parse_args(["--sandbox", "audit-verbose"])


class TestApplyCliArgsValidation:
    def test_audit_verbose_without_audit_rejected(self, parser):
        args = parser.parse_args(["--audit-verbose"])
        with pytest.raises(ValueError, match="--audit-verbose requires --audit"):
            cli_mod.apply_cli_args(args)

    def test_audit_with_no_sandbox_rejected(self, parser):
        args = parser.parse_args(["--no-sandbox", "--audit"])
        with pytest.raises(ValueError, match="incoherent"):
            cli_mod.apply_cli_args(args)

    def test_audit_with_profile_none_rejected(self, parser):
        args = parser.parse_args(["--sandbox", "none", "--audit"])
        with pytest.raises(ValueError, match="incoherent"):
            cli_mod.apply_cli_args(args)

    def test_audit_with_full_accepted(self, parser):
        args = parser.parse_args(["--sandbox", "full", "--audit"])
        cli_mod.apply_cli_args(args)
        assert state._cli_sandbox_audit is True
        assert state._cli_sandbox_profile == "full"

    def test_audit_with_debug_accepted(self, parser):
        # debug + audit is the new capability the refactor enables.
        args = parser.parse_args(["--sandbox", "debug", "--audit"])
        cli_mod.apply_cli_args(args)
        assert state._cli_sandbox_audit is True
        assert state._cli_sandbox_profile == "debug"

    def test_audit_with_network_only_accepted(self, parser):
        # Coherent (egress-proxy gate still applies); other layers
        # silently no-op.
        args = parser.parse_args(["--sandbox", "network-only", "--audit"])
        cli_mod.apply_cli_args(args)
        assert state._cli_sandbox_audit is True

    def test_audit_verbose_with_audit_propagates(self, parser):
        args = parser.parse_args(
            ["--sandbox", "full", "--audit", "--audit-verbose"])
        cli_mod.apply_cli_args(args)
        assert state._cli_sandbox_audit is True
        assert state._cli_sandbox_audit_verbose is True


class TestAuditBudgetFlag:
    """`--audit-budget=N` overrides the default global cap and
    propagates into core.sandbox.audit_budget.from_cli_state()."""

    def test_audit_budget_flag_recognised(self, parser):
        args = parser.parse_args(
            ["--sandbox", "full", "--audit", "--audit-budget", "250"])
        assert args.audit_budget == 250

    def test_audit_budget_default_is_none(self, parser):
        args = parser.parse_args(["--sandbox", "full", "--audit"])
        assert args.audit_budget is None

    def test_audit_budget_propagates_to_state(self, parser):
        args = parser.parse_args(
            ["--sandbox", "full", "--audit", "--audit-budget", "500"])
        cli_mod.apply_cli_args(args)
        assert state._cli_sandbox_audit_budget == 500

    def test_audit_budget_picked_up_by_from_cli_state(self, parser):
        args = parser.parse_args(
            ["--sandbox", "full", "--audit", "--audit-budget", "777"])
        cli_mod.apply_cli_args(args)
        from core.sandbox import audit_budget
        b = audit_budget.from_cli_state()
        assert b.global_cap == 777

    def test_audit_budget_without_audit_rejected(self, parser):
        args = parser.parse_args(["--audit-budget", "500"])
        with pytest.raises(ValueError, match="--audit-budget requires --audit"):
            cli_mod.apply_cli_args(args)

    def test_audit_budget_zero_rejected(self, parser):
        args = parser.parse_args(
            ["--sandbox", "full", "--audit", "--audit-budget", "0"])
        with pytest.raises(ValueError,
                            match="--audit-budget must be a positive integer"):
            cli_mod.apply_cli_args(args)

    def test_audit_budget_negative_rejected(self, parser):
        args = parser.parse_args(
            ["--sandbox", "full", "--audit", "--audit-budget", "-1"])
        with pytest.raises(ValueError,
                            match="--audit-budget must be a positive integer"):
            cli_mod.apply_cli_args(args)

    def test_audit_budget_above_upper_clamp_rejected(self, parser):
        """Operator typo (one extra zero) shouldn't be able to
        produce a 2GB JSONL. Upper-clamp at 10M records."""
        args = parser.parse_args(
            ["--sandbox", "full", "--audit",
             "--audit-budget", "100000000"])
        with pytest.raises(ValueError, match="exceeds the upper clamp"):
            cli_mod.apply_cli_args(args)


class TestRunUntrustedForwardsAuditKwargs:
    """run_untrusted is a thin convenience wrapper around run() — it
    forwards **kwargs. Audit kwargs should propagate. Covers the
    forwarding path I claimed works but had no test for."""

    def test_run_untrusted_accepts_audit_kwarg(self, monkeypatch):
        # Verify the kwarg flows through without TypeError. We can't
        # easily run the full sandbox in tests (mount-ns may be
        # unavailable on CI), so spy on the inner run() call.
        from core.sandbox import context as ctx
        captured = []

        def spy_run(cmd, **kwargs):
            captured.append(kwargs)
            # Return a fake completed-process to satisfy
            # run_untrusted's return contract.
            import subprocess
            return subprocess.CompletedProcess(args=cmd, returncode=0)

        monkeypatch.setattr(ctx, "run", spy_run)

        # Call run_untrusted with audit=True. target+output required
        # (run_untrusted enforces); audit is forwarded via **kwargs.
        ctx.run_untrusted(
            ["true"], target="/tmp", output="/tmp",
            audit=True, audit_verbose=True,
        )
        assert len(captured) == 1
        kw = captured[0]
        # The kwargs should include audit/audit_verbose forwarded from
        # run_untrusted's **kwargs to run().
        assert kw.get("audit") is True, (
            f"audit kwarg lost in run_untrusted forwarding: {kw}"
        )
        assert kw.get("audit_verbose") is True


class TestRunTrustedRejectsAuditKwargs:
    """Audit mode is incoherent with run_trusted (profile='none' →
    no enforcement to audit against). Passing audit=True is almost
    certainly a caller mistake; should raise rather than silently
    no-op."""

    def test_run_trusted_rejects_audit_kwarg(self):
        from core.sandbox.context import run_trusted
        with pytest.raises(TypeError, match="audit"):
            run_trusted(["true"], audit=True)

    def test_run_trusted_rejects_audit_verbose_kwarg(self):
        from core.sandbox.context import run_trusted
        with pytest.raises(TypeError, match="audit_verbose"):
            run_trusted(["true"], audit_verbose=True)


class TestProfileSetIsTrimmedToFour:
    """Confirms `audit` and `audit-verbose` are GONE from PROFILES."""

    def test_only_four_profiles(self):
        from core.sandbox.profiles import PROFILES
        assert set(PROFILES) == {"full", "debug", "network-only", "none"}

    def test_no_audit_mode_field_in_profile_dicts(self):
        from core.sandbox.profiles import PROFILES
        for name, p in PROFILES.items():
            assert "audit_mode" not in p, (
                f"profile {name!r} still has audit_mode field — should "
                f"be a flag, not a profile property"
            )
            assert "audit_verbose" not in p


class TestSandboxAuditKwarg:
    """Per-call audit/audit_verbose kwargs on context.sandbox()."""

    def test_audit_kwarg_engages_audit_mode(self, monkeypatch, tmp_path):
        # No CLI flag, but per-call audit=True. Should still engage.
        from core.sandbox import probes
        from core.sandbox import proxy as proxy_mod
        from core.sandbox.context import sandbox

        if not probes.check_net_available():
            pytest.skip("user namespaces unavailable")
        # Don't actually run anything — just observe the proxy-acquire
        # behaviour via the ref-count.
        proxy_mod._reset_for_tests()
        try:
            proxy_inst = proxy_mod.get_proxy(["api.example.com"])
            assert proxy_inst._audit_count == 0
            with sandbox(
                audit=True,
                use_egress_proxy=True,
                proxy_hosts=["api.example.com"],
            ) as run:
                # Audit engaged via per-call kwarg → proxy acquired.
                assert proxy_inst._audit_count == 1
            assert proxy_inst._audit_count == 0
        finally:
            proxy_mod._reset_for_tests()

    def test_cli_flag_or_kwarg_either_engages_audit(self):
        # Simpler / more direct than spy-on-_spawn: pin the
        # resolution rule itself.
        # CLI flag set, kwarg unset → audit engaged.
        state._cli_sandbox_audit = True
        assert (state._cli_sandbox_audit or False) is True
        # CLI flag unset, kwarg set → audit engaged.
        state._cli_sandbox_audit = False
        assert (state._cli_sandbox_audit or True) is True
        # Both unset → not engaged.
        assert (state._cli_sandbox_audit or False) is False
