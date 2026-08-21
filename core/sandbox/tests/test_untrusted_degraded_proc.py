"""run_untrusted degradation handling on namespace-less hosts.

run_untrusted's credential-exfil defence is the PID namespace: host
/proc/<pid>/ entries become unreachable inside it. On hosts without
unprivileged user namespaces the tier silently never engages, so
run_untrusted fails CLOSED (_require_userns_or_optin) unless the
operator explicitly overrides via RAPTOR_ALLOW_DEGRADED_UNTRUSTED.
Pre-fix, that override still granted /proc wholesale through the
restrict_reads allowlist — leaving same-UID /proc/<pid>/environ
credential reads open to the very code the helper labels untrusted.

Now every override-degraded run_untrusted / run_untrusted_networked
call warns (per call, not once) and withdraws /proc from the read
allowlist via omit_proc_reads.
"""

from __future__ import annotations

import logging
import sys
from unittest import mock

import pytest

from core.sandbox import context as context_mod

pytestmark = pytest.mark.skipif(
    sys.platform == "darwin",
    reason="degradation path is Linux-only (seatbelt covers macOS)",
)


@pytest.fixture
def preexec_recorder():
    """Wrap _make_preexec_fn so tests can inspect the readable_paths
    the Landlock preexec was actually built with."""
    calls = []
    real = context_mod._make_preexec_fn

    def _record(*args, **kwargs):
        calls.append(kwargs)
        return real(*args, **kwargs)

    with mock.patch.object(context_mod, "_make_preexec_fn",
                           side_effect=_record):
        yield calls


def _degraded():
    return mock.patch.object(
        context_mod, "check_net_available", return_value=False,
    )


@pytest.fixture
def degraded_override(monkeypatch):
    """Operator override that engages Landlock/seccomp-only degraded
    mode instead of the default fail-closed refusal."""
    monkeypatch.setenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", "1")


class TestDegradedFailsClosedWithoutOverride:

    def test_refuses_without_override(self, tmp_path, monkeypatch):
        monkeypatch.delenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED",
                           raising=False)
        out = tmp_path / "out"
        out.mkdir()
        from core.sandbox.errors import SandboxSetupError
        with _degraded(), pytest.raises(SandboxSetupError):
            context_mod.run_untrusted(
                ["true"], output=str(out),
                capture_output=True, text=True, timeout=60,
            )


class TestDegradedRunUntrusted:

    def test_warns_every_call_and_drops_proc(
            self, tmp_path, caplog, preexec_recorder, degraded_override):
        out = tmp_path / "out"
        out.mkdir()
        with _degraded(), caplog.at_level(
                logging.WARNING, logger="core.sandbox.context"):
            for _ in range(2):
                result = context_mod.run_untrusted(
                    ["true"], output=str(out),
                    capture_output=True, text=True, timeout=60,
                )
                assert result.returncode == 0
        warnings = [
            r for r in caplog.records
            if "run_untrusted:" in r.getMessage()
            and "/proc is dropped" in r.getMessage()
        ]
        assert len(warnings) == 2, (
            "degraded run_untrusted must warn on EVERY call, "
            f"got {len(warnings)}")
        assert len(preexec_recorder) == 2
        for kwargs in preexec_recorder:
            readable = kwargs.get("readable_paths") or []
            assert "/proc" not in readable, (
                "degraded run_untrusted must withdraw the /proc read "
                "grant")
            # The rest of the system allowlist survives.
            assert "/usr" in readable

    def test_restrict_reads_false_still_warns(
            self, tmp_path, caplog, degraded_override):
        out = tmp_path / "out"
        out.mkdir()
        with _degraded(), caplog.at_level(
                logging.WARNING, logger="core.sandbox.context"):
            context_mod.run_untrusted(
                ["true"], output=str(out), restrict_reads=False,
                capture_output=True, text=True, timeout=60,
            )
        warnings = [
            r for r in caplog.records
            if "run_untrusted:" in r.getMessage()
            and "restrict_reads=False" in r.getMessage()
        ]
        assert warnings, (
            "restrict_reads=False on a degraded host must still name "
            "the open /proc exposure")


class TestHealthyHostKeepsProc:

    def test_sandbox_default_allowlist_keeps_proc(
            self, tmp_path, preexec_recorder):
        # Context construction alone builds the preexec; no exec needed.
        out = tmp_path / "out"
        out.mkdir()
        with context_mod.sandbox(
                target=str(out), output=str(out), restrict_reads=True):
            pass
        assert preexec_recorder
        readable = preexec_recorder[-1].get("readable_paths") or []
        assert "/proc" in readable, (
            "default allowlist must keep /proc — the drop is only for "
            "the degraded untrusted contract")

    def test_omit_proc_reads_kwarg_drops_proc(
            self, tmp_path, preexec_recorder):
        out = tmp_path / "out"
        out.mkdir()
        with context_mod.sandbox(
                target=str(out), output=str(out), restrict_reads=True,
                omit_proc_reads=True):
            pass
        readable = preexec_recorder[-1].get("readable_paths") or []
        assert "/proc" not in readable
        assert "/sys" in readable
