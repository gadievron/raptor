"""Verify that run_untrusted_networked() forwards strict_env=True to run().

Defensive parity with the existing run_untrusted() wire (W36.B / F067).
Without strict_env=True the helper would not strip DANGEROUS_ENV_VARS
from caller-supplied env= dicts, leaving a contract gap for future
cc_dispatch-style migrations that build env from semi-trusted sources.
"""

import pytest

from core.sandbox import context as _ctx


def test_run_untrusted_networked_forwards_strict_env(monkeypatch):
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs

        # Return a sentinel so the caller's `return run(...)` is fine;
        # no real subprocess is spawned.
        class _Stub:
            returncode = 0
        return _Stub()

    monkeypatch.setattr(_ctx, "run", fake_run)

    _ctx.run_untrusted_networked(
        ["echo", "ok"],
        target="/tmp/raptor-target",
        output="/tmp/raptor-output",
        proxy_hosts=["api.example.com"],
    )

    # Defensive parity assertion: strict_env must be True regardless of
    # any caller default. The helper is the security-sensitive entry
    # point for hostname-allowlisted egress; callers must not have to
    # remember to pass strict_env themselves.
    assert captured["kwargs"].get("strict_env") is True, (
        "run_untrusted_networked must forward strict_env=True to run(); "
        f"saw kwargs.strict_env={captured['kwargs'].get('strict_env')!r}"
    )

    # Sanity: the other fixed-policy kwargs should also be set as the
    # helper's docstring promises.
    assert captured["kwargs"].get("block_network") is False
    assert captured["kwargs"].get("use_egress_proxy") is True
    assert captured["kwargs"].get("allowed_tcp_ports") == [443]
    assert captured["kwargs"].get("proxy_hosts") == ["api.example.com"]


def test_run_untrusted_rejects_caller_strict_env():
    """Caller passing strict_env= must get the clean guard message, not
    a confusing "multiple values for keyword argument" TypeError.

    run_untrusted() hardcodes strict_env=True; allowing the caller to
    override would either bypass DANGEROUS_ENV_VARS stripping (silent
    misuse) or collide with the wire (TypeError that doesn't name the
    real problem). The forbidden-kwargs guard surfaces the misuse.
    """
    with pytest.raises(TypeError, match="strict_env"):
        _ctx.run_untrusted(
            ["echo", "ok"],
            target="/tmp/raptor-target",
            output="/tmp/raptor-output",
            strict_env=False,
        )


def test_run_untrusted_networked_rejects_caller_strict_env():
    """Same defensive parity for the networked variant."""
    with pytest.raises(TypeError, match="strict_env"):
        _ctx.run_untrusted_networked(
            ["echo", "ok"],
            target="/tmp/raptor-target",
            output="/tmp/raptor-output",
            proxy_hosts=["api.example.com"],
            strict_env=False,
        )
