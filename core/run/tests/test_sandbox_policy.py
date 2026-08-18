"""Fail-closed policy for the try-import-sandbox-except-bare-subprocess
shape (core.run.sandbox_policy)."""

from __future__ import annotations

import pytest

from core.run import sandbox_policy as policy


class TestRequireSandboxOrOptout:
    def test_raises_by_default(self, monkeypatch):
        monkeypatch.delenv(policy.ALLOW_UNSANDBOXED_ENV, raising=False)
        with pytest.raises(policy.SandboxUnavailableError) as ei:
            policy.require_sandbox_or_optout(
                "some-tool", ImportError("no landlock"),
            )
        msg = str(ei.value)
        # The error names the tool AND the remedy.
        assert "some-tool" in msg
        assert policy.ALLOW_UNSANDBOXED_ENV in msg
        assert "refuses to run" in msg

    def test_error_chains_the_import_failure(self, monkeypatch):
        monkeypatch.delenv(policy.ALLOW_UNSANDBOXED_ENV, raising=False)
        cause = ImportError("boom")
        with pytest.raises(policy.SandboxUnavailableError) as ei:
            policy.require_sandbox_or_optout("t", cause)
        assert ei.value.__cause__ is cause

    def test_optout_returns_and_emits_security_event(self, monkeypatch,
                                                     caplog):
        monkeypatch.setenv(policy.ALLOW_UNSANDBOXED_ENV, "1")
        events: list = []
        monkeypatch.setattr(
            policy, "log_security_event",
            lambda etype, msg, **kw: events.append((etype, msg, kw)),
        )
        with caplog.at_level("WARNING"):
            policy.require_sandbox_or_optout(
                "dev-tool", ImportError("no landlock"),
            )
        assert events, "security event must be emitted on opt-in"
        etype, msg, kw = events[0]
        assert etype == "unsandboxed_tool_fallback"
        assert "dev-tool" in msg
        assert kw.get("tool") == "dev-tool"
        # Loud operator-visible warning.
        assert any("SANDBOX WAIVED" in r.getMessage()
                   for r in caplog.records)

    @pytest.mark.parametrize("value", ["0", "", "true", "yes"])
    def test_only_literal_1_opts_in(self, monkeypatch, value):
        monkeypatch.setenv(policy.ALLOW_UNSANDBOXED_ENV, value)
        with pytest.raises(policy.SandboxUnavailableError):
            policy.require_sandbox_or_optout("t", ImportError("x"))
