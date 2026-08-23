"""Credential-proxy wiring in the shared skill-dispatch runner.

Covers the RAPTOR_CC_CREDENTIAL_MODE knob, the fail-fast mint
preconditions, route/bridge derivation, and post-run settlement
(max-of-ledgers reconcile + revoke + spend artifact). Hermetic: the
dispatcher client calls are monkeypatched; no sandbox, no LLM.
"""

from __future__ import annotations

import json

import pytest

import core.orchestration.skill_dispatch as sd


class TestCredentialModeKnob:

    def test_default_is_env(self, monkeypatch):
        monkeypatch.delenv(sd._CC_CREDENTIAL_MODE_ENV, raising=False)
        assert sd._cc_credential_mode() == "env"

    @pytest.mark.parametrize("raw,expected", [
        ("env", "env"),
        ("proxy", "proxy"),
        ("PROXY", "proxy"),
        ("  proxy  ", "proxy"),
        ("garbage", "env"),
        ("", "env"),
    ])
    def test_resolution(self, monkeypatch, raw, expected):
        monkeypatch.setenv(sd._CC_CREDENTIAL_MODE_ENV, raw)
        assert sd._cc_credential_mode() == expected


class TestProxyCredentialSetup:

    def _allow_netns(self, monkeypatch, available=True):
        import core.sandbox
        monkeypatch.setattr(
            core.sandbox, "check_net_available", lambda: available,
        )
        monkeypatch.setattr(
            core.sandbox, "check_mount_available", lambda: True,
        )

    def test_requires_fork_backend(self, monkeypatch):
        import core.sandbox
        monkeypatch.setenv("RAPTOR_LLM_SOCKET", "/tmp/llm.sock")
        monkeypatch.setattr(
            core.sandbox, "check_net_available", lambda: True,
        )
        monkeypatch.setattr(
            core.sandbox, "check_mount_available", lambda: False,
        )
        with pytest.raises(RuntimeError, match="fork spawn backend"):
            sd._setup_cc_proxy_credentials("5.00", 900, "test")

    def test_requires_dispatcher_route(self, monkeypatch):
        monkeypatch.delenv("RAPTOR_LLM_SOCKET", raising=False)
        with pytest.raises(RuntimeError, match="RAPTOR_LLM_SOCKET"):
            sd._setup_cc_proxy_credentials("5.00", 900, "test")

    def test_requires_netns_tier(self, monkeypatch):
        monkeypatch.setenv("RAPTOR_LLM_SOCKET", "/tmp/llm.sock")
        self._allow_netns(monkeypatch, available=False)
        with pytest.raises(RuntimeError, match="netns"):
            sd._setup_cc_proxy_credentials("5.00", 900, "test")

    @staticmethod
    def _socket_dir(monkeypatch, tmp_path):
        """Point RAPTOR_LLM_SOCKET at a fake dispatcher socket dir that
        also carries the child-plane socket (the bridge target)."""
        worker = tmp_path / "llm.sock"
        worker.touch()
        child = tmp_path / "llm-child.sock"
        child.touch()
        monkeypatch.setenv("RAPTOR_LLM_SOCKET", str(worker))
        return worker, child

    def test_mints_and_derives_route(self, monkeypatch, tmp_path):
        _worker, child = self._socket_dir(monkeypatch, tmp_path)
        monkeypatch.delenv("CLAUDE_CODE_USE_BEDROCK", raising=False)
        monkeypatch.setenv("ANTHROPIC_MODEL", "claude-opus-4-8")
        monkeypatch.delenv("ANTHROPIC_SMALL_FAST_MODEL", raising=False)
        monkeypatch.delenv("RAPTOR_CC_MODEL", raising=False)
        monkeypatch.delenv("RAPTOR_CC_FALLBACK_MODEL", raising=False)
        self._allow_netns(monkeypatch)
        captured: dict = {}

        def _fake_mint(**kwargs):
            captured.update(kwargs)
            return {"token": "tok-secret", "token_id": "tid123",
                    "expires_at": 0, "budget_usd": kwargs["budget_usd"],
                    "request_budget": 1000}

        import core.llm.dispatcher.client as client_mod
        monkeypatch.setattr(client_mod, "mint_child_token", _fake_mint)
        creds = sd._setup_cc_proxy_credentials("5.00", 900, "prepass")
        assert creds.token == "tok-secret"
        assert creds.token_id == "tid123"
        # Gateway ORIGIN — cc_subprocess_env derives the per-install
        # route family from it.
        assert creds.base_url == (
            f"http://127.0.0.1:{sd._CC_PROXY_BRIDGE_PORT}"
        )
        # The bridge terminates inside the sandbox — it must target the
        # child-plane socket, never the full-capability worker socket.
        assert creds.bridges == {
            sd._CC_PROXY_BRIDGE_PORT: str(child),
        }
        assert captured["budget_usd"] == 5.0
        assert captured["models"] == ["claude-opus-4-8"]
        # TTL sized to the pass timeout plus slack.
        assert captured["ttl_s"] == 900 + 600
        assert captured["label"] == "prepass"

    def test_bedrock_install_same_origin(self, monkeypatch, tmp_path):
        """Route selection lives in cc_subprocess_env (it follows the
        CLI's backend mode) — the mint side always hands out the
        gateway origin, Bedrock install or not."""
        self._socket_dir(monkeypatch, tmp_path)
        monkeypatch.setenv("CLAUDE_CODE_USE_BEDROCK", "1")
        self._allow_netns(monkeypatch)
        import core.llm.dispatcher.client as client_mod
        monkeypatch.setattr(
            client_mod, "mint_child_token",
            lambda **kw: {"token": "t", "token_id": "i",
                          "expires_at": 0, "budget_usd": 1,
                          "request_budget": 1000},
        )
        creds = sd._setup_cc_proxy_credentials("1.00", 60, "x")
        assert creds.base_url == (
            f"http://127.0.0.1:{sd._CC_PROXY_BRIDGE_PORT}"
        )

    def test_bad_budget_fails_fast(self, monkeypatch):
        monkeypatch.setenv("RAPTOR_LLM_SOCKET", "/tmp/llm.sock")
        self._allow_netns(monkeypatch)
        with pytest.raises(RuntimeError, match="budget"):
            sd._setup_cc_proxy_credentials("not-a-number", 60, "x")

    def test_missing_child_plane_socket_fails_fast(
        self, monkeypatch, tmp_path,
    ):
        """No child-plane socket next to the worker socket → refuse.
        Falling back to bridging the worker socket would silently hand
        the sandbox the admin plane (renewal + /_child/*)."""
        worker = tmp_path / "llm.sock"
        worker.touch()
        monkeypatch.setenv("RAPTOR_LLM_SOCKET", str(worker))
        self._allow_netns(monkeypatch)
        with pytest.raises(RuntimeError, match="child-plane"):
            sd._setup_cc_proxy_credentials("5.00", 900, "test")


class TestSettlement:

    def _creds(self):
        return sd._CCProxyCredentials(
            token="tok", token_id="tid", base_url="http://127.0.0.1:1/a",
            bridges={1: "/tmp/x"}, budget_usd=5.0,
        )

    def test_settle_reconciles_revokes_and_writes_artifact(
        self, monkeypatch, tmp_path,
    ):
        calls = {"revoked": []}
        import core.llm.dispatcher.client as client_mod
        monkeypatch.setattr(
            client_mod, "child_token_spend",
            lambda tid, **kw: {
                "token_id": tid, "spent_usd": 0.75, "budget_usd": 5.0,
                "requests_made": 3, "unpriced_requests": 0,
                "last_model": "claude-opus-4-8", "status": "active",
            },
        )
        monkeypatch.setattr(
            client_mod, "revoke_child_token",
            lambda tid, **kw: calls["revoked"].append(tid) or {
                "revoked": True,
            },
        )
        sd._settle_cc_proxy_credentials(self._creds(), tmp_path, "test")
        assert calls["revoked"] == ["tid"]
        artifact = json.loads(
            (tmp_path / "cc-proxy-spend.json").read_text(),
        )
        assert artifact["dispatcher_spent_usd"] == 0.75
        # Max-of-ledgers with a 0 child report → dispatcher ledger.
        assert artifact["reconciled_usd"] == 0.75
        assert artifact["token_id"] == "tid"
        assert artifact["budget_usd"] == 5.0

    def test_settle_survives_dispatcher_gone(self, monkeypatch, tmp_path):
        """Best-effort: a dispatcher that died mid-run must not turn
        settlement into a crash (the dispatch outcome already stands)."""
        import core.llm.dispatcher.client as client_mod

        def _raise(*a, **kw):
            raise RuntimeError("LLM dispatcher unreachable")

        monkeypatch.setattr(client_mod, "child_token_spend", _raise)
        monkeypatch.setattr(client_mod, "revoke_child_token", _raise)
        sd._settle_cc_proxy_credentials(self._creds(), tmp_path, "test")
        artifact = json.loads(
            (tmp_path / "cc-proxy-spend.json").read_text(),
        )
        assert artifact["dispatcher_spent_usd"] == 0.0


class TestRunSkillDispatchProxyMode:

    def test_proxy_setup_failure_fails_pass_no_env_fallback(
        self, monkeypatch, tmp_path,
    ):
        """Knob on + no dispatcher route → the pass FAILS with a clear
        reason; the CC child is never spawned with env credentials."""
        monkeypatch.setenv(sd._CC_CREDENTIAL_MODE_ENV, "proxy")
        monkeypatch.delenv("RAPTOR_LLM_SOCKET", raising=False)

        # Pass the gate chain without touching real infrastructure.
        import core.security.rule_of_two as rot
        monkeypatch.setattr(
            rot, "require_human_or_sandbox_for_agentic_pass",
            lambda _cmd: None,
        )
        import core.llm.cc_adapter as cc_adapter
        monkeypatch.setattr(
            cc_adapter, "resolve_claude_cli",
            lambda _e=None: "/usr/bin/claude",
        )
        run_dir = tmp_path / "run"
        run_dir.mkdir()
        monkeypatch.setattr(sd, "start_lifecycle",
                            lambda _c, _t: run_dir)
        failures: list = []
        monkeypatch.setattr(
            sd, "fail_lifecycle",
            lambda rd, msg: failures.append((rd, msg)),
        )
        spawned: list = []
        monkeypatch.setattr(
            sd, "run_untrusted_networked",
            lambda *a, **kw: spawned.append(kw),
        )

        result = sd.run_skill_dispatch(
            command="understand",
            target=tmp_path,
            tools="Read",
            budget_usd="5.00",
            timeout_s=60,
            caller_label="test",
            log_label="test-pass",
            build_prompt=lambda _rd: "prompt",
        )
        assert result.ran is False
        assert "credential-proxy setup failed" in result.skipped_reason
        assert "RAPTOR_LLM_SOCKET" in result.skipped_reason
        assert spawned == []          # never dispatched
        assert failures and "credential-proxy setup" in failures[0][1]
