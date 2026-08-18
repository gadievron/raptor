"""Audit-pipeline in-process dispatcher self-serve.

Bedrock is dispatcher-only, and the audit entry points
(``raptor-audit run``, the corpus runner) call the LLM in the invoking
process — there is no ``spawn_worker`` hop to inject a route. Pre-fix,
a standalone audit run against a ``{"provider": "bedrock"}``
models.json entry had no ``RAPTOR_LLM_SOCKET``: every review died with
'requires the RAPTOR LLM dispatcher' and the client silently fell
back to the claudecode transport (which then shipped a Bedrock-shaped
model id to the direct API — HTTP 400).

These tests pin the gate: the standalone audit entry self-serves a
dispatcher route (stubbed here — no real socket, no network) exactly
when a resolved model routes to Bedrock, and never otherwise.
"""

from __future__ import annotations

import json

import pytest


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch, tmp_path):
    """Neutral CC/AWS env + cold caches so entry resolution is
    hermetic (mirrors test_bedrock_entry_resolution's fixture)."""
    for var in (
        "CLAUDE_CODE_USE_BEDROCK",
        "CLAUDE_CODE_USE_MANTLE",
        "ANTHROPIC_MODEL",
        "ANTHROPIC_API_KEY",
        "AWS_BEARER_TOKEN_BEDROCK",
        "RAPTOR_BEDROCK_API",
        "RAPTOR_BEDROCK_MODEL",
        "RAPTOR_BEDROCK_PROFILE",
        "RAPTOR_BEDROCK_REGION",
        "AWS_PROFILE",
        "AWS_SHARED_CREDENTIALS_FILE",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "RAPTOR_LLM_SOCKET",
        "RAPTOR_LLM_TOKEN_FD",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv(
        "RAPTOR_CC_PROBE_CACHE", str(tmp_path / "cc-probe.json"),
    )
    import core.llm.config as cfg
    import core.llm.detection as det
    det._cached_llm_availability = None
    cfg._cached_thinking_model = None
    cfg._thinking_model_checked = False
    monkeypatch.setattr(cfg, "_operator_primary_override", None)
    yield
    det._cached_llm_availability = None
    cfg._cached_thinking_model = None
    cfg._thinking_model_checked = False


@pytest.fixture
def bedrock_config(monkeypatch, tmp_path):
    """models.json with a Bedrock entry whose SigV4 auth is resolvable
    (pinned profile — the dispatcher signs; no static keys)."""
    config = tmp_path / "models.json"
    config.write_text(json.dumps({
        "models": [
            {
                "provider": "bedrock",
                "model": "anthropic.claude-opus-4-8",
                "aws_profile": "audit-test-profile",
                "region": "us-east-1",
            },
        ],
    }))
    monkeypatch.setenv("RAPTOR_CONFIG", str(config))
    # SigV4 credential signal (detection.bedrock_sigv4_intent reads
    # the env, not the entry fields) — a profile NAME only; nothing
    # signs in these tests.
    monkeypatch.setenv("AWS_PROFILE", "audit-test-profile")
    return config


@pytest.fixture
def stub_selfserve(monkeypatch):
    """Stub the dispatcher start: records the label and exports a fake
    route, so the gate is observable without a live socket."""
    import core.llm.dispatcher.lifecycle as lifecycle

    calls: list[str] = []

    def _fake_ensure(label: str = "inprocess"):
        calls.append(label)
        monkeypatch.setenv("RAPTOR_LLM_SOCKET", "/tmp/stub-route.sock")
        monkeypatch.setenv("RAPTOR_LLM_TOKEN_FD", "42")
        return None

    monkeypatch.setattr(
        lifecycle, "ensure_inprocess_dispatcher_env", _fake_ensure,
    )
    return calls


class TestAuditDispatcherSelfServe:

    def test_standalone_bedrock_entry_selfserves_route(
        self, bedrock_config, stub_selfserve,
    ):
        """The evidence shape: standalone audit entry + bedrock-provider
        entry → the dispatcher route is self-served and the primary
        stays on the bedrock provider (no claudecode fallback)."""
        import os

        from core.audit.pipeline import AuditPipelineOpts, _make_llm_client

        client, models, primary = _make_llm_client(AuditPipelineOpts())

        assert stub_selfserve == ["raptor-audit"]
        assert os.environ.get("RAPTOR_LLM_SOCKET") == "/tmp/stub-route.sock"
        assert client.config.primary_model is not None
        assert client.config.primary_model.provider == "bedrock", (
            "bedrock entry must resolve as primary — a claudecode "
            "fallback here is the pre-fix misroute"
        )

    def test_pinned_bedrock_model_selfserves_route(
        self, bedrock_config, stub_selfserve,
    ):
        """--model with a Bedrock-routed name (panel member) triggers
        the same gate through config_for_model resolution."""
        from core.audit.pipeline import AuditPipelineOpts, _make_llm_client

        _client, _models, _primary = _make_llm_client(
            AuditPipelineOpts(models=["anthropic.claude-opus-4-8"]),
        )
        assert stub_selfserve == ["raptor-audit"]

    def test_noop_when_route_already_exists(
        self, bedrock_config, stub_selfserve, monkeypatch,
    ):
        """A live session socket (pipeline runs under raptor.py) wins —
        no second dispatcher."""
        monkeypatch.setenv("RAPTOR_LLM_SOCKET", "/tmp/session.sock")

        from core.audit.pipeline import AuditPipelineOpts, _make_llm_client

        _make_llm_client(AuditPipelineOpts())
        assert stub_selfserve == []

    def test_noop_for_non_bedrock_models(
        self, monkeypatch, tmp_path, stub_selfserve,
    ):
        """Key-auth providers need no dispatcher — the gate must not
        fire (resolution order / behaviour byte-identical to today
        when no bedrock entry is configured)."""
        config = tmp_path / "models.json"
        config.write_text(json.dumps({
            "models": [
                {
                    "provider": "anthropic",
                    "model": "claude-opus-4-8",
                    "api_key": "sk-ant-test",
                },
            ],
        }))
        monkeypatch.setenv("RAPTOR_CONFIG", str(config))

        from core.audit.pipeline import AuditPipelineOpts, _make_llm_client

        _make_llm_client(AuditPipelineOpts())
        assert stub_selfserve == []

    def test_selfserve_failure_does_not_kill_audit(
        self, bedrock_config, monkeypatch,
    ):
        """Best-effort: a dispatcher start failure surfaces later as a
        provider error, never as a pipeline-setup crash."""
        import core.llm.dispatcher.lifecycle as lifecycle

        def _boom(label: str = "inprocess"):
            raise RuntimeError("no socket dir")

        monkeypatch.setattr(
            lifecycle, "ensure_inprocess_dispatcher_env", _boom,
        )

        from core.audit.pipeline import AuditPipelineOpts, _make_llm_client

        client, _models, _primary = _make_llm_client(AuditPipelineOpts())
        assert client is not None
