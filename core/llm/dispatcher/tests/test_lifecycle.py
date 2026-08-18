"""Tests for ``core.llm.dispatcher.lifecycle``.

Confirms:
  * ``dispatcher_for_run`` derives ``run_id`` from the run dir basename.
  * Audit log lands at ``<run_dir>/audit-llm-dispatcher.jsonl``.
  * Context-manager shuts the dispatcher down on normal + exceptional exits.
  * Missing run_dir raises early (rather than silently writing audit
    to a nonexistent path and losing entries).
"""

from __future__ import annotations

import pytest

from core.llm.dispatcher.auth import CredentialStore
from core.llm.dispatcher.lifecycle import (
    _AUDIT_FILENAME,
    dispatcher_for_run,
    llm_dispatcher_in_run,
)


@pytest.fixture
def fake_creds():
    creds = CredentialStore.__new__(CredentialStore)
    creds._keys = {"anthropic": "fake-key", "openai": None, "gemini": None}
    return creds


class TestDispatcherForRun:

    def test_audit_path_is_inside_run_dir(self, fake_creds, tmp_path):
        run_dir = tmp_path / "run_20260507_120000"
        run_dir.mkdir()
        d = dispatcher_for_run(run_dir, creds=fake_creds)
        try:
            assert d._audit_path == run_dir / _AUDIT_FILENAME
            # An event is written immediately on start, so the file
            # must already exist.
            assert (run_dir / _AUDIT_FILENAME).exists()
        finally:
            d.shutdown()

    def test_run_id_matches_run_dir_name(self, fake_creds, tmp_path):
        run_dir = tmp_path / "scan_alpha"
        run_dir.mkdir()
        d = dispatcher_for_run(run_dir, creds=fake_creds)
        try:
            assert d.run_id == "scan_alpha"
        finally:
            d.shutdown()

    def test_missing_run_dir_raises(self, fake_creds, tmp_path):
        run_dir = tmp_path / "does-not-exist"
        with pytest.raises(FileNotFoundError):
            dispatcher_for_run(run_dir, creds=fake_creds)

    def test_kwargs_flow_through_to_dispatcher(self, fake_creds, tmp_path):
        run_dir = tmp_path / "tuned"
        run_dir.mkdir()
        d = dispatcher_for_run(
            run_dir, creds=fake_creds,
            token_ttl_s=1234, token_budget=42,
        )
        try:
            assert d._token_ttl_s == 1234
            assert d._token_budget == 42
        finally:
            d.shutdown()


class TestLlmDispatcherInRun:

    def test_normal_exit_shuts_down(self, fake_creds, tmp_path):
        run_dir = tmp_path / "ctx_normal"
        run_dir.mkdir()
        with llm_dispatcher_in_run(run_dir, creds=fake_creds) as d:
            sock_dir = d._sock_dir
            assert sock_dir.exists()
        # After context exit, socket dir is gone
        assert not sock_dir.exists()

    def test_exception_still_shuts_down(self, fake_creds, tmp_path):
        run_dir = tmp_path / "ctx_excpt"
        run_dir.mkdir()
        sock_dir_holder = {}
        with pytest.raises(RuntimeError):
            with llm_dispatcher_in_run(run_dir, creds=fake_creds) as d:
                sock_dir_holder["path"] = d._sock_dir
                raise RuntimeError("boom")
        assert not sock_dir_holder["path"].exists()


class TestEnsureInprocessDispatcherEnv:
    def test_noop_when_route_exists(self, monkeypatch):
        from core.llm.dispatcher.lifecycle import (
            ensure_inprocess_dispatcher_env,
        )
        monkeypatch.setenv("RAPTOR_LLM_SOCKET", "/tmp/existing.sock")
        assert ensure_inprocess_dispatcher_env() is None

    def test_starts_and_exports_route(self, monkeypatch):
        from core.llm.dispatcher.lifecycle import (
            ensure_inprocess_dispatcher_env,
        )
        monkeypatch.delenv("RAPTOR_LLM_SOCKET", raising=False)
        monkeypatch.delenv("RAPTOR_LLM_TOKEN_FD", raising=False)
        d = ensure_inprocess_dispatcher_env(label="test-inproc")
        try:
            assert d is not None
            import os
            sock = os.environ["RAPTOR_LLM_SOCKET"]
            assert sock == str(d.socket_path)
            fd = int(os.environ["RAPTOR_LLM_TOKEN_FD"])
            # The exported FD carries a readable token, same contract
            # spawn_worker gives a child process.
            from core.llm.dispatcher.client import read_token
            token = read_token(fd)
            assert token
        finally:
            # The helper mutates os.environ by design (its process IS
            # the worker); scrub the route so later tests don't dial a
            # dead dispatcher socket.
            import os
            os.environ.pop("RAPTOR_LLM_SOCKET", None)
            os.environ.pop("RAPTOR_LLM_TOKEN_FD", None)
            if d is not None:
                d.shutdown()


class TestEnsureRouteForModelConfigs:
    """Shared self-serve gate for standalone entry points
    (raptor-llm-ask, the audit pipeline): starts an in-process
    dispatcher only when a resolved model is dispatcher-only
    (Bedrock) and no route exists."""

    def test_noop_when_route_exists(self, monkeypatch):
        from types import SimpleNamespace

        from core.llm.dispatcher.lifecycle import (
            ensure_route_for_model_configs,
        )
        monkeypatch.setenv("RAPTOR_LLM_SOCKET", "/tmp/existing.sock")
        assert ensure_route_for_model_configs(
            [SimpleNamespace(provider="bedrock")], label="t",
        ) is None

    def test_noop_without_dispatcher_only_provider(self, monkeypatch):
        from types import SimpleNamespace

        from core.llm.dispatcher.lifecycle import (
            ensure_route_for_model_configs,
        )
        monkeypatch.delenv("RAPTOR_LLM_SOCKET", raising=False)
        assert ensure_route_for_model_configs(
            [
                None,
                SimpleNamespace(provider="anthropic"),
                SimpleNamespace(provider="claudecode"),
            ],
            label="t",
        ) is None
        import os
        assert "RAPTOR_LLM_SOCKET" not in os.environ

    def test_starts_and_exports_route_for_bedrock(self, monkeypatch):
        from types import SimpleNamespace

        from core.llm.dispatcher.lifecycle import (
            ensure_route_for_model_configs,
        )
        monkeypatch.delenv("RAPTOR_LLM_SOCKET", raising=False)
        monkeypatch.delenv("RAPTOR_LLM_TOKEN_FD", raising=False)
        d = ensure_route_for_model_configs(
            [SimpleNamespace(provider="bedrock")], label="test-route",
        )
        try:
            assert d is not None
            import os
            assert os.environ["RAPTOR_LLM_SOCKET"] == str(d.socket_path)
            assert os.environ["RAPTOR_LLM_TOKEN_FD"]
        finally:
            if d is not None:
                d.shutdown()
            import os
            os.environ.pop("RAPTOR_LLM_SOCKET", None)
            os.environ.pop("RAPTOR_LLM_TOKEN_FD", None)
