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


class TestConcurrentFirstCallers:
    def test_concurrent_first_callers_construct_one_dispatcher(
        self, monkeypatch,
    ):
        """The env check-then-set sequence is locked: two racing first
        callers must not both pass the RAPTOR_LLM_SOCKET check — the
        loser's dispatcher would be stray (socket dir until the
        atexit/dead-owner sweep) and its env write would silently
        clobber the winner's route."""
        import os
        import threading
        import time as _time

        from core.llm.dispatcher import lifecycle
        from core.llm.dispatcher.server import LLMDispatcher

        monkeypatch.delenv("RAPTOR_LLM_SOCKET", raising=False)
        monkeypatch.delenv("RAPTOR_LLM_TOKEN_FD", raising=False)

        constructed: list = []
        real_init = LLMDispatcher.__init__

        def slow_init(self, *a, **k):
            constructed.append(self)
            _time.sleep(0.3)  # hold the construction window open
            real_init(self, *a, **k)

        monkeypatch.setattr(LLMDispatcher, "__init__", slow_init)

        results: list = []

        def caller(tag: str) -> None:
            results.append(
                lifecycle.ensure_inprocess_dispatcher_env(
                    label=f"race-{tag}"))

        t1 = threading.Thread(target=caller, args=("a",))
        t2 = threading.Thread(target=caller, args=("b",))
        t1.start()
        t2.start()
        t1.join(timeout=30)
        t2.join(timeout=30)
        live = [d for d in results if d is not None]
        try:
            assert len(constructed) == 1, (
                "concurrent first callers constructed "
                f"{len(constructed)} dispatchers"
            )
            assert len(live) == 1
            assert os.environ["RAPTOR_LLM_SOCKET"] == str(
                live[0].socket_path)
        finally:
            os.environ.pop("RAPTOR_LLM_SOCKET", None)
            os.environ.pop("RAPTOR_LLM_TOKEN_FD", None)
            for d in live:
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


class TestInprocessTokenTTL:
    """The in-process route's token must out-last long runs.

    The 8 h spawned-worker default decapitated the trailing phases of
    any run longer than the TTL (observed: every Phase-2 call after
    hour 8 of an 8.2 h run 401'd). In-process, the token store dies
    with the process, so a run-length-outlasting TTL costs nothing.
    """

    def _issued_ttl(self, dispatcher):
        recs = list(dispatcher._tokens.values())
        assert len(recs) == 1
        rec = recs[0]
        return rec.expires_at - rec.issued_at

    def test_default_ttl_outlasts_worker_default(self, monkeypatch):
        from core.llm.dispatcher.lifecycle import (
            _INPROCESS_TOKEN_TTL_S,
            ensure_inprocess_dispatcher_env,
        )
        monkeypatch.delenv("RAPTOR_LLM_SOCKET", raising=False)
        monkeypatch.delenv("RAPTOR_LLM_TOKEN_FD", raising=False)
        monkeypatch.delenv(
            "RAPTOR_LLM_DISPATCHER_TOKEN_TTL_S", raising=False,
        )
        d = ensure_inprocess_dispatcher_env(label="test-ttl")
        try:
            assert d is not None
            ttl = self._issued_ttl(d)
            assert ttl == _INPROCESS_TOKEN_TTL_S
            assert ttl > 8 * 60 * 60
        finally:
            import os
            os.environ.pop("RAPTOR_LLM_SOCKET", None)
            os.environ.pop("RAPTOR_LLM_TOKEN_FD", None)
            if d is not None:
                d.shutdown()

    def test_operator_env_override_wins(self, monkeypatch):
        from core.llm.dispatcher.lifecycle import (
            ensure_inprocess_dispatcher_env,
        )
        monkeypatch.delenv("RAPTOR_LLM_SOCKET", raising=False)
        monkeypatch.delenv("RAPTOR_LLM_TOKEN_FD", raising=False)
        monkeypatch.setenv("RAPTOR_LLM_DISPATCHER_TOKEN_TTL_S", "1234")
        d = ensure_inprocess_dispatcher_env(label="test-ttl-env")
        try:
            assert d is not None
            assert self._issued_ttl(d) == 1234
        finally:
            import os
            os.environ.pop("RAPTOR_LLM_SOCKET", None)
            os.environ.pop("RAPTOR_LLM_TOKEN_FD", None)
            if d is not None:
                d.shutdown()


class TestAuditPathWiring:
    """The L5 audit JSONL must land inside the run's output directory
    whenever a run dir is resolvable at dispatcher construction —
    in-memory-only is reserved for genuinely run-less invocations."""

    def test_audit_path_for_run_dir_accessor(self, tmp_path):
        from core.llm.dispatcher.lifecycle import audit_path_for_run_dir
        assert audit_path_for_run_dir(tmp_path) == tmp_path / _AUDIT_FILENAME

    def test_inprocess_route_writes_audit_into_run_dir(
        self, monkeypatch, tmp_path,
    ):
        import os

        from core.llm.dispatcher.lifecycle import (
            ensure_inprocess_dispatcher_env,
        )
        monkeypatch.delenv("RAPTOR_LLM_SOCKET", raising=False)
        monkeypatch.delenv("RAPTOR_LLM_TOKEN_FD", raising=False)
        d = ensure_inprocess_dispatcher_env(
            label="test-audit", run_dir=tmp_path,
        )
        try:
            assert d is not None
            # server.start is audited at construction, so the trail
            # exists immediately.
            assert (tmp_path / _AUDIT_FILENAME).exists()
        finally:
            os.environ.pop("RAPTOR_LLM_SOCKET", None)
            os.environ.pop("RAPTOR_LLM_TOKEN_FD", None)
            if d is not None:
                d.shutdown()

    def test_inprocess_route_without_run_dir_stays_in_memory(
        self, monkeypatch,
    ):
        import os

        from core.llm.dispatcher.lifecycle import (
            ensure_inprocess_dispatcher_env,
        )
        monkeypatch.delenv("RAPTOR_LLM_SOCKET", raising=False)
        monkeypatch.delenv("RAPTOR_LLM_TOKEN_FD", raising=False)
        d = ensure_inprocess_dispatcher_env(label="test-noaudit")
        try:
            assert d is not None
            assert d._audit_path is None
        finally:
            os.environ.pop("RAPTOR_LLM_SOCKET", None)
            os.environ.pop("RAPTOR_LLM_TOKEN_FD", None)
            if d is not None:
                d.shutdown()


class TestAuditTrailHardening:
    """The audit append goes through the hardened trail writer: a
    symlink planted at the predictable audit path must be refused
    (O_NOFOLLOW), not followed to redirect the append."""

    def test_symlinked_audit_path_refused(self, fake_creds, tmp_path):
        victim = tmp_path / "victim.txt"
        victim.write_text("untouched\n")
        run_dir = tmp_path / "run"
        run_dir.mkdir()
        (run_dir / _AUDIT_FILENAME).symlink_to(victim)
        d = dispatcher_for_run(run_dir, creds=fake_creds)
        try:
            # The append was refused: nothing rode through the
            # symlink, and the failure latched the once-per-process
            # warning flag instead of raising into the caller.
            assert victim.read_text() == "untouched\n"
            assert getattr(d, "_audit_warned", False) is True
        finally:
            d.shutdown()


class TestSocketPathBudget:
    def test_deep_tmpdir_still_binds(self, monkeypatch, tmp_path):
        """AF_UNIX sun_path tops out around 108 bytes: a deep TMPDIR
        (nested session/pytest scratch layers) used to push
        <sock_dir>/llm-child.sock past the limit and bind() failed at
        dispatcher init. The fallback must land the socket somewhere
        bindable."""
        import tempfile as _tempfile

        from core.llm.dispatcher.auth import CredentialStore
        from core.llm.dispatcher.server import LLMDispatcher

        creds = CredentialStore.__new__(CredentialStore)
        creds._keys = {}

        deep = tmp_path
        for i in range(12):
            deep = deep / f"layer-{i:02d}"
        deep.mkdir(parents=True)
        monkeypatch.setenv("TMPDIR", str(deep))
        _tempfile.tempdir = None  # re-derive gettempdir from env
        try:
            d = LLMDispatcher(
                run_id="deep-tmpdir-e2e",
                creds=creds,
                audit_path=tmp_path / "audit.jsonl",
            )
            try:
                assert d.socket_path.exists()
                assert len(str(d.child_socket_path).encode()) <= 104
            finally:
                d.shutdown()
        finally:
            _tempfile.tempdir = None
