"""Bounded restart path for the Joern server.

A query timeout triggers a restart (stop → boot → CPG reload — worst
case minutes). The restart path is bounded: exactly one restarter
proceeds; concurrent restart callers fail fast instead of queueing on
the restart lock, and queries arriving during the restart window fail
fast with a clear error instead of posting into the dead/booting
server and blocking for their full timeout. All tests are hermetic —
no real Joern process is started.
"""

from __future__ import annotations

import threading
import time
from unittest.mock import patch

from packages.joern.server import JoernServer


class TestSingleRestarter:
    def test_concurrent_restart_fails_fast(self):
        """While one thread restarts, another restart() call returns
        False quickly rather than blocking for the restart duration."""
        srv = JoernServer()

        release = threading.Event()
        first_inside = threading.Event()

        def slow_stop():
            first_inside.set()
            release.wait(timeout=10)

        results = {}
        with patch.object(srv, "stop", side_effect=slow_stop), \
             patch.object(srv, "start"), \
             patch.object(srv, "import_cpg", return_value=True):

            t1 = threading.Thread(target=lambda: results.update(
                first=srv.restart()))
            t1.start()
            assert first_inside.wait(timeout=5)

            t0 = time.monotonic()
            results["second"] = srv.restart()
            waited = time.monotonic() - t0

            release.set()
            t1.join(timeout=10)

        assert results["second"] is False
        assert waited < 1.0, (
            f"concurrent restart() blocked for {waited:.1f}s — "
            f"must fail fast, not queue behind the restart"
        )
        # The single restarter completed normally (no CPG path set →
        # True without reload).
        assert results["first"] is True

    def test_restart_clears_restarting_flag_on_success(self):
        srv = JoernServer()
        with patch.object(srv, "stop"), patch.object(srv, "start"):
            assert srv.restart() is True
        assert srv.restarting is False

    def test_restart_clears_restarting_flag_on_boot_failure(self):
        srv = JoernServer()
        with patch.object(srv, "stop"), \
             patch.object(srv, "start", side_effect=RuntimeError("boom")):
            assert srv.restart() is False
        assert srv.restarting is False

    def test_restarting_flag_set_during_restart(self):
        srv = JoernServer()
        seen = {}

        def observing_stop():
            seen["during"] = srv.restarting

        with patch.object(srv, "stop", side_effect=observing_stop), \
             patch.object(srv, "start"):
            srv.restart()
        assert seen["during"] is True


class TestQueryFailsFastDuringRestart:
    def _server(self):
        srv = JoernServer()
        srv._cpg_loaded = True
        srv._base_url = "http://127.0.0.1:9999"
        return srv

    def test_query_fails_fast(self):
        srv = self._server()
        srv._restarting.set()

        def must_not_post(*a, **kw):
            raise AssertionError("query must not post during restart")

        with patch.object(srv, "_post_sync", side_effect=must_not_post):
            t0 = time.monotonic()
            result = srv.query("cpg.method.l")
            waited = time.monotonic() - t0

        assert result.errors
        assert "restarting" in result.errors[0]
        assert waited < 1.0

    def test_query_cancellable_fails_fast(self):
        srv = self._server()
        srv._restarting.set()

        with patch.object(srv, "_post_async",
                          side_effect=AssertionError("must not post")), \
             patch.object(srv, "_post_sync",
                          side_effect=AssertionError("must not post")):
            result = srv.query_cancellable("cpg.method.l", timeout=5)

        assert result.errors
        assert "restarting" in result.errors[0]

    def test_query_normal_after_restart_window(self):
        srv = self._server()
        srv._restarting.set()
        srv._restarting.clear()

        with patch.object(
            srv, "_post_sync",
            return_value={"stdout": "ok", "stderr": "", "success": True},
        ):
            result = srv.query("cpg.method.l")
        assert not result.errors


class TestBudgetClampedVerificationTimeouts:
    """Audit verification paths clamp Joern per-query timeouts to the
    remaining run budget."""

    def _config(self, tmp_path, deadline=None):
        from core.audit.orchestrator import OrchestratorConfig
        cfg = OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path)
        cfg.run_deadline_monotonic = deadline
        return cfg

    def test_no_deadline_uses_default(self, tmp_path):
        from core.audit.orchestrator import _joern_budget_timeout_s
        assert _joern_budget_timeout_s(self._config(tmp_path)) is None

    def test_ample_budget_clamps_to_default(self, tmp_path):
        from core.audit.joern_verify import default_query_timeout
        from core.audit.orchestrator import _joern_budget_timeout_s

        cfg = self._config(tmp_path, deadline=time.monotonic() + 100000)
        assert _joern_budget_timeout_s(cfg) == default_query_timeout()

    def test_small_budget_clamps_to_remaining(self, tmp_path):
        from core.audit.orchestrator import _joern_budget_timeout_s

        cfg = self._config(tmp_path, deadline=time.monotonic() + 60)
        clamped = _joern_budget_timeout_s(cfg)
        assert 30 <= clamped <= 60

    def test_exhausted_budget_returns_zero(self, tmp_path):
        from core.audit.orchestrator import _joern_budget_timeout_s

        cfg = self._config(tmp_path, deadline=time.monotonic() + 2)
        assert _joern_budget_timeout_s(cfg) == 0

    def _run_chain(self, tmp_path, monkeypatch, deadline):
        """Drive the joern_guard branch of _run_tool_chain with a
        stubbed verifier; returns the captured timeout kwarg (or the
        sentinel 'not-called')."""
        import core.audit.joern_verify as jv
        from core.audit.orchestrator import _run_tool_chain

        captured = {"timeout": "not-called"}

        def fake_guard_check(**kwargs):
            captured["timeout"] = kwargs.get("timeout")
            from core.audit.sweep import SweepResult
            return SweepResult(
                tool="joern", file_path=kwargs["file_path"],
                function_name=kwargs["function_name"],
                outcome="refuted",
            )

        monkeypatch.setattr(
            jv, "run_guard_dominance_check", fake_guard_check,
        )
        monkeypatch.setattr(
            jv, "extract_guard_target",
            lambda hypothesis, sinks: ("payload_len", "memcpy"),
        )

        cfg = self._config(tmp_path, deadline=deadline)
        _run_tool_chain(
            [{"type": "joern_guard", "config": {"sinks": ["memcpy"]}}],
            config=cfg,
            file_path="a.c",
            function_name="f",
            source=None,
            hypothesis="missing payload_len check before memcpy",
            joern_server=object(),
        )
        return captured["timeout"]

    def test_chain_passes_clamped_timeout(self, tmp_path, monkeypatch):
        deadline = time.monotonic() + 60
        timeout = self._run_chain(tmp_path, monkeypatch, deadline)
        assert timeout != "not-called"
        assert 30 <= timeout <= 60

    def test_chain_skips_query_when_budget_exhausted(
        self, tmp_path, monkeypatch,
    ):
        deadline = time.monotonic() + 2
        timeout = self._run_chain(tmp_path, monkeypatch, deadline)
        assert timeout == "not-called"

    def test_chain_uses_default_without_deadline(
        self, tmp_path, monkeypatch,
    ):
        # timeout=None → the verifier resolves the tunables default
        # itself (default_query_timeout()).
        timeout = self._run_chain(tmp_path, monkeypatch, None)
        assert timeout is None
