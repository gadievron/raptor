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

import logging
import threading
import time
from unittest.mock import patch

from packages.joern.models import JoernResult, TaintFlow
from packages.joern.server import _RESTARTING_ERROR, JoernServer


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


class TestTaintRetryAfterRestartWindow:
    """Taint entry points retry exactly once after a restart-window
    fail-fast, so a restart no longer drops every claim whose query
    landed in the window. ``query()`` itself keeps failing fast."""

    def _server(self) -> JoernServer:
        srv = JoernServer()
        srv._cpg_loaded = True
        srv._base_url = "http://127.0.0.1:9999"
        return srv

    @staticmethod
    def _restarting_result(q: str = "q") -> JoernResult:
        return JoernResult(query=q, errors=[_RESTARTING_ERROR])

    @staticmethod
    def _healthy_result(q: str = "q") -> JoernResult:
        flow = TaintFlow(source_method="readData", source_param="p0",
                         sink_call="writeData", sink_arg_idx=0)
        return JoernResult(query=q, flows=[flow], raw_output="ok")

    def test_restart_marker_retried_once_flows_recovered(self, caplog):
        """Restart finishes inside the deadline → one retry, evidence
        recovered, both INFO trail lines emitted."""
        srv = self._server()
        results = [self._restarting_result(), self._healthy_result()]
        calls: list[str] = []

        def fake_query(q, **kw):
            calls.append(q)
            return results[len(calls) - 1]

        errors_out: list[str] = []
        with patch.object(srv, "query", side_effect=fake_query), \
             caplog.at_level(logging.INFO, logger="packages.joern.server"):
            flows = srv.run_taint_query(
                "readData", "writeData", errors_out=errors_out,
            )

        assert len(calls) == 2
        assert len(flows) == 1
        assert errors_out == []
        assert "retrying once" in caplog.text
        assert "taint query retried after server restart" in caplog.text

    def test_non_restarting_errors_not_retried(self):
        """Timeouts / scala errors keep today's single-shot behavior."""
        srv = self._server()
        calls: list[str] = []

        def fake_query(q, **kw):
            calls.append(q)
            return JoernResult(query=q, errors=["timeout (async poll)"])

        errors_out: list[str] = []
        with patch.object(srv, "query", side_effect=fake_query):
            flows = srv.run_taint_query(
                "readData", "writeData", errors_out=errors_out,
            )

        assert len(calls) == 1
        assert flows == []
        assert errors_out == ["timeout (async poll)"]

    def test_deadline_expiry_returns_original_failfast(self):
        """Server still restarting when the deadline lapses → the
        original fail-fast errors come back, no retry attempted."""
        srv = self._server()
        srv._restarting.set()
        srv._cpg_loaded = False
        srv._last_import_timeout = 1
        calls: list[str] = []

        def fake_query(q, **kw):
            calls.append(q)
            return self._restarting_result(q)

        errors_out: list[str] = []
        # Negative margin collapses the deadline to "already expired"
        # so the too-short direction is exercised without wall-clock
        # waiting (the too-long direction is the retried-once test,
        # where the restart completes inside the window).
        with patch.object(srv, "query", side_effect=fake_query), \
             patch("packages.joern.server._RESTART_RETRY_MARGIN_S", -1.0), \
             patch("packages.joern.server._RESTART_RETRY_POLL_S", 0.01):
            flows = srv.run_taint_query(
                "readData", "writeData", errors_out=errors_out,
            )

        assert len(calls) == 1
        assert flows == []
        assert errors_out == [_RESTARTING_ERROR]

    def test_retry_failure_returned_as_is(self, caplog):
        """The single retry also fails → its errors propagate, exactly
        two calls total (never a loop), no success INFO."""
        srv = self._server()
        results = [
            self._restarting_result(),
            JoernResult(query="q", errors=["query failed: boom"]),
        ]
        calls: list[str] = []

        def fake_query(q, **kw):
            calls.append(q)
            return results[len(calls) - 1]

        errors_out: list[str] = []
        with patch.object(srv, "query", side_effect=fake_query), \
             caplog.at_level(logging.INFO, logger="packages.joern.server"):
            flows = srv.run_taint_query(
                "readData", "writeData", errors_out=errors_out,
            )

        assert len(calls) == 2
        assert flows == []
        assert errors_out == ["query failed: boom"]
        assert "retrying once" in caplog.text
        assert "taint query retried after server restart" not in caplog.text

    def test_exists_query_shares_the_retry_policy(self):
        """run_taint_exists_query routes through the same helper."""
        srv = self._server()
        results = [
            self._restarting_result(),
            JoernResult(query="q", raw_output="JOERN_EXISTS:true"),
        ]
        calls: list[str] = []

        def fake_query(q, **kw):
            calls.append(q)
            return results[len(calls) - 1]

        with patch.object(srv, "query", side_effect=fake_query):
            assert srv.run_taint_exists_query("readData", "writeData") is True
        assert len(calls) == 2


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


class TestRetryWaitBounds:
    """The restart-window wait must not outlive its usefulness."""

    @staticmethod
    def _restarting_result(q: str = "q") -> JoernResult:
        return JoernResult(query=q, errors=[_RESTARTING_ERROR])

    def test_failed_restart_exits_wait_immediately(self):
        """``restarting`` cleared with no loaded CPG = the restart
        FAILED; waiting further can only stall every waiter for the
        full deadline on a server that already reported failure."""
        srv = JoernServer()
        srv._restarting.clear()
        srv._cpg_loaded = False
        calls: list[int] = []

        def fake_query() -> JoernResult:
            calls.append(1)
            return self._restarting_result()

        t0 = time.monotonic()
        result = srv._retry_once_after_restart(fake_query)
        assert time.monotonic() - t0 < 1.0
        assert result.errors == [_RESTARTING_ERROR]
        assert len(calls) == 1

    def test_caller_timeout_caps_the_wait(self):
        """A budget-clamped query must not wait past its own timeout."""
        srv = JoernServer()
        srv._restarting.set()
        srv._cpg_loaded = False
        calls: list[int] = []

        def fake_query() -> JoernResult:
            calls.append(1)
            return self._restarting_result()

        try:
            t0 = time.monotonic()
            result = srv._retry_once_after_restart(
                fake_query, max_wait_s=0.0,
            )
            assert time.monotonic() - t0 < 1.0
            assert result.errors == [_RESTARTING_ERROR]
            assert len(calls) == 1
        finally:
            srv._restarting.clear()


class TestCpgLoadEpoch:
    """Every successful CPG load bumps ``cpg_load_epoch`` — the memo
    key consumers use to discard per-graph caches across the
    ``restart()`` re-import (which never passes through lane start)."""

    def test_import_cpg_bumps_epoch(self, tmp_path):
        srv = JoernServer()
        cpg = tmp_path / "c.bin"
        cpg.write_bytes(b"x")
        assert srv.cpg_load_epoch == 0
        with patch.object(srv, "_post_sync",
                          return_value={"success": True}), \
             patch.object(srv, "_verify_cpg_binding", return_value=True), \
             patch.object(srv, "_warmup_dataflow"):
            assert srv.import_cpg(cpg, timeout=5)
        assert srv.cpg_load_epoch == 1

    def test_failed_import_does_not_bump(self, tmp_path):
        srv = JoernServer()
        cpg = tmp_path / "c.bin"
        cpg.write_bytes(b"x")
        with patch.object(srv, "_post_sync",
                          return_value={"success": False, "stderr": "x"}):
            assert not srv.import_cpg(cpg, timeout=5)
        assert srv.cpg_load_epoch == 0

    def test_import_code_bumps_epoch(self, tmp_path):
        srv = JoernServer()
        with patch.object(srv, "_post_sync",
                          return_value={"success": True}), \
             patch.object(srv, "_verify_cpg_binding", return_value=True):
            assert srv.import_code(tmp_path, timeout=5)
        assert srv.cpg_load_epoch == 1


class TestNoRestartSeam:
    """query(no_restart=True) opts a side-channel query out of the
    timeout-triggered restart: only queries whose timeout evidences a
    stuck REPL may wield the recovery ladder."""

    @staticmethod
    def _timeout_post(srv):
        def fake_post(query_str, *, timeout=30):
            srv._last_post_error = f"query timed out after {timeout}s"
            return None
        return fake_post

    def test_timeout_with_no_restart_skips_restart(self):
        srv = JoernServer()
        srv._cpg_loaded = True
        with patch.object(srv, "_post_sync",
                          side_effect=self._timeout_post(srv)), \
             patch.object(srv, "restart") as restart:
            result = srv.query("cpg.method.name.l", timeout=1,
                               no_restart=True)
        assert restart.call_count == 0
        assert any("timed out" in e for e in result.errors)

    def test_timeout_without_no_restart_still_restarts(self):
        srv = JoernServer()
        srv._cpg_loaded = True
        with patch.object(srv, "_post_sync",
                          side_effect=self._timeout_post(srv)), \
             patch.object(srv, "restart") as restart:
            srv.query("cpg.method.name.l", timeout=1)
        assert restart.call_count == 1


class TestPostErrorClassificationRace:
    """_last_post_error is read by query() AFTER _post_sync returns to
    decide the stuck-REPL restart; sweep threads share the instance,
    so the classification must be per-thread — a sibling's entry-reset
    used to clobber a genuine timeout before its own query() read it,
    skipping the restart and cross-attributing the error text."""

    def test_sibling_entry_reset_cannot_clobber_timeout(self):
        srv = JoernServer()
        srv._cpg_loaded = True
        srv._base_url = "http://joern-local"
        srv._uds_path = "/nonexistent.sock"  # route _post_sync → uds

        restarts: list[int] = []
        a_set_error = threading.Event()
        b_done = threading.Event()

        def stub_uds(method, path, payload, timeout):
            if "QUERY_A" in payload["query"]:
                # A's transport timed out: classification written...
                srv._last_post_error = f"query timed out after {timeout}s"
                a_set_error.set()
                # ...then B's whole round-trip (entry-reset included)
                # lands before A's query() reads it.
                b_done.wait(5)
                return None
            return {"stdout": 'val res0: String = "ok"', "stderr": ""}

        results: dict = {}
        with patch.object(srv, "_uds_request", side_effect=stub_uds), \
             patch.object(srv, "restart",
                          side_effect=lambda: restarts.append(1) or True):
            ta = threading.Thread(target=lambda: results.update(
                a=srv.query("QUERY_A", timeout=10, validate=False)))
            ta.start()
            assert a_set_error.wait(5)
            results["b"] = srv.query("QUERY_B", timeout=10, validate=False)
            b_done.set()
            ta.join(10)

        # A keeps ITS classification: restart fires for the genuine
        # timeout and the error text is not cross-attributed.
        assert results["a"].errors == ["query timed out after 10s"]
        assert restarts == [1]
        assert not results["b"].errors
