"""Duplicate operator-console lines — each message on ONE channel.

Observed on a real instrumented run: the Joern pre-sweep announcement
printed twice (logger + progress callback), and the budget-exhausted
stop line printed multiple times (logger + progress callback, plus
one client-side "Budget exceeded" line per post-exhaustion dispatch
attempt).
"""

from __future__ import annotations

import logging
import types

import core.audit.orchestrator as orch
from core.audit import joern_backend
from core.audit.orchestrator import (
    OrchestratorResult,
    _announce_budget_stop,
)


def _capture(monkeypatch, module, method="warning"):
    lines: list[str] = []
    real = getattr(module.logger, method)

    def _sink(msg, *args, **kwargs):
        try:
            lines.append(str(msg) % args if args else str(msg))
        except (TypeError, ValueError):
            lines.append(str(msg))
        real(msg, *args, **kwargs)

    monkeypatch.setattr(module.logger, method, _sink)
    return lines


class _Graph:
    pending = 3

    def __len__(self):
        return 5


class TestBudgetStopSingleChannel:
    def _stats(self):
        return types.SimpleNamespace(completed=2, repass_completed=0)

    def test_progress_callback_is_the_only_channel(self, monkeypatch):
        warned = _capture(monkeypatch, orch, "warning")
        progressed: list[str] = []

        result = OrchestratorResult()
        result.terminated_by = "llm_budget_exceeded"
        _announce_budget_stop(
            result, self._stats(), _Graph(),
            lambda idx, total, outcome: progressed.append(outcome.body),
        )

        assert len(progressed) == 1
        assert "budget exhausted" in progressed[0]
        # No second copy through the logger.
        assert not [m for m in warned if "budget exhausted" in m]

    def test_logger_fallback_without_callback(self, monkeypatch):
        warned = _capture(monkeypatch, orch, "warning")
        result = OrchestratorResult()
        result.terminated_by = "max_cost_usd"
        _announce_budget_stop(result, self._stats(), _Graph(), None)
        assert len([m for m in warned if "budget exhausted" in m]) == 1

    def test_logger_fallback_when_callback_raises(self, monkeypatch):
        warned = _capture(monkeypatch, orch, "warning")

        def _boom(idx, total, outcome):
            raise RuntimeError("progress pipe closed")

        result = OrchestratorResult()
        result.terminated_by = "llm_budget_exceeded"
        _announce_budget_stop(result, self._stats(), _Graph(), _boom)
        assert len([m for m in warned if "budget exhausted" in m]) == 1


class TestJoernProgressSingleChannel:
    def _resolve(self, monkeypatch, tmp_path, *, callback):
        monkeypatch.setattr(
            joern_backend, "joern_available", lambda overrides=None: True,
        )
        monkeypatch.setattr(
            joern_backend, "target_has_c_sources", lambda p: True,
        )
        monkeypatch.setattr(
            joern_backend, "build_joern_evidence",
            lambda *a, **kw: None,
        )
        server = types.SimpleNamespace(is_alive=lambda: True)
        return joern_backend.resolve_joern_evidence(
            tmp_path,
            on_joern_progress=callback,
            joern_server=server,
        )

    def test_callback_suppresses_logger_copy(self, monkeypatch, tmp_path):
        infos = _capture(monkeypatch, joern_backend, "info")
        seen: list[str] = []
        _, future = self._resolve(monkeypatch, tmp_path, callback=seen.append)
        if future is not None:
            future.result(timeout=10)
        assert len([m for m in seen if "Joern pre-sweep" in m]) == 1
        assert not [m for m in infos if "Joern pre-sweep" in m]

    def test_logger_used_without_callback(self, monkeypatch, tmp_path):
        infos = _capture(monkeypatch, joern_backend, "info")
        _, future = self._resolve(monkeypatch, tmp_path, callback=None)
        if future is not None:
            future.result(timeout=10)
        assert len([m for m in infos if "Joern pre-sweep" in m]) == 1


class TestClientBudgetLogOnce:
    def _client(self, cap=1.0):
        from core.llm.client import LLMClient
        from core.llm.config import LLMConfig, ModelConfig

        config = LLMConfig(
            primary_model=ModelConfig(
                provider="anthropic", model_name="m", api_key="k",
            ),
            enable_caching=False,
            enable_fallback=False,
            enable_cost_tracking=True,
            max_cost_per_scan=cap,
        )
        return LLMClient(config)

    def test_repeated_refusals_log_error_once(self, monkeypatch):
        import core.llm.client as client_mod

        records: list[tuple[int, str]] = []

        def _make_sink(level, real):
            def _sink(msg, *args, **kwargs):
                records.append(
                    (level, str(msg) % args if args else str(msg)),
                )
                real(msg, *args, **kwargs)
            return _sink

        monkeypatch.setattr(
            client_mod.logger, "info",
            _make_sink(logging.INFO, client_mod.logger.info),
        )
        monkeypatch.setattr(
            client_mod.logger, "debug",
            _make_sink(logging.DEBUG, client_mod.logger.debug),
        )

        client = self._client(cap=1.0)
        client.total_cost = 1.0
        for _ in range(5):
            assert client._check_budget(0.5) is False
        for _ in range(5):
            assert client._acquire_budget(0.5) is False

        budget_lines = [r for r in records if "Budget exceeded" in r[1]]
        # INFO, not ERROR: a designed budget stop is not a failure.
        infos = [r for r in budget_lines if r[0] == logging.INFO]
        debugs = [r for r in budget_lines if r[0] == logging.DEBUG]
        assert len(infos) == 1, budget_lines
        assert len(debugs) == 9
