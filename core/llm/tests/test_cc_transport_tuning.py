"""Tests for claudecode transport tuning: model pinning, worker
derivation, dispatch knobs, and retry classification of surfaced
abort causes."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in (
        "RAPTOR_CC_MODEL",
        "RAPTOR_CC_PIN_MODEL",
        "RAPTOR_CC_MAX_WORKERS",
        "RAPTOR_CC_EFFORT",
        "RAPTOR_CC_FALLBACK_MODEL",
    ):
        monkeypatch.delenv(var, raising=False)


class TestResolveClaudecodeModel:
    def test_env_override_wins(self, monkeypatch):
        from core.llm import config as cfg

        monkeypatch.setenv("RAPTOR_CC_MODEL", "operator-choice")
        monkeypatch.setattr(
            "core.llm.cc_probe.cached_cc_session_model",
            lambda: "probed-model",
        )
        assert cfg._resolve_claudecode_model() == "operator-choice"

    def test_cached_probe_pins(self, monkeypatch):
        from core.llm import config as cfg

        monkeypatch.setattr(
            "core.llm.cc_probe.cached_cc_session_model",
            lambda: "backend.resolved-id",
        )
        assert cfg._resolve_claudecode_model() == "backend.resolved-id"

    def test_pin_opt_out_returns_sentinel(self, monkeypatch):
        from core.llm import config as cfg

        monkeypatch.setenv("RAPTOR_CC_PIN_MODEL", "0")
        monkeypatch.setattr(
            "core.llm.cc_probe.cached_cc_session_model",
            lambda: "backend.resolved-id",
        )
        assert (
            cfg._resolve_claudecode_model() == cfg.CLAUDECODE_SESSION_MODEL
        )

    def test_cold_cache_returns_sentinel(self, monkeypatch):
        from core.llm import config as cfg

        monkeypatch.setattr(
            "core.llm.cc_probe.cached_cc_session_model", lambda: None,
        )
        assert (
            cfg._resolve_claudecode_model() == cfg.CLAUDECODE_SESSION_MODEL
        )

    def test_provider_omits_model_flag_only_for_sentinel(self):
        from core.llm.config import CLAUDECODE_SESSION_MODEL, ModelConfig
        from core.llm.providers import ClaudeCodeLLMProvider

        sentinel = ClaudeCodeLLMProvider(ModelConfig(
            provider="claudecode",
            model_name=CLAUDECODE_SESSION_MODEL,
            api_key=None, timeout=30,
        ))
        assert sentinel._cli_model() is None

        pinned = ClaudeCodeLLMProvider(ModelConfig(
            provider="claudecode",
            model_name="backend.resolved-id",
            api_key=None, timeout=30,
        ))
        assert pinned._cli_model() == "backend.resolved-id"


class TestClaudecodeWorkerCap:
    def _mock_primary(self, monkeypatch, provider, model_name):
        class _MC:
            pass
        mc = _MC()
        mc.provider = provider
        mc.model_name = model_name
        monkeypatch.setattr(
            "core.llm.config._get_default_primary_model",
            lambda prefer=None: mc,
        )

    def test_claudecode_primary_clamped(self, monkeypatch):
        from core.llm.concurrency import (
            CC_MAX_WORKERS_DEFAULT,
            derive_max_workers,
        )

        self._mock_primary(
            monkeypatch, "claudecode", "anthropic.claude-fable-5",
        )
        monkeypatch.setattr(
            "core.llm.concurrency.read_tuning_max_llm_workers",
            lambda: None,
        )
        assert (
            derive_max_workers("anthropic.claude-fable-5")
            == CC_MAX_WORKERS_DEFAULT
        )

    def test_env_override_raises_cap(self, monkeypatch):
        from core.llm.concurrency import derive_max_workers

        self._mock_primary(
            monkeypatch, "claudecode", "anthropic.claude-fable-5",
        )
        monkeypatch.setattr(
            "core.llm.concurrency.read_tuning_max_llm_workers",
            lambda: None,
        )
        monkeypatch.setenv("RAPTOR_CC_MAX_WORKERS", "8")
        assert derive_max_workers("anthropic.claude-fable-5") == 8

    def test_non_claudecode_primary_uncapped(self, monkeypatch):
        from core.llm.concurrency import derive_max_workers

        self._mock_primary(monkeypatch, "anthropic", "claude-opus-5")
        monkeypatch.setattr(
            "core.llm.concurrency.read_tuning_max_llm_workers",
            lambda: None,
        )
        assert derive_max_workers("claude-opus-5") > 4

    def test_tuning_override_beats_cc_cap(self, monkeypatch):
        from core.llm.concurrency import derive_max_workers

        self._mock_primary(
            monkeypatch, "claudecode", "anthropic.claude-fable-5",
        )
        monkeypatch.setattr(
            "core.llm.concurrency.read_tuning_max_llm_workers",
            lambda: 12,
        )
        assert derive_max_workers("anthropic.claude-fable-5") == 12


class TestUnknownRpmWorkerFloor:
    """derive_max_workers when the model's RPM is unknown (rpm=0).

    The claudecode transport's session-default sentinel (and unknown
    backend ids) resolve to rpm=0 — the worker floor there is the
    subprocess ceiling, not 1.
    """

    def _mock_primary(self, monkeypatch, provider, model_name):
        class _MC:
            pass
        mc = _MC()
        mc.provider = provider
        mc.model_name = model_name
        monkeypatch.setattr(
            "core.llm.config._get_default_primary_model",
            lambda prefer=None: mc,
        )

    def _mock_rpm(self, monkeypatch, rpm):
        monkeypatch.setattr(
            "core.llm.model_data.rpm_for", lambda model, **kw: rpm,
        )

    def _no_tuning(self, monkeypatch):
        monkeypatch.setattr(
            "core.llm.concurrency.read_tuning_max_llm_workers",
            lambda: None,
        )

    def test_claudecode_primary_unknown_rpm_floors_at_cc_cap(
        self, monkeypatch,
    ):
        from core.llm.concurrency import (
            CC_MAX_WORKERS_DEFAULT,
            derive_max_workers,
        )

        self._mock_primary(monkeypatch, "claudecode", "session-default")
        self._mock_rpm(monkeypatch, 0)
        self._no_tuning(monkeypatch)
        assert (
            derive_max_workers("session-default") == CC_MAX_WORKERS_DEFAULT
        )

    def test_cc_env_override_applies_to_unknown_rpm_floor(
        self, monkeypatch,
    ):
        from core.llm.concurrency import derive_max_workers

        self._mock_primary(monkeypatch, "claudecode", "session-default")
        self._mock_rpm(monkeypatch, 0)
        self._no_tuning(monkeypatch)
        monkeypatch.setenv("RAPTOR_CC_MAX_WORKERS", "2")
        assert derive_max_workers("session-default") == 2

    def test_non_claudecode_unknown_rpm_stays_serial(self, monkeypatch):
        from core.llm.concurrency import derive_max_workers

        self._mock_primary(monkeypatch, "anthropic", "mystery-model")
        self._mock_rpm(monkeypatch, 0)
        self._no_tuning(monkeypatch)
        assert derive_max_workers("mystery-model") == 1

    def test_known_rpm_still_derives_and_clamps(self, monkeypatch):
        from core.llm.concurrency import (
            CC_MAX_WORKERS_DEFAULT,
            derive_max_workers,
        )

        self._mock_primary(monkeypatch, "claudecode", "session-default")
        self._mock_rpm(monkeypatch, 60)
        self._no_tuning(monkeypatch)
        # 60 rpm → 30 workers, clamped to the claudecode ceiling.
        assert (
            derive_max_workers("session-default") == CC_MAX_WORKERS_DEFAULT
        )

    def test_tuning_override_beats_unknown_rpm_floor(self, monkeypatch):
        from core.llm.concurrency import derive_max_workers

        self._mock_primary(monkeypatch, "claudecode", "session-default")
        self._mock_rpm(monkeypatch, 0)
        monkeypatch.setattr(
            "core.llm.concurrency.read_tuning_max_llm_workers",
            lambda: 6,
        )
        assert derive_max_workers("session-default") == 6


class TestLocalWorkerCap:
    """derive_max_workers for a single local inference server (Ollama, or
    a vLLM/LM Studio endpoint on a loopback host). A local model carries
    no RPM, so it lands in the rpm=0 floor — the cap must be the small
    local ceiling, not the serial-by-accident 1, and not an unbounded
    manual worker count."""

    def _mock_primary(self, monkeypatch, provider, model_name, api_base=None):
        class _MC:
            pass
        mc = _MC()
        mc.provider = provider
        mc.model_name = model_name
        mc.api_base = api_base
        monkeypatch.setattr(
            "core.llm.config._get_default_primary_model",
            lambda prefer=None: mc,
        )

    def _mock_rpm(self, monkeypatch, rpm):
        monkeypatch.setattr(
            "core.llm.model_data.rpm_for", lambda model, **kw: rpm,
        )

    def _no_tuning(self, monkeypatch):
        monkeypatch.setattr(
            "core.llm.concurrency.read_tuning_max_llm_workers",
            lambda: None,
        )

    @pytest.fixture(autouse=True)
    def _clear_env(self, monkeypatch):
        monkeypatch.delenv("RAPTOR_LOCAL_MAX_WORKERS", raising=False)

    def test_ollama_primary_unknown_rpm_caps_at_local_default(
        self, monkeypatch,
    ):
        from core.llm.concurrency import (
            LOCAL_MAX_WORKERS_DEFAULT,
            derive_max_workers,
        )

        self._mock_primary(monkeypatch, "ollama", "qwen3-27b")
        self._mock_rpm(monkeypatch, 0)
        self._no_tuning(monkeypatch)
        assert (
            derive_max_workers("qwen3-27b") == LOCAL_MAX_WORKERS_DEFAULT
        )

    def test_local_env_override_applies(self, monkeypatch):
        from core.llm.concurrency import derive_max_workers

        self._mock_primary(monkeypatch, "ollama", "qwen3-27b")
        self._mock_rpm(monkeypatch, 0)
        self._no_tuning(monkeypatch)
        monkeypatch.setenv("RAPTOR_LOCAL_MAX_WORKERS", "4")
        assert derive_max_workers("qwen3-27b") == 4

    def test_loopback_openai_endpoint_is_capped(self, monkeypatch):
        """A vLLM/LM Studio server configured as provider=openai with a
        loopback api_base is a single local server too."""
        from core.llm.concurrency import (
            LOCAL_MAX_WORKERS_DEFAULT,
            derive_max_workers,
        )

        self._mock_primary(
            monkeypatch, "openai", "qwen3-vllm",
            api_base="http://localhost:8000/v1",
        )
        self._mock_rpm(monkeypatch, 0)
        self._no_tuning(monkeypatch)
        assert (
            derive_max_workers("qwen3-vllm") == LOCAL_MAX_WORKERS_DEFAULT
        )

    def test_cloud_openai_endpoint_not_capped_stays_serial(self, monkeypatch):
        """Two-direction guard: a cloud provider at rpm=0 (no api_base, or
        a non-loopback one) is NOT a local server and keeps the serial
        fallback."""
        from core.llm.concurrency import derive_max_workers

        self._mock_primary(
            monkeypatch, "openai", "gpt-mystery",
            api_base="https://api.openai.com/v1",
        )
        self._mock_rpm(monkeypatch, 0)
        self._no_tuning(monkeypatch)
        assert derive_max_workers("gpt-mystery") == 1

    def test_known_rpm_local_model_clamped_to_local_cap(self, monkeypatch):
        """Rare: a local model with a known RPM still clamps to the local
        cap rather than rpm//2."""
        from core.llm.concurrency import (
            LOCAL_MAX_WORKERS_DEFAULT,
            derive_max_workers,
        )

        self._mock_primary(monkeypatch, "ollama", "qwen3-27b")
        self._mock_rpm(monkeypatch, 120)  # would be 60 workers uncapped
        self._no_tuning(monkeypatch)
        assert (
            derive_max_workers("qwen3-27b") == LOCAL_MAX_WORKERS_DEFAULT
        )

    def test_tuning_override_clamped_to_local_cap(self, monkeypatch):
        """tuning.json max_llm_workers is clamped by the local cap —
        a stale global override from a cloud run must not flood a
        single GPU (no 429 backpressure, just OOM)."""
        from core.llm.concurrency import (
            LOCAL_MAX_WORKERS_DEFAULT,
            derive_max_workers,
        )

        self._mock_primary(monkeypatch, "ollama", "qwen3-27b")
        self._mock_rpm(monkeypatch, 0)
        monkeypatch.setattr(
            "core.llm.concurrency.read_tuning_max_llm_workers",
            lambda: 16,
        )
        assert derive_max_workers("qwen3-27b") == LOCAL_MAX_WORKERS_DEFAULT

    def test_tuning_override_with_explicit_local_env(self, monkeypatch):
        """RAPTOR_LOCAL_MAX_WORKERS is the escape hatch: an operator who
        explicitly raises the local cap gets that cap even when
        tuning.json is also set."""
        from core.llm.concurrency import derive_max_workers

        self._mock_primary(monkeypatch, "ollama", "qwen3-27b")
        self._mock_rpm(monkeypatch, 0)
        monkeypatch.setenv("RAPTOR_LOCAL_MAX_WORKERS", "8")
        monkeypatch.setattr(
            "core.llm.concurrency.read_tuning_max_llm_workers",
            lambda: 16,
        )
        assert derive_max_workers("qwen3-27b") == 8

    def test_tuning_override_below_local_cap_not_clamped(self, monkeypatch):
        """When tuning.json sets a value at or below the local cap,
        the clamp is a no-op — no warning, no change."""
        from core.llm.concurrency import derive_max_workers

        self._mock_primary(monkeypatch, "ollama", "qwen3-27b")
        self._mock_rpm(monkeypatch, 0)
        monkeypatch.setattr(
            "core.llm.concurrency.read_tuning_max_llm_workers",
            lambda: 1,
        )
        assert derive_max_workers("qwen3-27b") == 1

    def test_invalid_env_falls_back_to_default(self, monkeypatch):
        from core.llm.concurrency import (
            LOCAL_MAX_WORKERS_DEFAULT,
            derive_max_workers,
        )

        self._mock_primary(monkeypatch, "ollama", "qwen3-27b")
        self._mock_rpm(monkeypatch, 0)
        self._no_tuning(monkeypatch)
        monkeypatch.setenv("RAPTOR_LOCAL_MAX_WORKERS", "abc")
        assert derive_max_workers("qwen3-27b") == LOCAL_MAX_WORKERS_DEFAULT

    def test_env_zero_clamped_to_one(self, monkeypatch):
        from core.llm.concurrency import derive_max_workers

        self._mock_primary(monkeypatch, "ollama", "qwen3-27b")
        self._mock_rpm(monkeypatch, 0)
        self._no_tuning(monkeypatch)
        monkeypatch.setenv("RAPTOR_LOCAL_MAX_WORKERS", "0")
        assert derive_max_workers("qwen3-27b") == 1

    def test_non_matching_model_not_capped(self, monkeypatch):
        """A model name that doesn't match the configured primary should
        not trigger the local cap — falls through to serial(1)."""
        from core.llm.concurrency import derive_max_workers

        self._mock_primary(monkeypatch, "ollama", "qwen3-27b")
        self._mock_rpm(monkeypatch, 0)
        self._no_tuning(monkeypatch)
        assert derive_max_workers("some-other-model") == 1


class TestWarmClaudecodeProbe:
    def _mock_primary(self, monkeypatch, provider):
        class _MC:
            pass
        mc = _MC()
        mc.provider = provider
        mc.model_name = "session-default"
        monkeypatch.setattr(
            "core.llm.config._get_default_primary_model",
            lambda prefer=None: mc,
        )

    def test_warms_once_when_claudecode_primary(self, monkeypatch):
        from core.llm.concurrency import warm_claudecode_probe

        self._mock_primary(monkeypatch, "claudecode")
        monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
        calls = []
        monkeypatch.setattr(
            "core.llm.cc_probe.probe_cc_session_model",
            lambda *a, **kw: calls.append(1) or "backend.resolved-id",
        )
        assert warm_claudecode_probe() == "backend.resolved-id"
        assert len(calls) == 1

    def test_skipped_under_pytest(self, monkeypatch):
        from core.llm.concurrency import warm_claudecode_probe

        self._mock_primary(monkeypatch, "claudecode")
        # PYTEST_CURRENT_TEST is naturally present here — the guard
        # this test exercises is the one protecting every other test
        # in the suite from a live probe call.
        called = []
        monkeypatch.setattr(
            "core.llm.cc_probe.probe_cc_session_model",
            lambda *a, **kw: called.append(1),
        )
        assert warm_claudecode_probe() is None
        assert not called

    def test_operator_opt_out(self, monkeypatch):
        from core.llm.concurrency import warm_claudecode_probe

        self._mock_primary(monkeypatch, "claudecode")
        monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
        monkeypatch.setenv("RAPTOR_CC_PROBE_WARM", "0")
        called = []
        monkeypatch.setattr(
            "core.llm.cc_probe.probe_cc_session_model",
            lambda *a, **kw: called.append(1),
        )
        assert warm_claudecode_probe() is None
        assert not called

    def test_skipped_for_non_claudecode_primary(self, monkeypatch):
        from core.llm.concurrency import warm_claudecode_probe

        self._mock_primary(monkeypatch, "anthropic")
        monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
        called = []
        monkeypatch.setattr(
            "core.llm.cc_probe.probe_cc_session_model",
            lambda *a, **kw: called.append(1),
        )
        assert warm_claudecode_probe() is None
        assert not called

    def test_probe_failure_tolerated(self, monkeypatch):
        from core.llm.concurrency import warm_claudecode_probe

        self._mock_primary(monkeypatch, "claudecode")
        monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)

        def _boom(*a, **kw):
            raise RuntimeError("probe exploded")

        monkeypatch.setattr(
            "core.llm.cc_probe.probe_cc_session_model", _boom,
        )
        assert warm_claudecode_probe() is None  # no raise


class TestDispatchKnobs:
    def _cmd(self):
        from core.llm.cc_adapter import CCDispatchConfig, build_cc_command
        return build_cc_command(CCDispatchConfig(claude_bin="claude"))

    def test_exclude_dynamic_sections_default_on(self):
        assert "--exclude-dynamic-system-prompt-sections" in self._cmd()

    def test_exclude_dynamic_sections_can_be_disabled(self):
        from core.llm.cc_adapter import CCDispatchConfig, build_cc_command
        cmd = build_cc_command(CCDispatchConfig(
            claude_bin="claude", exclude_dynamic_sections=False,
        ))
        assert "--exclude-dynamic-system-prompt-sections" not in cmd

    def test_effort_env_knob(self, monkeypatch):
        monkeypatch.setenv("RAPTOR_CC_EFFORT", "low")
        cmd = self._cmd()
        idx = cmd.index("--effort")
        assert cmd[idx + 1] == "low"

    def test_invalid_effort_dropped(self, monkeypatch):
        monkeypatch.setenv("RAPTOR_CC_EFFORT", "turbo")
        assert "--effort" not in self._cmd()

    def test_fallback_model_env_knob(self, monkeypatch):
        monkeypatch.setenv("RAPTOR_CC_FALLBACK_MODEL", "backup-model")
        cmd = self._cmd()
        idx = cmd.index("--fallback-model")
        assert cmd[idx + 1] == "backup-model"

    def test_knobs_absent_by_default(self):
        cmd = self._cmd()
        assert "--effort" not in cmd
        assert "--fallback-model" not in cmd


class TestSurfacedCauseRetryClassification:
    """The stream-json abort causes surfaced on nonzero exit classify
    correctly: budget aborts never retry (same cost every time),
    transient transport failures do."""

    def test_budget_abort_not_retryable(self):
        from core.llm.client import _is_retryable_error

        err = RuntimeError("claude -p exited 1: error_max_budget_usd")
        assert _is_retryable_error(err) is False

    def test_timeout_retryable(self):
        from core.llm.client import _is_retryable_error

        err = RuntimeError("claude -p timed out after 600s")
        assert _is_retryable_error(err) is True

    def test_connection_failure_retryable(self):
        from core.llm.client import _is_retryable_error

        err = RuntimeError(
            "claude -p exited 1: connection refused by upstream",
        )
        assert _is_retryable_error(err) is True
