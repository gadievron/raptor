"""Default cost ceiling for uncapped runs (LLMClient._ensure_cost_ceiling).

Every run-level cap is opt-in today, and consumers express "no cap"
as ``max_cost_per_scan = float('inf')``. At first dispatch the client
now either (a) adopts tuning.json's ``default_max_cost_usd`` exactly
as if it had been passed on the CLI — a CLI/programmatic cap always
wins, because a finite cap short-circuits the resolution — or (b)
warns once per process that spend is uncapped. No hard default cap is
ever imposed: the knob plus the banner is the whole mechanism.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import core.llm.client as client_mod
from core.llm.client import LLMBudgetExceededError, LLMClient
from core.llm.config import LLMConfig, ModelConfig
from core.llm.providers import LLMResponse


@pytest.fixture(autouse=True)
def _fresh_banner_latches(monkeypatch):
    """Each test observes its own once-per-process banner."""
    monkeypatch.setattr(client_mod, "_UNCAPPED_BANNER_SHOWN", False)
    monkeypatch.setattr(client_mod, "_DEFAULT_CEILING_LOG_SHOWN", False)


@pytest.fixture()
def tuning(tmp_path: Path, monkeypatch):
    """Point the tuning.json reader at a per-test file; returns a
    writer callable."""
    path = tmp_path / "tuning.json"

    def write(payload: dict) -> None:
        path.write_text(json.dumps(payload))

    from core.llm import concurrency
    monkeypatch.setattr(concurrency, "_tuning_path", lambda: path)
    return write


def _client(max_cost: float, *, tracking: bool = True) -> LLMClient:
    config = LLMConfig(
        primary_model=ModelConfig(
            provider="anthropic", model_name="primary",
            api_key="test-key",
        ),
        fallback_models=[], enable_caching=False,
        enable_fallback=False, max_retries=1,
    )
    config.enable_cost_tracking = tracking
    config.max_cost_per_scan = max_cost
    return LLMClient(config)


def _generate_ok(client: LLMClient, prompt: str = "p") -> LLMResponse:
    with patch.object(client, "_get_provider") as mock_get:
        prov = MagicMock()
        prov.generate.return_value = LLMResponse(
            content="fine", model="primary", provider="anthropic",
            tokens_used=1, cost=0.0, finish_reason="stop",
        )
        mock_get.return_value = prov
        return client.generate(prompt)


def _warnings(mock_logger: MagicMock, needle: str) -> list:
    return [
        c for c in mock_logger.warning.call_args_list
        if needle in str(c.args[0])
    ]


class TestUncappedBanner:
    def test_banner_appears_exactly_once(self, tuning):
        tuning({})  # no knob configured
        with patch.object(client_mod, "logger", MagicMock()) as log:
            first = _client(float("inf"))
            _generate_ok(first, "a")
            _generate_ok(first, "b")
            second = _client(float("inf"))
            _generate_ok(second, "c")
        assert len(_warnings(log, "UNCAPPED")) == 1
        # Uncapped stays uncapped — no silently imposed default.
        assert math.isinf(first.config.max_cost_per_scan)
        assert math.isinf(second.config.max_cost_per_scan)

    def test_capped_run_gets_no_banner(self, tuning):
        tuning({})
        with patch.object(client_mod, "logger", MagicMock()) as log:
            client = _client(10.0)
            _generate_ok(client)
        assert not _warnings(log, "UNCAPPED")
        assert client.config.max_cost_per_scan == 10.0

    def test_tracking_disabled_is_a_deliberate_opt_out(self, tuning):
        # enable_cost_tracking=False (fakes, wired test clients) is a
        # programmatic choice — no banner, no knob application.
        tuning({"default_max_cost_usd": 25})
        with patch.object(client_mod, "logger", MagicMock()) as log:
            client = _client(float("inf"), tracking=False)
            _generate_ok(client)
        assert not _warnings(log, "UNCAPPED")
        assert math.isinf(client.config.max_cost_per_scan)

    def test_structured_entry_resolves_the_ceiling_too(self, tuning):
        tuning({})
        with patch.object(client_mod, "logger", MagicMock()) as log:
            client = _client(float("inf"))
            with patch.object(client, "_get_provider") as mock_get:
                prov = MagicMock()
                prov.generate_structured.side_effect = ValueError("bad")
                for attr in ("total_cost", "total_tokens",
                             "total_input_tokens", "total_output_tokens",
                             "total_cache_read_tokens",
                             "total_cache_write_tokens"):
                    setattr(prov, attr, 0)
                mock_get.return_value = prov
                with pytest.raises(RuntimeError, match="failed for all"):
                    client.generate_structured("p", {"type": "object"})
        assert len(_warnings(log, "UNCAPPED")) == 1


class TestDefaultCeilingKnob:
    def test_knob_applies_to_uncapped_run(self, tuning):
        tuning({"default_max_cost_usd": 25})
        with patch.object(client_mod, "logger", MagicMock()) as log:
            client = _client(float("inf"))
            _generate_ok(client)
        assert client.config.max_cost_per_scan == 25.0
        # The knob replaces the banner — the run is capped now.
        assert not _warnings(log, "UNCAPPED")
        assert log.info.called

    def test_knob_cap_is_enforced_like_a_cli_cap(self, tuning):
        tuning({"default_max_cost_usd": 25})
        client = _client(float("inf"))
        _generate_ok(client)
        client.total_cost = 30.0  # spend past the adopted ceiling
        with pytest.raises(LLMBudgetExceededError):
            client.generate("over the ceiling")

    def test_cli_cap_wins_over_knob(self, tuning):
        tuning({"default_max_cost_usd": 25})
        client = _client(5.0)
        _generate_ok(client)
        assert client.config.max_cost_per_scan == 5.0

    @pytest.mark.parametrize(
        "bad", ["banana", 0, -3, float("nan"), "auto", True],
    )
    def test_invalid_knob_values_leave_run_uncapped(self, tuning, bad):
        # A tuning.json typo must surface as "still uncapped" (loud
        # banner), never as a surprise zero cap refusing every call.
        tuning({"default_max_cost_usd": bad})
        with patch.object(client_mod, "logger", MagicMock()) as log:
            client = _client(float("inf"))
            _generate_ok(client)
        assert math.isinf(client.config.max_cost_per_scan)
        assert len(_warnings(log, "UNCAPPED")) == 1

    def test_missing_tuning_file_leaves_run_uncapped(
            self, tmp_path, monkeypatch):
        from core.llm import concurrency
        monkeypatch.setattr(
            concurrency, "_tuning_path",
            lambda: tmp_path / "absent-tuning.json",
        )
        with patch.object(client_mod, "logger", MagicMock()) as log:
            client = _client(float("inf"))
            _generate_ok(client)
        assert math.isinf(client.config.max_cost_per_scan)
        assert len(_warnings(log, "UNCAPPED")) == 1


class TestReader:
    def test_read_default_max_cost_usd(self, tuning):
        from core.llm.concurrency import read_default_max_cost_usd
        tuning({"default_max_cost_usd": "12.5"})
        assert read_default_max_cost_usd() == 12.5
        tuning({})
        assert read_default_max_cost_usd() is None
        tuning({"default_max_cost_usd": float("inf")})
        assert read_default_max_cost_usd() is None
