"""Non-finite cost figures must never reach a spend ledger.

Stdlib ``json.loads`` accepts the ``NaN`` / ``Infinity`` literals, and
``isinstance(x, (int, float))`` passes them (and ``bool``). One NaN
``cost_usd`` in the CC stream-json envelope then poisons ``total_cost``
— and every budget comparison against NaN is False, silently disabling
``max_cost_per_scan`` for the rest of the run.

Two layers pinned here:
  1. the parse gate refuses non-finite / negative / bool cost and
     token figures (same finite-guard idiom as the EPSS score gate);
  2. belt-and-braces — every ledger write sanitises, and the budget
     comparator fails CLOSED on a non-finite ledger regardless.
"""
from __future__ import annotations

import math
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from core.llm.cc_adapter import parse_stream_json_lines  # noqa: E402
from core.llm.client import LLMClient  # noqa: E402
from core.llm.config import LLMConfig, ModelConfig  # noqa: E402
from core.llm.dispatcher.client import reconcile_child_spend  # noqa: E402
from core.llm.providers import LLMProvider  # noqa: E402


class _Provider(LLMProvider):
    def generate(self, *a: object, **k: object) -> object:
        raise NotImplementedError

    def generate_structured(self, *a: object, **k: object) -> object:
        raise NotImplementedError


def _model() -> ModelConfig:
    return ModelConfig(provider="openai", model_name="m", api_key="k")


class TestParseGate:
    """``parse_stream_json_lines`` refuses non-finite cost/token figures."""

    def _result_line(self, fields: str) -> list[str]:
        return ['{"type":"result",%s,"usage":{}}' % fields]

    def test_nan_cost_refused(self) -> None:
        res = parse_stream_json_lines(
            self._result_line('"total_cost_usd": NaN'))
        assert res.cost_usd == 0.0

    def test_infinity_cost_refused(self) -> None:
        res = parse_stream_json_lines(
            self._result_line('"total_cost_usd": Infinity'))
        assert res.cost_usd == 0.0

    def test_negative_cost_refused(self) -> None:
        res = parse_stream_json_lines(
            self._result_line('"total_cost_usd": -0.5'))
        assert res.cost_usd == 0.0

    def test_bool_cost_refused(self) -> None:
        res = parse_stream_json_lines(
            self._result_line('"total_cost_usd": true'))
        assert res.cost_usd == 0.0

    def test_valid_cost_kept(self) -> None:
        res = parse_stream_json_lines(
            self._result_line('"total_cost_usd": 0.42'))
        assert res.cost_usd == 0.42

    def test_result_token_fields_refuse_non_ints(self) -> None:
        res = parse_stream_json_lines([
            '{"type":"result","usage":'
            '{"input_tokens": NaN, "output_tokens": true}}'
        ])
        assert res.input_tokens == 0
        assert res.output_tokens == 0

    def test_assistant_token_fields_refuse_non_ints(self) -> None:
        res = parse_stream_json_lines([
            '{"type":"assistant","message":{"usage":'
            '{"input_tokens": Infinity, "output_tokens": -3,'
            '"cache_read_input_tokens": NaN}}}'
        ])
        assert res.input_tokens == 0
        assert res.output_tokens == 0
        assert res.cache_read_tokens == 0

    def test_assistant_token_fields_accumulate_valid_ints(self) -> None:
        res = parse_stream_json_lines([
            '{"type":"assistant","message":{"usage":'
            '{"input_tokens": 5, "output_tokens": 7}}}',
            '{"type":"assistant","message":{"usage":'
            '{"input_tokens": 2, "output_tokens": 1}}}',
        ])
        assert res.input_tokens == 7
        assert res.output_tokens == 8


class TestLedgerWrites:
    """Every spend ledger write sanitises non-finite figures to 0.0."""

    def test_track_usage_refuses_nan(self) -> None:
        prov = _Provider(_model())
        prov.track_usage(tokens=10, cost=float("nan"))
        assert prov.total_cost == 0.0
        prov.track_usage(tokens=10, cost=0.25)
        assert prov.total_cost == 0.25

    def test_record_usage_refuses_nan(self) -> None:
        client = LLMClient(LLMConfig(
            primary_model=_model(), enable_caching=False))
        client._record_usage("alias", cost=float("nan"), tokens=3)
        usage = client._fired_usage["alias"]
        assert usage["cost_usd"] == 0.0

    def test_reconcile_child_spend_refuses_nan(self) -> None:
        assert reconcile_child_spend(float("nan"), 5.0) == 5.0
        assert reconcile_child_spend(5.0, float("nan")) == 5.0
        assert reconcile_child_spend(float("nan"), float("inf")) == 0.0

    def test_telemetry_aggregate_refuses_nan(self) -> None:
        from core.llm.telemetry import TelemetrySink
        sink = TelemetrySink.__new__(TelemetrySink)
        sink._lock = __import__("threading").Lock()
        sink._by_class = {}
        sink._aggregate({"call_class": "c", "cost_usd": float("nan"),
                         "duration_s": 0.1})
        sink._aggregate({"call_class": "c", "cost_usd": 0.5,
                         "duration_s": 0.1})
        assert sink._by_class["c"].cost_usd == 0.5
        assert sink.mean_call_cost("c") is not None
        assert math.isfinite(sink.mean_call_cost("c"))


class TestBudgetComparatorFailsClosed:
    """Belt-and-braces: a non-finite ledger refuses further spend."""

    def _client(self) -> LLMClient:
        return LLMClient(LLMConfig(
            primary_model=_model(), enable_caching=False,
            max_cost_per_scan=10.0))

    def test_nan_total_cost_refuses_spend(self) -> None:
        client = self._client()
        client.total_cost = float("nan")
        assert client._check_budget(9999.0) is False
        assert client._acquire_budget(9999.0) is False
        assert client.is_budget_exhausted(9999.0) is True

    def test_nan_provider_ledger_refuses_spend(self) -> None:
        client = self._client()
        prov = _Provider(_model())
        prov.total_cost = float("nan")
        client.providers["openai:m"] = prov
        assert client._check_budget(9999.0) is False
        assert client.is_budget_exhausted(9999.0) is True

    def test_finite_ledger_still_admits(self) -> None:
        client = self._client()
        client.total_cost = 1.0
        assert client._check_budget(1.0) is True
        assert client.is_budget_exhausted(1.0) is False
