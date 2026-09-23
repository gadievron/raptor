"""Per-call LLM telemetry: sink mechanics + client emission points.

No LLM calls — providers are mocked. Pins:
* sink writes one JSONL record per event and aggregates per class
* the client emits on success, failed attempt, and local cache hit
* call_class pops before provider dispatch (never leaks into kwargs)
* structured calls report provider-counter deltas (tokens + cache)
* sink I/O failure degrades silently (no exception, summary survives)
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from core.llm import telemetry
from core.llm.client import LLMClient
from core.llm.config import LLMConfig, ModelConfig
from core.llm.telemetry import TelemetrySink, emit, set_sink


@pytest.fixture(autouse=True)
def _clean_sink():
    set_sink(None)
    yield
    set_sink(None)


def _read_jsonl(path):
    return [
        json.loads(line)
        for line in path.read_text().splitlines()
        if line.strip()
    ]


class TestSink:
    def test_records_appended_as_jsonl(self, tmp_path):
        sink = TelemetrySink(tmp_path / "llm-telemetry.jsonl")
        sink.record({"event": "call", "call_class": "review",
                     "cost_usd": 0.5, "duration_s": 10.0,
                     "tokens_in": 100, "tokens_out": 20})
        sink.record({"event": "attempt_failed", "call_class": "review",
                     "disposition": "timeout", "duration_s": 480.0})
        recs = _read_jsonl(tmp_path / "llm-telemetry.jsonl")
        assert len(recs) == 2
        assert recs[0]["event"] == "call"
        assert recs[1]["disposition"] == "timeout"
        assert all("ts" in r for r in recs)

    def test_summary_line_aggregates(self, tmp_path):
        sink = TelemetrySink(tmp_path / "t.jsonl")
        sink.record({"event": "call", "call_class": "review",
                     "cost_usd": 1.5, "tokens_in": 2000,
                     "tokens_out": 500, "cache_read_tokens": 6000,
                     "cache_write_tokens": 100})
        sink.record({"event": "call", "call_class": "summary",
                     "cost_usd": 0.25})
        sink.record({"event": "attempt_failed", "call_class": "review",
                     "disposition": "timeout"})
        sink.record({"event": "call", "disposition": "cache_hit",
                     "call_class": "review", "cost_usd": 0.0})
        line = sink.summary_line()
        assert "2 calls" in line
        assert "$1.75" in line
        assert "cache 6.0k read" in line
        assert "1 failed attempts (1 timeout)" in line
        assert "1 local cache hits" in line
        assert "review=1/$1.50" in line
        assert "summary=1/$0.25" in line
        assert sink.total_records == 4

    def test_summary_line_reports_blocked_separately(self, tmp_path):
        sink = TelemetrySink(tmp_path / "t.jsonl")
        sink.record({"event": "attempt_failed", "call_class": "summary",
                     "disposition": "blocked"})
        sink.record({"event": "attempt_failed", "call_class": "review",
                     "disposition": "timeout"})
        line = sink.summary_line()
        assert "2 failed attempts (1 timeout, 1 blocked)" in line

    def test_summary_line_omits_blocked_when_zero(self, tmp_path):
        sink = TelemetrySink(tmp_path / "t.jsonl")
        sink.record({"event": "attempt_failed", "call_class": "review",
                     "disposition": "timeout"})
        assert "1 failed attempts (1 timeout)" in sink.summary_line()

    def test_summary_line_reports_consumed_separately(self, tmp_path):
        """Consumed = mid-response deaths the spend-aware retry gate
        refused to re-send (each a generation billed upstream but
        never received) — broken out so an operator can spot a
        flaky-provider day from the rollup."""
        sink = TelemetrySink(tmp_path / "t.jsonl")
        sink.record({"event": "attempt_failed", "call_class": "review",
                     "disposition": "consumed"})
        sink.record({"event": "attempt_failed", "call_class": "review",
                     "disposition": "timeout"})
        line = sink.summary_line()
        assert "2 failed attempts (1 timeout, 1 consumed)" in line

    def test_summary_line_omits_consumed_when_zero(self, tmp_path):
        sink = TelemetrySink(tmp_path / "t.jsonl")
        sink.record({"event": "attempt_failed", "call_class": "review",
                     "disposition": "timeout"})
        assert "consumed" not in sink.summary_line()

    def test_write_failure_is_silent_and_keeps_aggregates(self, tmp_path):
        target = tmp_path / "not-a-dir"
        target.write_text("occupied")  # parent path is a FILE
        sink = TelemetrySink(target / "t.jsonl")
        sink.record({"event": "call", "call_class": "x", "cost_usd": 1.0})
        sink.record({"event": "call", "call_class": "x", "cost_usd": 1.0})
        assert sink.total_records == 2
        assert "$2.00" in sink.summary_line()

    def test_append_refuses_symlinked_trail(self, tmp_path):
        # A run-dir-writable child can plant a symlink at the
        # predictable trail name; the append must refuse (O_NOFOLLOW),
        # never redirect attacker-influenced content onto the victim.
        victim = tmp_path / "victim.log"
        victim.write_text("pre\n")
        run = tmp_path / "run"
        run.mkdir()
        trail = run / "llm-telemetry.jsonl"
        trail.symlink_to(victim)
        sink = TelemetrySink(trail)
        sink.record({"event": "call", "call_class": "x", "cost_usd": 1.0})
        assert victim.read_text() == "pre\n"
        assert sink.total_records == 1  # aggregation survives

    def test_trail_created_owner_only(self, tmp_path):
        import stat as _stat
        trail = tmp_path / "llm-telemetry.jsonl"
        sink = TelemetrySink(trail)
        sink.record({"event": "call", "call_class": "x", "cost_usd": 1.0})
        assert _stat.S_IMODE(trail.stat().st_mode) == 0o600

    def test_unserialisable_values_degrade_per_record(self, tmp_path):
        # Non-finite floats / exotic objects degrade to strings for
        # THAT record — they must not trip the one-warning latch and
        # disable telemetry for the rest of the run.
        from pathlib import Path as _Path
        trail = tmp_path / "llm-telemetry.jsonl"
        sink = TelemetrySink(trail)
        sink.record({"event": "call", "call_class": "x",
                     "cost_usd": float("nan"), "extra": _Path("/x")})
        sink.record({"event": "call", "call_class": "x", "cost_usd": 1.0})
        recs = _read_jsonl(trail)
        assert len(recs) == 2

    def test_emit_without_sink_is_noop(self):
        emit(event="call", call_class="review")  # must not raise

    def test_emit_routes_to_installed_sink(self, tmp_path):
        sink = TelemetrySink(tmp_path / "t.jsonl")
        set_sink(sink)
        emit(event="call", call_class="review", cost_usd=0.1)
        assert sink.total_records == 1
        assert telemetry.current_sink() is sink


def _model(provider: str, name: str) -> ModelConfig:
    return ModelConfig(provider=provider, model_name=name, api_key="k")


def _client(max_retries: int = 3) -> LLMClient:
    return LLMClient(LLMConfig(
        primary_model=_model("anthropic", "primary-stub"),
        fallback_models=[], enable_caching=False,
        max_retries=max_retries, enable_fallback=False,
    ))


def _good_response():
    good = MagicMock()
    good.cost = 0.05
    good.tokens_used = 120
    good.input_tokens = 100
    good.output_tokens = 20
    good.cache_read_tokens = 900
    good.cache_write_tokens = 30
    good.content = "ok"
    good.resolved_model = None
    return good


class TestClientEmission:
    def test_generate_emits_call_record(self, tmp_path):
        sink = TelemetrySink(tmp_path / "t.jsonl")
        set_sink(sink)
        client = _client()
        with patch.object(client, "_get_provider") as mock_get:
            prov = MagicMock()
            prov.generate.return_value = _good_response()
            mock_get.return_value = prov
            client.generate("p", task_type="audit")

        recs = _read_jsonl(tmp_path / "t.jsonl")
        assert len(recs) == 1
        rec = recs[0]
        assert rec["event"] == "call"
        assert rec["disposition"] == "ok"
        assert rec["call_class"] == "audit"  # defaults to task_type
        assert rec["cost_usd"] == 0.05
        assert rec["tokens_in"] == 100
        assert rec["cache_read_tokens"] == 900

    def test_call_class_kwarg_pops_and_labels(self, tmp_path):
        sink = TelemetrySink(tmp_path / "t.jsonl")
        set_sink(sink)
        client = _client()
        with patch.object(client, "_get_provider") as mock_get:
            prov = MagicMock()
            prov.generate.return_value = _good_response()
            mock_get.return_value = prov
            client.generate("p", call_class="summary")

        # label recorded, kwarg never reached the provider
        rec = _read_jsonl(tmp_path / "t.jsonl")[0]
        assert rec["call_class"] == "summary"
        _, kwargs = prov.generate.call_args
        assert "call_class" not in kwargs

    def test_failed_attempts_emit_timeout_disposition(
        self, tmp_path, monkeypatch,
    ):
        import core.llm.client as client_mod
        monkeypatch.setattr(client_mod.time, "sleep", lambda _s: None)
        sink = TelemetrySink(tmp_path / "t.jsonl")
        set_sink(sink)
        client = _client(max_retries=3)
        with patch.object(client, "_get_provider") as mock_get:
            prov = MagicMock()
            prov.generate.side_effect = RuntimeError(
                "claude -p timed out after 480s",
            )
            mock_get.return_value = prov
            with pytest.raises(RuntimeError):
                client.generate("p", call_class="review")

        recs = _read_jsonl(tmp_path / "t.jsonl")
        # default timeout policy: initial attempt + one retry
        assert len(recs) == 2
        assert all(r["event"] == "attempt_failed" for r in recs)
        assert all(r["disposition"] == "timeout" for r in recs)
        assert [r["attempt"] for r in recs] == [1, 2]

    def test_model_refusal_emits_blocked_disposition_no_retry(
        self, tmp_path, monkeypatch,
    ):
        """A refusal-shaped provider error (the message
        AnthropicProvider raises for stop_reason=refusal) must label
        the attempt 'blocked' — a model boundary, distinct from
        transport failures — and must not be retried: an identical
        retry cannot change a refusal."""
        import core.llm.client as client_mod
        monkeypatch.setattr(client_mod.time, "sleep", lambda _s: None)
        sink = TelemetrySink(tmp_path / "t.jsonl")
        set_sink(sink)
        client = _client(max_retries=3)
        with patch.object(client, "_get_provider") as mock_get:
            prov = MagicMock()
            prov.generate.side_effect = RuntimeError(
                "Anthropic model refused request "
                "(stop_reason=refusal, empty content)",
            )
            mock_get.return_value = prov
            with pytest.raises(RuntimeError):
                client.generate("p", call_class="summary")

        recs = _read_jsonl(tmp_path / "t.jsonl")
        assert len(recs) == 1  # non-retryable: single attempt only
        assert recs[0]["event"] == "attempt_failed"
        assert recs[0]["disposition"] == "blocked"

    def test_structured_emits_counter_deltas(self, tmp_path):
        sink = TelemetrySink(tmp_path / "t.jsonl")
        set_sink(sink)
        client = _client()

        class _Prov:
            total_cost = 1.0
            total_tokens = 500
            total_input_tokens = 400
            total_output_tokens = 100
            total_cache_read_tokens = 9000
            total_cache_write_tokens = 250

            def generate_structured(self, prompt, schema,
                                    system_prompt=None, **kwargs):
                # simulate track_usage side effects
                _Prov.total_cost += 0.5
                _Prov.total_tokens += 60
                _Prov.total_input_tokens += 50
                _Prov.total_output_tokens += 10
                _Prov.total_cache_read_tokens += 4000
                _Prov.total_cache_write_tokens += 20
                return {"status": "clean"}, "{}"

        with patch.object(client, "_get_provider", return_value=_Prov()):
            resp = client.generate_structured(
                "p", {"type": "object"}, call_class="review",
            )

        assert resp.input_tokens == 50
        assert resp.output_tokens == 10
        assert resp.cache_read_tokens == 4000
        assert resp.cache_write_tokens == 20
        rec = _read_jsonl(tmp_path / "t.jsonl")[0]
        assert rec["call_class"] == "review"
        assert rec["structured"] is True
        assert rec["cost_usd"] == 0.5
        assert rec["cache_read_tokens"] == 4000

    def test_structured_counter_deltas_tolerate_mock_providers(self):
        # MagicMock counters aren't int-coercible — deltas must
        # degrade to 0, never raise.
        client = _client()
        with patch.object(client, "_get_provider") as mock_get:
            prov = MagicMock()
            prov.total_cost = 0.0
            prov.total_tokens = 0
            prov.generate_structured.return_value = ({"s": 1}, "{}")
            mock_get.return_value = prov
            resp = client.generate_structured("p", {"type": "object"})
        assert resp.cache_read_tokens == 0

    def test_local_cache_hit_emits(self, tmp_path):
        sink = TelemetrySink(tmp_path / "t.jsonl")
        set_sink(sink)
        client = LLMClient(LLMConfig(
            primary_model=_model("anthropic", "primary-stub"),
            fallback_models=[], enable_caching=True,
            max_retries=1, enable_fallback=False,
        ))
        import uuid
        prompt = f"telemetry-cache-hit-{uuid.uuid4()}"
        with patch.object(client, "_get_provider") as mock_get:
            prov = MagicMock()
            prov.generate.return_value = _good_response()
            mock_get.return_value = prov
            client.generate(prompt, call_class="review")
            client.generate(prompt, call_class="review")

        recs = _read_jsonl(tmp_path / "t.jsonl")
        assert len(recs) == 2
        assert recs[0]["disposition"] == "ok"
        assert recs[1]["disposition"] == "cache_hit"


class TestPaidCallAttributionStubExemption:
    """The live-API-leak attribution must flag nonzero-cost calls from
    unstubbed tests, but not from *-stub aliases — the repo convention
    for mocked providers whose fake responses carry cost because cost
    plumbing is the thing under test."""

    def _record(self, alias, monkeypatch):
        client = _client()
        monkeypatch.setenv(
            "PYTEST_CURRENT_TEST", "fake_test.py::test_x (call)")
        client._record_usage(alias, cost=0.10, tokens=10)
        return getattr(client, "_paid_test_ctxs", None)

    def test_stub_alias_not_attributed(self, monkeypatch):
        assert self._record("primary-stub", monkeypatch) is None

    def test_non_stub_alias_attributed(self, monkeypatch):
        ctxs = self._record("gemini-2.5-pro", monkeypatch)
        assert ctxs == {"fake_test.py::test_x"}


class TestFailedAttemptSpend:
    """Failed-attempt records that carry paid usage (guard-rejected but
    billed generations) book into a dedicated per-class counter: the
    money stays visible in the rollup and the cost breakdown, the
    completed-call mean that sizes budget reservations stays honest."""

    def test_failed_cost_books_separate_counter(self, tmp_path):
        sink = TelemetrySink(tmp_path / "t.jsonl")
        sink.record({"event": "call", "call_class": "study",
                     "cost_usd": 0.50})
        sink.record({"event": "attempt_failed", "call_class": "study",
                     "disposition": "fatal", "cost_usd": 0.95,
                     "tokens_in": 14000, "tokens_out": 16384})
        assert sink.failed_class_costs() == {"study": (1, 0.95)}
        # completed-call snapshot and reservation mean are unaffected
        assert sink.class_costs()["study"] == (1, 0.50)
        assert sink.mean_call_cost("study") == 0.50
        # ...but "money actually gone" counts both
        assert sink.total_cost_usd() == pytest.approx(1.45)

    def test_summary_line_surfaces_failed_spend_and_rate(self, tmp_path):
        sink = TelemetrySink(tmp_path / "t.jsonl")
        sink.record({"event": "call", "call_class": "study",
                     "cost_usd": 0.50})
        sink.record({"event": "attempt_failed", "call_class": "study",
                     "disposition": "fatal", "cost_usd": 0.95})
        line = sink.summary_line()
        assert "$0.95 paid" in line
        # rate signal: 1 failed of 2 attempts — a class failing half
        # its calls interleaved with successes trips no consecutive
        # counter, so the rollup must carry the ratio.
        assert "50% of attempts" in line

    def test_failed_only_class_appears_in_rollup(self, tmp_path):
        """A class with ZERO completed calls (fully wedged) was
        previously absent from the per-class rollup entirely — the
        worst failure mode was the least visible one."""
        sink = TelemetrySink(tmp_path / "t.jsonl")
        sink.record({"event": "attempt_failed", "call_class": "study",
                     "disposition": "fatal", "cost_usd": 0.95})
        line = sink.summary_line()
        assert "study=" in line
        assert "100% of attempts" in line

    def test_client_emits_paid_usage_from_stamped_error(
        self, tmp_path, monkeypatch,
    ):
        """A provider guard that stamped billed usage on its exception
        produces an attempt_failed row carrying the paid cost and
        token counts — and stays non-retryable (attempt 1 only)."""
        import core.llm.client as client_mod
        from core.llm.providers import (
            _attach_billed_usage,
            _llm_truncation_error,
        )
        monkeypatch.setattr(client_mod.time, "sleep", lambda _s: None)
        sink = TelemetrySink(tmp_path / "t.jsonl")
        set_sink(sink)
        err = _llm_truncation_error(
            "Anthropic returned no text content block "
            "(got: thinking; stop_reason=max_tokens)",
        )
        _attach_billed_usage(
            err, cost_usd=0.95, tokens_in=14000, tokens_out=16384,
        )
        client = _client(max_retries=3)
        with patch.object(client, "_get_provider") as mock_get:
            prov = MagicMock()
            prov.generate.side_effect = err
            mock_get.return_value = prov
            with pytest.raises(RuntimeError):
                client.generate("p", call_class="study")

        recs = _read_jsonl(tmp_path / "t.jsonl")
        assert len(recs) == 1  # deterministic truncation: no retry
        rec = recs[0]
        assert rec["event"] == "attempt_failed"
        assert rec["cost_usd"] == 0.95
        assert rec["tokens_in"] == 14000
        assert rec["tokens_out"] == 16384

    def test_unstamped_failures_carry_no_cost_fields(
        self, tmp_path, monkeypatch,
    ):
        """Transport failures that never reached generation cost
        nothing — their rows must not grow zero-value fields."""
        import core.llm.client as client_mod
        monkeypatch.setattr(client_mod.time, "sleep", lambda _s: None)
        sink = TelemetrySink(tmp_path / "t.jsonl")
        set_sink(sink)
        client = _client(max_retries=3)
        with patch.object(client, "_get_provider") as mock_get:
            prov = MagicMock()
            prov.generate.side_effect = RuntimeError(
                "Anthropic model refused request "
                "(stop_reason=refusal, empty content)",
            )
            mock_get.return_value = prov
            with pytest.raises(RuntimeError):
                client.generate("p", call_class="study")
        rec = _read_jsonl(tmp_path / "t.jsonl")[0]
        assert "cost_usd" not in rec

    def test_billed_usage_read_through_wrapper_chain(self):
        from core.llm.client import _billed_failure_usage
        from core.llm.providers import (
            _attach_billed_usage,
            _llm_truncation_error,
        )
        inner = _llm_truncation_error("truncated")
        _attach_billed_usage(
            inner, cost_usd=0.5, tokens_in=100, tokens_out=200,
        )
        try:
            try:
                raise inner
            except RuntimeError as e:
                raise RuntimeError("wrapped") from e
        except RuntimeError as outer:
            assert _billed_failure_usage(outer) == (0.5, 100, 200)
