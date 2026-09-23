"""Truncation-shape × call-class contract matrix.

One observed incident produced three sibling failure shapes on the
same transport — plain JSON-fallback truncation, instructor-leg
structured truncation, and thinking-only max_tokens (reasoning
consumed the whole shared output budget) — split across the study and
review call classes. Each shape is deterministic at the same
max_tokens: an identical retry re-buys the failure. This matrix pins,
for every shape × class:

* classification: typed ``llm_truncation`` marker present, and the
  study lane's chain-walking classifier agrees;
* retry decision: non-retryable ("fatal" disposition, exactly one
  attempt, no re-send);
* telemetry cost: the attempt_failed row carries the paid usage the
  guard stamped — a burn loop must read as spend, not free noise.

Hermetic: providers mocked, no network.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from core.llm.telemetry import TelemetrySink, set_sink


@pytest.fixture(autouse=True)
def _clean_sink():
    set_sink(None)
    yield
    set_sink(None)


def _shape(kind):
    """Build the error exactly as the provider guards construct it."""
    from core.llm.providers import (
        _attach_billed_usage,
        _llm_truncation_error,
    )
    msg = {
        "plain": (
            "Response truncated (output token limit reached, "
            "finish_reason=max_tokens)"
        ),
        "structured": (
            "Structured response truncated (output token limit "
            "reached, stop_reason=max_tokens, instructor tool-use leg)"
        ),
        "thinking_only": (
            "Anthropic returned no text content block "
            "(got: thinking; stop_reason=max_tokens)"
        ),
    }[kind]
    err = _llm_truncation_error(msg)
    _attach_billed_usage(
        err, cost_usd=0.95, tokens_in=14000, tokens_out=16384,
    )
    return err


SHAPES = ["plain", "structured", "thinking_only"]
CLASSES = ["study", "review"]


@pytest.mark.parametrize("kind", SHAPES)
def test_shape_classifies_as_typed_truncation(kind):
    from core.concepts.study import _is_truncation_error

    err = _shape(kind)
    assert getattr(err, "llm_truncation", False) is True
    assert _is_truncation_error(err)


@pytest.mark.parametrize("kind", SHAPES)
def test_shape_is_fatal_not_retryable(kind):
    from core.llm.client import _failure_disposition, _is_retryable_error

    err = _shape(kind)
    assert _failure_disposition(err) == "fatal"
    assert not _is_retryable_error(err)


def _client():
    from core.llm.config import LLMConfig, ModelConfig
    from core.llm.client import LLMClient

    return LLMClient(LLMConfig(
        primary_model=ModelConfig(
            provider="anthropic", model_name="claude-fable-5",
            api_key="k",
        ),
        fallback_models=[],
        max_retries=3,
        enable_caching=False,
        scorecard_enabled=False,
    ))


@pytest.mark.parametrize("kind", SHAPES)
@pytest.mark.parametrize("call_class", CLASSES)
def test_matrix_single_attempt_with_paid_telemetry(
    kind, call_class, tmp_path, monkeypatch,
):
    """Every shape × class: exactly ONE paid attempt (no identical
    retry), disposition fatal, and the row carries the stamped cost."""
    import core.llm.client as client_mod
    monkeypatch.setattr(client_mod.time, "sleep", lambda _s: None)
    sink = TelemetrySink(tmp_path / "t.jsonl")
    set_sink(sink)

    client = _client()
    with patch.object(client, "_get_provider") as mock_get:
        prov = MagicMock()
        prov.generate.side_effect = _shape(kind)
        prov.generate_structured.side_effect = _shape(kind)
        # counter reads on the structured path
        prov.total_cost = 0.0
        prov.total_tokens = 0
        mock_get.return_value = prov
        with pytest.raises(RuntimeError):
            if call_class == "study":
                client.generate_structured(
                    "p", {"type": "object", "properties": {}},
                    call_class="study",
                )
            else:
                client.generate("p", call_class="review")

    recs = [
        json.loads(line)
        for line in (tmp_path / "t.jsonl").read_text().splitlines()
        if line.strip()
    ]
    fails = [r for r in recs if r["event"] == "attempt_failed"]
    assert len(fails) == 1, (
        f"{kind}/{call_class}: expected one attempt, got {len(fails)}"
    )
    rec = fails[0]
    assert rec["call_class"] == call_class
    assert rec["disposition"] == "fatal"
    assert rec["cost_usd"] == 0.95
    assert rec["tokens_out"] == 16384
    # aggregate: money visible under failed spend, not the call mean
    assert sink.failed_class_costs()[call_class] == (1, 0.95)
    assert sink.mean_call_cost(call_class) is None
