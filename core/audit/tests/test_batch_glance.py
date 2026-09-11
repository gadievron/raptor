"""Tests for GLANCE batching — batch_glance.py and executor integration."""

from __future__ import annotations

import json
import logging
import re
from types import SimpleNamespace
from typing import Any, Callable
from unittest.mock import MagicMock

from core.audit import batch_glance
from core.audit.batch_glance import (
    _classify_batch_error,
    _is_refusal_error,
    format_batch_prompt,
    make_batch_review_fn,
    parse_batch_response,
)


def _ctx(file: str, func: str, source: str = "pass") -> dict:
    return {
        "file": file,
        "function": func,
        "source": source,
        "line_start": 1,
        "line_end": 2,
    }


class TestFormatBatchPrompt:
    def test_includes_all_functions(self) -> None:
        # Enveloped shape: (user, system) — per-function source in
        # untrusted blocks whose origin carries file:function:lines,
        # count/instructions in the system text.
        contexts = [_ctx("a.py", "f1"), _ctx("b.py", "f2")]
        user, system = format_batch_prompt(contexts)
        assert "a.py:f1" in user
        assert "b.py:f2" in user
        assert "2 functions" in system

    def test_includes_count_instruction(self) -> None:
        contexts = [_ctx("a.py", f"f{i}") for i in range(5)]
        _user, system = format_batch_prompt(contexts)
        assert "exactly 5 objects" in system

    def test_source_travels_in_untrusted_block(self) -> None:
        contexts = [_ctx("a.py", "f1", source="do_thing()")]
        user, _system = format_batch_prompt(contexts)
        assert "do_thing()" in user
        assert 'kind="source-code"' in user


class TestParseBatchResponse:
    def test_valid_json_array(self) -> None:
        contexts = [_ctx("a.py", "f1")]
        raw = json.dumps([{"file": "a.py", "function": "f1", "status": "clean", "body": "ok"}])
        results = parse_batch_response(raw, contexts)
        assert len(results) == 1
        assert results[0]["status"] == "clean"

    def test_markdown_fenced(self) -> None:
        contexts = [_ctx("a.py", "f1")]
        raw = '```json\n[{"file": "a.py", "function": "f1", "status": "clean", "body": "ok"}]\n```'
        results = parse_batch_response(raw, contexts)
        assert len(results) == 1

    def test_embedded_array(self) -> None:
        contexts = [_ctx("a.py", "f1")]
        raw = 'Here are the results:\n[{"file": "a.py", "function": "f1", "status": "clean", "body": "ok"}]\nDone.'
        results = parse_batch_response(raw, contexts)
        assert len(results) == 1

    def test_malformed_returns_empty(self) -> None:
        results = parse_batch_response("not json at all", [_ctx("a.py", "f1")])
        assert results == []

    def test_non_array_returns_empty(self) -> None:
        results = parse_batch_response('{"status": "clean"}', [_ctx("a.py", "f1")])
        assert results == []


class TestMakeBatchReviewFn:
    def test_returns_outcomes_for_all_contexts(self) -> None:
        mock_client = MagicMock()
        response = MagicMock()
        response.text = json.dumps([
            {"file": "a.py", "function": "f1", "status": "clean", "body": "safe"},
            {"file": "b.py", "function": "f2", "status": "suspicious", "body": "unchecked input"},
        ])
        response.model = "test-model"
        response.cost = 0.001
        mock_client.generate.return_value = response

        fn = make_batch_review_fn(mock_client)
        outcomes = fn([_ctx("a.py", "f1"), _ctx("b.py", "f2")], MagicMock())

        assert len(outcomes) == 2
        assert outcomes[0].status == "clean"
        assert outcomes[0].file == "a.py"
        assert outcomes[1].status == "suspicious"
        assert outcomes[1].file == "b.py"
        assert outcomes[0].model == "test-model"

    def test_llm_failure_returns_error_outcomes(self) -> None:
        mock_client = MagicMock()
        mock_client.generate.side_effect = RuntimeError("API down")

        fn = make_batch_review_fn(mock_client)
        outcomes = fn([_ctx("a.py", "f1")], MagicMock())

        assert len(outcomes) == 1
        assert outcomes[0].status == "error"

    def test_partial_parse_gives_error_for_missing(self) -> None:
        mock_client = MagicMock()
        response = MagicMock()
        response.text = json.dumps([
            {"file": "a.py", "function": "f1", "status": "clean", "body": "safe"},
        ])
        response.model = "test"
        response.cost = 0.001
        mock_client.generate.return_value = response

        fn = make_batch_review_fn(mock_client)
        outcomes = fn(
            [_ctx("a.py", "f1"), _ctx("b.py", "f2")],
            MagicMock(),
        )

        assert len(outcomes) == 2
        assert outcomes[0].status == "clean"
        assert outcomes[1].status == "error"

    def test_empty_contexts(self) -> None:
        fn = make_batch_review_fn(MagicMock())
        outcomes = fn([], MagicMock())
        assert outcomes == []


def _refusal_exc() -> RuntimeError:
    """Rebuild the live failure shape: providers.py raises the refusal,
    client.py wraps it (``raise ... from last_error``) in a message
    that itself carries no refusal vocabulary — detection must walk
    ``__cause__``."""
    inner = RuntimeError(
        "Anthropic model refused request (stop_reason=refusal, empty content)"
    )
    outer = RuntimeError("All cloud models failed (tried 1 model(s)).")
    outer.__cause__ = inner
    return outer


class _ScriptedBatchClient:
    """Stub llm_client whose ``generate`` parses the batch prompt's
    numbered function list, refuses when ``refuse_when(keys)`` is true
    (or raises ``exc_factory()``), and otherwise answers a valid clean
    verdict for every listed function."""

    def __init__(
        self,
        refuse_when: Callable[[list[str]], bool],
        exc_factory: Callable[[], Exception] = _refusal_exc,
    ) -> None:
        self.refuse_when = refuse_when
        self.exc_factory = exc_factory
        self.calls: list[list[str]] = []
        self.call_kwargs: list[dict[str, Any]] = []

    def generate(
        self, prompt: str, system_prompt: str | None = None, **kwargs: Any,
    ) -> SimpleNamespace:
        keys: list[str] = []
        for k in re.findall(r"\d+\. ([\w./-]+\.py:\w+)", prompt):
            if k not in keys:
                keys.append(k)
        self.calls.append(keys)
        self.call_kwargs.append(dict(kwargs))
        if self.refuse_when(keys):
            raise self.exc_factory()
        payload = [
            {
                "file": k.rsplit(":", 1)[0],
                "function": k.rsplit(":", 1)[1],
                "status": "clean",
                "body": "ok",
            }
            for k in keys
        ]
        return SimpleNamespace(
            content=json.dumps(payload), model="stub-model", cost=0.004,
        )


class TestIsRefusalError:
    def test_direct_refusal_message(self) -> None:
        exc = RuntimeError(
            "Anthropic model refused request (stop_reason=refusal, empty content)"
        )
        assert _is_refusal_error(exc)

    def test_wrapped_refusal_detected_via_cause_chain(self) -> None:
        # The wrapper message alone carries no refusal vocabulary.
        exc = _refusal_exc()
        assert not _is_refusal_error(RuntimeError(str(exc)))
        assert _is_refusal_error(exc)

    def test_timeout_and_transport_errors_are_not_refusals(self) -> None:
        assert not _is_refusal_error(RuntimeError("Request timed out"))
        assert not _is_refusal_error(ConnectionError("connection reset"))

    def test_classify_batch_error_buckets_refusal_first(self) -> None:
        assert _classify_batch_error(_refusal_exc()) == "refusal"
        assert _classify_batch_error(RuntimeError("Request timed out")) == "api_error"


class TestRefusalBisection:
    def _contexts(self) -> list[dict]:
        return [
            _ctx("a.py", "f1"),
            _ctx("b.py", "f2"),
            _ctx("c.py", "f3"),
            _ctx("d.py", "f4"),
        ]

    def test_full_batch_refusal_halves_succeed(self) -> None:
        # Refusal on the 4-wide call only; both halves succeed.
        client = _ScriptedBatchClient(lambda keys: len(keys) == 4)
        fn = make_batch_review_fn(client)
        outcomes = fn(self._contexts(), MagicMock())

        assert len(outcomes) == 4
        assert [o.status for o in outcomes] == ["clean"] * 4
        # Positional contract preserved after reassembly.
        assert [o.file for o in outcomes] == ["a.py", "b.py", "c.py", "d.py"]
        # 1 refused full call + 2 half calls.
        assert [len(c) for c in client.calls] == [4, 2, 2]

    def test_refusal_isolates_to_one_singleton(self) -> None:
        client = _ScriptedBatchClient(lambda keys: "b.py:f2" in keys)
        fn = make_batch_review_fn(client)
        outcomes = fn(self._contexts(), MagicMock())

        assert len(outcomes) == 4
        assert outcomes[1].status == "error"
        assert outcomes[1].error_class == "refusal"
        assert [outcomes[i].status for i in (0, 2, 3)] == ["clean"] * 3
        # full → [a,b] refused → [c,d] ok → [a] ok → [b] refused singleton.
        assert [len(c) for c in client.calls] == [4, 2, 2, 1, 1]

    def test_non_refusal_error_routes_whole_batch_one_call(self) -> None:
        # Timeout/transport failures are not content-dependent —
        # splitting would only multiply cost, so no bisection happens.
        client = _ScriptedBatchClient(
            lambda keys: True,
            exc_factory=lambda: RuntimeError("Request timed out"),
        )
        fn = make_batch_review_fn(client)
        outcomes = fn(self._contexts(), MagicMock())

        assert len(client.calls) == 1
        assert [o.status for o in outcomes] == ["error"] * 4
        assert all(o.error_class == "api_error" for o in outcomes)

    def test_call_cap_stops_bisection(self, monkeypatch) -> None:
        # Lower direction: a reduced cap abandons remaining sub-batches
        # without further calls once the retry budget is spent.
        monkeypatch.setattr(batch_glance, "_BISECTION_CALL_CAP_FACTOR", 1)
        client = _ScriptedBatchClient(lambda keys: True)
        fn = make_batch_review_fn(client)
        outcomes = fn(self._contexts(), MagicMock())

        assert [o.status for o in outcomes] == ["error"] * 4
        assert all(o.error_class == "refusal" for o in outcomes)
        # cap = 1*4 retries: initial + 4 retry calls, then the two
        # remaining singletons error-route without a call.
        assert len(client.calls) == 5
        assert sum("call cap" in o.body for o in outcomes) == 2

    def test_default_cap_never_truncates_full_bisection(self) -> None:
        # Upper direction: the default factor of 2 admits the full
        # all-refused bisection (2N-1 calls for N members) — every
        # member reaches its singleton attempt, none is cap-routed.
        client = _ScriptedBatchClient(lambda keys: True)
        fn = make_batch_review_fn(client)
        outcomes = fn(self._contexts(), MagicMock())

        assert [o.status for o in outcomes] == ["error"] * 4
        assert len(client.calls) == 7
        assert sorted(len(c) for c in client.calls) == [1, 1, 1, 1, 2, 2, 4]
        assert not any("call cap" in o.body for o in outcomes)

    def test_telemetry_call_class_and_log_lines(self, caplog) -> None:
        client = _ScriptedBatchClient(lambda keys: "b.py:f2" in keys)
        fn = make_batch_review_fn(client)
        with caplog.at_level(logging.INFO, logger="core.audit.batch_glance"):
            fn(self._contexts(), MagicMock())

        # Retried sub-batches keep the glance_batch telemetry label.
        assert all(
            kw.get("call_class") == "glance_batch" for kw in client.call_kwargs
        )
        assert "glance batch refused — bisecting" in caplog.text
        assert "recovered 3 of 4 functions from refused batch" in caplog.text


class TestRefusalVocabularyIsNarrow:
    """Transport blocks must not classify as refusals: a refusal is
    excluded from the recoverable-error re-queue AND triggers paid
    bisection, so an echoed proxy/WAF 403 body ("blocked by security
    policy") classified as refusal turns a retryable outage into 2N-1
    doomed calls that are then never re-queued."""

    def test_transport_block_is_api_error_not_refusal(self):
        from core.audit.batch_glance import _classify_batch_error
        exc = RuntimeError(
            "All cloud models failed (tried 1 model(s)). Last error: "
            "403 Forbidden: request blocked by security policy"
        )
        assert _classify_batch_error(exc) == "api_error"

    def test_wrapped_refusal_still_detected(self):
        from core.audit.batch_glance import _classify_batch_error
        cause = RuntimeError(
            "Anthropic model refused request (stop_reason=refusal, "
            "empty content)"
        )
        wrapper = RuntimeError("All cloud models failed (tried 1 model(s)).")
        wrapper.__cause__ = cause
        assert _classify_batch_error(wrapper) == "refusal"


class TestSiblingDisambiguation:
    """Same-file same-name siblings (static #if branches, overloads)
    must not collapse onto one result: the schema's line_start echo
    keys results back, and the bare-pair fallback fires only when the
    pair is unique in the batch."""

    @staticmethod
    def _client(items: list[dict]) -> MagicMock:
        client = MagicMock()
        response = MagicMock()
        response.text = json.dumps(items)
        response.model = "test-model"
        response.cost = 0.001
        client.generate.return_value = response
        return client

    def _sibling_contexts(self) -> list[dict]:
        a = _ctx("a.c", "handler")
        a["line_start"], a["line_end"] = 10, 30
        b = _ctx("a.c", "handler")
        b["line_start"], b["line_end"] = 100, 130
        return [a, b]

    def test_siblings_get_distinct_verdicts_via_line_echo(self) -> None:
        client = self._client([
            {"file": "a.c", "function": "handler", "line_start": 10,
             "status": "clean", "body": "first sibling"},
            {"file": "a.c", "function": "handler", "line_start": 100,
             "status": "suspicious", "body": "second sibling"},
        ])
        fn = make_batch_review_fn(client)
        outcomes = fn(self._sibling_contexts(), MagicMock())
        assert [o.status for o in outcomes] == ["clean", "suspicious"]
        assert outcomes[0].body == "first sibling"
        assert outcomes[1].body == "second sibling"

    def test_siblings_without_echo_error_route(self) -> None:
        # One un-echoed element for an AMBIGUOUS pair must not serve
        # both contexts (that was the verdict-swap bug) — both fall
        # back to individual review.
        client = self._client([
            {"file": "a.c", "function": "handler",
             "status": "suspicious", "body": "which one?"},
        ])
        fn = make_batch_review_fn(client)
        outcomes = fn(self._sibling_contexts(), MagicMock())
        assert all(o.status == "error" for o in outcomes)

    def test_unique_pair_matches_without_echo(self) -> None:
        # Models that omit the echo keep working for unambiguous
        # batches — the pre-existing behavior.
        client = self._client([
            {"file": "a.py", "function": "f1",
             "status": "clean", "body": "ok"},
        ])
        fn = make_batch_review_fn(client)
        outcomes = fn([_ctx("a.py", "f1")], MagicMock())
        assert outcomes[0].status == "clean"

    def test_prompt_asks_for_line_start_echo(self) -> None:
        contexts = self._sibling_contexts()
        user, system = format_batch_prompt(contexts)
        assert "line_start" in system
        # The listing distinguishes the siblings by line range.
        assert "a.c:handler:10-30" in user
        assert "a.c:handler:100-130" in user

    def test_line_start_is_schema_legal(self) -> None:
        # parse_batch_response's strict schema must not drop elements
        # carrying the requested echo field.
        raw = json.dumps([
            {"file": "a.c", "function": "handler", "line_start": 10,
             "status": "clean", "body": "ok"},
        ])
        results = parse_batch_response(raw, self._sibling_contexts())
        assert len(results) == 1
