"""Tests for GLANCE batching — batch_glance.py and executor integration."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

from core.audit.batch_glance import (
    format_batch_prompt,
    parse_batch_response,
    make_batch_review_fn,
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
        contexts = [_ctx("a.py", "f1"), _ctx("b.py", "f2")]
        prompt = format_batch_prompt(contexts)
        assert "a.py:f1" in prompt
        assert "b.py:f2" in prompt
        assert "2 functions" in prompt

    def test_includes_count_instruction(self) -> None:
        contexts = [_ctx("a.py", f"f{i}") for i in range(5)]
        prompt = format_batch_prompt(contexts)
        assert "exactly 5 objects" in prompt


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
