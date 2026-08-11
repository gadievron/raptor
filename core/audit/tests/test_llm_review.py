"""Tests for core.audit.llm_review — LLM review function factory."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

import pytest

from core.audit.llm_review import (
    REVIEW_SCHEMA,
    _is_content_filter_error,
    _counter_hypothesis_is_compelling,
    make_review_fn,
)
from core.audit.orchestrator import OrchestratorConfig, ReviewOutcome, _ContentFilterError


@dataclass
class FakeStructuredResponse:
    result: Dict[str, Any]
    raw: str = ""
    cost: float = 0.01
    model: str = "test-model"
    tokens_used: int = 100


class FakeLLMClient:
    def __init__(self, result: Dict[str, Any], *, raise_exc: Optional[Exception] = None):
        self._result = result
        self._raise_exc = raise_exc
        self.calls = []

    def generate_structured(self, prompt, schema, **kwargs):
        self.calls.append({"prompt": prompt, "schema": schema, **kwargs})
        if self._raise_exc:
            raise self._raise_exc
        return FakeStructuredResponse(result=self._result)


class TestIsContentFilterError:
    def test_content_filter_message(self):
        assert _is_content_filter_error(RuntimeError("Response blocked by content filter"))

    def test_model_refused(self):
        assert _is_content_filter_error(RuntimeError("Model refused request: safety"))

    def test_safety_filter(self):
        assert _is_content_filter_error(RuntimeError("safety filter triggered"))

    def test_normal_error(self):
        assert not _is_content_filter_error(RuntimeError("connection timeout"))

    def test_empty_message(self):
        assert not _is_content_filter_error(RuntimeError(""))


class TestMakeReviewFn:
    def _config(self, tmp_path: Path) -> OrchestratorConfig:
        target = tmp_path / "target"
        target.mkdir()
        out = tmp_path / "out"
        out.mkdir()
        return OrchestratorConfig(target_path=target, out_dir=out)

    def _ctx(self) -> Dict[str, Any]:
        return {
            "file": "src/auth.c",
            "function": "check_pw",
            "line_start": 1,
            "line_end": 10,
            "source": "int check_pw() { return 0; }",
        }

    def test_basic_review(self, tmp_path: Path):
        client = FakeLLMClient({
            "status": "clean",
            "body": "no issues found",
            "hypothesis": "buffer overflow",
            "evidence_tool": "codeql",
        })
        review_fn = make_review_fn(client)
        outcome = review_fn(self._ctx(), self._config(tmp_path))

        assert isinstance(outcome, ReviewOutcome)
        assert outcome.status == "clean"
        assert outcome.body == "no issues found"
        assert outcome.hypothesis == "buffer overflow"
        assert outcome.model == "test-model"
        assert outcome.cost_usd == 0.01
        assert outcome.review_result is not None
        assert outcome.review_result["status"] == "clean"

    def test_constraints_in_review_result(self, tmp_path: Path):
        client = FakeLLMClient({
            "status": "suspicious",
            "body": "needs bounds check",
            "constraints": [
                {"kind": "parameter", "target": "len", "rule": "must be <= 1024"},
            ],
        })
        review_fn = make_review_fn(client)
        outcome = review_fn(self._ctx(), self._config(tmp_path))

        assert outcome.review_result["constraints"][0]["kind"] == "parameter"

    def test_content_filter_raises(self, tmp_path: Path):
        client = FakeLLMClient(
            {},
            raise_exc=RuntimeError("Response blocked by content filter"),
        )
        review_fn = make_review_fn(client)

        with pytest.raises(_ContentFilterError):
            review_fn(self._ctx(), self._config(tmp_path))

    def test_non_filter_error_propagates(self, tmp_path: Path):
        client = FakeLLMClient(
            {},
            raise_exc=ConnectionError("timeout"),
        )
        review_fn = make_review_fn(client)

        with pytest.raises(ConnectionError):
            review_fn(self._ctx(), self._config(tmp_path))

    def test_invalid_status_becomes_suspicious(self, tmp_path: Path):
        client = FakeLLMClient({
            "status": "INVALID",
            "body": "something",
        })
        review_fn = make_review_fn(client)
        outcome = review_fn(self._ctx(), self._config(tmp_path))
        assert outcome.status == "suspicious"

    def test_prompt_includes_context(self, tmp_path: Path):
        client = FakeLLMClient({"status": "clean", "body": "ok"})
        review_fn = make_review_fn(client, system_prompt="be thorough")
        review_fn(self._ctx(), self._config(tmp_path))

        assert len(client.calls) == 1
        assert "check_pw" in client.calls[0]["prompt"]
        assert client.calls[0]["system_prompt"] == "be thorough"

    def test_schema_passed_through(self, tmp_path: Path):
        client = FakeLLMClient({"status": "clean", "body": "ok"})
        review_fn = make_review_fn(client)
        review_fn(self._ctx(), self._config(tmp_path))

        assert client.calls[0]["schema"] == REVIEW_SCHEMA

    def test_custom_schema(self, tmp_path: Path):
        custom = {"type": "object", "properties": {"status": {"type": "string"}}}
        client = FakeLLMClient({"status": "clean", "body": "ok"})
        review_fn = make_review_fn(client, schema=custom)
        review_fn(self._ctx(), self._config(tmp_path))

        assert client.calls[0]["schema"] == custom


    def test_hypotheses_array_extracted(self, tmp_path: Path):
        client = FakeLLMClient({
            "status": "suspicious",
            "body": "multiple issues",
            "hypothesis": "integer underflow",
            "hypotheses": [
                {"mechanism": "integer underflow in outlen", "confidence": "medium"},
                {"mechanism": "page-cache corruption via aliasing", "confidence": "low",
                 "counter": "src and dst may not alias"},
            ],
        })
        review_fn = make_review_fn(client)
        outcome = review_fn(self._ctx(), self._config(tmp_path))
        assert outcome.hypotheses is not None
        assert len(outcome.hypotheses) == 2
        assert outcome.hypotheses[0]["mechanism"] == "integer underflow in outlen"
        assert outcome.hypotheses[1]["confidence"] == "low"
        assert outcome.hypotheses[1]["counter"] == "src and dst may not alias"

    def test_evidence_tool_sanitised(self, tmp_path: Path):
        """LLM-claimed tool names get llm-claimed: prefix, not passed raw."""
        client = FakeLLMClient({
            "status": "finding",
            "body": "overflow",
            "hypothesis": "buffer overflow",
            "evidence_tool": "semgrep",
        })
        review_fn = make_review_fn(client)
        outcome = review_fn(self._ctx(), self._config(tmp_path))
        assert outcome.evidence_tool == "llm-claimed:semgrep"

    def test_evidence_tool_manual_cleared(self, tmp_path: Path):
        """LLM saying 'manual' produces empty evidence_tool."""
        client = FakeLLMClient({
            "status": "clean",
            "body": "ok",
            "evidence_tool": "manual code review",
        })
        review_fn = make_review_fn(client)
        outcome = review_fn(self._ctx(), self._config(tmp_path))
        assert outcome.evidence_tool == ""

    def test_hypotheses_empty_when_not_provided(self, tmp_path: Path):
        client = FakeLLMClient({
            "status": "clean",
            "body": "no issues",
        })
        review_fn = make_review_fn(client)
        outcome = review_fn(self._ctx(), self._config(tmp_path))
        assert outcome.hypotheses is None

    def test_hypotheses_filters_invalid_entries(self, tmp_path: Path):
        client = FakeLLMClient({
            "status": "suspicious",
            "body": "some issue",
            "hypotheses": [
                {"mechanism": "real hypothesis", "confidence": "high"},
                {"confidence": "low"},  # missing mechanism
                "not a dict",
            ],
        })
        review_fn = make_review_fn(client)
        outcome = review_fn(self._ctx(), self._config(tmp_path))
        assert outcome.hypotheses is not None
        assert len(outcome.hypotheses) == 1
        assert outcome.hypotheses[0]["mechanism"] == "real hypothesis"


class TestFormatContextExtensions:
    """Test that fuzz_coverage and batch_context appear in formatted prompts."""

    def test_fuzz_coverage_in_prompt(self):
        from core.audit.context import format_context_for_prompt
        ctx = {
            "file": "a.c",
            "function": "f",
            "line_start": 1,
            "fuzz_coverage": {
                "harness": "fuzz_input",
                "iterations": 100000,
                "crashes": 2,
            },
        }
        prompt = format_context_for_prompt(ctx)
        assert "fuzz_input" in prompt
        assert "100000" in prompt
        assert "does NOT replace review" in prompt
        assert "Crashes found" in prompt

    def test_batch_context_in_prompt(self):
        from core.audit.context import format_context_for_prompt
        ctx = {
            "file": "a.c",
            "function": "f",
            "line_start": 1,
            "batch_context": ["tiny1 (L1-3)", "tiny2 (L4-6)"],
        }
        prompt = format_context_for_prompt(ctx)
        assert "Batch review" in prompt
        assert "tiny1 (L1-3)" in prompt
        assert "tiny2 (L4-6)" in prompt

    def test_no_fuzz_no_section(self):
        from core.audit.context import format_context_for_prompt
        ctx = {"file": "a.c", "function": "f", "line_start": 1}
        prompt = format_context_for_prompt(ctx)
        assert "Fuzz coverage" not in prompt
        assert "Batch review" not in prompt


class TestCounterHypothesis:
    def test_empty_not_compelling(self):
        assert not _counter_hypothesis_is_compelling("")

    def test_short_not_compelling(self):
        assert not _counter_hypothesis_is_compelling("maybe bad")

    def test_dismissive_not_compelling(self):
        text = "No plausible attack vector exists for this function."
        assert not _counter_hypothesis_is_compelling(text)

    def test_specific_overflow_compelling(self):
        text = (
            "If the caller passes a length greater than the buffer size, "
            "the memcpy at line 42 would produce a heap buffer overflow "
            "allowing attacker-controlled write past the allocation."
        )
        assert _counter_hypothesis_is_compelling(text)

    def test_specific_null_deref_compelling(self):
        text = (
            "When the allocation fails and returns null, the subsequent "
            "dereference at line 15 would crash. An attacker could trigger "
            "this via a large allocation request."
        )
        assert _counter_hypothesis_is_compelling(text)

    def test_vague_without_mechanism_not_compelling(self):
        text = "This function could potentially be problematic in some edge cases."
        assert not _counter_hypothesis_is_compelling(text)

    def test_na_not_compelling(self):
        assert not _counter_hypothesis_is_compelling("N/A")

    def test_schema_has_counter_hypothesis_field(self):
        assert "counter_hypothesis" in REVIEW_SCHEMA["properties"]

    def test_escalation_on_compelling_counter(self):
        client = FakeLLMClient({
            "status": "clean",
            "body": "Function looks safe.",
            "counter_hypothesis": (
                "If the input buffer is larger than MAX_SIZE, the "
                "memcpy would overflow the stack buffer by up to "
                "256 bytes, allowing attacker-controlled overwrite."
            ),
        })
        config = OrchestratorConfig(
            target_path=Path("/fake"),
            out_dir=Path("/fake/out"),
        )
        review_fn = make_review_fn(client)
        ctx = {
            "file": "a.c",
            "function": "parse",
            "line_start": 1,
            "source": "void parse(char *input) {}",
            "metadata": {},
            "callers": [],
            "callees": [],
            "sinks": [],
            "trust_surface": {},
        }
        outcome = review_fn(ctx, config)
        assert outcome.status == "suspicious"

    def test_no_escalation_on_dismissive_counter(self):
        client = FakeLLMClient({
            "status": "clean",
            "body": "Function is safe.",
            "counter_hypothesis": "No plausible attack vector.",
        })
        config = OrchestratorConfig(
            target_path=Path("/fake"),
            out_dir=Path("/fake/out"),
        )
        review_fn = make_review_fn(client)
        ctx = {
            "file": "a.c",
            "function": "safe_fn",
            "line_start": 1,
            "source": "int safe_fn() { return 0; }",
            "metadata": {},
            "callers": [],
            "callees": [],
            "sinks": [],
            "trust_surface": {},
        }
        outcome = review_fn(ctx, config)
        assert outcome.status == "clean"


class TestDefaultSystemPrompt:
    def test_default_prompt_used_when_none(self):
        from core.audit.llm_review import _DEFAULT_SYSTEM_PROMPT
        calls = []

        class SpyClient:
            config = None

            def generate_structured(self, prompt, schema, *, system_prompt=None, **kw):
                calls.append(system_prompt)

                class R:
                    result = {"status": "clean", "body": "ok", "hypotheses": []}
                    model = "test"
                    cost = 0.0
                return R()

        review_fn = make_review_fn(SpyClient())
        config = OrchestratorConfig(
            target_path=Path("/fake"), out_dir=Path("/fake/out"),
        )
        ctx = {
            "file": "a.c", "function": "f", "line_start": 1,
            "source": "int f() {}", "metadata": {},
            "callers": [], "callees": [], "sinks": [], "trust_surface": {},
        }
        review_fn(ctx, config)
        assert len(calls) == 1
        assert calls[0] is _DEFAULT_SYSTEM_PROMPT

    def test_explicit_prompt_overrides_default(self):
        calls = []

        class SpyClient:
            config = None

            def generate_structured(self, prompt, schema, *, system_prompt=None, **kw):
                calls.append(system_prompt)

                class R:
                    result = {"status": "clean", "body": "ok", "hypotheses": []}
                    model = "test"
                    cost = 0.0
                return R()

        custom = "You are a custom auditor."
        review_fn = make_review_fn(SpyClient(), system_prompt=custom)
        config = OrchestratorConfig(
            target_path=Path("/fake"), out_dir=Path("/fake/out"),
        )
        ctx = {
            "file": "a.c", "function": "f", "line_start": 1,
            "source": "int f() {}", "metadata": {},
            "callers": [], "callees": [], "sinks": [], "trust_surface": {},
        }
        review_fn(ctx, config)
        assert len(calls) == 1
        assert calls[0] == custom
