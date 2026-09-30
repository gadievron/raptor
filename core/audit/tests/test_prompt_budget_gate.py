"""Tests for the audit budget gate's priority-0 elision disclosure.

``format_context_for_prompt`` (the /audit individual-review prompt
assembly) must never dispatch a silently over-budget prompt: when the
priority-0 sections alone exceed the budget it tail-truncates them
with explicit elision markers, warns once naming the row, and stamps
``ctx["prompt_budget_event"]`` so the review path can persist the
facts on the row's durable audit-log record.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from core.audit.collector import Collector
from core.audit.context import format_context_for_prompt
from core.audit.llm_review import make_review_fn
from core.audit.orchestrator import OrchestratorConfig, ReviewOutcome

_CTX_LOGGER = "core.audit.context"


def _ctx(source_chars: int = 200) -> dict[str, Any]:
    return {
        "file": "src/auth.c",
        "function": "check_pw",
        "line_start": 1,
        "line_end": 10,
        "source": "y" * source_chars,
    }


def _budget_event() -> dict[str, Any]:
    return {
        "tokens_elided": 3000,
        "overshoot_tokens": 0,
        "elisions": [{"label": "source", "tokens_elided": 3000}],
    }


class TestBudgetGateElision:

    def test_over_budget_prompt_is_elided_and_stamped(self) -> None:
        ctx = _ctx(source_chars=40_000)  # ~10k tokens of source
        prompt = format_context_for_prompt(ctx, budget_limit=2_000)
        assert "tokens elided from source" in prompt
        event = ctx["prompt_budget_event"]
        assert event["tokens_elided"] > 0
        assert event["overshoot_tokens"] == 0
        assert event["elisions"]
        assert event["elisions"][0]["label"] == "source"

    def test_one_warning_names_the_row(
        self, caplog: pytest.LogCaptureFixture,
    ) -> None:
        ctx = _ctx(source_chars=40_000)
        with caplog.at_level(logging.WARNING, logger=_CTX_LOGGER):
            format_context_for_prompt(ctx, budget_limit=2_000)
        warnings = [
            r for r in caplog.records
            if r.name == _CTX_LOGGER and "prompt_budget" in r.getMessage()
        ]
        assert len(warnings) == 1
        msg = warnings[0].getMessage()
        assert "src/auth.c:check_pw" in msg
        assert "elided" in msg

    def test_under_budget_no_stamp_no_warning(
        self, caplog: pytest.LogCaptureFixture,
    ) -> None:
        ctx = _ctx()
        with caplog.at_level(logging.WARNING):
            format_context_for_prompt(ctx, budget_limit=10**9)
        assert "prompt_budget_event" not in ctx
        assert [
            r for r in caplog.records if "prompt_budget" in r.getMessage()
        ] == []

    def test_under_budget_prompt_byte_identical_to_ungated(self) -> None:
        # Behaviour pin (green by design on the pre-elision code):
        # a prompt that fits the budget must be byte-identical to the
        # budget_limit=0 assembly — the gate reorders/rewrites nothing.
        gated = format_context_for_prompt(_ctx(), budget_limit=10**9)
        ungated = format_context_for_prompt(_ctx(), budget_limit=0)
        assert gated == ungated

    def test_stale_stamp_cleared_on_reentry(self) -> None:
        ctx = _ctx()
        ctx["prompt_budget_event"] = {"tokens_elided": 999}
        format_context_for_prompt(ctx, budget_limit=10**9)
        assert "prompt_budget_event" not in ctx

    def test_stale_stamp_cleared_on_glance_reentry(self) -> None:
        # The guard runs at the top of format_context_for_prompt,
        # before ANY early return: a stamped ctx re-entering through
        # the glance path must not carry the previous pass's stamp.
        ctx = _ctx()
        ctx["triage_bucket"] = "glance"
        ctx["prompt_budget_event"] = {"tokens_elided": 999}
        format_context_for_prompt(ctx, budget_limit=2_000)
        assert "prompt_budget_event" not in ctx

    def test_stale_stamp_cleared_on_budget_zero_reentry(self) -> None:
        # Same guard for the budget_limit=0 path (no budget gate at
        # all): a stale stamp must not survive that re-entry either.
        ctx = _ctx()
        ctx["prompt_budget_event"] = {"tokens_elided": 999}
        format_context_for_prompt(ctx, budget_limit=0)
        assert "prompt_budget_event" not in ctx


def _fence_balanced(prompt: str) -> bool:
    """CommonMark fence parity walk: a fence closes only with a bare
    backtick run at least as long as its opener."""
    in_fence = False
    fence_len = 0
    for line in prompt.split("\n"):
        stripped = line.strip()
        m = re.match(r"^(`{3,})", stripped)
        if not m:
            continue
        run = len(m.group(1))
        if not in_fence:
            in_fence = True
            fence_len = run
        elif run >= fence_len and set(stripped) == {"`"}:
            in_fence = False
    return not in_fence


class TestStructuralIntegrity:
    """Real-assembly regression for structure-blind tail elision.

    Eliding the fenced source section must not leave its code fence
    unterminated — every following section (including the untrusted
    evidence envelope) would render inside the fence, and a backtick
    run in target-derived text could flip fence parity and surface
    untrusted content as live prose.  Eliding the enveloped evidence
    section must not sever its ``</untrusted-...>`` close tag.
    """

    def test_elided_source_fence_and_envelope_balanced(self) -> None:
        ctx = _ctx()
        ctx["line_end"] = 900
        ctx["source"] = (
            "int check_pw(char *p){\n"
            + "  x += p[i]; /* pad */\n" * 3_000 + "}\n"
        )
        ctx["mechanical_evidence"] = (
            "taint_approx: param p flows to memcpy at line 40\n" * 40
        )
        prompt = format_context_for_prompt(ctx, budget_limit=2_000)
        assert ctx["prompt_budget_event"]["elisions"]
        assert _fence_balanced(prompt)
        lines = prompt.split("\n")
        opens = [ln for ln in lines if ln.startswith("<untrusted-")]
        closes = [ln for ln in lines if ln.startswith("</untrusted-")]
        assert len(opens) == 1
        assert len(closes) == 1
        # The marker sits OUTSIDE the re-closed fence: everything up
        # to the marker is fence-balanced, so the evidence envelope
        # that follows renders in normal (non-literal) context.
        i = prompt.find("[... prompt budget:")
        assert i != -1
        assert _fence_balanced(prompt[:i])

    def test_elided_evidence_envelope_reclosed(self) -> None:
        ctx = _ctx()
        ctx["source"] = "int check_pw(void){ return 1; }\n"
        ctx["mechanical_evidence"] = "sink hit detail line\n" * 4_000
        prompt = format_context_for_prompt(ctx, budget_limit=2_000)
        assert ctx["prompt_budget_event"]["elisions"]
        assert _fence_balanced(prompt)
        lines = prompt.split("\n")
        opens = [ln for ln in lines if ln.startswith("<untrusted-")]
        closes = [ln for ln in lines if ln.startswith("</untrusted-")]
        assert len(opens) == 1
        assert len(closes) == 1
        # The elided evidence section ends close-tag-then-marker: the
        # untrusted region is terminated and the marker sits outside.
        assert re.search(
            r"\n</untrusted-[0-9a-f]+>\n"
            r"\[\.\.\. prompt budget: \d+ tokens elided", prompt)


@dataclass
class _FakeStructuredResponse:
    result: dict[str, Any]
    raw: str = ""
    cost: float = 0.01
    model: str = "test-model"
    tokens_used: int = 100


class _FakeLLMClient:
    def __init__(self, result: dict[str, Any]) -> None:
        self._result = result
        self.calls: list[dict[str, Any]] = []

    def generate_structured(
        self, prompt: str, schema: dict[str, Any], **kwargs: Any,
    ) -> _FakeStructuredResponse:
        self.calls.append({"prompt": prompt, "schema": schema, **kwargs})
        return _FakeStructuredResponse(result=dict(self._result))


class TestReviewFnThreading:

    def _config(self, tmp_path: Path) -> OrchestratorConfig:
        target = tmp_path / "target"
        target.mkdir()
        out = tmp_path / "out"
        out.mkdir()
        return OrchestratorConfig(target_path=target, out_dir=out)

    def test_budget_event_rides_review_result(
        self, tmp_path: Path,
    ) -> None:
        client = _FakeLLMClient({"status": "clean", "body": "ok"})
        review_fn = make_review_fn(client)
        ctx = _ctx(source_chars=40_000)
        ctx["triage_token_budget"] = 2_000
        outcome = review_fn(ctx, self._config(tmp_path))
        assert outcome.review_result is not None
        event = outcome.review_result["prompt_budget_event"]
        assert event == ctx["prompt_budget_event"]
        assert event["tokens_elided"] > 0
        # The dispatched prompt carries the elision marker.
        assert "tokens elided from source" in client.calls[0]["prompt"]

    def test_no_event_no_result_key(self, tmp_path: Path) -> None:
        client = _FakeLLMClient({"status": "clean", "body": "ok"})
        review_fn = make_review_fn(client)
        outcome = review_fn(_ctx(), self._config(tmp_path))
        assert outcome.review_result is not None
        assert "prompt_budget_event" not in outcome.review_result


@dataclass
class _FakeOutcome:
    file: str = "src/auth.c"
    function: str = "check_pw"
    status: str = "suspicious"
    body: str = "possible overflow"
    model: str = "test-model"
    cost_usd: float = 0.01
    duration_s: float = 1.5
    hypothesis: str = ""
    hypotheses: list[dict[str, Any]] = field(default_factory=list)
    evidence_tool: str = ""
    review_result: dict[str, Any] | None = None


def _read_audit_log(out_dir: Path) -> list[dict[str, Any]]:
    text = (out_dir / ".audit-log.jsonl").read_text(encoding="utf-8")
    return [json.loads(line) for line in text.strip().split("\n")]


class TestDurableDisclosure:

    def test_collector_writes_prompt_budget_row(
        self, tmp_path: Path,
    ) -> None:
        c = Collector(out_dir=tmp_path, target_path=tmp_path)
        outcome = _FakeOutcome(
            review_result={"prompt_budget_event": _budget_event()},
        )
        c.submit(outcome, {"file": "src/auth.c", "name": "check_pw",
                           "line_start": 1, "line_end": 10})
        c.flush()
        rows = _read_audit_log(tmp_path)
        assert rows[0]["prompt_budget"] == _budget_event()

    def test_collector_omits_key_without_event(
        self, tmp_path: Path,
    ) -> None:
        c = Collector(out_dir=tmp_path, target_path=tmp_path)
        c.submit(_FakeOutcome(review_result={}),
                 {"file": "src/auth.c", "name": "check_pw",
                  "line_start": 1, "line_end": 10})
        c.flush()
        rows = _read_audit_log(tmp_path)
        assert "prompt_budget" not in rows[0]

    def test_commit_outcome_writes_prompt_budget_row(
        self, tmp_path: Path,
    ) -> None:
        from core.audit.orchestrator import _commit_outcome
        target = tmp_path / "target"
        target.mkdir()
        out = tmp_path / "out"
        out.mkdir()
        config = OrchestratorConfig(target_path=target, out_dir=out)
        outcome = ReviewOutcome(
            file="src/auth.c", function="check_pw",
            status="suspicious", body="possible overflow",
            review_result={"prompt_budget_event": _budget_event()},
        )
        gap = {"file": "src/auth.c", "name": "check_pw",
               "line_start": 1, "line_end": 10}
        _commit_outcome(config, outcome, gap)
        rows = _read_audit_log(out)
        assert rows[0]["prompt_budget"] == _budget_event()
