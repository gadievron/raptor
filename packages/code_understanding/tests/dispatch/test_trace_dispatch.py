"""Tests for default_trace_dispatch — same mocked-provider strategy as
test_hunt_dispatch.py."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Iterator
from unittest.mock import patch

import pytest

from core.llm.config import ModelConfig
from core.llm.tool_use.types import (
    StopReason,
    TextBlock,
    ToolCall,
    TurnResponse,
)


# ---------------------------------------------------------------------------
# Fake provider — duplicated from test_hunt_dispatch by design (each test
# file is self-contained so failures point clearly at the dispatcher under test).
# ---------------------------------------------------------------------------


@dataclass
class FakeTurn:
    text: str = ""
    tool_calls: list = None
    stop: StopReason | None = None


class FakeProvider:
    def __init__(self, turns: list[FakeTurn]):
        self._iter: Iterator[FakeTurn] = iter(turns)
        self._call_count = 0

    def supports_tool_use(self) -> bool:
        return True

    def supports_prompt_caching(self) -> bool:
        return False

    def estimate_tokens(self, text: str) -> int:
        return max(1, len(text) // 4)

    def context_window(self) -> int:
        return 200_000

    def compute_cost(self, response: TurnResponse) -> float:
        return 0.0

    def turn(self, messages, tools, **kwargs) -> TurnResponse:
        try:
            t = next(self._iter)
        except StopIteration:
            return TurnResponse(
                content=[TextBlock("[end]")],
                stop_reason=StopReason.COMPLETE,
                input_tokens=10, output_tokens=5,
            )

        self._call_count += 1
        content: list = []
        if t.text:
            content.append(TextBlock(t.text))
        if t.tool_calls:
            for i, (name, payload) in enumerate(t.tool_calls):
                content.append(ToolCall(
                    id=f"call_{self._call_count}_{i}",
                    name=name,
                    input=payload,
                ))

        stop = t.stop or (
            StopReason.NEEDS_TOOL_CALL if t.tool_calls
            else StopReason.COMPLETE
        )
        return TurnResponse(
            content=content,
            stop_reason=stop,
            input_tokens=10, output_tokens=5,
        )


@pytest.fixture
def repo(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "x.c").write_text("int foo() { return 0; }\n")
    return tmp_path


@pytest.fixture
def fake_model_config():
    return ModelConfig(
        provider="anthropic",
        model_name="fake-model-x",
        api_key="test",
    )


def _patch_provider(turns: list[FakeTurn]):
    return patch(
        "packages.code_understanding.dispatch.trace_dispatch.create_provider",
        return_value=FakeProvider(turns),
    )


def _sample_traces():
    return [
        {"trace_id": "EP-001",
         "entry": "POST /api/x", "sink": "exec(line 42)"},
        {"trace_id": "EP-002",
         "entry": "GET /api/y", "sink": "system(line 99)"},
    ]


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


class TestHappyPath:
    def test_model_submits_verdicts_directly(self, repo, fake_model_config):
        from packages.code_understanding.dispatch.trace_dispatch import (
            default_trace_dispatch,
        )

        verdicts = [
            {"trace_id": "EP-001", "verdict": "reachable",
             "confidence": "high", "reasoning": "Sink reached"},
            {"trace_id": "EP-002", "verdict": "not_reachable",
             "confidence": "high", "reasoning": "Path is dead"},
        ]
        turns = [
            FakeTurn(tool_calls=[("submit_verdicts", {"verdicts": verdicts})]),
        ]

        with _patch_provider(turns):
            result = default_trace_dispatch(
                fake_model_config, _sample_traces(), str(repo),
            )
        assert result == verdicts

    def test_multi_turn_dispatch(self, repo, fake_model_config):
        """Model reads files first, then submits."""
        from packages.code_understanding.dispatch.trace_dispatch import (
            default_trace_dispatch,
        )

        turns = [
            FakeTurn(tool_calls=[("read_file", {"path": "src/x.c"})]),
            FakeTurn(tool_calls=[("submit_verdicts", {
                "verdicts": [
                    {"trace_id": "EP-001", "verdict": "uncertain",
                     "confidence": "medium", "reasoning": "Need more info"},
                    {"trace_id": "EP-002", "verdict": "uncertain",
                     "confidence": "medium", "reasoning": "Need more info"},
                ],
            })]),
        ]

        with _patch_provider(turns):
            result = default_trace_dispatch(
                fake_model_config, _sample_traces(), str(repo),
            )
        assert len(result) == 2
        assert all(v["verdict"] == "uncertain" for v in result)


# ---------------------------------------------------------------------------
# Tool wiring
# ---------------------------------------------------------------------------


class TestToolWiring:
    def test_all_four_tools_present(self, repo):
        from packages.code_understanding.dispatch.trace_dispatch import _build_tools
        from packages.code_understanding.dispatch.tools import SandboxedTools

        tools = _build_tools(SandboxedTools.for_repo(repo))
        names = sorted(t.name for t in tools)
        assert names == ["glob_files", "grep", "read_file", "submit_verdicts"]

    def test_terminal_tool_is_submit_verdicts(self, repo):
        from packages.code_understanding.dispatch.trace_dispatch import _build_tools
        from packages.code_understanding.dispatch.tools import SandboxedTools

        tools = _build_tools(SandboxedTools.for_repo(repo))
        names = {t.name for t in tools}
        assert "submit_verdicts" in names
        assert "submit_variants" not in names  # that's hunt's terminal

    def test_read_file_handler_works(self, repo):
        from packages.code_understanding.dispatch.trace_dispatch import _build_tools
        from packages.code_understanding.dispatch.tools import SandboxedTools

        tools = _build_tools(SandboxedTools.for_repo(repo))
        read = next(t for t in tools if t.name == "read_file")
        out = json.loads(read.handler({"path": "src/x.c"}))
        assert "foo" in out["content"]


# ---------------------------------------------------------------------------
# Error paths
# ---------------------------------------------------------------------------


class TestErrorPaths:
    def test_empty_traces_returns_error(self, repo, fake_model_config):
        """default_trace_dispatch's own input validation."""
        from packages.code_understanding.dispatch.trace_dispatch import (
            default_trace_dispatch,
        )

        result = default_trace_dispatch(
            fake_model_config, [], str(repo),
        )
        assert len(result) == 1
        assert "error" in result[0]

    def test_loop_terminates_without_submit_returns_error(
        self, repo, fake_model_config,
    ):
        from packages.code_understanding.dispatch.trace_dispatch import (
            default_trace_dispatch,
        )

        turns = [
            FakeTurn(text="I'm stuck", stop=StopReason.COMPLETE),
        ]

        with _patch_provider(turns):
            result = default_trace_dispatch(
                fake_model_config, _sample_traces(), str(repo),
            )
        assert len(result) == 1
        assert "error" in result[0]
        assert "submit_verdicts" in result[0]["error"]

    def test_submit_with_missing_verdicts_key_returns_error(
        self, repo, fake_model_config,
    ):
        from packages.code_understanding.dispatch.trace_dispatch import (
            default_trace_dispatch,
        )

        turns = [
            FakeTurn(tool_calls=[("submit_verdicts", {"oops": "wrong"})]),
        ]

        with _patch_provider(turns):
            result = default_trace_dispatch(
                fake_model_config, _sample_traces(), str(repo),
            )
        assert len(result) == 1
        assert "error" in result[0]

    def test_submit_with_non_list_verdicts_returns_error(
        self, repo, fake_model_config,
    ):
        from packages.code_understanding.dispatch.trace_dispatch import (
            default_trace_dispatch,
        )

        turns = [
            FakeTurn(tool_calls=[("submit_verdicts", {"verdicts": "wrong shape"})]),
        ]

        with _patch_provider(turns):
            result = default_trace_dispatch(
                fake_model_config, _sample_traces(), str(repo),
            )
        assert len(result) == 1
        assert "error" in result[0]

    def test_non_dict_verdicts_filtered_out(self, repo, fake_model_config):
        from packages.code_understanding.dispatch.trace_dispatch import (
            default_trace_dispatch,
        )

        turns = [
            FakeTurn(tool_calls=[("submit_verdicts", {
                "verdicts": [
                    {"trace_id": "EP-001", "verdict": "reachable"},
                    "garbage",
                    None,
                    {"trace_id": "EP-002", "verdict": "uncertain"},
                ],
            })]),
        ]

        with _patch_provider(turns):
            result = default_trace_dispatch(
                fake_model_config, _sample_traces(), str(repo),
            )
        assert len(result) == 2
        ids = {v["trace_id"] for v in result}
        assert ids == {"EP-001", "EP-002"}

    def test_verdicts_without_trace_id_filtered(
        self, repo, fake_model_config,
    ):
        """CRITICAL regression: a verdict without trace_id would crash
        TraceAdapter.item_id (PR2a), and via _check_unique_ids the
        entire substrate run including OTHER models' valid results.
        Filter at dispatch boundary so one buggy model can't break
        the run."""
        from packages.code_understanding.dispatch.trace_dispatch import (
            default_trace_dispatch,
        )

        turns = [
            FakeTurn(tool_calls=[("submit_verdicts", {
                "verdicts": [
                    {"trace_id": "EP-001", "verdict": "reachable"},
                    {"verdict": "uncertain"},                # no trace_id
                    {"trace_id": "", "verdict": "uncertain"}, # empty
                    {"trace_id": 42, "verdict": "uncertain"}, # non-string
                    {"trace_id": "EP-002", "verdict": "uncertain"},
                ],
            })]),
        ]

        with _patch_provider(turns):
            result = default_trace_dispatch(
                fake_model_config, _sample_traces(), str(repo),
            )
        assert len(result) == 2
        ids = {v["trace_id"] for v in result}
        assert ids == {"EP-001", "EP-002"}

    def test_provider_exception_caught(self, repo, fake_model_config):
        from packages.code_understanding.dispatch.trace_dispatch import (
            default_trace_dispatch,
        )

        class ExplodingProvider(FakeProvider):
            def turn(self, messages, tools, **kwargs):
                raise RuntimeError("boom")

        with patch(
            "packages.code_understanding.dispatch.trace_dispatch.create_provider",
            return_value=ExplodingProvider([]),
        ):
            result = default_trace_dispatch(
                fake_model_config, _sample_traces(), str(repo),
            )
        assert len(result) == 1
        assert "error" in result[0]
        assert "RuntimeError" in result[0]["error"]


class TestDirectCallerValidation:
    """default_trace_dispatch satisfies TraceDispatchFn — direct callers
    bypass trace()'s input validation. Defensive guards return clean
    errors."""

    def test_non_list_traces_returns_error(self, repo, fake_model_config):
        from packages.code_understanding.dispatch.trace_dispatch import (
            default_trace_dispatch,
        )
        # Dict instead of list — would otherwise pass the empty-check
        # and break downstream.
        result = default_trace_dispatch(
            fake_model_config, {"trace_id": "x"}, str(repo),  # type: ignore[arg-type]
        )
        assert len(result) == 1
        assert "error" in result[0]

    def test_missing_repo_path_returns_error(self, fake_model_config, tmp_path):
        from packages.code_understanding.dispatch.trace_dispatch import (
            default_trace_dispatch,
        )
        result = default_trace_dispatch(
            fake_model_config, _sample_traces(), str(tmp_path / "missing"),
        )
        assert len(result) == 1
        assert "error" in result[0]
        assert "invalid repo_path" in result[0]["error"]

    def test_provider_construction_failure_caught(
        self, repo, fake_model_config,
    ):
        from packages.code_understanding.dispatch.trace_dispatch import (
            default_trace_dispatch,
        )
        with patch(
            "packages.code_understanding.dispatch.trace_dispatch.create_provider",
            side_effect=RuntimeError("missing SDK"),
        ):
            result = default_trace_dispatch(
                fake_model_config, _sample_traces(), str(repo),
            )
        assert len(result) == 1
        assert "error" in result[0]
        assert "provider construction" in result[0]["error"]

    def test_trace_without_trace_id_returns_error(
        self, repo, fake_model_config,
    ):
        # Regression: previously trace dicts without trace_id reached
        # the LLM, then verdicts came back, then substrate's
        # TraceAdapter.item_id crashed. Now caught up front.
        from packages.code_understanding.dispatch.trace_dispatch import (
            default_trace_dispatch,
        )
        bad_traces = [{"entry": "X", "sink": "Y"}]  # no trace_id
        result = default_trace_dispatch(
            fake_model_config, bad_traces, str(repo),
        )
        assert len(result) == 1
        assert "error" in result[0]
        assert "trace_id" in result[0]["error"]

    def test_trace_with_non_string_trace_id_returns_error(
        self, repo, fake_model_config,
    ):
        from packages.code_understanding.dispatch.trace_dispatch import (
            default_trace_dispatch,
        )
        bad_traces = [{"trace_id": 42}]
        result = default_trace_dispatch(
            fake_model_config, bad_traces, str(repo),
        )
        assert len(result) == 1
        assert "error" in result[0]

    def test_non_dict_trace_returns_error(self, repo, fake_model_config):
        from packages.code_understanding.dispatch.trace_dispatch import (
            default_trace_dispatch,
        )
        bad_traces = ["not a dict"]
        result = default_trace_dispatch(
            fake_model_config, bad_traces, str(repo),  # type: ignore[arg-type]
        )
        assert len(result) == 1
        assert "error" in result[0]
        assert "must be a dict" in result[0]["error"]

    def test_non_json_serializable_trace_value_caught(
        self, repo, fake_model_config,
    ):
        # If a trace dict contains a non-JSON-native value (e.g. Path),
        # json.dumps raises. Without our wrapper, this propagates as a
        # bare TypeError. Now returns clean error.
        from pathlib import Path

        from packages.code_understanding.dispatch.trace_dispatch import (
            default_trace_dispatch,
        )
        bad_traces = [{
            "trace_id": "EP-001",
            "entry": Path("/some/path"),  # not JSON-native
        }]
        result = default_trace_dispatch(
            fake_model_config, bad_traces, str(repo),
        )
        assert len(result) == 1
        assert "error" in result[0]
        assert "serialize" in result[0]["error"]


# ---------------------------------------------------------------------------
# Sandbox boundary
# ---------------------------------------------------------------------------


class TestSandboxBoundary:
    def test_read_outside_repo_blocked(self, repo):
        from packages.code_understanding.dispatch.trace_dispatch import _build_tools
        from packages.code_understanding.dispatch.tools import SandboxedTools

        tools = _build_tools(SandboxedTools.for_repo(repo))
        read = next(t for t in tools if t.name == "read_file")
        out = json.loads(read.handler({"path": "/etc/passwd"}))
        assert "error" in out
