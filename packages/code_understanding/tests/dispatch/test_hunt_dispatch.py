"""Tests for default_hunt_dispatch — verifies dispatch wiring without
calling a real LLM.

Strategy: monkeypatch ``create_provider`` to return a fake provider
whose ``turn()`` returns canned :class:`TurnResponse` objects. Each
test scripts a sequence of turns to exercise specific code paths.
"""

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
# Fake provider: scripts a sequence of TurnResponse values.
# ---------------------------------------------------------------------------


@dataclass
class FakeTurn:
    """One turn the fake provider will return.

    text: optional text block content.
    tool_calls: list of (name, input_dict) — given ids automatically.
    stop: stop reason. NEEDS_TOOL_CALL if any tool_calls else COMPLETE.
    """
    text: str = ""
    tool_calls: list = None
    stop: StopReason | None = None


class FakeProvider:
    """LLMProvider stub that returns scripted turns."""

    def __init__(self, turns: list[FakeTurn]):
        self._iter: Iterator[FakeTurn] = iter(turns)
        self._call_count = 0

    def supports_tool_use(self) -> bool:
        return True

    def supports_prompt_caching(self) -> bool:
        return False

    def estimate_tokens(self, text: str) -> int:
        # Coarse approximation; loop uses this for context-overflow gate.
        return max(1, len(text) // 4)

    def context_window(self) -> int:
        return 200_000

    def compute_cost(self, response: TurnResponse) -> float:
        # zero cost in tests so cost-cap never trips
        return 0.0

    def turn(self, messages, tools, **kwargs) -> TurnResponse:
        try:
            t = next(self._iter)
        except StopIteration:
            # Loop kept calling beyond scripted turns — surface as a
            # text-COMPLETE so the loop terminates with "complete".
            return TurnResponse(
                content=[TextBlock("[end of script]")],
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

        stop = t.stop
        if stop is None:
            stop = (
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
    """Small fixture repo for tests that exercise tool calls."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "x.c").write_text(
        "void f(char* p) { strcpy(buf, p); }\n"
    )
    return tmp_path


@pytest.fixture
def fake_model_config():
    """Stand-in ModelConfig — content doesn't matter since we mock create_provider."""
    return ModelConfig(
        provider="anthropic",
        model_name="fake-model-x",
        api_key="test",
    )


def _patch_provider(turns: list[FakeTurn]):
    """Returns a patcher that replaces create_provider with FakeProvider(turns)."""
    fake = FakeProvider(turns)
    return patch(
        "packages.code_understanding.dispatch.hunt_dispatch.create_provider",
        return_value=fake,
    )


# ---------------------------------------------------------------------------
# Happy path: model calls tools, then submits variants.
# ---------------------------------------------------------------------------


class TestHappyPath:
    def test_model_submits_variants_directly(self, repo, fake_model_config):
        """Simplest case: model emits submit_variants on the first turn."""
        from packages.code_understanding.dispatch.hunt_dispatch import (
            default_hunt_dispatch,
        )

        variants_payload = [
            {"file": "src/x.c", "line": 1, "function": "f",
             "snippet": "strcpy(buf, p)", "confidence": "high"},
        ]
        turns = [
            FakeTurn(tool_calls=[("submit_variants", {"variants": variants_payload})]),
        ]

        with _patch_provider(turns):
            result = default_hunt_dispatch(
                fake_model_config, "strcpy misuse", str(repo),
            )
        assert result == variants_payload

    def test_model_uses_grep_then_submits(self, repo, fake_model_config):
        """Multi-turn: model greps first, then submits."""
        from packages.code_understanding.dispatch.hunt_dispatch import (
            default_hunt_dispatch,
        )

        turns = [
            # Turn 1: model calls grep
            FakeTurn(tool_calls=[("grep", {"pattern": "strcpy"})]),
            # Turn 2: model receives results, calls submit_variants
            FakeTurn(tool_calls=[("submit_variants", {
                "variants": [
                    {"file": "src/x.c", "line": 1, "function": "f",
                     "confidence": "high"},
                ],
            })]),
        ]

        with _patch_provider(turns):
            result = default_hunt_dispatch(
                fake_model_config, "strcpy", str(repo),
            )
        assert len(result) == 1
        assert result[0]["file"] == "src/x.c"

    def test_empty_variants_list_is_valid(self, repo, fake_model_config):
        """Model finds nothing — empty list is the right answer."""
        from packages.code_understanding.dispatch.hunt_dispatch import (
            default_hunt_dispatch,
        )

        turns = [
            FakeTurn(tool_calls=[("submit_variants", {"variants": []})]),
        ]

        with _patch_provider(turns):
            result = default_hunt_dispatch(
                fake_model_config, "anything", str(repo),
            )
        assert result == []


# ---------------------------------------------------------------------------
# Tool wiring: handlers correctly delegate to SandboxedTools
# ---------------------------------------------------------------------------


class TestToolWiring:
    def test_read_file_handler_returns_real_content(self, repo, fake_model_config):
        """The model's read_file call should hit SandboxedTools and read x.c."""
        from packages.code_understanding.dispatch.hunt_dispatch import (
            default_hunt_dispatch,
        )

        turns = [
            FakeTurn(tool_calls=[("read_file", {"path": "src/x.c"})]),
            FakeTurn(tool_calls=[("submit_variants", {"variants": []})]),
        ]
        fake = FakeProvider(turns)
        with patch(
            "packages.code_understanding.dispatch.hunt_dispatch.create_provider",
            return_value=fake,
        ):
            default_hunt_dispatch(fake_model_config, "any", str(repo))

        # We can't easily inspect what the handler returned to the model,
        # but we can re-invoke the handler shape via building tools:
        from packages.code_understanding.dispatch.hunt_dispatch import _build_tools
        from packages.code_understanding.dispatch.tools import SandboxedTools
        tools = _build_tools(SandboxedTools.for_repo(repo))
        read_tool = next(t for t in tools if t.name == "read_file")
        out = json.loads(read_tool.handler({"path": "src/x.c"}))
        assert "strcpy" in out["content"]

    def test_grep_handler_finds_matches(self, repo):
        from packages.code_understanding.dispatch.hunt_dispatch import _build_tools
        from packages.code_understanding.dispatch.tools import SandboxedTools

        tools = _build_tools(SandboxedTools.for_repo(repo))
        grep_tool = next(t for t in tools if t.name == "grep")
        out = json.loads(grep_tool.handler({"pattern": "strcpy"}))
        assert len(out["matches"]) >= 1

    def test_glob_handler_lists_files(self, repo):
        from packages.code_understanding.dispatch.hunt_dispatch import _build_tools
        from packages.code_understanding.dispatch.tools import SandboxedTools

        tools = _build_tools(SandboxedTools.for_repo(repo))
        glob_tool = next(t for t in tools if t.name == "glob_files")
        out = json.loads(glob_tool.handler({"pattern": "src/*.c"}))
        assert out["matches"] == ["src/x.c"]

    def test_submit_variants_handler_returns_ack(self, repo):
        from packages.code_understanding.dispatch.hunt_dispatch import _build_tools
        from packages.code_understanding.dispatch.tools import SandboxedTools

        tools = _build_tools(SandboxedTools.for_repo(repo))
        sub = next(t for t in tools if t.name == "submit_variants")
        out = json.loads(sub.handler({"variants": []}))
        assert out == {"received": True}

    def test_all_four_tools_present(self, repo):
        from packages.code_understanding.dispatch.hunt_dispatch import _build_tools
        from packages.code_understanding.dispatch.tools import SandboxedTools

        tools = _build_tools(SandboxedTools.for_repo(repo))
        names = sorted(t.name for t in tools)
        assert names == ["glob_files", "grep", "read_file", "submit_variants"]


# ---------------------------------------------------------------------------
# Error paths: malformed terminal payload, premature termination, exceptions
# ---------------------------------------------------------------------------


class TestErrorPaths:
    def test_loop_terminates_without_submit_returns_error(
        self, repo, fake_model_config,
    ):
        """Model finishes (e.g., max_iterations) without calling submit_variants."""
        from packages.code_understanding.dispatch.hunt_dispatch import (
            default_hunt_dispatch,
        )

        # Model gives up — final turn is text-only, COMPLETE
        turns = [
            FakeTurn(text="I'm not sure how to find variants.",
                     stop=StopReason.COMPLETE),
        ]

        with _patch_provider(turns):
            result = default_hunt_dispatch(
                fake_model_config, "any", str(repo),
            )
        assert len(result) == 1
        assert "error" in result[0]
        assert "submit_variants" in result[0]["error"]

    def test_submit_with_missing_variants_key_returns_error(
        self, repo, fake_model_config,
    ):
        """submit_variants payload missing the variants list."""
        from packages.code_understanding.dispatch.hunt_dispatch import (
            default_hunt_dispatch,
        )

        turns = [
            FakeTurn(tool_calls=[("submit_variants", {"oops": "wrong"})]),
        ]

        with _patch_provider(turns):
            result = default_hunt_dispatch(
                fake_model_config, "any", str(repo),
            )
        assert len(result) == 1
        assert "error" in result[0]

    def test_submit_with_non_list_variants_returns_error(
        self, repo, fake_model_config,
    ):
        from packages.code_understanding.dispatch.hunt_dispatch import (
            default_hunt_dispatch,
        )

        turns = [
            FakeTurn(tool_calls=[("submit_variants", {"variants": "not a list"})]),
        ]

        with _patch_provider(turns):
            result = default_hunt_dispatch(
                fake_model_config, "any", str(repo),
            )
        assert len(result) == 1
        assert "error" in result[0]

    def test_non_dict_variants_filtered_out(self, repo, fake_model_config):
        """Stray non-dict items in the variants list are dropped."""
        from packages.code_understanding.dispatch.hunt_dispatch import (
            default_hunt_dispatch,
        )

        turns = [
            FakeTurn(tool_calls=[("submit_variants", {
                "variants": [
                    {"file": "x.c", "line": 1},  # valid
                    "garbage",                    # filtered
                    None,                         # filtered
                    {"file": "y.c", "line": 2},  # valid
                ],
            })]),
        ]

        with _patch_provider(turns):
            result = default_hunt_dispatch(
                fake_model_config, "any", str(repo),
            )
        assert len(result) == 2
        files = {v["file"] for v in result}
        assert files == {"x.c", "y.c"}

    def test_variants_missing_required_fields_filtered(
        self, repo, fake_model_config,
    ):
        """Variants without file/line are dropped to prevent phantom items
        polluting the substrate's correlation."""
        from packages.code_understanding.dispatch.hunt_dispatch import (
            default_hunt_dispatch,
        )

        turns = [
            FakeTurn(tool_calls=[("submit_variants", {
                "variants": [
                    {"file": "x.c", "line": 1},   # valid
                    {"file": "y.c"},               # missing line — filtered
                    {"line": 5},                   # missing file — filtered
                    {"file": "", "line": 1},      # empty file — filtered
                    {"file": "z.c", "line": None},  # None line — filtered
                    {"file": "ok.c", "line": 10}, # valid
                ],
            })]),
        ]

        with _patch_provider(turns):
            result = default_hunt_dispatch(
                fake_model_config, "any", str(repo),
            )
        assert len(result) == 2
        files = {v["file"] for v in result}
        assert files == {"x.c", "ok.c"}

    def test_provider_exception_caught(self, repo, fake_model_config):
        """If the provider itself raises (e.g. transport error), surface as error entry."""
        from packages.code_understanding.dispatch.hunt_dispatch import (
            default_hunt_dispatch,
        )

        class ExplodingProvider(FakeProvider):
            def turn(self, messages, tools, **kwargs):
                raise RuntimeError("transport boom")

        with patch(
            "packages.code_understanding.dispatch.hunt_dispatch.create_provider",
            return_value=ExplodingProvider([]),
        ):
            result = default_hunt_dispatch(
                fake_model_config, "any", str(repo),
            )
        assert len(result) == 1
        assert "error" in result[0]
        assert "RuntimeError" in result[0]["error"]


class TestDirectCallerValidation:
    """default_hunt_dispatch satisfies HuntDispatchFn — direct callers
    bypass hunt()'s input validation. Defensive guards inside the
    function ensure they get clean errors instead of confusing
    downstream crashes."""

    def test_empty_pattern_returns_error(self, repo, fake_model_config):
        from packages.code_understanding.dispatch.hunt_dispatch import (
            default_hunt_dispatch,
        )
        result = default_hunt_dispatch(fake_model_config, "", str(repo))
        assert len(result) == 1
        assert "error" in result[0]

    def test_whitespace_pattern_returns_error(self, repo, fake_model_config):
        from packages.code_understanding.dispatch.hunt_dispatch import (
            default_hunt_dispatch,
        )
        result = default_hunt_dispatch(fake_model_config, "   ", str(repo))
        assert len(result) == 1
        assert "error" in result[0]

    def test_non_string_pattern_returns_error(self, repo, fake_model_config):
        from packages.code_understanding.dispatch.hunt_dispatch import (
            default_hunt_dispatch,
        )
        result = default_hunt_dispatch(fake_model_config, None, str(repo))  # type: ignore[arg-type]
        assert len(result) == 1
        assert "error" in result[0]

    def test_missing_repo_path_returns_error(self, fake_model_config, tmp_path):
        from packages.code_understanding.dispatch.hunt_dispatch import (
            default_hunt_dispatch,
        )
        result = default_hunt_dispatch(
            fake_model_config, "anything", str(tmp_path / "does-not-exist"),
        )
        assert len(result) == 1
        assert "error" in result[0]
        assert "invalid repo_path" in result[0]["error"]

    def test_repo_path_is_file_returns_error(
        self, fake_model_config, tmp_path,
    ):
        from packages.code_understanding.dispatch.hunt_dispatch import (
            default_hunt_dispatch,
        )
        f = tmp_path / "afile.txt"
        f.write_text("x")
        result = default_hunt_dispatch(fake_model_config, "any", str(f))
        assert len(result) == 1
        assert "error" in result[0]

    def test_provider_construction_failure_caught(
        self, repo, fake_model_config,
    ):
        from packages.code_understanding.dispatch.hunt_dispatch import (
            default_hunt_dispatch,
        )

        with patch(
            "packages.code_understanding.dispatch.hunt_dispatch.create_provider",
            side_effect=RuntimeError("missing SDK"),
        ):
            result = default_hunt_dispatch(
                fake_model_config, "any", str(repo),
            )
        assert len(result) == 1
        assert "error" in result[0]
        assert "provider construction" in result[0]["error"]

    def test_pattern_stripped_before_user_message(self, repo, fake_model_config):
        # Regression: previously default_hunt_dispatch validated pattern.strip()
        # but passed unstripped pattern through to _format_user_message.
        # Direct callers (bypassing the orchestrator's strip) now get the
        # same canonicalisation behaviour as via the orchestrator.
        from packages.code_understanding.dispatch.hunt_dispatch import (
            _format_user_message,
            default_hunt_dispatch,
        )
        # Capture the user message by patching _format_user_message
        captured = {}
        original = _format_user_message

        def _capture(p):
            captured["pattern"] = p
            return original(p)

        # Run a happy-path-shaped script; we just need the dispatch to
        # hit _format_user_message before terminating.
        turns = [
            FakeTurn(tool_calls=[("submit_variants", {"variants": []})]),
        ]
        with _patch_provider(turns), patch(
            "packages.code_understanding.dispatch.hunt_dispatch._format_user_message",
            side_effect=_capture,
        ):
            default_hunt_dispatch(
                fake_model_config, "  strcpy_misuse  ", str(repo),
            )
        assert captured["pattern"] == "strcpy_misuse"


# ---------------------------------------------------------------------------
# Sandbox boundary: tool handlers respect the path traversal constraint
# even when called via the dispatch path.
# ---------------------------------------------------------------------------


class TestSandboxBoundary:
    def test_read_outside_repo_blocked_via_dispatch(self, repo, fake_model_config):
        """Model trying to read /etc/passwd through the loop should get a
        sandbox error in the tool result, not the file content."""
        from packages.code_understanding.dispatch.hunt_dispatch import _build_tools
        from packages.code_understanding.dispatch.tools import SandboxedTools

        tools = _build_tools(SandboxedTools.for_repo(repo))
        read_tool = next(t for t in tools if t.name == "read_file")
        # Direct handler invocation — the model would receive this string
        out = json.loads(read_tool.handler({"path": "/etc/passwd"}))
        assert "error" in out

    def test_traversal_outside_repo_blocked(self, repo):
        from packages.code_understanding.dispatch.hunt_dispatch import _build_tools
        from packages.code_understanding.dispatch.tools import SandboxedTools

        tools = _build_tools(SandboxedTools.for_repo(repo))
        read_tool = next(t for t in tools if t.name == "read_file")
        out = json.loads(read_tool.handler({"path": "../../etc/passwd"}))
        assert "error" in out
