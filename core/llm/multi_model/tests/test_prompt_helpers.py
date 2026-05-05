"""Tests for wrap_model_output()."""

import json
import threading

import pytest

from core.llm.multi_model.prompt_helpers import (
    wrap_model_output, _normalize_kind,
)
from core.security.prompt_envelope import UntrustedBlock


class TestWrapModelOutput:
    def test_wraps_string_content(self):
        block = wrap_model_output("verdict text", model_name="claude-opus-4-6")
        assert isinstance(block, UntrustedBlock)
        assert block.content == "verdict text"
        assert block.kind == "MODEL_OUTPUT"
        assert block.origin == "model-output:claude-opus-4-6"

    def test_serializes_dict_content(self):
        block = wrap_model_output(
            {"verdict": "exploitable", "score": 9},
            model_name="gpt-5",
            purpose="analysis",
        )
        # Deterministic ordering via sort_keys
        loaded = json.loads(block.content)
        assert loaded == {"verdict": "exploitable", "score": 9}
        assert "  " in block.content  # indent=2

    def test_serializes_list_content(self):
        block = wrap_model_output(
            [{"id": "a"}, {"id": "b"}],
            model_name="gpt-5",
        )
        assert json.loads(block.content) == [{"id": "a"}, {"id": "b"}]

    def test_serializes_scalars(self):
        for v in [42, 3.14, True, False, None]:
            block = wrap_model_output(v, model_name="m")
            assert json.loads(block.content) == v

    def test_purpose_normalized_to_upper_snake(self):
        block = wrap_model_output("x", model_name="m", purpose="judge-review")
        assert block.kind == "JUDGE_REVIEW"
        # origin keeps the original (human-readable) purpose
        assert block.origin == "judge-review:m"

    def test_purpose_with_spaces_normalized(self):
        block = wrap_model_output("x", model_name="m", purpose="cross family check")
        assert block.kind == "CROSS_FAMILY_CHECK"

    def test_purpose_with_dots_normalized(self):
        block = wrap_model_output("x", model_name="m", purpose="step.A.verdict")
        assert block.kind == "STEP_A_VERDICT"

    def test_purpose_already_upper_snake(self):
        block = wrap_model_output("x", model_name="m", purpose="MODEL_OUTPUT")
        assert block.kind == "MODEL_OUTPUT"

    def test_invalid_purpose_raises(self):
        with pytest.raises(ValueError, match="cannot be normalized"):
            wrap_model_output("x", model_name="m", purpose="bad@chars")

    def test_empty_purpose_raises(self):
        with pytest.raises(ValueError, match="non-empty"):
            wrap_model_output("x", model_name="m", purpose="")

    def test_empty_model_name_raises(self):
        with pytest.raises(ValueError, match="non-empty"):
            wrap_model_output("x", model_name="")

    def test_non_string_model_name_raises(self):
        with pytest.raises(ValueError, match="non-empty"):
            wrap_model_output("x", model_name=None)  # type: ignore[arg-type]

    def test_unsupported_content_type_raises(self):
        # Sets aren't JSON-serializable and not in the allowed type list.
        with pytest.raises(TypeError, match="Pre-serialize"):
            wrap_model_output({"a", "b"}, model_name="m")  # type: ignore[arg-type]

    def test_dict_with_non_json_value_raises(self):
        # Outer type passes (dict), but inner value (Path) is not JSON-native.
        # Strict mode rejects rather than silently str()-coercing.
        from pathlib import Path
        with pytest.raises(TypeError, match="Pre-serialize"):
            wrap_model_output({"file": Path("/x")}, model_name="m")

    def test_dict_with_datetime_value_raises(self):
        from datetime import datetime
        with pytest.raises(TypeError, match="Pre-serialize"):
            wrap_model_output({"ts": datetime(2026, 1, 1)}, model_name="m")

    def test_circular_dict_raises_cleanly(self):
        # json.dumps raises ValueError on circular refs; we wrap as TypeError
        # so consumers have one error class to catch.
        d: dict = {}
        d["self"] = d
        with pytest.raises(TypeError, match="Pre-serialize"):
            wrap_model_output(d, model_name="m")

    def test_unicode_in_purpose_raises(self):
        # Unicode letters survive uppercasing as still-unicode and fail the
        # ASCII-only [A-Z_]+ check. Tests the distinct unicode rejection
        # path separately from the general special-char rejection.
        with pytest.raises(ValueError, match="cannot be normalized"):
            wrap_model_output("x", model_name="m", purpose="café-review")

    def test_multiline_content_preserved(self):
        # Real model output is multi-line; should pass through unchanged.
        block = wrap_model_output("line one\nline two\n  indented", model_name="m")
        assert block.content == "line one\nline two\n  indented"

    def test_model_name_with_hyphens_and_dots(self):
        # Real names contain hyphens and dots; both should pass through to
        # origin without complaint (they get XML-escaped downstream).
        block = wrap_model_output("x", model_name="claude-opus-4.6")
        assert block.origin == "model-output:claude-opus-4.6"

    def test_block_is_frozen(self):
        block = wrap_model_output("x", model_name="m")
        with pytest.raises(Exception):  # FrozenInstanceError from dataclass
            block.content = "mutated"  # type: ignore[misc]

    def test_thread_safe_under_concurrent_calls(self):
        # Helper has no shared state; sanity check it doesn't blow up
        # when called from many threads at once. Use letters-only purposes
        # to satisfy the kind constraint; differentiate via content/model.
        results = []
        lock = threading.Lock()

        def worker(i):
            block = wrap_model_output(
                {"index": i}, model_name=f"model-{chr(ord('a') + i % 26)}",
                purpose="analysis",
            )
            with lock:
                results.append(block)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(results) == 50
        # All have correct shape; content differentiates them
        assert all(b.kind == "ANALYSIS" for b in results)
        assert len({b.content for b in results}) == 50


class TestNormalizeKind:
    def test_lowercase_word(self):
        assert _normalize_kind("analysis") == "ANALYSIS"

    def test_kebab_case(self):
        assert _normalize_kind("judge-review") == "JUDGE_REVIEW"

    def test_collapses_runs_of_separators(self):
        assert _normalize_kind("a---b") == "A_B"
        assert _normalize_kind("a   b") == "A_B"
        assert _normalize_kind("a-.b") == "A_B"

    def test_already_normalized(self):
        assert _normalize_kind("ALREADY_GOOD") == "ALREADY_GOOD"

    def test_rejects_digits(self):
        with pytest.raises(ValueError):
            _normalize_kind("step1")

    def test_rejects_special_chars(self):
        with pytest.raises(ValueError):
            _normalize_kind("a@b")

    def test_rejects_empty(self):
        with pytest.raises(ValueError, match="non-empty"):
            _normalize_kind("")
