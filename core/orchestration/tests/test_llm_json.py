"""Unit tests for the shared LLM-JSON helpers.

strip_json_fences replaced seven per-module fence-strip copies whose
edge behavior had drifted (filter-all-fence-lines vs first-block vs
strip-backticks); these tests pin the one shared shape.
"""

from contextlib import contextmanager
import sys

import pytest

from core.orchestration import llm_json
from core.orchestration.llm_json import dict_rows, list_at, strip_json_fences
from core.testing.module_views import module_function_view


class TestStripJsonFences:
    def test_plain_json_passes_through(self):
        assert strip_json_fences('  {"a": 1}\n') == '{"a": 1}'

    def test_language_tagged_fence(self):
        assert strip_json_fences('```json\n{"a": 1}\n```') == '{"a": 1}'

    def test_bare_fence(self):
        assert strip_json_fences('```\n{"a": 1}\n```') == '{"a": 1}'

    def test_multiline_payload_kept(self):
        raw = '```json\n{"a": 1}\n{"b": 2}\n```'
        assert strip_json_fences(raw) == '{"a": 1}\n{"b": 2}'

    def test_unclosed_fence_keeps_rest(self):
        assert strip_json_fences('```json\n{"a": 1}') == '{"a": 1}'

    def test_trailing_prose_after_close_dropped(self):
        raw = '```json\n{"a": 1}\n```\nHope that helps!'
        assert strip_json_fences(raw) == '{"a": 1}'

    def test_mid_text_fence_not_triggered(self):
        # Leading-fence detection only: callers that tolerate prose
        # before the fence slice it off first (core/iris/specs.py) or
        # use core.json.tolerant.parse_llm_json's full ladder.
        raw = 'Here you go:\n```json\n{"a": 1}\n```'
        assert strip_json_fences(raw) == raw.strip()

    def test_empty_and_fence_only(self):
        assert strip_json_fences("") == ""
        assert strip_json_fences("```json\n```") == ""


class TestListAt:
    def test_non_dict_container(self):
        assert list_at(None, "k") == []
        assert list_at(42, "k") == []

    def test_non_list_value(self):
        assert list_at({"k": "scalar"}, "k") == []
        assert list_at({"k": None}, "k") == []

    def test_list_value(self):
        assert list_at({"k": [1, 2]}, "k") == [1, 2]


class TestDictRows:
    def test_non_dict_rows_skipped(self):
        d = {"k": [{"a": 1}, "prose row", None, {"b": 2}]}
        assert dict_rows(d, "k") == [{"a": 1}, {"b": 2}]


@contextmanager
def split_work():
    if sys.getprofile() is not None:
        pytest.skip("profiling hook already owned")
    sizes = []

    def observe(frame, event, arg):
        if event == "c_call" and getattr(arg, "__name__", None) == "splitlines":
            owner = getattr(arg, "__self__", None)
            if type(owner) is str:
                sizes.append(len(owner))

    try:
        sys.setprofile(observe)
        yield sizes
    finally:
        sys.setprofile(None)


@pytest.mark.parametrize("newline", [
    pytest.param("\n", id="lf"), pytest.param("\r\n", id="crlf"),
    pytest.param("\r", id="cr"), pytest.param("\v", id="vt"),
    pytest.param("\x85", id="nel"), pytest.param("\u2028", id="line-separator"),
])
def test_early_close_does_not_split_the_large_tail(newline):
    source = newline.join(["```json", '  {"ok": 1}', "``` trailing text", "tail" * 20000])
    with split_work() as sizes:
        assert strip_json_fences(source) == '{"ok": 1}'
    assert sizes and max(sizes) < len(source)


@pytest.mark.parametrize("closed", [False, True], ids=["open-only", "late-close"])
def test_large_body_keeps_full_fallback_when_prefix_has_no_close(closed):
    body = "body\n" * 16000 + "end"
    source = "```text\n" + body + ("\n```\ntrailing prose" if closed else "")
    assert strip_json_fences(source) == body


@pytest.mark.parametrize("offset", [-4, -3, -2, -1, 0, 1])
def test_closing_marker_across_prefix_edge_keeps_exact_body(offset):
    opening = "```text\n"
    body = "x" * (llm_json._FENCE_PREFIX_CHARS + offset - len(opening) - 1)
    source = opening + body + "\n``` suffix" + "tail" * 20000
    assert strip_json_fences(source) == body


def test_adjacent_close_keeps_an_empty_body_without_splitting_tail():
    source = "```json\n```\n" + "tail" * 20000
    with split_work() as sizes:
        assert strip_json_fences(source) == ""
    assert sizes and max(sizes) < len(source)


def test_large_split_adapter_keeps_its_own_lines():
    seen = []

    class Source(str):
        def strip(self):
            return self

        def splitlines(self):
            seen.append("split")
            return ["```", "adapter body", "```"]

    assert strip_json_fences(Source("```" + "x" * 80000)) == "adapter body"
    assert seen == ["split"]


def test_custom_length_remains_authoritative_for_large_native_fence():
    view = module_function_view(llm_json, bindings={"len": lambda value: 0})
    source = "```json\n{\"ok\": 1}\n```\n" + "tail" * 20000
    assert view.strip_json_fences(source) == ""


def test_custom_range_keeps_the_original_full_fallback():
    view = module_function_view(llm_json, bindings={"range": lambda *args: ()})
    source = "```json\n{\"ok\": 1}\n```\n" + "tail" * 20000
    assert view.strip_json_fences(source) == "\n".join(source.splitlines()[1:]).strip()
