"""Summary excerpts preserve reader policy, boundaries and provider hooks."""

import builtins

import pytest

from core.audit import llm_summaries as summary
import core.source as source_module
from core.testing.module_views import scoped_function_imports


@pytest.fixture
def read_summary(monkeypatch, tmp_path):
    (tmp_path / "module.py").write_text("fixture\n")

    def read(text, start, end, *, truncated=False):
        with scoped_function_imports(summary, ("_read_source",), {"core.source": source_module}) as imports:
            def capped(path, limit):
                assert limit == 500000
                return text, truncated
            with monkeypatch.context() as scope:
                scope.setattr(getattr(imports, "core.source"), "read_text_capped", capped)
                return summary._read_source(tmp_path, "module.py", "owner", start, end)
    return read


@pytest.mark.parametrize("newline", [pytest.param("\n", id="lf"), pytest.param("\r\n", id="crlf")])
@pytest.mark.parametrize("end", [None, 0, 2])
def test_summary_single_line_default_keeps_source_coordinates(read_summary, newline, end):
    source = newline.join(["first", "  é🙂\v\f\x85\u2028\r value", "third"] + ["padding"] * 4000) + newline
    assert read_summary(source, 2, end) == "  é🙂\v\f\x85\u2028\r value"


@pytest.mark.parametrize("tail,expected", [
    pytest.param("last\n", "last", id="trailing-lf"),
    pytest.param("last\n\r", "last", id="final-cr-only-row"),
    pytest.param("last\n\n", "last\n", id="final-blank-row"),
    pytest.param("last\r\r", "last\r", id="trim-one-cr"),
])
def test_summary_final_line_shape_and_missing_span(read_summary, tail, expected):
    source = "padding\n" * 3000 + tail
    assert read_summary(source, 3001, 9000) == expected
    assert read_summary(source, 9000, 9001) == ""


def test_summary_inverted_span_and_read_truncation_still_refuse(read_summary, caplog):
    source = "padding\n" * 4000
    assert read_summary(source, 3, 1) is None
    assert "inverted span" in caplog.text
    assert read_summary(source, 1, 3, truncated=True) is None
    assert read_summary(source, None, None, truncated=True) is None


def test_summary_without_span_keeps_whole_file(read_summary):
    source = "padding\r\n" * 4000
    assert read_summary(source, None, None) == source


def test_summary_splitter_override_is_authoritative(monkeypatch, read_summary):
    source = "padding\n" * 4000
    calls = []
    def split(text):
        calls.append(text)
        return ["first", "replacement", "third"]
    monkeypatch.setattr(summary, "split_lines", split)
    assert read_summary(source, 2, 2) == "replacement"
    assert calls == [source]


def test_summary_source_adapter_keeps_its_split(read_summary):
    calls = []
    class Source(str):
        def split(self, separator):
            calls.append(separator)
            return ["first", "replacement", "third"]
    assert read_summary(Source("padding\n" * 4000), 2, 2) == "replacement"
    assert calls == ["\n"]


@pytest.mark.parametrize("provider,count", [("len", 1), ("min", 1), ("max", 2)])
def test_summary_numeric_provider_hooks_keep_original_calls(monkeypatch, read_summary, provider, count):
    original = getattr(builtins, provider)
    calls = []
    def observe(*args):
        calls.append(args)
        return original(*args)
    monkeypatch.setattr(summary, provider, observe, raising=False)
    assert read_summary("first\nsecond\n" + "padding\n" * 4000, 1, 2) == "first\nsecond"
    assert len(calls) == count


def test_summary_truncation_flag_is_evaluated_once(read_summary):
    calls = []
    class Flag:
        def __bool__(self):
            calls.append("flag")
            return False
    assert read_summary("first\n" + "padding\n" * 4000, 1, 1, truncated=Flag()) == "first"
    assert calls == ["flag"]
