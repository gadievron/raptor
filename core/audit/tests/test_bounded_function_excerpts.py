"""Bounded excerpts preserve source coordinates and each reader's policy."""

from contextlib import ExitStack

import pytest

from core.audit import diagnostics, discovery, edge_review, triage
from core.source import lines as source_lines
import core.source as source_module
import core.audit.context as audit_context
from core.testing.module_views import scoped_function_imports


CONSUMERS = ("diagnostics", "triage", "discovery", "edge")


@pytest.fixture
def excerpt(monkeypatch, tmp_path):
    # diagnostics checks for a regular in-root file before reading it.
    (tmp_path / "app.c").write_text("fixture\n")

    def invoke(consumer, text, span, *, truncated=False, splitter=None, max_tokens=10000):
        start, end = span
        gap = {"file": "app.c", "line_start": start, "line_end": end}
        with ExitStack() as stack:
            scope = stack.enter_context(monkeypatch.context())
            if consumer == "diagnostics":
                imports = stack.enter_context(scoped_function_imports(
                    diagnostics, ("read_function_source",), {"core.source": source_module},
                ))
                local = getattr(imports, "core.source")
                scope.setattr(local, "read_text_capped", lambda *a, **kw: (text, truncated))
                if splitter is not None:
                    scope.setattr(local, "split_lines", splitter)
                return diagnostics.read_function_source(tmp_path, "app.c", "owner", start, end)
            if consumer == "triage":
                scope.setattr(triage, "read_text_capped", lambda *a, **kw: (text, truncated))
                if splitter is not None:
                    scope.setattr(triage, "split_lines", splitter)
                return triage._read_function_source(gap, tmp_path)
            if consumer == "edge":
                imports = stack.enter_context(scoped_function_imports(
                    edge_review, ("_read_span",), {"core.source": source_module},
                ))
                scope.setattr(getattr(imports, "core.source"), "read_text_capped", lambda *a, **kw: (text, truncated))
                if splitter is not None:
                    scope.setattr(edge_review, "split_lines", splitter)
                return edge_review._read_span(tmp_path, "app.c", span)
            imports = stack.enter_context(scoped_function_imports(
                discovery, ("_read_function_source",), {
                    "core.audit.context": audit_context, "core.source.lines": source_lines,
                },
            ))
            scope.setattr(getattr(imports, "core.audit.context"), "_read_target_text", lambda *a, **kw: text)
            if splitter is not None:
                scope.setattr(getattr(imports, "core.source.lines"), "split_lines", splitter)
            return discovery._read_function_source(tmp_path, gap, max_tokens)

    return invoke


@pytest.mark.parametrize("consumer", CONSUMERS)
@pytest.mark.parametrize("separator", [pytest.param("\n", id="lf"), pytest.param("\r\n", id="crlf")])
def test_large_excerpt_keeps_coordinates_and_exotic_bytes(excerpt, consumer, separator):
    rows = ["void owner() {", "  x\v\f\x85\u2028\r = 1;", "}"] + ["// unrelated source"] * 4000
    assert excerpt(consumer, separator.join(rows) + separator, (1, 3)) == "void owner() {\n  x\v\f\x85\u2028\r = 1;\n}"


@pytest.mark.parametrize("consumer", CONSUMERS)
@pytest.mark.parametrize("tail, expected", [
    pytest.param("last\n", "last", id="trailing-lf"),
    pytest.param("last\r\n", "last", id="trailing-crlf"),
    pytest.param("last\n\r", "last", id="final-cr-only-line"),
    pytest.param("last\n\n", "last\n", id="final-blank-line"),
    pytest.param("last\r\r", "last\r", id="trim-one-cr"),
])
def test_final_line_shape_and_out_of_range_span(excerpt, consumer, tail, expected):
    source = "// unrelated\n" * 2000 + tail
    assert excerpt(consumer, source, (2001, 9000)) == expected
    assert excerpt(consumer, source, (9000, 9001)) == ""


@pytest.mark.parametrize("consumer", CONSUMERS)
def test_replaced_splitter_keeps_authority(excerpt, consumer):
    calls = []

    def splitter(text):
        calls.append(text)
        return ["replacement one", "replacement two", "replacement three"]

    source = "unrelated\n" * 4000
    assert excerpt(consumer, source, (2, 3), splitter=splitter) == "replacement two\nreplacement three"
    assert calls == [source]


@pytest.mark.parametrize("consumer", CONSUMERS)
def test_source_subclass_keeps_its_split(excerpt, consumer):
    calls = []

    class Source(str):
        def split(self, sep):
            calls.append(sep)
            return ["adapter one", "adapter two", "adapter three"]

    assert excerpt(consumer, Source("unused\n" * 4000), (2, 3)) == "adapter two\nadapter three"
    assert calls == ["\n"]


def test_reader_truncation_policies_remain_distinct(excerpt):
    source = "head\nbody\npartial"
    assert excerpt("diagnostics", source, (1, 2), truncated=True) == ""
    assert excerpt("edge", source, (1, 2), truncated=True) == "head\nbody"
    assert excerpt("edge", source, (1, 3), truncated=True) == "(source not available)"
    assert excerpt("triage", source, (1, 3), truncated=True) == "head\nbody\npartial"


def test_discovery_retains_centre_truncation(excerpt):
    body = "a" * 200 + "middle" + "z" * 200
    source = body + "\n" + "// unrelated\n" * 2000
    assert excerpt("discovery", source, (1, 1), max_tokens=10) == "a" * 20 + "\n/* ... truncated ... */\n" + "z" * 20


def test_edge_retains_explicit_prompt_cap(excerpt):
    source = "a" * 20000 + "\n" + "// unrelated\n" * 2000
    assert excerpt("edge", source, (1, 1)) == "a" * 16000 + "\n[...truncated for prompt budget]"


def test_real_diagnostic_reader_preserves_raw_cr_and_refuses_escape(tmp_path):
    path = tmp_path / "app.c"
    path.write_bytes(b"head\r\nbody\rinside\r\ntail\r\n" + b"// unrelated\n" * 3000)
    assert diagnostics.read_function_source(tmp_path, "app.c", "owner", 2, 2) == "body\rinside"
    assert diagnostics.read_function_source(tmp_path, "../outside.c", "owner", 2, 2) == ""


@pytest.mark.parametrize("value", [False, True])
def test_custom_truncation_flag_is_evaluated_once(excerpt, value):
    calls = []

    class Flag:
        def __bool__(self):
            calls.append(value)
            return value

    source = "head\nbody\n" + "// unrelated\n" * 4000
    assert excerpt("edge", source, (1, 2), truncated=Flag()) == "head\nbody"
    assert calls == [value]
