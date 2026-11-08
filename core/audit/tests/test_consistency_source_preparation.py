"""Consistency preparation avoids unused copies while preserving receipts."""

from contextlib import contextmanager
import sys

import pytest

from core.audit import consistency_dimensions as dim
from core.source.lines import split_lines


EXTRACTORS = (
    ("_arg_sites_for_file", dict), ("_function_spans_for_file", list),
    ("_shape_sites_for_file", dict), ("_call_events_for_file", dict),
)


def source_text(body="int value = 42;\n"):
    return "/*\n" + "padding\v\f\x85\u2028\r text\n" * 2000 + "*/\n" + body


def require_c(source):
    tree, _ = dim.parse_source_cached("app.c", source)
    if tree is None:
        pytest.skip("C grammar unavailable")
    return tree


@contextmanager
def source_splits(source):
    # Observe the real canonical splitter: replacing it would deliberately
    # select adapter behavior. Own the thread-local profiling hook briefly.
    previous = sys.getprofile()
    if previous is not None:
        pytest.skip("profiling hook is already owned")
    calls = []
    code = split_lines.__code__

    def observe(frame, event, arg):
        if event == "call" and frame.f_code is code and frame.f_locals.get("text") is source:
            calls.append(source)

    try:
        sys.setprofile(observe)
        yield calls
    finally:
        sys.setprofile(previous)


@pytest.mark.parametrize("name,factory", EXTRACTORS)
def test_no_retained_sites_need_no_source_splits(name, factory):
    source = source_text()
    require_c(source)
    records = factory()
    with source_splits(source) as calls:
        getattr(dim, name)("app.c", source, records)
    assert records == factory()
    assert calls == []


@pytest.mark.parametrize("name,factory", EXTRACTORS)
def test_retained_sites_share_one_canonical_snapshot(name, factory):
    source = source_text("int owner(void) {\n    use(value);\n    use(value);\n}\n")
    require_c(source)
    records = factory()
    with source_splits(source) as calls:
        getattr(dim, name)("app.c", source, records)
    assert records
    assert calls == [source]


@pytest.mark.parametrize("name,factory", EXTRACTORS)
def test_replaced_splitter_keeps_eager_order(monkeypatch, name, factory):
    source = source_text()
    require_c(source)
    events = []
    original_walk = dim._walk_descendants

    def split(text):
        events.append("split")
        return split_lines(text)

    def walk(node):
        events.append("walk")
        yield from original_walk(node)

    monkeypatch.setattr(dim, "split_lines", split)
    monkeypatch.setattr(dim, "_walk_descendants", walk)
    getattr(dim, name)("app.c", source, factory())
    assert events[:2] == ["split", "walk"]


@pytest.mark.parametrize("name,factory", EXTRACTORS)
def test_source_subclass_keeps_eager_split(monkeypatch, name, factory):
    seen = []

    class Source(str):
        def split(self, separator):
            seen.append(separator)
            return super().split(separator)

    source = Source(source_text())
    require_c(source)
    getattr(dim, name)("app.c", source, factory())
    assert seen == ["\n"]


@pytest.mark.parametrize("name,factory", EXTRACTORS)
def test_snapshot_uses_splitter_captured_before_callbacks(monkeypatch, name, factory):
    source = source_text("int owner(void) {\n    use(value);\n}\n")
    require_c(source)
    original = dim._get_func_name
    replacements = []

    def replacement(text):
        replacements.append(text)
        return ["replacement"]

    def get_name(*args):
        monkeypatch.setattr(dim, "split_lines", replacement)
        return original(*args)

    monkeypatch.setattr(dim, "_get_func_name", get_name)
    records = factory()
    getattr(dim, name)("app.c", source, records)
    assert replacements == []
    if name == "_function_spans_for_file":
        assert "use(value)" in "\n".join(records[0][3])
    else:
        assert all("use(value)" in item.snippet for group in records.values() for item in group)


def test_zero_argument_shape_calls_need_no_snippet():
    source = source_text("int owner(void) {\n    use();\n}\n")
    require_c(source)
    records = {}
    with source_splits(source) as calls:
        dim._shape_sites_for_file("app.c", source, records)
    assert records == {}
    assert calls == []


def test_shape_snapshot_freezes_length_provider_before_argument_callbacks(monkeypatch):
    source = source_text("int owner(void) {\n    use(value);\n}\n")
    tree = require_c(source)
    call = next(n for n in dim._walk_descendants(tree.root_node) if n.type == "call_expression")
    argument = next(n for n in call.child_by_field_name("arguments").children if n.is_named)

    def changed_length(value):
        return 0 if isinstance(value, list) else len(value)

    class Argument:
        @property
        def is_named(self):
            monkeypatch.setattr(dim, "len", changed_length, raising=False)
            return True

        def __getattr__(self, name):
            return getattr(argument, name)

    class Arguments:
        children = [Argument()]

    class Call:
        def child_by_field_name(self, name):
            return Arguments() if name == "arguments" else call.child_by_field_name(name)

        def __getattr__(self, name):
            return getattr(call, name)

    monkeypatch.setattr(dim, "_walk_descendants", lambda root: iter([Call()]))
    records = {}
    dim._shape_sites_for_file("app.c", source, records)
    assert records[("use", 0)][0].snippet == "use(value);"


def events_for_sink(line):
    return {
        ("app.c", f"owner{index}"): [dim._CallEvent(
            "emit", line, False, frozenset(),
            frozenset({"clean"}) if index < 3 else frozenset({"raw"}), "sink evidence",
        )] for index in range(4)
    }


@pytest.mark.parametrize("line,expected", [(2, "é🙂\v value"), (0, None), (99999, None)])
def test_sanitizer_exhibits_use_bounded_windows(monkeypatch, line, expected):
    source = "first\n  é🙂\v value\r\n" + "padding\n" * 4000
    monkeypatch.setattr(dim, "_extract_call_events", lambda source: events_for_sink(line))
    with source_splits(source) as calls:
        result = dim.detect_sanitize_sink_deviations(
            {"app.c": source}, {"emit": {"source": "learned", "cwe": "CWE-89"}}, frozenset({"clean"}),
        )[0]
    assert calls == []
    assert result.n == 4 and result.conforming == 3
    assert [e.snippet for e in result.peer_evidence.exhibits] == [expected or "clean() dominates emit()"] * 3


def test_sanitizer_exhibit_splitter_override_stays_authoritative(monkeypatch):
    seen = []
    def splitter(source):
        seen.append(source)
        return ["first", "replacement"]
    source = "padding\n" * 4000
    monkeypatch.setattr(dim, "split_lines", splitter)
    monkeypatch.setattr(dim, "_extract_call_events", lambda source: events_for_sink(2))
    result = dim.detect_sanitize_sink_deviations(
        {"app.c": source}, {"emit": {"source": "learned"}}, frozenset({"clean"}),
    )[0]
    assert seen == [source]
    assert [e.snippet for e in result.peer_evidence.exhibits] == ["replacement"] * 3


@pytest.mark.parametrize("name,factory", EXTRACTORS)
def test_invalid_splitter_result_is_not_retried(monkeypatch, name, factory):
    source = source_text("int owner(void) {\n    use(value);\n}\n")
    require_c(source)
    calls = []
    def split(text):
        calls.append(text)
        return None
    monkeypatch.setattr(dim, "split_lines", split)
    with pytest.raises(TypeError):
        getattr(dim, name)("app.c", source, factory())
    assert calls == [source]


def test_shape_adapter_snippet_none_is_not_recomputed(monkeypatch):
    source = source_text("int owner(void) {\n    use(first, second);\n}\n")
    require_c(source)
    calls = []
    class Line:
        def strip(self):
            calls.append("strip")
            return self
        def __getitem__(self, key):
            return None
    def split(text):
        return [Line() if "use(" in line else line for line in split_lines(text)]
    monkeypatch.setattr(dim, "split_lines", split)
    records = {}
    dim._shape_sites_for_file("app.c", source, records)
    assert [records[("use", index)][0].snippet for index in range(2)] == [None, None]
    assert calls == ["strip"]
