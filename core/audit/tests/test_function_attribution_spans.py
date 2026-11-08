"""Function attribution keeps scope priority without expanding source rows."""

import ast
import builtins
from types import SimpleNamespace

import pytest

from core.audit import fail_open_lang as fol
from core.audit import sentinel_collapse as sc
from core.audit import ts_extract
from core.source.line_index import LineSpanIndex
from core.testing.module_views import module_function_view


@pytest.fixture
def fallback():
    def imports(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 1 and name == "ts_extract":
            return SimpleNamespace(_parse_file=lambda *args: None, _iter_functions=ts_extract._iter_functions)
        return builtins.__import__(name, globals, locals, fromlist, level)
    return module_function_view(sc, import_hook=imports)


def js_view(rows):
    """A private parse-provider view for adapter/error-path contracts."""
    def imports(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 1 and name == "ts_extract":
            return SimpleNamespace(_parse_file=lambda *args: (object(), "javascript", b""), _iter_functions=lambda *args: iter(rows))
        return builtins.__import__(name, globals, locals, fromlist, level)
    return module_function_view(sc, import_hook=imports)


def node(start, end):
    return SimpleNamespace(start_point=(start - 1, 0), end_point=(end - 1, 0))


@pytest.mark.parametrize("header", ["if (enabled)", "for (;;)", "while (enabled)", "switch (value)", "catch (error)", "with (context)"])
def test_js_fallback_keeps_owner_across_control_headers(fallback, header):
    results = fallback._detect_js_sentinel("app.js", f"function owner() {{\n  {header} {{\n    cached || [];\n  }}\n}}\n")
    assert [(r.function, r.line) for r in results] == [("owner", 3)]


def test_js_fallback_checks_coercion_on_control_header_itself(fallback):
    results = fallback._detect_js_sentinel("app.js", "function owner() {\n  if (cached || []) {\n  }\n}\n")
    assert [(r.function, r.line, r.read_coercion) for r in results] == [("owner", 2, "cached || []")]


@pytest.mark.parametrize("header, name", [("method(value)", "method"), ("if: function(value)", "if"), ("catch: function(error)", "catch")])
def test_js_fallback_keeps_unambiguous_method_and_property_names(fallback, header, name):
    results = fallback._detect_js_sentinel("app.js", f"const methods = {{\n  {header} {{\n    cached || [];\n  }}\n}};\n")
    assert [r.function for r in results] == [name]


def test_js_keyword_named_shorthand_uses_parser_attribution():
    source = "class Owner {\n  if(value) {\n    cached || [];\n  }\n}\n"
    if ts_extract._parse_file("app.js", source) is None:
        pytest.skip("JavaScript grammar unavailable")
    assert [r.function for r in sc._detect_js_sentinel("app.js", source)] == ["if"]


def test_js_nested_and_gap_attribution_matches_existing_scan():
    source = "function outer() {\n" + "  value = 42;\n" * 300 + "  function inner() {\n    cached || [];\n  }\n  cached || [];\n}\ncached || [];\n"
    if ts_extract._parse_file("app.js", source) is None:
        pytest.skip("JavaScript grammar unavailable")
    results = sc._detect_js_sentinel("app.js", source)
    assert [(r.function, r.line) for r in results] == [("inner", 303), ("outer", 305), ("outer", 307)]


def test_js_index_queries_only_emitted_findings(monkeypatch):
    view = js_view([(node(1, 50000), "owner", None)])
    calls = []

    class Index(LineSpanIndex):
        def preceding(self, line, default="", **kwargs):
            calls.append(line)
            return super().preceding(line, default, **kwargs)

    monkeypatch.setattr(view, "LineSpanIndex", Index)
    source = "plain\n" * 10000 + "cached || [];\n"
    assert [r.function for r in view._detect_js_sentinel("app.js", source)] == ["owner"]
    assert calls == [10001]


def test_js_custom_range_provider_retains_original_calls(monkeypatch):
    view = js_view([(node(1, 5), "first", None), (node(3, 8), "second", None)])
    calls = []

    def ranges(start, stop):
        calls.append((start, stop))
        return range(start, stop)

    monkeypatch.setattr(view, "range", ranges, raising=False)
    assert [r.function for r in view._detect_js_sentinel("app.js", "cached || []\n")] == ["first"]
    assert calls == [(1, 6), (3, 9)]


def test_js_custom_labels_keep_identity():
    class Label(str):
        pass
    label = Label("custom")
    view = js_view([(node(1, 5), label, None)])
    assert view._detect_js_sentinel("app.js", "cached || []\n")[0].function is label


def test_js_partial_import_failure_keeps_completed_native_spans():
    def rows():
        yield node(1, 500), "owner", None
        raise ImportError("provider stopped")
    view = js_view(rows())
    source = "\n" * 300 + "cached || []\n"
    assert [r.function for r in view._detect_js_sentinel("app.js", source)] == ["owner"]


def test_replaced_js_header_keeps_its_group_calls(monkeypatch, fallback):
    original = sc._JS_FUNC_RE
    calls = []

    class Header:
        def match(self, line):
            match = original.match(line)
            if not match:
                return None
            class Match:
                def group(self, number):
                    calls.append(number)
                    return match.group(number)
            return Match()

    monkeypatch.setattr(fallback, "_JS_FUNC_RE", Header())
    results = fallback._detect_js_sentinel("app.js", "if (enabled) {\n cached || [];\n}")
    assert [r.function for r in results] == ["if"]
    assert calls == [1, 2, 3]


def test_python_compact_and_default_queries_match_for_nested_scopes():
    source = "class Owner:\n    async def outer(self):\n" + "        value = 42\n" * 300 + "        def inner():\n            return 1\n        return inner()\n"
    tree = ast.parse(source)
    original = fol._enclosing_function_names(tree)
    compact = fol._enclosing_function_names(tree, compact=True)
    assert type(original) is dict
    assert isinstance(compact, LineSpanIndex)
    for line in range(1, 310):
        assert compact.get(line, "") == original.get(line, "")


def test_python_handler_uses_qualified_scope_without_expansion():
    source = "class Owner:\n    def run(self):\n" + "        value = 42\n" * 300 + "        try:\n            work()\n        except Exception:\n            pass\n"
    results = fol.python_handlers(source, "app.py")
    assert [(r.enclosing_function, r.line) for r in results] == [("Owner.run", 305)]


def test_replaced_python_name_helper_keeps_original_signature(monkeypatch):
    calls = []
    def names(tree):
        calls.append(tree)
        return {1: "custom"}
    monkeypatch.setattr(fol, "_enclosing_function_names", names)
    results = fol.python_handlers("with contextlib.suppress(Exception):\n    work()\n", "app.py")
    assert len(calls) == 1
    assert results[0].enclosing_function == "custom"


def test_python_custom_range_provider_retains_materialization(monkeypatch):
    calls = []
    def ranges(start, stop):
        calls.append((start, stop))
        return range(start, stop)
    monkeypatch.setattr(fol, "range", ranges, raising=False)
    tree = ast.parse("def owner():\n    pass\n")
    result = fol._enclosing_function_names(tree, compact=True)
    assert result == {1: "owner", 2: "owner"}
    assert calls == [(1, 3)]


@pytest.mark.parametrize("declaration,name", [
    ("method(value)", "method"), ("if(value)", "if"),
    ("#private(value)", "#private"), ("get value()", "value"),
    ("set value(input)", "value"), ("static method(value)", "method"),
])
def test_js_method_names_use_shared_parser_helper(declaration, name):
    source = f"class Owner {{\n  {declaration} {{\n    cached || [];\n  }}\n}}\n"
    parsed = ts_extract._parse_file("app.js", source)
    if parsed is None:
        pytest.skip("JavaScript grammar unavailable")
    tree, lang, src = parsed
    methods = list(ts_extract._iter_functions(tree, lang, src, "app.js"))
    assert [row[1] for row in methods] == [name]
    assert [r.function for r in sc._detect_js_sentinel("app.js", source)] == [name]


def test_computed_js_method_name_remains_unknown():
    source = "class Owner { [chooseName()]() { cached || []; } }"
    parsed = ts_extract._parse_file("app.js", source)
    if parsed is None:
        pytest.skip("JavaScript grammar unavailable")
    tree, lang, src = parsed
    assert [row[1] for row in ts_extract._iter_functions(tree, lang, src, "app.js")] == ["<unknown>"]


def test_js_native_prefix_flushes_before_custom_label():
    class Label(str):
        pass
    label = Label("custom")
    view = js_view([(node(1, 500), "owner", None), (node(2, 3), label, None)])
    source = "plain\ncached || []\n" + "plain\n" * 300
    result = view._detect_js_sentinel("app.js", source)
    assert result[0].function is label


def test_js_range_replacement_only_observes_later_spans(monkeypatch):
    calls = []
    def ranges(start, stop):
        calls.append((start, stop))
        return range(start, stop)
    def rows():
        yield node(1, 500), "owner", None
        monkeypatch.setattr(view, "range", ranges, raising=False)
        yield node(4, 8), "later", None
    view = js_view(rows())
    source = "plain\n" * 300 + "cached || []\n"
    assert [r.function for r in view._detect_js_sentinel("app.js", source)] == ["owner"]
    assert calls == [(4, 9)]


@pytest.mark.parametrize("replace_from_stream", [False, True])
def test_custom_scan_order_retains_per_row_gap_carry(monkeypatch, replace_from_stream):
    view = js_view([(node(300, 700), "owner", None)])
    def enumeration(lines):
        return iter([(399, "cached || []"), (799, "cached || []"), (99, "cached || []")])
    if replace_from_stream:
        def lines(source):
            monkeypatch.setattr(view, "enumerate", enumeration, raising=False)
            return iter(["ignored"])
        monkeypatch.setattr(view, "iter_source_lines", lines)
    else:
        monkeypatch.setattr(view, "enumerate", enumeration, raising=False)
    results = view._detect_js_sentinel("app.js", "plain\n" * 1000)
    assert [(r.function, r.line) for r in results] == [("owner", 400), ("owner", 800), ("owner", 100)]


def test_single_line_sources_do_not_accumulate_span_metadata(monkeypatch):
    view = js_view([(node(1, 1), f"owner{index}", None) for index in range(1000)])
    class Index(LineSpanIndex):
        @staticmethod
        def worthwhile(spans):
            raise AssertionError("single-line attribution must retain direct assignments")
    monkeypatch.setattr(view, "LineSpanIndex", Index)
    assert view._detect_js_sentinel("app.js", "unrelated " * 1000) == []
