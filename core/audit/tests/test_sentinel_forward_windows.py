"""Forward sentinel windows preserve source rows, first witnesses and adapters."""

import builtins
import weakref
from types import SimpleNamespace

import pytest

from core.audit import sentinel_collapse as sc
from core.source.lines import split_lines
from core.testing.module_views import module_function_view


def go_view(*, returns=(), bindings=None):
    def import_local(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "ts_extract" and level == 1:
            return SimpleNamespace(extract_function_returns=lambda path, source: returns)
        return builtins.__import__(name, globals, locals, fromlist, level)

    return module_function_view(sc, bindings=bindings, import_hook=import_local)


@pytest.mark.parametrize("gap", range(6))
@pytest.mark.parametrize("newline", [pytest.param("\n", id="lf"), pytest.param("\r\n", id="crlf")])
@pytest.mark.parametrize("trailing", [False, True], ids=["eof", "trailing-lf"])
def test_python_forward_window_boundary(gap, newline, trailing):
    rows = ["def owner():", "    value = fetch()"] + ["    # padding\v\f\x85\u2028\r"] * gap
    rows.append("    return value or []")
    source = newline.join(rows) + (newline if trailing else "")
    assert sc._find_coercion_of_call(source, "owner", "fetch") == (gap + 3 if gap < 4 else None)


@pytest.mark.parametrize("gap", range(6))
@pytest.mark.parametrize("newline", [pytest.param("\n", id="lf"), pytest.param("\r\n", id="crlf")])
def test_go_forward_window_boundary(gap, newline):
    rows = ["func owner() {", "    value := cache[key]"] + ["    // padding\v\u2028\r"] * gap
    rows.append("    if value == nil { value = fallback }")
    results = go_view()._detect_go_sentinel("owner.go", newline.join(rows))
    assert [(r.function, r.line) for r in results] == ([("owner", 2)] if gap < 4 else [])


def test_python_keeps_call_order_before_coercion_order_and_crosses_headers():
    # The first assignment's four following rows include a later function
    # header; the lookup intentionally retains that existing text behavior.
    source = "def owner():\n    first = fetch()\n    second = fetch()\ndef next():\n    second or []\n    first or {}"
    assert sc._find_coercion_of_call(source, "owner", "fetch") == 6


@pytest.mark.parametrize("kind", ["python", "go"])
def test_custom_splitter_stays_authoritative(kind):
    seen = []

    def split(source):
        seen.append(source)
        return ["def owner():", "    value = fetch()", "    value or []"] if kind == "python" else [
            "func owner() {", "    value := cache[key]", "    if value == nil { value = fallback }",
        ]

    view = go_view(bindings={"split_lines": split})
    result = (view._find_coercion_of_call("unused", "owner", "fetch") if kind == "python"
              else view._detect_go_sentinel("owner.go", "unused"))
    assert (result == 3 if kind == "python" else len(result) == 1)
    assert seen == ["unused"]


@pytest.mark.parametrize("kind", ["python", "go"])
def test_source_subclass_keeps_its_split(kind):
    seen = []

    class Source(str):
        def split(self, separator):
            seen.append(separator)
            return ["unrelated"]

    view = go_view()
    if kind == "python":
        assert view._find_coercion_of_call(Source("unused"), "owner", "fetch") is None
    else:
        assert view._detect_go_sentinel("owner.go", Source("unused")) == []
    assert seen == ["\n"]


def test_go_parser_fallback_retains_complete_bodies_and_result_order():
    source = "func owner() {\n value := cache[key]\n if value == nil { value = fallback }\n if err != nil { return nil }\n return nil, nil\n}"
    results = go_view(returns=None)._detect_go_sentinel("owner.go", source)
    assert [(r.function, r.line, r.confidence) for r in results] == [
        ("owner", 2, "medium"), ("owner", 1, "high"),
    ]


@pytest.mark.parametrize("kind", ["python", "go"])
def test_forward_scans_retain_bounded_live_rows(kind):
    live = weakref.WeakSet()
    high_water = []

    class Line(str):
        pass

    def rows(source):
        for index in range(1000):
            line = Line(f"unrelated_{index}")
            live.add(line)
            high_water.append(len(live))
            yield line

    view = go_view(bindings={"iter_source_lines": rows})
    if kind == "python":
        assert view._find_coercion_of_call("owner fetch", "owner", "fetch") is None
    else:
        assert view._detect_go_sentinel("owner.go", "[nil") == []
    assert max(high_water) <= 8
    assert len(live) == 0


@pytest.mark.parametrize("kind", ["python", "go"])
def test_overlapping_windows_match_eager_path(kind):
    source = ("def owner():\n" + "    value = fetch()\n" * 20 + "    value or []\n" if kind == "python" else
              "func owner() {\n" + " value := cache[key]\n" * 20 + " if value == nil { value = fallback }\n}")
    streamed = go_view()
    eager = go_view(bindings={"split_lines": lambda text: split_lines(text)})
    if kind == "python":
        assert streamed._find_coercion_of_call(source, "owner", "fetch") == eager._find_coercion_of_call(source, "owner", "fetch")
    else:
        assert streamed._detect_go_sentinel("owner.go", source) == eager._detect_go_sentinel("owner.go", source)


@pytest.mark.parametrize("kind", ["python", "go"])
def test_no_candidate_does_not_prepare_forward_context(kind):
    def unwanted(*args):
        pytest.fail("forward context prepared without a candidate")

    view = go_view(bindings={"_forward_window": unwanted})
    source = "# unrelated\n" * 1000
    if kind == "python":
        assert view._find_coercion_of_call(source, "owner", "fetch") is None
    else:
        assert view._detect_go_sentinel("owner.go", source) == []


def test_python_first_witness_consumes_only_bounded_prefix():
    seen = []

    def rows(source):
        for line in ["def owner():", " value = fetch()", " value or []"] + ["# padding"] * 1000:
            seen.append(line)
            yield line

    view = module_function_view(sc, bindings={"iter_source_lines": rows})
    assert view._find_coercion_of_call("owner fetch", "owner", "fetch") == 3
    assert len(seen) == 6


@pytest.mark.parametrize("binding", ["len", "min", "range", "enumerate"])
def test_python_custom_iteration_operations_keep_eager_sequence(binding):
    source = "def owner():\n value = fetch()\n value or []"
    original = getattr(builtins, binding)

    def exercise(view):
        calls = []

        def operation(*args):
            calls.append(args)
            return original(*args)

        vars(view)[binding] = operation
        assert view._find_coercion_of_call(source, "owner", "fetch") == 3
        return calls

    native = module_function_view(sc)
    eager = module_function_view(sc, bindings={"split_lines": lambda text: split_lines(text)})
    assert exercise(native) == exercise(eager)


def test_custom_header_can_replace_window_length_operation():
    source = "def owner():\n value = fetch()\n value or []"
    seen = []
    view = module_function_view(sc)

    def length(value):
        seen.append(value)
        return len(value)

    class Header:
        def match(self, line):
            vars(view)["len"] = length
            return sc._SENTINEL_PY_INDENT_DEF_RE.match(line)

    vars(view)["_SENTINEL_PY_INDENT_DEF_RE"] = Header()
    assert view._find_coercion_of_call(source, "owner", "fetch") == 3
    assert seen == ["", split_lines(source)]


@pytest.mark.parametrize("kind,source", [
    pytest.param("python", "def owner():\n value = other()", id="missing-callee"),
    pytest.param("python", "def other():\n value = fetch()\n value or []", id="missing-caller"),
    pytest.param("go", "func owner() { return nil }", id="missing-map"),
    pytest.param("go", "func owner() { value := cache[key] }", id="missing-nil"),
])
def test_native_negative_probes_avoid_line_preparation(kind, source):
    def unwanted(source):
        pytest.fail("lines prepared despite missing required literal")

    view = go_view(bindings={"iter_source_lines": unwanted})
    if kind == "python":
        assert view._find_coercion_of_call(source, "owner", "fetch") is None
    else:
        assert view._detect_go_sentinel("owner.go", source) == []


def test_go_negative_probe_preserves_parser_findings():
    fact = SimpleNamespace(function="owner", returns=[SimpleNamespace(line=9)], sentinel_ambiguous=True)
    results = go_view(returns=[fact])._detect_go_sentinel("owner.go", "func owner() {}")
    assert [(r.function, r.line, r.confidence) for r in results] == [("owner", 9, "high")]
