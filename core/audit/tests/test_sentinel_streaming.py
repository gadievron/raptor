"""Sentinel scans retain guard windows, witness order and provider behavior."""

import weakref

import pytest

from core.audit import sentinel_collapse as sc


SCANS = (sc._detect_falsy_coercion, sc._detect_cache_sentinel, sc._detect_js_sentinel)


@pytest.mark.parametrize("kind", ["python", "javascript"])
@pytest.mark.parametrize("gap, findings", [(2, 0), (3, 1)])
@pytest.mark.parametrize("newline", [pytest.param("\n", id="lf"), pytest.param("\r\n", id="crlf")])
def test_guard_window_includes_exactly_three_preceding_rows(kind, gap, findings, newline):
    prefix = ["// padding " + "x" * 4050]
    if kind == "python":
        rows = ["def owner():", "    if cached is not None:"]
        tail = "    result = cached or []"
        scan = sc._detect_falsy_coercion
    else:
        rows = ["function owner() {", "  if (cached !== null)"]
        tail = "    result = cached || [];"
        scan = sc._detect_js_sentinel
    source_rows = prefix + rows + ["    // padding\v\f\x85\u2028\r"] * gap + [tail]
    results = scan("source.unparsed", newline.join(source_rows) + newline)
    assert len(results) == findings
    if results:
        assert (results[0].function, results[0].line) == ("owner", len(source_rows))


@pytest.mark.parametrize("scan", SCANS, ids=["python", "cache", "javascript"])
def test_source_adapter_keeps_its_split(scan):
    seen = []

    class Source(str):
        def split(self, separator):
            seen.append(separator)
            return ["no finding"]

    assert scan("source.unparsed", Source("ignored")) == []
    assert seen == ["\n"]


@pytest.mark.parametrize("scan", SCANS, ids=["python", "cache", "javascript"])
def test_replaced_splitter_is_authoritative(monkeypatch, scan):
    calls = []

    def split(text):
        calls.append(text)
        return ["unrelated"]

    monkeypatch.setattr(sc, "split_lines", split)
    assert scan("source.unparsed", "anything\n" * 1000) == []
    assert calls == ["anything\n" * 1000]


@pytest.mark.parametrize("scan", [sc._detect_falsy_coercion, sc._detect_js_sentinel], ids=["python", "javascript"])
def test_streamed_guard_window_has_bounded_live_rows(monkeypatch, scan):
    live = weakref.WeakSet()
    counts = []

    class Line(str):
        pass

    def lines(source):
        for index in range(1000):
            line = Line(f"unrelated_{index}")
            live.add(line)
            counts.append(len(live))
            yield line

    monkeypatch.setattr(sc, "iter_source_lines", lines)
    assert scan("source.unparsed", "unused") == []
    assert max(counts) <= 6
    assert len(live) == 0


@pytest.mark.parametrize("binding", ["_FALSY_COERCION_PATTERNS", "_JS_FALSY_COERCION"])
@pytest.mark.parametrize("index", [0, 1, 2])
def test_replaced_pattern_observes_operator_free_rows(monkeypatch, binding, index):
    seen = []
    patterns = list(getattr(sc, binding))
    original = patterns[index]

    class Pattern:
        def search(self, line):
            seen.append(line)
            return original.search(line)

    patterns[index] = Pattern()
    monkeypatch.setattr(sc, binding, patterns)
    scan = sc._detect_falsy_coercion if binding == "_FALSY_COERCION_PATTERNS" else sc._detect_js_sentinel
    assert scan("source.unparsed", "operator_free") == []
    assert seen == ["operator_free"]


@pytest.mark.parametrize("binding", ["_FALSY_COERCION_PATTERNS", "_JS_FALSY_COERCION"])
def test_pattern_collection_adapter_retains_iteration(monkeypatch, binding):
    seen = []

    class Patterns(list):
        def __iter__(self):
            seen.append("iterate")
            return super().__iter__()

    monkeypatch.setattr(sc, binding, Patterns(getattr(sc, binding)))
    scan = sc._detect_falsy_coercion if binding == "_FALSY_COERCION_PATTERNS" else sc._detect_js_sentinel
    assert scan("source.unparsed", "operator_free") == []
    assert seen == ["iterate"]


def test_cache_reports_first_witness_per_function_after_many_coercions():
    source = (
        "def first():\n    cache[key] = None\n    cached or []\n"
        + "    later or {}\n" * 5000
        + "def second():\n    memo[key] = None\n    value or {}\n"
    )
    results = sc._detect_cache_sentinel("app.py", source)
    assert [(r.function, r.line, r.read_coercion) for r in results] == [
        ("first", 3, "cached or []"), ("second", 5006, "value or {}"),
    ]


def test_cache_provider_can_change_next_classifier(monkeypatch):
    writes = sc._CACHE_WRITE_IMPL.search("cache[key] = None")
    read = sc._CACHE_READ_IMPL.search("cached or []")
    seen = []

    class Read:
        def search(self, line):
            seen.append(("read", line))
            return read

    class Write:
        def search(self, line):
            seen.append(("write", line))
            monkeypatch.setattr(sc, "_CACHE_READ_COERCE", Read())
            return writes

    monkeypatch.setattr(sc, "_CACHE_WRITE_NONE", Write())
    results = sc._detect_cache_sentinel("app.py", "plain")
    assert seen == [("write", "plain"), ("read", "plain")]
    assert [(r.line, r.read_coercion) for r in results] == [(1, "cached or []")]


def test_custom_cache_provider_keeps_all_group_calls_after_replacing_itself(monkeypatch):
    calls = []
    original = sc._CACHE_READ_IMPL
    original_header = sc._SENTINEL_PY_DEF_RE

    class Match:
        def __init__(self, match):
            self.match = match

        def __bool__(self):
            # Admission must use the provider that actually made this match.
            monkeypatch.setattr(sc, "_CACHE_READ_COERCE", original)
            return True

        def group(self, index):
            calls.append(self.match.group(index))
            return self.match.group(index)

    class Read:
        def search(self, line):
            match = original.search(line)
            return Match(match) if match else None

    class Header:
        def match(self, line):
            monkeypatch.setattr(sc, "_CACHE_READ_COERCE", Read())
            return original_header.match(line)

    # A fresh provider each row keeps both coercions on the adapter path.
    monkeypatch.setattr(sc, "_SENTINEL_PY_DEF_RE", Header())
    results = sc._detect_cache_sentinel("app.py", "cache[key] = None\ncached or []\nlater or {}")
    assert calls == ["cached or []", "later or {}"]
    assert results[0].read_coercion == "cached or []"


@pytest.mark.parametrize("null", ["None", "none", "NONE", "NoNe"])
def test_cache_prefilter_preserves_case_insensitive_write_matches(null):
    results = sc._detect_cache_sentinel("app.py", f"cache[key] = {null}\ncached or []")
    assert [(r.line, r.read_coercion) for r in results] == [(2, "cached or []")]
