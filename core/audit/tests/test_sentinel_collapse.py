"""Tests for core.audit.sentinel_collapse."""

from __future__ import annotations

import pytest
try:
    import tree_sitter  # noqa: F401
    _HAS_TS = True
except ImportError:
    _HAS_TS = False
pytestmark = pytest.mark.skipif(not _HAS_TS, reason="tree-sitter not installed")

from core.audit.sentinel_collapse import detect_sentinel_collapses  # noqa: E402


class TestFalsyCoercion:
    """Sub-detector (a): falsy coercion on Optional."""

    def test_list_cached_if_cached_else_empty(self):
        src = """\
def get_deps(pkg):
    cached = cache.get(pkg)
    return list(cached) if cached else []
"""
        findings = detect_sentinel_collapses({"crates.py": src})
        assert len(findings) == 1
        f = findings[0]
        assert f.file == "crates.py"
        assert f.function == "get_deps"
        assert f.line == 3
        assert "None" in f.write_value
        assert "[]" in f.semantic_loss

    def test_x_or_empty_list(self):
        src = """\
def fetch_items(key):
    result = lookup(key)
    return result or []
"""
        findings = detect_sentinel_collapses({"items.py": src})
        assert len(findings) == 1
        f = findings[0]
        assert f.function == "fetch_items"
        assert "result or []" in f.read_coercion

    def test_x_or_empty_dict(self):
        src = """\
def fetch_scores(key):
    data = lookup(key)
    return data or {}
"""
        findings = detect_sentinel_collapses({"scores.py": src})
        assert len(findings) == 1
        assert "{}" in findings[0].semantic_loss

    def test_x_if_x_else_empty(self):
        src = """\
def get_data(k):
    v = cache.get(k)
    return v if v else []
"""
        findings = detect_sentinel_collapses({"data.py": src})
        assert len(findings) == 1
        assert findings[0].function == "get_data"

    def test_is_not_none_guard_no_detect(self):
        """Correct code using ``if x is not None`` should NOT fire."""
        src = """\
def get_deps(pkg):
    cached = cache.get(pkg)
    if cached is not None:
        return list(cached)
    return []
"""
        findings = detect_sentinel_collapses({"good.py": src})
        assert len(findings) == 0

    def test_different_var_guard_still_detects(self):
        """Guard on a DIFFERENT variable must not suppress the finding."""
        src = """\
def process(config, data):
    if config is not None:
        items = data or []
    return items
"""
        findings = detect_sentinel_collapses({"mixed.py": src})
        assert len(findings) == 1
        assert "data or []" in findings[0].read_coercion


class TestExceptSameAsSuccess:
    """Sub-detector (b): except returning same value as success path."""

    def test_except_returns_empty_dict_like_success(self):
        src = """\
def _fetch_chunk(url):
    try:
        resp = http_get(url)
        if not resp.data:
            return {}
        return resp.data
    except HttpError:
        return {}
"""
        findings = detect_sentinel_collapses({"epss.py": src})
        assert len(findings) == 1
        f = findings[0]
        assert f.function == "_fetch_chunk"
        assert f.confidence == "high"
        assert "error" in f.semantic_loss.lower() or "empty" in f.semantic_loss.lower()

    def test_except_returns_empty_list_like_success(self):
        src = """\
def scan(path):
    try:
        items = do_scan(path)
        if not items:
            return []
        return items
    except ScanError:
        return []
"""
        findings = detect_sentinel_collapses({"scanner.py": src})
        assert len(findings) == 1
        loss = findings[0].semantic_loss.lower()
        assert "error" in loss or "empty" in loss

    def test_except_returns_different_value_no_detect(self):
        src = """\
def _fetch_chunk(url):
    try:
        return http_get(url)
    except HttpError:
        return None
"""
        findings = detect_sentinel_collapses({"ok.py": src})
        assert len(findings) == 0


class TestCacheSentinel:
    """Sub-detector (c): cache write None + read coercion."""

    def test_cache_write_none_read_or(self):
        src = """\
def resolve(key):
    try:
        val = expensive_fetch(key)
    except FetchError:
        _cache[key] = None
        return
    _cache[key] = val
    return val

def consume(key):
    cached = _cache.get(key)
    return cached or []
"""
        findings = detect_sentinel_collapses({"resolver.py": src})
        # The cache-sentinel detector works per-function, so it won't
        # match cross-function cache write+read by design (that requires
        # interprocedural analysis). The falsy-coercion detector fires
        # on the ``cached or []`` line regardless.
        coercion_findings = [
            f for f in findings if f.read_coercion and "or []" in f.read_coercion
        ]
        assert len(coercion_findings) >= 1

    def test_cache_write_none_and_coerce_same_function(self):
        src = """\
def get_or_fetch(key):
    cached = _cache.get(key)
    result = cached or []
    if result:
        return result
    try:
        val = fetch(key)
    except FetchError:
        _cache[key] = None
        return []
    _cache[key] = val
    return val
"""
        findings = detect_sentinel_collapses({"combined.py": src})
        # Both falsy-coercion and cache-sentinel should fire.
        assert len(findings) >= 1
        cache_findings = [
            f for f in findings if "cache" in f.write_value.lower()
        ]
        assert len(cache_findings) == 1

    def test_cache_set_method(self):
        src = """\
def lookup(key):
    try:
        val = fetch(key)
    except FetchError:
        cache.set(key, None)
        return
    cached = cache.get(key)
    result = cached or []
    cache.set(key, val)
    return result
"""
        findings = detect_sentinel_collapses({"method.py": src})
        cache_findings = [
            f for f in findings if "cache" in f.write_value.lower()
        ]
        assert len(cache_findings) == 1


class TestEdgeCases:
    """Boundary conditions and false-positive suppression."""

    def test_empty_source(self):
        findings = detect_sentinel_collapses({"empty.py": ""})
        assert findings == []

    def test_no_functions(self):
        src = "x = val or []\n"
        findings = detect_sentinel_collapses({"toplevel.py": src})
        # Should still detect at module level.
        assert len(findings) == 1
        assert findings[0].function == "<module>"

    def test_multiple_files(self):
        sources = {
            "a.py": "def f():\n    return x or []\n",
            "b.py": "def g():\n    return y or {}\n",
        }
        findings = detect_sentinel_collapses(sources)
        assert len(findings) == 2
        files = {f.file for f in findings}
        assert files == {"a.py", "b.py"}

    def test_findings_sorted_by_file_then_line(self):
        sources = {
            "b.py": "def f():\n    return x or []\n",
            "a.py": "def g():\n    return y or {}\n",
        }
        findings = detect_sentinel_collapses(sources)
        assert findings[0].file == "a.py"
        assert findings[1].file == "b.py"


class TestAsyncDef:
    """Async function definitions are correctly attributed."""

    def test_async_function_detected(self):
        src = """\
async def fetch_items(key):
    result = await lookup(key)
    return result or []
"""
        findings = detect_sentinel_collapses({"async_mod.py": src})
        assert len(findings) == 1
        assert findings[0].function == "fetch_items"


class TestGoSentinel:
    """Sub-detector (d): Go sentinel confusion."""

    def test_nil_on_error_and_not_found(self):
        src = """\
func Lookup(key string) (*Item, error) {
    item, err := db.Get(key)
    if err != nil {
        return nil, err
    }
    if item == nil {
        return nil, nil
    }
    return item, nil
}
"""
        findings = detect_sentinel_collapses({"store.go": src})
        assert len(findings) >= 1
        f = [f for f in findings if f.confidence == "high"]
        assert len(f) >= 1
        assert "nil" in f[0].write_value.lower() or "nil" in f[0].semantic_loss.lower()

    def test_no_double_nil_no_finding(self):
        src = """\
func Lookup(key string) (*Item, error) {
    item, err := db.Get(key)
    if err != nil {
        return nil, err
    }
    return item, nil
}
"""
        findings = detect_sentinel_collapses({"ok.go": src})
        high = [f for f in findings if f.confidence == "high"]
        assert len(high) == 0

    def test_python_not_affected_by_go_detector(self):
        src = """\
def lookup(key):
    return cache.get(key)
"""
        findings = detect_sentinel_collapses({"app.py": src})
        go_findings = [f for f in findings if "nil" in f.write_value.lower()]
        assert len(go_findings) == 0


class TestJsSentinel:
    """Sub-detector (e): JS/TS sentinel confusion."""

    def test_or_empty_array(self):
        src = """\
function getItems(key) {
    const result = cache.get(key);
    return result || [];
}
"""
        findings = detect_sentinel_collapses({"app.js": src})
        assert len(findings) >= 1
        assert findings[0].function == "getItems"

    def test_nullish_coalesce_empty_object(self):
        src = """\
const fetchData = async (url) => {
    const resp = await fetch(url);
    const data = resp.json();
    return data ?? {};
};
"""
        findings = detect_sentinel_collapses({"api.ts": src})
        assert len(findings) >= 1

    def test_guarded_not_null_no_finding(self):
        src = """\
function safe(key) {
    const result = cache.get(key);
    if (result !== null) {
        return result || [];
    }
    return [];
}
"""
        findings = detect_sentinel_collapses({"safe.js": src})
        assert len(findings) == 0


class TestCrossFunctionCollapse:
    """Sub-detector (f): cross-function sentinel collapse."""

    def test_ambiguous_return_with_caller_coercion(self):
        src = """\
def fetch_scores(url):
    try:
        resp = http_get(url)
        if not resp.data:
            return None
        return resp.data
    except HttpError:
        return None

def consume():
    scores = fetch_scores("http://example.com")
    items = scores or []
    return items
"""
        call_graphs = {
            "module.py": {
                "calls": [
                    {"caller": "consume", "chain": ["fetch_scores"]},
                ],
            },
        }
        findings = detect_sentinel_collapses(
            {"module.py": src}, call_graphs=call_graphs,
        )
        cross_findings = [
            f for f in findings if "fetch_scores" in f.semantic_loss
        ]
        assert len(cross_findings) >= 1
        assert cross_findings[0].confidence == "high"

    def test_no_coercion_no_finding(self):
        src = """\
def fetch_scores(url):
    try:
        return http_get(url)
    except HttpError:
        return None

def consume():
    scores = fetch_scores("http://example.com")
    if scores is None:
        return "error"
    return scores
"""
        call_graphs = {
            "module.py": {
                "calls": [
                    {"caller": "consume", "chain": ["fetch_scores"]},
                ],
            },
        }
        findings = detect_sentinel_collapses(
            {"module.py": src}, call_graphs=call_graphs,
        )
        cross_findings = [
            f for f in findings if "cross" in f.semantic_loss.lower()
            or "fetch_scores" in f.semantic_loss
        ]
        assert len(cross_findings) == 0

    def test_no_call_graphs_backward_compat(self):
        src = """\
def f():
    return x or []
"""
        findings_without = detect_sentinel_collapses({"a.py": src})
        findings_with = detect_sentinel_collapses({"a.py": src}, call_graphs={})
        assert len(findings_without) == len(findings_with)
