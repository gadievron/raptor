"""Lock receipts use LF coordinates and prepare only one function's rows."""

from functools import lru_cache
from pathlib import Path

import pytest

from core.audit import lock_region as lr
from core.audit.field_census import FunctionSpan
from core.audit.tests.test_lock_region import SSL_SESS, SSL_SESS_UNLOCK_FIRST, HYP, _Vocab
from core.source.lines import split_lines
from core.testing import requires_ts
from core.testing.module_views import module_function_view


@pytest.fixture
def owned_caches(monkeypatch, request):
    for name in ("_lines_cached", "_scan_lines_cached", "_spans_cached"):
        cache = lru_cache(maxsize=128)(getattr(lr, name).__wrapped__)
        request.addfinalizer(cache.cache_clear)
        monkeypatch.setattr(lr, name, cache)


@requires_ts("c")
@pytest.mark.usefixtures("owned_caches")
@pytest.mark.parametrize("separator", [
    pytest.param("\v", id="vt"), pytest.param("\f", id="ff"),
    pytest.param("\r ", id="bare-cr"),
])
@pytest.mark.parametrize("source,outcome", [(SSL_SESS, "confirmed"), (SSL_SESS_UNLOCK_FIRST, "refuted")], ids=["under-lock", "after-release"])
def test_valid_c_whitespace_does_not_shift_callback_receipts(separator, source, outcome):
    text = separator + source
    result = lr.run_lock_region_check(
        Path("/nonexistent"), "owner.c", "flush_sessions", HYP,
        source_texts={"owner.c": text},
        domain_vocab=_Vocab(lock_pairs={("CRYPTO_THREAD_write_lock", "CRYPTO_THREAD_unlock")}),
    )
    assert result.outcome == outcome
    if outcome == "confirmed":
        line = next(i for i, row in enumerate(split_lines(text), 1) if "ctx->remove_cb(1)" in row)
        assert result.callback["line"] == line
        assert result.callback["code"] == "ctx->remove_cb(1);"
        assert result.region["span"][0] <= line <= result.region["span"][1]


@pytest.mark.usefixtures("owned_caches")
@pytest.mark.parametrize("breaker", [
    pytest.param("\v", id="vt"), pytest.param("\f", id="ff"), pytest.param("\r", id="cr"),
    pytest.param("\x1c", id="fs"), pytest.param("\x1d", id="gs"), pytest.param("\x1e", id="rs"),
    pytest.param("\x85", id="nel"), pytest.param("\u2028", id="ls"), pytest.param("\u2029", id="ps"),
])
def test_raw_cached_rows_match_external_source_coordinates(breaker):
    source = "first " + breaker + " second\nlast\r\n\r"
    assert lr._lines_cached(source) == tuple(split_lines(source))


@pytest.mark.parametrize("start,end", [(1, 3), (2499, 2503), (2502, 2510), (1, 9999), (0, 3), (3, 2)])
def test_raw_function_rows_match_eager_slices(start, end):
    source = "padding\r\n" * 2500 + "\n\r\n"
    assert lr._raw_function_lines(source, FunctionSpan("owner", start, end)) == split_lines(source)[start - 1:end]


def test_scan_tuple_only_copies_requested_rows():
    rows = tuple(f"row {i}" for i in range(10000))
    view = module_function_view(lr, bindings={"_scan_lines_cached": lambda source: rows})
    result = view._scan_function_lines("unused", FunctionSpan("owner", 300, 302))
    assert type(result) is list
    assert result == ["row 299", "row 300", "row 301"]


def test_custom_scan_provider_is_materialized_before_reading_span():
    seen = []

    class Rows:
        def __iter__(self):
            seen.append("iterate")
            yield from ["first", "", "last"]

    class Span:
        @property
        def start(self):
            seen.append("start")
            return 1

        @property
        def end(self):
            seen.append("end")
            return 2

    view = module_function_view(lr, bindings={"_scan_lines_cached": lambda source: Rows()})
    assert view._scan_function_lines("unused", Span()) == ["first", ""]
    assert seen == ["iterate", "start", "end"]


def test_raw_custom_splitter_stays_authoritative():
    seen = []

    def split(source):
        seen.append(source)
        return ["first", "", "last"]

    source = "padding\n" * 2500
    view = module_function_view(lr, bindings={"split_lines": split})
    assert view._raw_function_lines(source, FunctionSpan("owner", 1, 2)) == ["first", ""]
    assert seen == [source]


@pytest.mark.usefixtures("owned_caches")
def test_raw_cache_preserves_source_adapter_splitlines():
    calls = []

    class Source(str):
        def splitlines(self):
            calls.append("splitlines")
            return ["adapter", "rows"]

    assert lr._lines_cached(Source("custom-source")) == ("adapter", "rows")
    assert calls == ["splitlines"]


def test_custom_scan_materialization_can_change_native_span():
    span = FunctionSpan("owner", 1, 1)

    class Rows:
        def __iter__(self):
            span.start, span.end = 2, 3
            yield from ["first", "", "last"]

    view = module_function_view(lr, bindings={"_scan_lines_cached": lambda source: Rows()})
    assert view._scan_function_lines("unused", span) == ["", "last"]


@requires_ts("c")
@pytest.mark.usefixtures("owned_caches")
def test_cross_function_release_uses_canonical_raw_rows():
    source = (
        "\f" * 20 + "void do_unlock(struct s *s) {\n"
        "    pthread_mutex_unlock(s->m);\n}\n"
        "void f(struct s *s) {\n"
        "    pthread_mutex_lock(s->m);\n"
        "    s->cb(1);\n    do_unlock(s);\n}\n"
    )
    result = lr.run_lock_region_check(Path("/nonexistent"), "owner.c", "f", HYP,
                                      source_texts={"owner.c": source})
    assert result.outcome == "inconclusive"
    assert result.reason.startswith(lr.REASON_REGION_SPANS_CALLEE)
    assert "do_unlock" in result.reason
