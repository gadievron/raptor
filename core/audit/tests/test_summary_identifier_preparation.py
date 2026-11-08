"""Native identifier batches retain complete tokens and provider contracts."""

import pytest

from core.audit import llm_summaries as summaries
from core.testing.module_views import module_function_view


@pytest.mark.parametrize("offset", [-2, -1, 0, 1, 2])
@pytest.mark.parametrize("separator", ["\n", "\r\n"])
def test_identifier_boundaries(offset, separator):
    source = ("a" * (32768 + offset) + separator + "identifier_123\t") * 3
    assert summaries._summary_identifiers(source) == set(summaries._IDENT_RE.findall(source))


@pytest.mark.parametrize("source", ["", "\n" * 80000, "identifier" * 10000,
                                     "a\u2028b\u0085c\rD" * 10000])
def test_degenerate_and_unicode_separators(source):
    assert summaries._summary_identifiers(source) == set(summaries._IDENT_RE.findall(source))


def test_foreign_regex_keeps_single_argument_findall():
    calls = []

    class Matcher:
        def findall(self, source):
            calls.append(source)
            return ["provider"]

    view = module_function_view(summaries, bindings={"_IDENT_RE": Matcher()})
    source = "word\n" * 20000
    assert view._summary_identifiers(source) == {"provider"}
    assert calls == [source]


def test_source_adapter_does_not_use_window_methods():
    class Source(str):
        def rfind(self, *args):
            raise AssertionError("adapter windowed")

    source = Source("word\n" * 20000)
    assert summaries._summary_identifiers(source) == {"word"}


def test_foreign_set_keeps_match_list():
    calls = []

    def collect(values):
        assert type(values) is list
        calls.append(values)
        return {"provider"}

    view = module_function_view(summaries, bindings={"set": collect})
    assert view._summary_identifiers("word\n" * 20000) == {"provider"}
    assert len(calls) == 1


@pytest.mark.parametrize("name", ["len", "min"])
def test_foreign_scanner_primitive_keeps_whole_source(name):
    def foreign(*args):
        raise AssertionError("new scanner primitive reached")

    view = module_function_view(summaries, bindings={name: foreign})
    assert view._summary_identifiers("word\n" * 20000) == {"word"}
