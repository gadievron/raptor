"""Parse-cache hits require native source equality, not a hash summary."""

from collections import OrderedDict
from types import SimpleNamespace

import pytest

from core.audit import callsite_consistency as census
from core.testing import requires_ts
from core.testing.module_views import module_function_view


FIRST = "int first(void) { return 1; }\n"
OTHER = "int other(void) { return 2; }\n"


@pytest.fixture
def consumer():
    return module_function_view(census, bindings={"_parse_cache": OrderedDict()})


@requires_ts("c")
def test_different_native_sources_cannot_share_a_hash_only_entry(consumer):
    # Force the former hash-summary seam without changing shared builtins.
    vars(consumer)["hash"] = lambda source: 17
    first, language = consumer.parse_source_cached("owned.c", FIRST)
    other, _ = consumer.parse_source_cached("owned.c", OTHER)
    assert language == "c" and first is not None and other is not None
    assert b"first" in first.root_node.text
    assert b"other" in other.root_node.text
    assert first is not other


@requires_ts("c")
def test_equal_native_content_reuses_the_tree_without_parser_work(consumer):
    selected = []

    def parser(language):
        selected.append(language)
        return census._get_parser(language)

    vars(consumer)["_get_parser"] = parser
    equal = FIRST.encode().decode()
    assert equal == FIRST and equal is not FIRST
    first = consumer.parse_source_cached("owned.c", FIRST)
    second = consumer.parse_source_cached("owned.c", equal)
    assert first[0] is not None and second[0] is first[0]
    assert consumer.parse_source_cached("owned.c", equal) is second
    assert consumer.parse_source_cached("owned.c", FIRST.encode().decode()) is second
    assert selected == ["c"]
    assert len(consumer._parse_cache) == 1


@requires_ts("c")
def test_source_adapters_with_colliding_hashes_parse_their_own_content(consumer):
    class Source(str):
        def __hash__(self):
            return 17

    first_source, other_source = Source(FIRST), Source(OTHER)
    assert len(first_source) == len(other_source)
    assert hash(first_source) == hash(other_source)
    first, language = consumer.parse_source_cached("owned.c", first_source)
    other, _ = consumer.parse_source_cached("owned.c", other_source)
    assert language == "c" and first is not None and other is not None
    assert b"first" in first.root_node.text
    assert b"other" in other.root_node.text
    assert consumer._parse_cache == {}


@requires_ts("c")
def test_source_adapter_encoding_is_not_hidden_by_a_cache_hit(consumer):
    encodings = []

    class Source(str):
        def encode(self, *args, **kwargs):
            text = FIRST if not encodings else OTHER
            encodings.append(text)
            return text.encode(*args, **kwargs)

    source = Source("adapter text")
    first, _ = consumer.parse_source_cached("owned.c", source)
    other, _ = consumer.parse_source_cached("owned.c", source)
    assert first is not None and other is not None
    assert b"first" in first.root_node.text and b"other" in other.root_node.text
    assert encodings == [FIRST, OTHER]


@requires_ts("c")
def test_unhashable_string_adapter_still_parses(consumer):
    class Source(str):
        __hash__ = None

    tree, language = consumer.parse_source_cached("owned.c", Source(FIRST))
    assert language == "c" and tree is not None
    assert b"first" in tree.root_node.text


@requires_ts("c")
def test_path_adapters_do_not_alias_cache_entries(consumer):
    class Path(str):
        def __eq__(self, other):
            return True

        def __hash__(self):
            return 17

    first, _ = consumer.parse_source_cached(Path("first.c"), FIRST)
    other, _ = consumer.parse_source_cached(Path("other.c"), OTHER)
    assert first is not None and other is not None
    assert b"first" in first.root_node.text and b"other" in other.root_node.text
    assert consumer._parse_cache == {}


@requires_ts("c")
def test_native_cache_still_refreshes_lru_recency_and_evicts(consumer):
    vars(consumer)["_PARSE_CACHE_MAX"] = 2
    first, _ = consumer.parse_source_cached("first.c", FIRST)
    other, _ = consumer.parse_source_cached("other.c", OTHER)
    assert first is not None and other is not None
    assert consumer.parse_source_cached("first.c", FIRST.encode().decode())[0] is first
    consumer.parse_source_cached("third.c", FIRST)
    assert consumer.parse_source_cached("first.c", FIRST)[0] is first
    assert consumer.parse_source_cached("other.c", OTHER)[0] is not other
    assert len(consumer._parse_cache) == 2


@requires_ts("c")
def test_clear_releases_native_entries_and_reparses(consumer):
    first, _ = consumer.parse_source_cached("owned.c", FIRST)
    assert first is not None
    consumer.clear_parse_cache()
    assert consumer._parse_cache == {}
    second, _ = consumer.parse_source_cached("owned.c", FIRST)
    assert second is not None and second is not first
    assert second.root_node.text == first.root_node.text


def test_missing_tree_sitter_never_selects_a_parser(consumer):
    def unexpected(language):
        pytest.fail("selected a parser while tree-sitter is unavailable")

    vars(consumer).update(_TS_AVAILABLE=False, _get_parser=unexpected)
    assert consumer.parse_source_cached("owned.c", FIRST) == (None, None)
    assert consumer._parse_cache == {}


def test_missing_language_parser_keeps_native_negative_cache(consumer):
    selected = []

    def missing(language):
        selected.append(language)
        return None

    vars(consumer).update(_TS_AVAILABLE=True, _get_parser=missing)
    assert consumer.parse_source_cached("owned.c", FIRST) == (None, None)
    assert consumer.parse_source_cached("owned.c", FIRST) == (None, None)
    assert selected == ["c"]


def test_failed_parse_is_propagated_and_not_cached(consumer):
    reached = []

    def fail(source):
        reached.append(source)
        raise MemoryError("owned parse failure")

    vars(consumer).update(_TS_AVAILABLE=True,
                          _get_parser=lambda language: SimpleNamespace(parse=fail))
    with pytest.raises(MemoryError, match="owned parse failure"):
        consumer.parse_source_cached("owned.c", FIRST)
    assert reached == [FIRST.encode()]
    assert consumer._parse_cache == {}
